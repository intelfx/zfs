// SPDX-License-Identifier: CDDL-1.0
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2021-2022 Tino Reichardt <milky-zfs@mcmilk.de>
 */

#include <sys/zio_checksum.h>
#include <sys/zfs_context.h>
#include <sys/zfs_chksum.h>
#include <sys/zfs_impl.h>

#include <sys/blake3.h>
#include <sys/sha2.h>
#include <zfs_fletcher.h>

/* Block sizes to benchmark, and how many rounds to batch per timing loop */
static const uint64_t chksum_bs[] = {
	1<<10, 1<<12, 1<<14, 1<<16, 1<<17, 1<<18, 1<<20, 1<<22, 1<<24
};
static const uint32_t chksum_bs_loops[] = {
	128, 64, 32, 16, 8, 8, 4, 1, 1
};
static const char *const chksum_bs_name[] = {
	"1k", "4k", "16k", "64k", "128k", "256k", "1m", "4m", "16m"
};

#define	CHKSUM_BS_CNT	ARRAY_SIZE(chksum_bs)

/* Block sizes below this index use a linear abd, the rest a scattered one */
#define	CHKSUM_BS_LINEAR	7

/* Block size the implementation selection is based on */
#define	CHKSUM_BS_SELECT	5

typedef enum {
	CHKSUM_ROW_BENCH = 0,	/* timings of one algorithm+implementation */
	CHKSUM_ROW_IMPL,	/* implementation in use for one algorithm */
	CHKSUM_ROW_BEST,	/* fastest algorithm per block size */
} chksum_row_t;

typedef struct {
	chksum_row_t row;
	const char *name;
	const char *impl;
	uint64_t bs[CHKSUM_BS_CNT];
	zio_cksum_salt_t salt;
	zio_checksum_t *(func);
	zio_checksum_tmpl_init_t *(init);
	zio_checksum_tmpl_free_t *(free);

	/*
	 * CHKSUM_ROW_BENCH: the checksum= value this row measures, or
	 * ZIO_CHECKSUM_INHERIT if the row is not selectable as one - which is
	 * the case for the byteswapping direction of fletcher4.
	 */
	enum zio_checksum ck;

	/*
	 * CHKSUM_ROW_IMPL: names the implementation that would be used for a
	 * checksum computed right now.
	 */
	const char *(*used_impl)(void);

	/* CHKSUM_ROW_BEST: only compare dedup-capable algorithms */
	boolean_t dedup_only;
} chksum_stat_t;

/*
 * Width of the implementation column.  The longest "<algorithm>-<impl>" pair
 * currently emitted is "fletcher4_byteswap-superscalar4"; longer ones are
 * truncated to keep the columns aligned.
 */
#define	CHKSUM_IMPL_WIDTH	34

/*
 * Width of the per-block-size columns.  Sized for "fletcher4" in the summary
 * rows, which is longer than any throughput figure we expect.
 */
#define	CHKSUM_DATA_WIDTH	10

#define	AT_STARTUP	0
#define	AT_BENCHMARK	1
#define	AT_DONE		2

static chksum_stat_t *chksum_stat_data = 0;
static kstat_t *chksum_kstat = NULL;
static int chksum_stat_limit = AT_STARTUP;
static int chksum_stat_cnt = 0;
static void chksum_benchmark(void);

/*
 * fletcher4 is reported twice, as "fletcher4" for the native and
 * "fletcher4_byteswap" for the byteswapping direction, since ZFS picks an
 * implementation for each of them separately.
 *
 * The last two rows answer which "-o checksum=" is cheapest at a given block
 * size: "best-overall" over all algorithms, "best-dedup" over those usable as
 * a dedup checksum on their own.  Note that edonr is absent from the latter
 * because it is only accepted as "dedup=edonr,verify".
 *
 * Sample output on i3-1005G1 System, fletcher4 rows elided.  Every algorithm
 * is followed by a
 * "-fastest" row, which carries no timings and instead names the
 * implementation that a checksum computed right now would use - the benchmark
 * winner, unless the algorithm's module parameter pins a specific one.
 *
 * implementation   1k      4k     16k     64k    128k    256k      1m     16m
 * edonr-generic  1278    1625    1769    1776    1783    1778    1771    1767
 * edonr-fastest         generic
 * skein-generic   548     594     613     623     621     623     621     486
 * skein-fastest         generic
 * sha256-generic  255     270     281     278     279     281     283     283
 * sha256-x64      288     310     316     317     318     317     317     316
 * sha256-ssse3    304     342     351     355     356     357     356     356
 * sha256-avx      311     348     359     362     362     363     363     362
 * sha256-avx2     330     378     389     395     395     395     395     395
 * sha256-shani    908    1127    1212    1230    1233    1234    1223    1230
 * sha256-fastest          shani
 * sha512-generic  359     409     431     427     429     430     428     423
 * sha512-x64      420     473     490     496     497     497     496     495
 * sha512-avx      406     522     546     560     560     560     556     560
 * sha512-avx2     464     568     601     606     609     610     607     608
 * sha512-fastest           avx2
 * blake3-generic  330     327     324     323     324     320     323     322
 * blake3-sse2     424    1366    1449    1468    1458    1453    1395    1408
 * blake3-sse41    453    1554    1658    1703    1689    1669    1622    1630
 * blake3-avx2     452    2013    3225    3351    3356    3261    3076    3101
 * blake3-avx512   498    2869    5269    5926    5872    5643    5014    5005
 * blake3-fastest         avx512
 * best-dedup             sha256  blake3  blake3  blake3  blake3  blake3  blake3
 */
static int
chksum_kstat_headers(char *buf, size_t size)
{
	ssize_t off = 0;

	off += kmem_scnprintf(buf + off, size, "%-*s", CHKSUM_IMPL_WIDTH,
	    "implementation");
	for (int i = 0; i < CHKSUM_BS_CNT; i++)
		off += kmem_scnprintf(buf + off, size - off, "%*s",
		    CHKSUM_DATA_WIDTH, chksum_bs_name[i]);
	(void) kmem_scnprintf(buf + off, size - off, "\n");

	return (0);
}

/*
 * Fastest algorithm at each block size, taken over the fastest implementation
 * of each one.  Answers which "-o checksum=" performs best on this machine.
 */
static ssize_t
chksum_kstat_best(char *buf, size_t size, boolean_t dedup_only)
{
	ssize_t off = 0;

	for (int i = 0; i < CHKSUM_BS_CNT; i++) {
		const char *best = "-";
		uint64_t max = 0;

		for (int n = 0; n < chksum_stat_cnt; n++) {
			const chksum_stat_t *cs = &chksum_stat_data[n];

			if (cs->row != CHKSUM_ROW_BENCH ||
			    cs->ck == ZIO_CHECKSUM_INHERIT)
				continue;
			if (dedup_only && !(zio_checksum_table[cs->ck].ci_flags
			    & ZCHECKSUM_FLAG_DEDUP))
				continue;
			if (cs->bs[i] > max) {
				max = cs->bs[i];
				best = cs->name;
			}
		}

		off += kmem_scnprintf(buf + off, size - off, "%*s",
		    CHKSUM_DATA_WIDTH, best);
	}

	return (off);
}

static int
chksum_kstat_data(char *buf, size_t size, void *data)
{
	chksum_stat_t *cs;
	ssize_t off = 0;
	char b[CHKSUM_IMPL_WIDTH + 1];

	cs = (chksum_stat_t *)data;
	kmem_scnprintf(b, CHKSUM_IMPL_WIDTH, "%s-%s", cs->name, cs->impl);
	off += kmem_scnprintf(buf + off, size - off, "%-*s",
	    CHKSUM_IMPL_WIDTH, b);

	switch (cs->row) {
	case CHKSUM_ROW_IMPL:
		off += kmem_scnprintf(buf + off, size - off, "%*s",
		    CHKSUM_DATA_WIDTH, cs->used_impl());
		break;
	case CHKSUM_ROW_BEST:
		off += chksum_kstat_best(buf + off, size - off,
		    cs->dedup_only);
		break;
	case CHKSUM_ROW_BENCH:
		for (int i = 0; i < CHKSUM_BS_CNT; i++)
			off += kmem_scnprintf(buf + off, size - off, "%*llu",
			    CHKSUM_DATA_WIDTH, (u_longlong_t)cs->bs[i]);
		break;
	}
	(void) kmem_scnprintf(buf + off, size - off, "\n");

	return (0);
}

static void *
chksum_kstat_addr(kstat_t *ksp, loff_t n)
{
	/* full benchmark */
	chksum_benchmark();

	if (n < chksum_stat_cnt)
		ksp->ks_private = (void *)(chksum_stat_data + n);
	else
		ksp->ks_private = NULL;

	return (ksp->ks_private);
}

static void
chksum_run(chksum_stat_t *cs, abd_t *abd, void *ctx, int round)
{
	hrtime_t start;
	uint64_t run_bw, run_time_ns, run_count = 0;
	uint64_t size = chksum_bs[round];
	uint32_t l, loops = chksum_bs_loops[round];
	zio_cksum_t zcp;

	kpreempt_disable();
	start = gethrtime();
	do {
		for (l = 0; l < loops; l++, run_count++)
			cs->func(abd, size, ctx, &zcp);

		run_time_ns = gethrtime() - start;
	} while (run_time_ns < MSEC2NSEC(1));
	kpreempt_enable();

	run_bw = size * run_count * NANOSEC;
	run_bw /= run_time_ns; /* B/s */
	cs->bs[round] = run_bw/1024/1024; /* MiB/s */
}

/*
 * Resolvers for the summary rows.  edonr and skein have a single generic
 * implementation each; the remaining algorithms dispatch at runtime.
 */
static const char *
chksum_impl_generic(void)
{
	return ("generic");
}

static const char *
chksum_impl_sha256(void)
{
	return (zfs_impl_get_ops("sha256")->get_effective_name());
}

static const char *
chksum_impl_sha512(void)
{
	return (zfs_impl_get_ops("sha512")->get_effective_name());
}

static const char *
chksum_impl_blake3(void)
{
	return (zfs_impl_get_ops("blake3")->get_effective_name());
}

static const char *
chksum_impl_fletcher_4_native(void)
{
	return (fletcher_4_impl_get_effective_name(B_FALSE));
}

static const char *
chksum_impl_fletcher_4_byteswap(void)
{
	return (fletcher_4_impl_get_effective_name(B_TRUE));
}

static void
chksum_summary(chksum_stat_t *cs, const char *name,
    const char *(*used_impl)(void))
{
	cs->row = CHKSUM_ROW_IMPL;
	cs->name = name;
	cs->impl = "fastest";
	cs->used_impl = used_impl;
}

static void
chksum_best(chksum_stat_t *cs, const char *impl, boolean_t dedup_only)
{
	cs->row = CHKSUM_ROW_BEST;
	cs->name = "best";
	cs->impl = impl;
	cs->dedup_only = dedup_only;
}

static void
chksum_benchit(chksum_stat_t *cs)
{
	abd_t *abd;
	void *ctx = 0;
	void *salt = &cs->salt.zcs_bytes;

	memset(salt, 0, sizeof (cs->salt.zcs_bytes));
	if (cs->init)
		ctx = cs->init(&cs->salt);

	/* benchmarks in startup mode */
	if (chksum_stat_limit == AT_STARTUP) {
		abd = abd_alloc_linear(chksum_bs[CHKSUM_BS_SELECT], B_FALSE);
		chksum_run(cs, abd, ctx, CHKSUM_BS_SELECT);
		goto done;
	}

	/* allocate test memory via abd linear interface */
	abd = abd_alloc_linear(chksum_bs[CHKSUM_BS_LINEAR - 1], B_FALSE);

	/* benchmarks when requested */
	for (int i = 0; i < CHKSUM_BS_LINEAR; i++)
		chksum_run(cs, abd, ctx, i);
	abd_free(abd);

	/* allocate test memory via abd non linear interface */
	abd = abd_alloc(chksum_bs[CHKSUM_BS_CNT - 1], B_FALSE);
	for (int i = CHKSUM_BS_LINEAR; i < CHKSUM_BS_CNT; i++)
		chksum_run(cs, abd, ctx, i);

done:
	abd_free(abd);

	/* free up temp memory */
	if (cs->free)
		cs->free(ctx);
}

/*
 * Initialize and benchmark all supported implementations.
 */
static void
chksum_benchmark(void)
{
#ifndef _KERNEL
	/* we need the benchmark only for the kernel module */
	return;
#endif
	chksum_stat_t *cs;
	uint64_t max;
	uint32_t id, cbid = 0, id_save;
	const zfs_impl_t *blake3 = zfs_impl_get_ops("blake3");
	const zfs_impl_t *sha256 = zfs_impl_get_ops("sha256");
	const zfs_impl_t *sha512 = zfs_impl_get_ops("sha512");

	/* benchmarks are done */
	if (chksum_stat_limit == AT_DONE)
		return;

	/* count implementations, plus one summary row per algorithm */
	if (chksum_stat_limit == AT_STARTUP) {
		chksum_stat_cnt = 1 + 1;  /* edonr */
		chksum_stat_cnt += 1 + 1; /* skein */
		chksum_stat_cnt += sha256->getcnt() + 1;
		chksum_stat_cnt += sha512->getcnt() + 1;
		chksum_stat_cnt += blake3->getcnt() + 1;
		/* fletcher4 is measured natively and byteswapping */
		chksum_stat_cnt += 2 * (fletcher_4_impl_getcnt() + 1);
		/* fastest algorithm overall, and among dedup-capable ones */
		chksum_stat_cnt += 2;
		chksum_stat_data = kmem_zalloc(
		    sizeof (chksum_stat_t) * chksum_stat_cnt, KM_SLEEP);
	}

	/* edonr - needs to be the first one here (slow CPU check) */
	cs = &chksum_stat_data[cbid++];

	/* edonr */
	cs->init = abd_checksum_edonr_tmpl_init;
	cs->func = abd_checksum_edonr_native;
	cs->free = abd_checksum_edonr_tmpl_free;
	cs->name = "edonr";
	cs->impl = "generic";
	cs->ck = ZIO_CHECKSUM_EDONR;
	chksum_benchit(cs);
	chksum_summary(&chksum_stat_data[cbid++], "edonr", chksum_impl_generic);

	/* skein */
	cs = &chksum_stat_data[cbid++];
	cs->init = abd_checksum_skein_tmpl_init;
	cs->func = abd_checksum_skein_native;
	cs->free = abd_checksum_skein_tmpl_free;
	cs->name = "skein";
	cs->impl = "generic";
	cs->ck = ZIO_CHECKSUM_SKEIN;
	chksum_benchit(cs);
	chksum_summary(&chksum_stat_data[cbid++], "skein", chksum_impl_generic);

	/* sha256 */
	id_save = sha256->getid();
	for (max = 0, id = 0; id < sha256->getcnt(); id++) {
		sha256->setid(id);
		cs = &chksum_stat_data[cbid++];
		cs->init = 0;
		cs->func = abd_checksum_sha256;
		cs->free = 0;
		cs->name = sha256->name;
		cs->impl = sha256->getname();
		cs->ck = ZIO_CHECKSUM_SHA256;
		chksum_benchit(cs);
		if (cs->bs[CHKSUM_BS_SELECT] > max) {
			max = cs->bs[CHKSUM_BS_SELECT];
			sha256->set_fastest(id);
		}
	}
	sha256->setid(id_save);
	chksum_summary(&chksum_stat_data[cbid++], "sha256", chksum_impl_sha256);

	/* sha512 */
	id_save = sha512->getid();
	for (max = 0, id = 0; id < sha512->getcnt(); id++) {
		sha512->setid(id);
		cs = &chksum_stat_data[cbid++];
		cs->init = 0;
		cs->func = abd_checksum_sha512_native;
		cs->free = 0;
		cs->name = sha512->name;
		cs->impl = sha512->getname();
		cs->ck = ZIO_CHECKSUM_SHA512;
		chksum_benchit(cs);
		if (cs->bs[CHKSUM_BS_SELECT] > max) {
			max = cs->bs[CHKSUM_BS_SELECT];
			sha512->set_fastest(id);
		}
	}
	sha512->setid(id_save);
	chksum_summary(&chksum_stat_data[cbid++], "sha512", chksum_impl_sha512);

	/* blake3 */
	id_save = blake3->getid();
	for (max = 0, id = 0; id < blake3->getcnt(); id++) {
		blake3->setid(id);
		cs = &chksum_stat_data[cbid++];
		cs->init = abd_checksum_blake3_tmpl_init;
		cs->func = abd_checksum_blake3_native;
		cs->free = abd_checksum_blake3_tmpl_free;
		cs->name = blake3->name;
		cs->impl = blake3->getname();
		cs->ck = ZIO_CHECKSUM_BLAKE3;
		chksum_benchit(cs);
		if (cs->bs[CHKSUM_BS_SELECT] > max) {
			max = cs->bs[CHKSUM_BS_SELECT];
			blake3->set_fastest(id);
		}
	}
	blake3->setid(id_save);
	chksum_summary(&chksum_stat_data[cbid++], "blake3", chksum_impl_blake3);

	/*
	 * fletcher4.  Unlike the algorithms above, the implementation actually
	 * used is picked by fletcher_4_init(), which runs its own benchmark;
	 * we only measure and report here.  The startup pass exists solely to
	 * select implementations, so skip it.
	 */
	id_save = fletcher_4_impl_getid();
	for (id = 0; id < fletcher_4_impl_getcnt(); id++) {
		cs = &chksum_stat_data[cbid++];
		cs->init = 0;
		cs->func = abd_fletcher_4_native;
		cs->free = 0;
		cs->name = "fletcher4";
		cs->impl = fletcher_4_impl_getname(id);
		cs->ck = ZIO_CHECKSUM_FLETCHER_4;
		if (chksum_stat_limit != AT_STARTUP) {
			fletcher_4_impl_setid(id);
			chksum_benchit(cs);
		}
	}
	chksum_summary(&chksum_stat_data[cbid++], "fletcher4",
	    chksum_impl_fletcher_4_native);

	for (id = 0; id < fletcher_4_impl_getcnt(); id++) {
		cs = &chksum_stat_data[cbid++];
		cs->init = 0;
		cs->func = abd_fletcher_4_byteswap;
		cs->free = 0;
		cs->name = "fletcher4_byteswap";
		cs->impl = fletcher_4_impl_getname(id);
		if (chksum_stat_limit != AT_STARTUP) {
			fletcher_4_impl_setid(id);
			chksum_benchit(cs);
		}
	}
	chksum_summary(&chksum_stat_data[cbid++], "fletcher4_byteswap",
	    chksum_impl_fletcher_4_byteswap);
	fletcher_4_impl_setid(id_save);

	/*
	 * Fastest algorithm per block size.  The byteswapping rows are left
	 * out of the comparison: their checksum= value is the same fletcher4,
	 * the direction is dictated by the pool's endianness.
	 */
	chksum_best(&chksum_stat_data[cbid++], "overall", B_FALSE);
	chksum_best(&chksum_stat_data[cbid++], "dedup", B_TRUE);

	ASSERT3U(cbid, ==, chksum_stat_cnt);

	switch (chksum_stat_limit) {
	case AT_STARTUP:
		/* next time we want a full benchmark */
		chksum_stat_limit = AT_BENCHMARK;
		break;
	case AT_BENCHMARK:
		/* no further benchmarks */
		chksum_stat_limit = AT_DONE;
		break;
	}
}

void
chksum_init(void)
{
#ifdef _KERNEL
	blake3_per_cpu_ctx_init();
#endif

	/* 256KiB benchmark */
	chksum_benchmark();

	/* Install kstats for all implementations */
	chksum_kstat = kstat_create("zfs", 0, "chksum_bench", "misc",
	    KSTAT_TYPE_RAW, 0, KSTAT_FLAG_VIRTUAL);

	if (chksum_kstat != NULL) {
		chksum_kstat->ks_data = NULL;
		chksum_kstat->ks_ndata = UINT32_MAX;
		kstat_set_raw_ops(chksum_kstat,
		    chksum_kstat_headers,
		    chksum_kstat_data,
		    chksum_kstat_addr);
		kstat_install(chksum_kstat);
	}
}

void
chksum_fini(void)
{
	if (chksum_kstat != NULL) {
		kstat_delete(chksum_kstat);
		chksum_kstat = NULL;
	}

	if (chksum_stat_cnt) {
		kmem_free(chksum_stat_data,
		    sizeof (chksum_stat_t) * chksum_stat_cnt);
		chksum_stat_cnt = 0;
		chksum_stat_data = 0;
	}

#ifdef _KERNEL
	blake3_per_cpu_ctx_fini();
#endif
}
