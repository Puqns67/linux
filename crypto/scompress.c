// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Synchronous Compression operations
 *
 * Copyright 2015 LG Electronics Inc.
 * Copyright (c) 2016, Intel Corporation
 * Author: Giovanni Cabiddu <giovanni.cabiddu@intel.com>
 */

#include <crypto/internal/acompress.h>
#include <crypto/internal/scompress.h>
#include <crypto/scatterwalk.h>
#include <linux/cryptouser.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <net/netlink.h>

#include "compress.h"

struct scomp_scratch {
	spinlock_t	lock;
	void		*src;
	void		*dst;
};

static DEFINE_PER_CPU(struct scomp_scratch, scomp_scratch) = {
	.lock = __SPIN_LOCK_UNLOCKED(scomp_scratch.lock),
};

static const struct crypto_type crypto_scomp_type;
static int scomp_scratch_users;
static DEFINE_MUTEX(scomp_lock);

static int __maybe_unused crypto_scomp_report(
	struct sk_buff *skb, struct crypto_alg *alg)
{
	struct crypto_report_comp rscomp;

	memset(&rscomp, 0, sizeof(rscomp));

	strscpy(rscomp.type, "scomp", sizeof(rscomp.type));

	return nla_put(skb, CRYPTOCFGA_REPORT_COMPRESS,
		       sizeof(rscomp), &rscomp);
}

static void crypto_scomp_show(struct seq_file *m, struct crypto_alg *alg)
	__maybe_unused;

static void crypto_scomp_show(struct seq_file *m, struct crypto_alg *alg)
{
	seq_puts(m, "type         : scomp\n");
}

static void crypto_scomp_free_scratches(void)
{
	struct scomp_scratch *scratch;
	int i;

	for_each_possible_cpu(i) {
		scratch = per_cpu_ptr(&scomp_scratch, i);

		vfree(scratch->src);
		vfree(scratch->dst);
		scratch->src = NULL;
		scratch->dst = NULL;
	}
}

static int crypto_scomp_alloc_scratches(void)
{
	struct scomp_scratch *scratch;
	int i;

	for_each_possible_cpu(i) {
		void *mem;

		scratch = per_cpu_ptr(&scomp_scratch, i);

		mem = vmalloc_node(SCOMP_SCRATCH_SIZE, cpu_to_node(i));
		if (!mem)
			goto error;
		scratch->src = mem;
		mem = vmalloc_node(SCOMP_SCRATCH_SIZE, cpu_to_node(i));
		if (!mem)
			goto error;
		scratch->dst = mem;
	}
	return 0;
error:
	crypto_scomp_free_scratches();
	return -ENOMEM;
}

static void scomp_free_streams(struct scomp_alg *alg)
{
	struct crypto_acomp_stream __percpu *stream = alg->stream;
	int i;

	for_each_possible_cpu(i) {
		struct crypto_acomp_stream *ps = per_cpu_ptr(stream, i);

		if (!ps->ctx)
			break;

		alg->free_ctx(ps);
	}

	free_percpu(stream);
}

static int scomp_alloc_streams(struct scomp_alg *alg)
{
	struct crypto_acomp_stream __percpu *stream;
	int i;

	stream = alloc_percpu(struct crypto_acomp_stream);
	if (!stream)
		return -ENOMEM;

	for_each_possible_cpu(i) {
		struct crypto_acomp_stream *ps = per_cpu_ptr(stream, i);

		ps->ctx = alg->alloc_ctx();
		if (IS_ERR(ps->ctx)) {
			scomp_free_streams(alg);
			return PTR_ERR(ps->ctx);
		}

		spin_lock_init(&ps->lock);
	}

	alg->stream = stream;
	return 0;
}

static int crypto_scomp_init_tfm(struct crypto_tfm *tfm)
{
	struct scomp_alg *alg = crypto_scomp_alg(__crypto_scomp_tfm(tfm));
	int ret = 0;

	mutex_lock(&scomp_lock);
	if (!alg->stream) {
		ret = scomp_alloc_streams(alg);
		if (ret)
			goto unlock;
	}
	if (!scomp_scratch_users++)
		ret = crypto_scomp_alloc_scratches();
unlock:
	mutex_unlock(&scomp_lock);

	return ret;
}

static int scomp_acomp_comp_decomp(struct acomp_req *req, int dir)
{
	struct crypto_acomp *tfm = crypto_acomp_reqtfm(req);
	void **tfm_ctx = acomp_tfm_ctx(tfm);
	struct crypto_scomp *scomp = *tfm_ctx;
	struct crypto_acomp_stream *stream;
	struct scomp_scratch *scratch;
	void *src, *dst;
	unsigned int dlen;
	int ret;

	if (!req->src || !req->slen || req->slen > SCOMP_SCRATCH_SIZE)
		return -EINVAL;

	if (req->dst && !req->dlen)
		return -EINVAL;

	if (!req->dlen || req->dlen > SCOMP_SCRATCH_SIZE)
		req->dlen = SCOMP_SCRATCH_SIZE;

	dlen = req->dlen;

	scratch = raw_cpu_ptr(&scomp_scratch);
	spin_lock_bh(&scratch->lock);

	if (sg_nents(req->src) == 1 && !PageHighMem(sg_page(req->src))) {
		src = page_to_virt(sg_page(req->src)) + req->src->offset;
	} else {
		scatterwalk_map_and_copy(scratch->src, req->src, 0,
					 req->slen, 0);
		src = scratch->src;
	}

	if (req->dst && sg_nents(req->dst) == 1 && !PageHighMem(sg_page(req->dst)))
		dst = page_to_virt(sg_page(req->dst)) + req->dst->offset;
	else
		dst = scratch->dst;

	stream = raw_cpu_ptr(crypto_scomp_alg(scomp)->stream);
	spin_lock(&stream->lock);
	if (dir)
		ret = crypto_scomp_compress(scomp, src, req->slen,
					    dst, &req->dlen, stream->ctx);
	else
		ret = crypto_scomp_decompress(scomp, src, req->slen,
					      dst, &req->dlen, stream->ctx);
	spin_unlock(&stream->lock);
	if (!ret) {
		if (!req->dst) {
			req->dst = sgl_alloc(req->dlen, GFP_ATOMIC, NULL);
			if (!req->dst) {
				ret = -ENOMEM;
				goto out;
			}
		} else if (req->dlen > dlen) {
			ret = -ENOSPC;
			goto out;
		}
		if (dst == scratch->dst) {
			scatterwalk_map_and_copy(scratch->dst, req->dst, 0,
						 req->dlen, 1);
		} else {
			int nr_pages = DIV_ROUND_UP(req->dst->offset + req->dlen, PAGE_SIZE);
			int i;
			struct page *dst_page = sg_page(req->dst);

			for (i = 0; i < nr_pages; i++)
				flush_dcache_page(dst_page + i);
		}
	}
out:
	spin_unlock_bh(&scratch->lock);
	return ret;
}

static int scomp_acomp_compress(struct acomp_req *req)
{
	return scomp_acomp_comp_decomp(req, 1);
}

static int scomp_acomp_decompress(struct acomp_req *req)
{
	return scomp_acomp_comp_decomp(req, 0);
}

static void crypto_exit_scomp_ops_async(struct crypto_tfm *tfm)
{
	struct crypto_scomp **ctx = crypto_tfm_ctx(tfm);

	crypto_free_scomp(*ctx);

	mutex_lock(&scomp_lock);
	if (!--scomp_scratch_users)
		crypto_scomp_free_scratches();
	mutex_unlock(&scomp_lock);
}

int crypto_init_scomp_ops_async(struct crypto_tfm *tfm)
{
	struct crypto_alg *calg = tfm->__crt_alg;
	struct crypto_acomp *crt = __crypto_acomp_tfm(tfm);
	struct crypto_scomp **ctx = crypto_tfm_ctx(tfm);
	struct crypto_scomp *scomp;

	if (!crypto_mod_get(calg))
		return -EAGAIN;

	scomp = crypto_create_tfm(calg, &crypto_scomp_type);
	if (IS_ERR(scomp)) {
		crypto_mod_put(calg);
		return PTR_ERR(scomp);
	}

	*ctx = scomp;
	tfm->exit = crypto_exit_scomp_ops_async;

	crt->compress = scomp_acomp_compress;
	crt->decompress = scomp_acomp_decompress;
	crt->dst_free = sgl_free;

	return 0;
}

static void crypto_scomp_destroy(struct crypto_alg *alg)
{
	scomp_free_streams(__crypto_scomp_alg(alg));
}

static const struct crypto_type crypto_scomp_type = {
	.extsize = crypto_alg_extsize,
	.init_tfm = crypto_scomp_init_tfm,
	.destroy = crypto_scomp_destroy,
#ifdef CONFIG_PROC_FS
	.show = crypto_scomp_show,
#endif
#if IS_ENABLED(CONFIG_CRYPTO_USER)
	.report = crypto_scomp_report,
#endif
	.maskclear = ~CRYPTO_ALG_TYPE_MASK,
	.maskset = CRYPTO_ALG_TYPE_MASK,
	.type = CRYPTO_ALG_TYPE_SCOMPRESS,
	.tfmsize = offsetof(struct crypto_scomp, base),
};

int crypto_register_scomp(struct scomp_alg *alg)
{
	struct crypto_alg *base = &alg->calg.base;

	comp_prepare_alg(&alg->calg);

	base->cra_type = &crypto_scomp_type;
	base->cra_flags |= CRYPTO_ALG_TYPE_SCOMPRESS;

	return crypto_register_alg(base);
}
EXPORT_SYMBOL_GPL(crypto_register_scomp);

void crypto_unregister_scomp(struct scomp_alg *alg)
{
	crypto_unregister_alg(&alg->base);
}
EXPORT_SYMBOL_GPL(crypto_unregister_scomp);

int crypto_register_scomps(struct scomp_alg *algs, int count)
{
	int i, ret;

	for (i = 0; i < count; i++) {
		ret = crypto_register_scomp(&algs[i]);
		if (ret)
			goto err;
	}

	return 0;

err:
	for (--i; i >= 0; --i)
		crypto_unregister_scomp(&algs[i]);

	return ret;
}
EXPORT_SYMBOL_GPL(crypto_register_scomps);

void crypto_unregister_scomps(struct scomp_alg *algs, int count)
{
	int i;

	for (i = count - 1; i >= 0; --i)
		crypto_unregister_scomp(&algs[i]);
}
EXPORT_SYMBOL_GPL(crypto_unregister_scomps);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Synchronous compression type");
