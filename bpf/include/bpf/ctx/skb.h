/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __BPF_CTX_SKB_H_
#define __BPF_CTX_SKB_H_

#define __ctx_buff		__sk_buff
#define __ctx_is		__ctx_skb

#include "common.h"
#include "../bpf_helpers.h"
#include "../features_skb.h"

#ifndef TC_ACT_OK
# define TC_ACT_OK		0
#endif

#ifndef TC_ACT_SHOT
# define TC_ACT_SHOT		2
#endif

#ifndef TC_ACT_REDIRECT
# define TC_ACT_REDIRECT	7
#endif

#define CTX_ACT_OK		TC_ACT_OK
#define CTX_ACT_DROP		TC_ACT_SHOT
#define CTX_ACT_TX		TC_ACT_REDIRECT
#define CTX_ACT_REDIRECT	TC_ACT_REDIRECT

/* Discouraged since prologue will unclone full skb. */
#define CTX_DIRECT_WRITE_OK	0

#define META_PIVOT		field_sizeof(struct __sk_buff, cb)

#define ctx_load_bytes		bpf_skb_load_bytes
#define ctx_store_bytes		bpf_skb_store_bytes

#define ctx_adjust_hroom	bpf_skb_adjust_room

#define ctx_change_type		bpf_skb_change_type
#define ctx_change_proto	bpf_skb_change_proto
#define ctx_change_tail		bpf_skb_change_tail

#define ctx_pull_data		bpf_skb_pull_data

#define ctx_get_tunnel_key	bpf_skb_get_tunnel_key
#define ctx_set_tunnel_key	bpf_skb_set_tunnel_key

#define ctx_event_output	bpf_perf_event_output

#define l3_csum_replace		bpf_l3_csum_replace
#define l4_csum_replace		bpf_l4_csum_replace

#define ctx_adjust_meta		({ -ENOTSUPP; })

/* Avoid expensive calls into the kernel flow dissector if it's not an L4
 * hash. We currently only use the hash for debugging. If needed later, we
 * can map it to BPF_FUNC(get_hash_recalc) to get the L4 hash.
 */
#define get_hash(ctx)		ctx->hash
#define get_hash_recalc(ctx)	get_hash(ctx)

static __always_inline __maybe_unused int
ctx_redirect(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags)
{
	return bpf_redirect(ifindex, flags);
}

static __always_inline __maybe_unused int
ctx_redirect_peer(const struct __sk_buff *ctx __maybe_unused, int ifindex, __u32 flags)
{
	return bpf_redirect_peer(ifindex, flags);
}

static __always_inline __maybe_unused int
ctx_adjust_troom(struct __sk_buff *ctx, const __s32 len_diff)
{
	return bpf_skb_change_tail(ctx, ctx->len + len_diff, 0);
}

static __always_inline __maybe_unused __u64
ctx_full_len(const struct __sk_buff *ctx)
{
	return ctx->len;
}

static __always_inline __maybe_unused __u32
ctx_wire_len(const struct __sk_buff *ctx)
{
	return ctx->wire_len;
}

static __always_inline __maybe_unused void
ctx_store_meta(struct __sk_buff *ctx, const __u32 off, __u32 data)
{
	ctx->cb[off] = data;
}

static __always_inline __maybe_unused __u32
ctx_load_meta(const struct __sk_buff *ctx, const __u32 off)
{
	return ctx->cb[off];
}

static __always_inline __maybe_unused __u16
ctx_get_protocol(const struct __sk_buff *ctx)
{
	return (__u16)ctx->protocol;
}

static __always_inline __maybe_unused __u32
ctx_get_ifindex(const struct __sk_buff *ctx)
{
	return ctx->ifindex;
}

#endif /* __BPF_CTX_SKB_H_ */
