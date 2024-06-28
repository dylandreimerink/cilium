/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2006 Bob Jenkins <bob_jenkins@burtleburtle.net> */
/* Copyright (C) 2006-2020 Authors of the Linux kernel */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#define JHASH_INITVAL	0xdeadbeef

static __always_inline __u32 rol32(__u32 word, __u32 shift)
{
	return (word << shift) | (word >> ((-shift) & 31));
}

static __always_inline __jhash_mix(__u32 *a_ptr, __u32 *b_ptr, __u32 *c_ptr)
{
	__u32 a = *a_ptr;
	__u32 b = *b_ptr;
	__u32 c = *c_ptr;

	a -= c;  a ^= rol32(c, 4);  c += b;
	b -= a;  b ^= rol32(a, 6);  a += c;
	c -= b;  c ^= rol32(b, 8);  b += a;
	a -= c;  a ^= rol32(c, 16); c += b;
	b -= a;  b ^= rol32(a, 19); a += c;
	c -= b;  c ^= rol32(b, 4);  b += a;
}

static __always_inline __jhash_final(__u32 *a_ptr, __u32 *b_ptr, __u32 *c_ptr)
{
	__u32 a = *a_ptr;
	__u32 b = *b_ptr;
	__u32 c = *c_ptr;

	c ^= b; c -= rol32(b, 14);
	a ^= c; a -= rol32(c, 11);
	b ^= a; b -= rol32(a, 25);
	c ^= b; c -= rol32(b, 16);
	a ^= c; a -= rol32(c, 4);
	b ^= a; b -= rol32(a, 14);
	c ^= b; c -= rol32(b, 24);
}

static __always_inline __u32 jhash(const void *key, __u32 length,
				   __u32 initval)
{
	const unsigned char *k = key;
	__u32 a, b, c;

	if (!__builtin_constant_p(length))
		__throw_build_bug();

	a = JHASH_INITVAL + length + initval;
	b = JHASH_INITVAL + length + initval;
	c = JHASH_INITVAL + length + initval;

	while (length > 12) {
		a += *(__u32 *)(k);
		b += *(__u32 *)(k + 4);
		c += *(__u32 *)(k + 8);

		__jhash_mix(&a, &b, &c);
		length -= 12;
		k += 12;
	}

	switch (length) {
	case 12: c += (__u32)k[11] << 24; fallthrough;
	case 11: c += (__u32)k[10] << 16; fallthrough;
	case 10: c +=  (__u32)k[9] <<  8; fallthrough;
	case 9:  c +=  (__u32)k[8];       fallthrough;
	case 8:  b +=  (__u32)k[7] << 24; fallthrough;
	case 7:  b +=  (__u32)k[6] << 16; fallthrough;
	case 6:  b +=  (__u32)k[5] <<  8; fallthrough;
	case 5:  b +=  (__u32)k[4];       fallthrough;
	case 4:  a +=  (__u32)k[3] << 24; fallthrough;
	case 3:  a +=  (__u32)k[2] << 16; fallthrough;
	case 2:  a +=  (__u32)k[1] <<  8; fallthrough;
	case 1:  a +=  (__u32)k[0];

		__jhash_final(&a, &b, &c);
		break;
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

static __always_inline __u32 __jhash_nwords(__u32 a, __u32 b, __u32 c,
					    __u32 initval)
{
	a += initval;
	b += initval;
	c += initval;
	__jhash_final(&a, &b, &c);
	return c;
}

static __always_inline __u32 jhash_3words(__u32 a, __u32 b, __u32 c,
					  __u32 initval)
{
	return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static __always_inline __u32 jhash_2words(__u32 a, __u32 b, __u32 initval)
{
	return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static __always_inline __u32 jhash_1word(__u32 a, __u32 initval)
{
	return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}
