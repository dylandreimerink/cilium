// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

#include "bpf_host.c"

ASSIGN_CONFIG(bool, vlan_filter_enabled, true);
#define DEFAULT_VLAN_FILER {\
        {.ifindex = 116, .vlan_id = 4000}, \
        {.ifindex = 116, .vlan_id = 4001}, \
        {.ifindex = 117, .vlan_id = 4003}, \
        {.ifindex = 117, .vlan_id = 4004}, \
        {.ifindex = 117, .vlan_id = 4005} \
}
ASSIGN_CONFIG(vlan_filter_t, vlan_filter, DEFAULT_VLAN_FILER)

CHECK("tc", "vlan_filter")
int checkVlanFilter()
{
        test_init();

        assert(allow_vlan(116, 4000));
        assert(allow_vlan(116, 4001));
        assert(!allow_vlan(116, 4002));
        assert(allow_vlan(117, 4003));
        assert(allow_vlan(117, 4004));
        assert(allow_vlan(117, 4005));
        assert(!allow_vlan(117, 4006));

	test_finish();
}
