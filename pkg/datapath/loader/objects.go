// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"io"

	"github.com/cilium/ebpf"
)

// XDPObjects receives eBPF objects for attaching to XDP interfaces. Objects
// originate from bpf_xdp.c.
type XDPObjects struct {
	Entrypoint *ebpf.Program `ebpf:"cil_xdp_entry"`
}

func (o *XDPObjects) Close() {
	bpfClose(o.Entrypoint)
}

// LXCObjects receives eBPF objects for attaching to endpoint interfaces.
// Objects originate from bpf_lxc.c.
type LXCObjects struct {
	ToContainer   *ebpf.Program `ebpf:"cil_to_container"`
	FromContainer *ebpf.Program `ebpf:"cil_from_container"`

	PolicyProg *ebpf.Program `ebpf:"cil_lxc_policy"`
	PolicyMap  *ebpf.Map     `ebpf:"cilium_call_policy"`

	EgressPolicyProg *ebpf.Program `ebpf:"cil_lxc_policy_egress"`
	EgressPolicyMap  *ebpf.Map     `ebpf:"cilium_egresscall_policy"`
}

func (o *LXCObjects) Close() {
	bpfClose(o.ToContainer, o.FromContainer, o.PolicyProg, o.PolicyMap, o.EgressPolicyProg, o.EgressPolicyMap)
}

// HostObjects receives eBPF objects for attaching to cilium_host. Objects
// originate from bpf_host.c.
type HostObjects struct {
	ToHost   *ebpf.Program `ebpf:"cil_to_host"`
	FromHost *ebpf.Program `ebpf:"cil_from_host"`

	PolicyProg *ebpf.Program `ebpf:"cil_host_policy"`
	PolicyMap  *ebpf.Map     `ebpf:"cilium_call_policy"`
}

func (o *HostObjects) Close() {
	bpfClose(o.ToHost, o.FromHost, o.PolicyProg, o.PolicyMap)
}

// HostNetObjects receives eBPF objects for attaching to cilium_net. Objects
// originate from bpf_host.c.
type HostNetObjects struct {
	ToHost *ebpf.Program `ebpf:"cil_to_host"`
}

func (o *HostNetObjects) Close() {
	bpfClose(o.ToHost)
}

// HostNetdevObjects receives eBPF objects for attaching to external interfaces.
// Objects originate from bpf_host.c.
type HostNetdevObjects struct {
	FromNetdev *ebpf.Program `ebpf:"cil_from_netdev"`
	ToNetdev   *ebpf.Program `ebpf:"cil_to_netdev"`
}

func (o *HostNetdevObjects) Close() {
	bpfClose(o.FromNetdev, o.ToNetdev)
}

// OverlayObjects receives eBPF objects for attaching to overlay interfaces.
// Objects originate from bpf_overlay.c.
type OverlayObjects struct {
	FromOverlay *ebpf.Program `ebpf:"cil_from_overlay"`
	ToOverlay   *ebpf.Program `ebpf:"cil_to_overlay"`
}

func (o *OverlayObjects) Close() {
	bpfClose(o.FromOverlay, o.ToOverlay)
}

// NetworkObjects receives eBPF objects for attaching to IPsec interfaces.
// Objects originate from bpf_network.c.
type NetworkObjects struct {
	FromNetwork *ebpf.Program `ebpf:"cil_from_network"`
}

func (o *NetworkObjects) Close() {
	bpfClose(o.FromNetwork)
}

// WireguardObjects receives eBPF objects for attaching to Wireguard interfaces.
// Objects originate from bpf_wireguard.c.
type WireguardObjects struct {
	FromWireguard *ebpf.Program `ebpf:"cil_from_wireguard"`
	ToWireguard   *ebpf.Program `ebpf:"cil_to_wireguard"`
}

func (o *WireguardObjects) Close() {
	bpfClose(o.FromWireguard, o.ToWireguard)
}

func bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}
