// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

type HostPreLoad func(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec, collOpts *bpf.CollectionOptions) error

type HostPreAttach func(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, objs HostObjects) error

type HostNetPreLoad func(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec, collOpts *bpf.CollectionOptions) error

type HostNetPreAttach func(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, objs HostNetObjects) error

type HostNetdevPreLoad func(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, iface netlink.Link, spec *ebpf.CollectionSpec, collOpts *bpf.CollectionOptions) error

type HostNetdevPreAttach func(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, iface netlink.Link, objs HostNetdevObjects) error

type EndpointPreLoad func(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec, collOpts *bpf.CollectionOptions) error

type EndpointPreAttach func(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, objs LXCObjects) error

type WireguardPreLoad func(lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec, collOpts *bpf.CollectionOptions) error

type WireguardPreAttach func(lnc *datapath.LocalNodeConfiguration, objs WireguardObjects) error

type OverlayPreLoad func(lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec, collOpts *bpf.CollectionOptions) error

type OverlayPreAttach func(lnc *datapath.LocalNodeConfiguration, objs OverlayObjects) error

type IPSecPreLoad func(lnc *datapath.LocalNodeConfiguration, spec *ebpf.CollectionSpec, collOpts *bpf.CollectionOptions) error

type IPSecPreAttach func(lnc *datapath.LocalNodeConfiguration, objs NetworkObjects) error

type XDPPreLoad func(lnc *datapath.LocalNodeConfiguration, iface netlink.Link, spec *ebpf.CollectionSpec, collOpts *bpf.CollectionOptions) error

type XDPPreAttach func(lnc *datapath.LocalNodeConfiguration, iface netlink.Link, objs XDPObjects) error

type callbackFn interface {
	HostPreLoad | HostPreAttach |
		HostNetPreLoad | HostNetPreAttach |
		HostNetdevPreLoad | HostNetdevPreAttach |
		EndpointPreLoad | EndpointPreAttach |
		WireguardPreLoad | WireguardPreAttach |
		OverlayPreLoad | OverlayPreAttach |
		IPSecPreLoad | IPSecPreAttach |
		XDPPreLoad | XDPPreAttach
}

type CallbackRegistry struct {
	HostPreLoad         callbackRegistry[HostPreLoad]
	HostPreAttach       callbackRegistry[HostPreAttach]
	HostNetPreLoad      callbackRegistry[HostNetPreLoad]
	HostNetPreAttach    callbackRegistry[HostNetPreAttach]
	HostNetdevPreLoad   callbackRegistry[HostNetdevPreLoad]
	HostNetdevPreAttach callbackRegistry[HostNetdevPreAttach]
	EndpointPreLoad     callbackRegistry[EndpointPreLoad]
	EndpointPreAttach   callbackRegistry[EndpointPreAttach]
	WireguardPreLoad    callbackRegistry[WireguardPreLoad]
	WireguardPreAttach  callbackRegistry[WireguardPreAttach]
	OverlayPreLoad      callbackRegistry[OverlayPreLoad]
	OverlayPreAttach    callbackRegistry[OverlayPreAttach]
	IPSecPreLoad        callbackRegistry[IPSecPreLoad]
	IPSecPreAttach      callbackRegistry[IPSecPreAttach]
	XDPPreLoad          callbackRegistry[XDPPreLoad]
	XDPPreAttach        callbackRegistry[XDPPreAttach]
}

type callback[T callbackFn] struct {
	fn       T
	priority int
}

type callbackRegistry[T callbackFn] []callback[T]

func (cr *callbackRegistry[T]) Register(cb T, priority int) {
	(*cr) = append(*cr, callback[T]{fn: cb, priority: priority})
	return
}

func (cr *callbackRegistry[T]) sort() {
	slices.SortFunc(*cr, func(a, b callback[T]) int {
		return a.priority - b.priority
	})
}

func NewCallbackRegistry(lifecycle cell.Lifecycle) *CallbackRegistry {
	cr := &CallbackRegistry{}
	lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			cr.EndpointPreAttach.sort()
			cr.HostPreAttach.sort()
			cr.HostNetPreAttach.sort()
			cr.HostNetdevPreAttach.sort()
			cr.HostPreLoad.sort()
			cr.HostNetPreLoad.sort()
			cr.HostNetdevPreLoad.sort()
			cr.WireguardPreAttach.sort()
			cr.WireguardPreLoad.sort()
			cr.OverlayPreAttach.sort()
			cr.OverlayPreLoad.sort()
			cr.IPSecPreAttach.sort()
			cr.IPSecPreLoad.sort()
			cr.XDPPreAttach.sort()
			return nil
		},
	})
	return cr
}
