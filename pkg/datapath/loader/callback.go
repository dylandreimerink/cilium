// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

type ctx interface {
	context()
}

type PreLoadCtx[T any] struct {
	Inputs   T
	Spec     *ebpf.CollectionSpec
	CollOpts *bpf.CollectionOptions
}

func (c PreLoadCtx[T]) context() {}

type PreAttachCtx[I, O any] struct {
	Inputs I
	Objs   O
}

func (c PreAttachCtx[I, O]) context() {}

type NodeInputs struct {
	Lnc *datapath.LocalNodeConfiguration
}

type EndpointInputs struct {
	Ep  datapath.Endpoint
	Lnc *datapath.LocalNodeConfiguration
}

type NetdevInputs struct {
	Ep    datapath.Endpoint
	Lnc   *datapath.LocalNodeConfiguration
	Iface netlink.Link
}

type XDPInputs struct {
	Lnc   *datapath.LocalNodeConfiguration
	Iface netlink.Link
}

type PreHostLoadCtx = PreLoadCtx[EndpointInputs]
type PreHostAttachCtx = PreAttachCtx[EndpointInputs, hostObjects]

type PreHostNetLoadCtx = PreLoadCtx[NetdevInputs]
type PreHostNetAttachCtx = PreAttachCtx[NetdevInputs, hostNetObjects]

type PreEndpointLoadCtx = PreLoadCtx[EndpointInputs]
type PreEndpointAttachCtx = PreAttachCtx[EndpointInputs, lxcObjects]

type PreWireguardLoadCtx = PreLoadCtx[NodeInputs]
type PreWireguardAttachCtx = PreAttachCtx[NodeInputs, wireguardObjects]

type PreOverlayLoadCtx = PreLoadCtx[NodeInputs]
type PreOverlayAttachCtx = PreAttachCtx[NodeInputs, overlayObjects]

type PreIpsecLoadCtx = PreLoadCtx[NodeInputs]
type PreIpsecAttachCtx = PreAttachCtx[NodeInputs, networkObjects]

type PreXDPLoadCtx = PreLoadCtx[XDPInputs]
type PreXDPAttachCtx = PreAttachCtx[XDPInputs, xdpObjects]

type CallbackRegistry struct {
	callbacks map[reflect.Type][]any
}

func (r *CallbackRegistry) RegisterCallback(callback any) {
	if r.callbacks == nil {
		r.callbacks = make(map[reflect.Type][]any)
	}

	typ := reflect.TypeOf(callback)
	if typ.Kind() != reflect.Func {
		panic("callback must be a function")
	}

	if typ.NumIn() != 1 {
		panic("callback must take exactly one value")
	}
	in := typ.In(0)
	if !in.Implements(reflect.TypeOf((*ctx)(nil)).Elem()) {
		panic("callback must take an implementation of `ctx` as the first argument")
	}

	if typ.NumOut() != 1 {
		panic("callback must return exactly one input")
	}
	out := typ.Out(0)
	if out == reflect.TypeOf((*error)(nil)).Elem() {
		panic("callback must not return an error")
	}

	r.callbacks[in] = append(r.callbacks[in], callback)
}

func (r *CallbackRegistry) Invoke(context any) error {
	typ := reflect.TypeOf(context)
	if !typ.Implements(reflect.TypeOf((ctx)(nil)).Elem()) {
		panic("`context` must implement the `ctx` interface")
	}

	callbacks, ok := r.callbacks[typ]
	if !ok {
		return nil
	}

	for _, callback := range callbacks {
		fn := reflect.ValueOf(callback)
		results := fn.Call([]reflect.Value{reflect.ValueOf(context)})
		if len(results) > 0 && !results[0].IsNil() {
			return results[0].Interface().(error)
		}
	}

	return nil
}
