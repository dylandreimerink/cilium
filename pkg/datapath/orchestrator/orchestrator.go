// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"
	"errors"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
)

type orchestrator struct {
	params orchestratorParams

	dbInitialized chan struct{}
	trigger       chan reinitializeRequest
	devices       []string
}

type reinitializeRequest struct {
	ctx     context.Context
	errChan chan error
}

type orchestratorParams struct {
	cell.In

	Loader          types.Loader
	TunnelConfig    tunnel.Config
	MTU             mtu.MTU
	IPTablesManager *iptables.Manager
	Proxy           *proxy.Proxy
	DB              *statedb.DB
	Devices         statedb.Table[*tables.Device]
	JobRegistry     job.Registry
	Health          cell.Health
	Lifecycle       cell.Lifecycle
	EndpointManager endpointmanager.EndpointManager
	LocalNodeStore  *node.LocalNodeStore
}

func newOrchestrator(params orchestratorParams) *orchestrator {
	o := &orchestrator{
		params:        params,
		trigger:       make(chan reinitializeRequest, 1),
		dbInitialized: make(chan struct{}),
	}

	group := params.JobRegistry.NewGroup(params.Health)
	group.Add(job.OneShot("Reinitialize", o.reconciler))
	params.Lifecycle.Append(group)

	return o
}

func (o *orchestrator) reconciler(ctx context.Context, health cell.Health) error {
	// The loader is implicitly dependant on a few global variables being initialized.
	// Since we have not yet been able to add these to hive we have to wait for them to be initialized.
	// And can't assume they are ready when we start running.
	if option.Config.EnableIPv4 {
		<-node.Addrs.IPv4LoopbackSet
	}

	waitCtx, cancelWait := context.WithCancel(ctx)
	for n := range stream.ToChannel(waitCtx, o.params.LocalNodeStore) {
		doCancel := true
		if option.Config.EnableIPv4 {
			ipv4GW := n.GetCiliumInternalIP(false) != nil
			ipv4Range := n.IPv4AllocCIDR != nil
			if !ipv4GW || ipv4Range {
				doCancel = false
			}
		}
		if option.Config.EnableIPv6 {
			ipv6GW := n.GetCiliumInternalIP(true) != nil
			if !ipv6GW {
				doCancel = false
			}
		}
		if doCancel {
			cancelWait()
		}
	}
	cancelWait()

	nativeDevices, changed := tables.SelectedDevices(o.params.Devices, o.params.DB.ReadTxn())
	o.devices = tables.DeviceNames(nativeDevices)

	var request reinitializeRequest
	for {
		if err := o.reinitialize(ctx, request, o.devices); err != nil {
			health.Degraded("Failed to reinitialize datapath", err)
		} else {
			health.OK("OK")
		}

		request = reinitializeRequest{}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		case request = <-o.trigger:
		}

		nativeDevices, changed = tables.SelectedDevices(o.params.Devices, o.params.DB.ReadTxn())
		o.devices = tables.DeviceNames(nativeDevices)
	}
}

func (o *orchestrator) Reinitialize(ctx context.Context) error {
	errChan := make(chan error)
	o.trigger <- reinitializeRequest{
		ctx:     ctx,
		errChan: errChan,
	}
	return <-errChan
}

func (o *orchestrator) reinitialize(ctx context.Context, req reinitializeRequest, devices []string) error {
	if req.ctx != nil {
		ctx = req.ctx
	}

	var errs []error
	if err := o.params.Loader.Reinitialize(
		ctx,
		o.params.TunnelConfig,
		o.params.MTU.GetDeviceMTU(),
		o.params.IPTablesManager,
		o.params.Proxy,
		devices,
	); err != nil {
		errs = append(errs, err)
	}

	close(o.dbInitialized)

	reason := "Devices changed"
	if req.ctx != nil {
		reason = "Configuration changed"
	}

	regenRequest := &regeneration.ExternalRegenerationMetadata{
		Reason:            reason,
		RegenerationLevel: regeneration.RegenerateWithDatapathLoad,
		ParentContext:     ctx,
	}
	o.params.EndpointManager.RegenerateAllEndpoints(regenRequest).Wait()

	err := errors.Join(errs...)
	if req.errChan != nil {
		select {
		case req.errChan <- err:
		default:
		}
	}

	return err
}

func (o *orchestrator) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	select {
	case <-o.dbInitialized:
	case <-ctx.Done():
		return ctx.Err()
	}

	return o.params.Loader.ReloadDatapath(ctx, ep, o.devices, stats)
}

func (o *orchestrator) ReinitializeXDP(ctx context.Context, extraCArgs []string) error {
	select {
	case <-o.dbInitialized:
	case <-ctx.Done():
		return ctx.Err()
	}

	return o.params.Loader.ReinitializeXDP(ctx, extraCArgs, o.devices)
}

func (o *orchestrator) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	<-o.dbInitialized
	return o.params.Loader.EndpointHash(cfg)
}

func (o *orchestrator) Unload(ep datapath.Endpoint) {
	<-o.dbInitialized
	o.params.Loader.Unload(ep)
}
