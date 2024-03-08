// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/iptables"
	"github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/statedb"
)

type orchestrator struct {
	params orchestratorParams
}

type orchestratorParams struct {
	cell.In

	Loader       types.Loader
	DB           *statedb.DB
	DevicesTable statedb.Table[*tables.Device]
	// DaemonPromise promise.Promise[*cmd.Daemon]

	TunnelConfig    tunnel.Config
	MTU             mtu.MTU
	IPTablesManager *iptables.Manager
	Proxy           *proxy.Proxy
	Config          *option.DaemonConfig

	Logger      logrus.FieldLogger
	Scope       cell.Scope
	JobRegistry job.Registry
}

func newOrchestrator(params orchestratorParams) *orchestrator {
	group := params.JobRegistry.NewGroup(params.Scope, job.WithLogger(params.Logger))

	orch := &orchestrator{
		params: params,
	}
	group.Add(job.OneShot("loader-reconciler", orch.reconcileLoader))

	return orch
}

func (o *orchestrator) reconcileLoader(ctx context.Context, healthReporter cell.HealthReporter) error {
	return nil
}

func (o *orchestrator) Reinitialize(ctx context.Context) error {
	return o.params.Loader.Reinitialize(ctx, nil, o.params.TunnelConfig, o.params.MTU.GetDeviceMTU(), o.params.IPTablesManager, o.params.Proxy)
}
