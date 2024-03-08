// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/lock"
)

type NewProgramOwner interface {
	GetCompilationLock() *lock.RWMutex
	LocalConfig() *LocalNodeConfiguration
	SetPrefilter(pf PreFilter)
}

type Orchestrator interface {
	Reinitialize(ctx context.Context, owner BaseProgramOwner, tunnelConfig tunnel.Config, deviceMTU int, iptMgr IptablesManager, p Proxy) error
}
