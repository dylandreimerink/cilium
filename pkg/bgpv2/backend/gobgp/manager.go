// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"

	"github.com/cilium/cilium/pkg/bgpv2/backend"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"

	"github.com/sirupsen/logrus"
)

var Cell = cell.Module(
	"GoBGP-Speaker-Backend",
	cell.Provide(newRegisterManager),
)

var _ backend.BGPSpeakerManager = (*Manager)(nil)

func newRegisterManager(lc hive.Lifecycle, logger logrus.FieldLogger) backend.BGPSpeakerManager {
	mgr := &Manager{
		serverMap: make(ServerMap),
		logger:    logger,
	}
	mgr.ctx, mgr.cancel = context.WithCancel(context.Background())

	lc.Append(mgr)

	return mgr
}

type Manager struct {
	ctx      context.Context
	cancel   context.CancelFunc
	doneChan chan struct{}

	logger logrus.FieldLogger

	serverMap ServerMap
}

func (m *Manager) Start(_ hive.HookContext) error {
	return nil
}

func (m *Manager) Stop(ctx hive.HookContext) error {
	m.cancel()

	select {
	case <-m.doneChan:
	case <-ctx.Done():
	}

	return nil
}
