// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/sirupsen/logrus"
)

var Cell = cell.Provide(NewManager)

type Manager struct {
	shutdowner hive.Shutdowner

	mu     lock.Mutex
	groups []*Group
}

func NewManager(shutdowner hive.Shutdowner) *Manager {
	return &Manager{
		shutdowner: shutdowner,
	}
}

func (m *Manager) NewGroup(name string, logger logrus.FieldLogger) *Group {
	m.mu.Lock()
	defer m.mu.Unlock()

	g := &Group{
		name:   name,
		logger: logger.WithField("group", name),
	}
	m.groups = append(m.groups, g)

	return g
}
