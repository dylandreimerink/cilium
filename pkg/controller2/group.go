// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/sirupsen/logrus"
)

type Group struct {
	name       string
	logger     logrus.FieldLogger
	shutdowner hive.Shutdowner

	wg     *sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc

	mu          lock.Mutex
	controllers []*controller
}

func (g *Group) NewController(name string, doFunc ControllerFunc, opts ...Opt) *controller {
	g.mu.Lock()
	defer g.mu.Unlock()

	ctl := newController(name, doFunc, g.shutdowner, g.logger)
	for _, opt := range opts {
		opt(ctl)
	}
	g.controllers = append(g.controllers, ctl)

	return ctl
}

func (g *Group) Start() {
	g.ctx, g.cancel = context.WithCancel(context.Background())

	g.wg.Add(len(g.controllers))
	for _, ctl := range g.controllers {
		go ctl.run(g.ctx, g.wg)
	}
}

func (g *Group) Stop(ctx context.Context) error {
	g.cancel()
	stopped := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}
