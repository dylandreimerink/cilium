// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"fmt"
	"sort"

	"github.com/cilium/cilium/pkg/bgpv2/backend"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

type BGPControlPlaneConfig struct {
	Enabled bool `mapstructure:"enable-bgp-control-plane"`
}

func (c BGPControlPlaneConfig) Flags(fs *pflag.FlagSet) {
	fs.Bool("enable-bgp-control-plane", false, "Enable the BGP Control Plane")
}

type bgpControllerParams struct {
	cell.In

	Logger logrus.FieldLogger
	LC     hive.Lifecycle

	Config BGPControlPlaneConfig

	SpeakerManager backend.BGPSpeakerManager

	NodeListener *nodeListener
	DiffSignaler *Signaler

	Reconcilers []ConfigReconciler `group:"config-reconcilers"`
}

func registerBGPController(params bgpControllerParams) error {
	spew.Dump(params.Config)
	if !params.Config.Enabled {
		return nil
	}

	// Sort the reconcilers so they are executed in order of priority
	sort.Slice(params.Reconcilers, func(i, j int) bool {
		return params.Reconcilers[i].Priority() < params.Reconcilers[j].Priority()
	})

	controller := &controller{
		logger: params.Logger,

		speakerManager: params.SpeakerManager,

		nodeUpdateChan: params.NodeListener.GetUpdateChan(),
		diffSignaler:   params.DiffSignaler,

		reconcilers: params.Reconcilers,
	}

	params.LC.Append(controller)

	return nil
}

// controller is in charge of calling the reconcilers when a change in the requested state is detected.
// The controller triggers whenever the nodeListener sends a new version of the current node config or when the
// signaler from one of the diffStores signals that there are changes.
type controller struct {
	logger logrus.FieldLogger

	ctx      context.Context
	cancel   context.CancelFunc
	doneChan chan struct{}

	speakerManager backend.BGPSpeakerManager

	nodeUpdateChan <-chan abstractNode
	currentNode    abstractNode

	diffSignaler *Signaler

	reconcilers []ConfigReconciler
}

func (c *controller) Start(_ hive.HookContext) error {
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.doneChan = make(chan struct{})
	go c.Run()
	return nil
}

func (c *controller) Stop(stopCtx hive.HookContext) error {
	c.cancel()

	select {
	case <-c.doneChan:
	case <-stopCtx.Done():
	}

	return nil
}

func (c *controller) Run() {
	defer close(c.doneChan)

	for {
		select {
		case newNode := <-c.nodeUpdateChan:
			c.logger.Debugf("node update, reconciling")

			c.currentNode = newNode

			err := c.Reconcile()
			if err != nil {
				c.logger.WithError(err).Error("Error while reconciling")
			}

		case <-c.diffSignaler.Sig:
			c.logger.Debugf("diff store signal, reconciling")

			err := c.Reconcile()
			if err != nil {
				c.logger.WithError(err).Error("Error while reconciling")
			}

		case <-c.ctx.Done():
			return
		}
	}
}

func (c *controller) Reconcile() error {
	for _, reconciler := range c.reconcilers {
		c.logger.Debugf("triggering reconciler %T", reconciler)

		err := reconciler.Reconcile(c.ctx, c.currentNode, c.speakerManager)
		if err != nil {
			return fmt.Errorf("%T: %w", reconciler, err)
		}
	}

	return nil
}
