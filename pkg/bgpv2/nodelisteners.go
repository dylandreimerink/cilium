// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	nodeaddr "github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/sirupsen/logrus"
	k8s_corev1 "k8s.io/api/core/v1"
)

func newNodeListener(params nodeListenerParams) *nodeListener {
	listener := &nodeListener{
		params:     params,
		nodeName:   nodetypes.GetName(),
		updateChan: make(chan abstractNode),
	}

	params.LC.Append(listener)

	return listener
}

type nodeListenerParams struct {
	cell.In

	LC hive.Lifecycle

	Logger logrus.FieldLogger

	AgentConfig *option.DaemonConfig

	CiliumNodeResource resource.Resource[*cilium_v2.CiliumNode] `optional:"true"`
	K8sNodeResource    resource.Resource[*k8s_corev1.Node]      `optional:"true"`
}

// nodeListener is an abstraction which listens for changes to cilium or k8s node objects depending on the
// configuration. It will send updates for the node on which this agent instance runs over the `updateChan`.
type nodeListener struct {
	params nodeListenerParams

	// TODO move to params as soon as it is available via hive
	nodeName string

	ctx      context.Context
	cancel   context.CancelFunc
	doneChan chan struct{}

	updateChan chan abstractNode
}

func (nl *nodeListener) GetUpdateChan() <-chan abstractNode {
	return nl.updateChan
}

func (nl *nodeListener) Start(_ hive.HookContext) error {
	nl.ctx, nl.cancel = context.WithCancel(context.TODO())
	nl.doneChan = make(chan struct{})

	switch nl.params.AgentConfig.IPAM {
	case ipamOption.IPAMClusterPoolV2, ipamOption.IPAMClusterPool:
		go nl.RunCiliumNode()
	case ipamOption.IPAMKubernetes:
		go nl.RunK8sNode()
	default:
		return fmt.Errorf("failed to determine a compatible IPAM mode, cannot initialize BGP control plane")
	}

	return nil
}

func (nl *nodeListener) RunCiliumNode() {
	defer close(nl.doneChan)
	errChan := make(chan error, 2)

	nodeChan := stream.ToChannel[resource.Event[*cilium_v2.CiliumNode]](nl.ctx, errChan, nl.params.CiliumNodeResource)
	for event := range nodeChan {
		event.Handle(
			nil,
			func(k resource.Key, cn *cilium_v2.CiliumNode) error {
				if k.Name != nl.nodeName {
					return nil
				}

				nl.updateChan <- abstractNode{
					IPv4:        nodeaddr.GetIPv4(),
					IPv6:        nodeaddr.GetIPv6(),
					PodCIDRs:    cn.Spec.IPAM.PodCIDRs,
					Labels:      cn.Labels,
					Annotations: cn.Annotations,
				}
				return nil
			},
			func(k resource.Key, cn *cilium_v2.CiliumNode) error {
				nl.updateChan <- abstractNode{
					IPv4:        nodeaddr.GetIPv4(),
					IPv6:        nodeaddr.GetIPv6(),
					PodCIDRs:    nil,
					Labels:      make(map[string]string),
					Annotations: make(map[string]string),
				}
				return nil
			},
		)
	}

	err := <-errChan
	if err != nil {
		nl.params.Logger.WithError(err).Error("Cilium node resource error")
	}
}

func (nl *nodeListener) RunK8sNode() {
	defer close(nl.doneChan)
	errChan := make(chan error, 2)

	nodeChan := stream.ToChannel[resource.Event[*k8s_corev1.Node]](nl.ctx, errChan, nl.params.K8sNodeResource)
	for event := range nodeChan {

		event.Handle(
			nil,
			func(k resource.Key, node *k8s_corev1.Node) error {
				if k.Name != nl.nodeName {
					return nil
				}

				an := abstractNode{
					Labels:      node.Labels,
					Annotations: node.Annotations,
				}

				if node.Spec.PodCIDRs != nil {
					an.PodCIDRs = node.Spec.PodCIDRs
					nl.updateChan <- an
					return nil
				}

				if node.Spec.PodCIDR != "" {
					an.PodCIDRs = []string{node.Spec.PodCIDR}
					nl.updateChan <- an
					return nil
				}

				return nil
			},
			func(k resource.Key, node *k8s_corev1.Node) error {
				nl.updateChan <- abstractNode{
					IPv4:        nodeaddr.GetIPv4(),
					IPv6:        nodeaddr.GetIPv6(),
					PodCIDRs:    nil,
					Labels:      make(map[string]string),
					Annotations: make(map[string]string),
				}
				return nil
			},
		)
	}

	err := <-errChan
	if err != nil {
		nl.params.Logger.WithError(err).Error("Cilium node resource error")
	}
}

func (nl *nodeListener) Stop(stopCtx hive.HookContext) error {
	nl.cancel()

	select {
	case <-nl.doneChan:
	case <-stopCtx.Done():
	}

	return nil
}

type abstractNode struct {
	IPv4        net.IP
	IPv6        net.IP
	PodCIDRs    []string
	Labels      map[string]string
	Annotations map[string]string
}
