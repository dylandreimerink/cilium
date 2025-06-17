// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"

	"github.com/cilium/ebpf"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

const (
	PolicyMapCallbackPriority = 10
)

func policyMapCallbacks(cr *CallbackRegistry) {
	cr.HostPreAttach.Register(policyEndpointPreAttach, PolicyMapCallbackPriority)
	cr.EndpointPreAttach.Register(newPolicyEndpointPreAttach, PolicyMapCallbackPriority)
}

func policyEndpointPreAttach(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, objs HostObjects) error {
	// Insert host endpoint policy program.
	if err := objs.PolicyMap.Update(uint32(ep.GetID()), objs.PolicyProg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting host endpoint policy program: %w", err)
	}

	return nil
}
func newPolicyEndpointPreAttach(ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration, objs LXCObjects) error {
	// Insert policy programs before attaching entrypoints to tc hooks.
	// Inserting a policy program is considered an attachment, since it makes
	// the code reachable by bpf_host when it evaluates policy for the endpoint.
	// All internal tail call plumbing needs to be done before this point.
	// If the agent dies uncleanly after the first program has been inserted,
	// the endpoint's connectivity will be partially broken or exhibit undefined
	// behaviour like missed tail calls or drops.
	if err := objs.PolicyMap.Update(uint32(ep.GetID()), objs.PolicyProg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting endpoint policy program: %w", err)
	}
	if err := objs.EgressPolicyMap.Update(uint32(ep.GetID()), objs.EgressPolicyProg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting endpoint egress policy program: %w", err)
	}

	return nil
}
