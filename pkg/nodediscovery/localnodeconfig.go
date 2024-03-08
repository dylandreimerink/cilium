// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"github.com/cilium/cilium/pkg/cidr"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/option"
)

func NewLocalNodeConfig(mtu mtu.MTU, config *option.DaemonConfig) datapath.LocalNodeConfiguration {
	auxPrefixes := []*cidr.CIDR{}

	if config.IPv4ServiceRange != AutoCIDR {
		serviceCIDR, err := cidr.ParseCIDR(config.IPv4ServiceRange)
		if err != nil {
			log.WithError(err).WithField(logfields.V4Prefix, config.IPv4ServiceRange).Fatal("Invalid IPv4 service prefix")
		}

		auxPrefixes = append(auxPrefixes, serviceCIDR)
	}

	if config.IPv6ServiceRange != AutoCIDR {
		serviceCIDR, err := cidr.ParseCIDR(config.IPv6ServiceRange)
		if err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, config.IPv6ServiceRange).Fatal("Invalid IPv6 service prefix")
		}

		auxPrefixes = append(auxPrefixes, serviceCIDR)
	}

	return datapath.LocalNodeConfiguration{
		MtuConfig:               mtu,
		EnableIPv4:              config.EnableIPv4,
		EnableIPv6:              config.EnableIPv6,
		EnableEncapsulation:     config.TunnelingEnabled(),
		EnableAutoDirectRouting: config.EnableAutoDirectRouting,
		EnableLocalNodeRoute: config.EnableLocalNodeRoute &&
			config.IPAM != ipamOption.IPAMENI &&
			config.IPAM != ipamOption.IPAMAzure &&
			config.IPAM != ipamOption.IPAMAlibabaCloud,
		AuxiliaryPrefixes: auxPrefixes,
		EnableIPSec:       config.EnableIPSec,
		EncryptNode:       config.EncryptNode,
		IPv4PodSubnets:    config.IPv4PodSubnets,
		IPv6PodSubnets:    config.IPv6PodSubnets,
	}
}
