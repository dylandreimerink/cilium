// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"nodediscovery",
	"Node Discovery",

	cell.Provide(NewNodeDiscovery),
)
