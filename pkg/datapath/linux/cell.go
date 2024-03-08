// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"datapath-linux",
	"Datapath Linux",
	cell.Provide(NewNodeHandler),
)
