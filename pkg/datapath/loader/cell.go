// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	loaderTypes "github.com/cilium/cilium/pkg/datapath/loader/types"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"loader",
	"Loader",
	cell.Provide(NewLoader),
)

type LoaderParams struct {
	cell.In

	Sysctl         sysctl.Sysctl
	ConfigWriter   datapath.ConfigWriter
	DaemonConfig   *option.DaemonConfig
	nodeHandler    datapath.NodeHandler
	localNodeStore *node.LocalNodeStore
}

// NewLoader returns a new loader.
func NewLoader(params LoaderParams) loaderTypes.Loader {
	return newLoader(
		params.Sysctl,
		params.ConfigWriter,
		params.DaemonConfig,
		params.nodeHandler,
		params.localNodeStore,
	)
}
