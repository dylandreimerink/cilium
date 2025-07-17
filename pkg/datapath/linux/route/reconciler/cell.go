package reconciler

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"route-reconciler",
	"Reconciles desired routes to the Linux kernel routing table",
	cell.Provide(
		newDesiredRouteTable,
	),
)
