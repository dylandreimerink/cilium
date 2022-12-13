// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"metrics",
	"Metrics",

	cell.Config(defaultRegistryConfig),
	cell.Metric(NewLegacyMetrics),
	cell.Provide(NewRegistry),

	cell.Metric(NewLoggingHookMetrics),
	cell.Provide(NewLoggingHook),

	cell.Metric(NewMapPressureMetric),
)
