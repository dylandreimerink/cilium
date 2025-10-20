// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bwmap

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/registry"
)

// Cell manages the cilium_throttle BPF map for implementing per-endpoint
// bandwidth management. The cell provides RWTable[Edt] to which per
// endpoint bandwidth limits can be inserted. Use [NewEdt] to create the
// object. The table can be inspected with "cilium-dbg shell -- db/show bandwidth-edts".
// A reconciler is registered that reconciles the table with the cilium_throttle
// map.
var Cell = cell.Module(
	"bwmap",
	"Manages the endpoint bandwidth limit BPF map",

	cell.Provide(
		NewEdtTable,
		statedb.RWTable[Edt].ToTable,
		provideMap,
	),
	cell.Invoke(
		createMap,
		registerReconciler,
		bpf.RegisterTablePressureMetricsJob[Edt, *throttleMap],
	),
)

// provideMap provides a throttleMap to the Hive and configures its MapSpec in
// the MapRegistry.
func provideMap(cfg types.BandwidthConfig, reg *registry.MapRegistry) (out bpf.MapOut[*throttleMap], err error) {
	if err := reg.Modify(MapName, func(m *registry.MapSpecPatch) {
		m.MaxEntries = uint32(MapSize)
	}); err != nil {
		return bpf.MapOut[*throttleMap]{}, err
	}

	return bpf.NewMapOut(&throttleMap{}), nil
}

// createMap creates and opens the throttle BPF map if the bandwidth manager is
// enabled.
func createMap(logger *slog.Logger, cfg types.BandwidthConfig, reg *registry.MapRegistry, m *throttleMap) error {
	if !cfg.EnableBandwidthManager {
		// Remove map pin if the map is disabled.
		bpf.Remove(bpf.MapPath(logger, MapName))

		return nil
	}

	spec, err := reg.Get(MapName)
	if err != nil {
		return fmt.Errorf("getting MapSpec: %w", err)
	}
	m.m = bpf.NewMapFromSpec(spec, &EdtId{}, &EdtInfo{})

	return m.m.OpenOrCreate()
}

// registerReconciler registers the reconciler for the bandwidth map if the map
// has been created.
func registerReconciler(cfg types.BandwidthConfig, m *throttleMap, edts statedb.RWTable[Edt], params reconciler.Params) error {
	// Only register the reconciler if the map has been created.
	if m.m == nil {
		return nil
	}

	ops := bpf.NewMapOps[Edt](m.m)
	if _, err := reconciler.Register(
		params,
		edts,
		func(e Edt) Edt { return e },
		func(e Edt, s reconciler.Status) Edt {
			e.Status = s
			return e
		},
		func(e Edt) reconciler.Status {
			return e.Status
		},
		ops,
		nil,
	); err != nil {
		return fmt.Errorf("registering bandwidth edt reconciler: %w", err)
	}

	return nil
}
