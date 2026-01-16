// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package registry

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
)

var Cell = cell.Module(
	"registry",
	"Registry of eBPF map specifications that can be modified",
	cell.Provide(new),
	cell.Invoke(start),
)

type registryParams struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group
}

// new creates a new MapRegistry instance.
func new(p registryParams) (*MapRegistry, error) {
	reg, err := newMapRegistry(p)
	if err != nil {
		return nil, err
	}

	p.JobGroup.Add(
		job.OneShot("registry", func(ctx context.Context, health cell.Health) error {
			health.OK("Registry started and read-only")
			return nil
		}))

	return reg, nil
}

// start marks the registry as started, making it read-only.
func start(r *MapRegistry) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.started = true

	return nil
}
