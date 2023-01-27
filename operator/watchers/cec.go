// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"

	"github.com/cilium/cilium/operator/pkg/ciliumenvoyconfig"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// StartCECController starts the service watcher if it hasn't already and looks
// for service of type with envoy enabled LB annotation. Once such service is
// found, it will try to create one CEC associated with the service.
func StartCECController(ctx context.Context, clientset k8sClient.Clientset, services cell.Optional[resource.Resource[*slim_corev1.Service]], ports []string, defaultAlgorithm string) {
	if services == nil {
		return
	}

	go func() {
		store, err := (*services).Store(ctx)
		if err != nil {
			log.WithError(err).Fatal("Failed to retrieve service store")
		}

		m, err := ciliumenvoyconfig.New(clientset, store.CacheStore(), ports, defaultAlgorithm)
		if err != nil {
			log.WithError(err).Fatal("Error creating CiliumEnvoyConfiguration manager")
		}
		go m.Run(ctx)
		for ev := range (*services).Events(ctx) {
			switch ev.Kind {
			case resource.Sync:
				m.MarkSynced()
				ev.Done(nil)
			case resource.Upsert:
				ev.Done(m.OnUpdateService(nil, ev.Object))
			case resource.Delete:
				ev.Done(m.OnDeleteService(ev.Object))
			}
		}
	}()
}
