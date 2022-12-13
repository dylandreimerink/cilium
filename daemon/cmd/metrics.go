// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"time"

	"github.com/go-openapi/runtime/middleware"

	restapi "github.com/cilium/cilium/api/v1/server/restapi/metrics"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/spanstat"
)

type getMetrics struct {
	daemon *Daemon
}

// NewGetMetricsHandler returns the metrics handler
func NewGetMetricsHandler(d *Daemon) restapi.GetMetricsHandler {
	return &getMetrics{daemon: d}
}

func (h *getMetrics) Handle(params restapi.GetMetricsParams) middleware.Responder {
	metrics, err := h.daemon.metricsRegistry.DumpMetrics()
	if err != nil {
		return api.Error(
			restapi.GetMetricsInternalServerErrorCode,
			fmt.Errorf("Cannot gather metrics from daemon"))
	}

	return restapi.NewGetMetricsOK().WithPayload(metrics)
}

// These spans need to start recording before hive has been invoked, these globals will be assigned to the
// hive initialized BootstrapMetrics as soon as its available.
var (
	overallBootstrap   spanstat.SpanStat
	earlyInitBootstrap spanstat.SpanStat
)

type BootstrapMetrics struct {
	BootstrapTimes metric.Vec[metric.Observer]
}

type BootstrapTimes struct {
	bootstrapMetrics *BootstrapMetrics

	overall         *spanstat.SpanStat
	earlyInit       *spanstat.SpanStat
	k8sInit         spanstat.SpanStat
	restore         spanstat.SpanStat
	healthCheck     spanstat.SpanStat
	ingressIPAM     spanstat.SpanStat
	initAPI         spanstat.SpanStat
	initDaemon      spanstat.SpanStat
	cleanup         spanstat.SpanStat
	bpfBase         spanstat.SpanStat
	clusterMeshInit spanstat.SpanStat
	ipam            spanstat.SpanStat
	daemonInit      spanstat.SpanStat
	mapsInit        spanstat.SpanStat
	workloadsInit   spanstat.SpanStat
	proxyStart      spanstat.SpanStat
	fqdn            spanstat.SpanStat
	enableConntrack spanstat.SpanStat
	kvstore         spanstat.SpanStat
}

func NewBootstrapMetrics() *BootstrapMetrics {
	return &BootstrapMetrics{
		BootstrapTimes: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        metrics.Namespace,
			Subsystem:        metrics.SubsystemAgent,
			Name:             "bootstrap_seconds",
			Help:             "Duration of bootstrap sequence",
			EnabledByDefault: true,
		}, []metric.LabelDescription{metrics.LabelScope, metrics.LabelOutcome}),
	}
}

func NewBootstrapTimes(metrics *BootstrapMetrics) *BootstrapTimes {
	return &BootstrapTimes{
		bootstrapMetrics: metrics,
		// This timespan will have been started before this constructor is called, adopt it now.
		overall:   &overallBootstrap,
		earlyInit: &earlyInitBootstrap,
	}
}

func (bm *BootstrapTimes) updateMetrics() {
	for scope, stat := range bm.getMap() {
		if stat.SuccessTotal() != time.Duration(0) {
			bm.bootstrapMetrics.BootstrapTimes.WithLabelValues(scope, metrics.LabelValueOutcomeSuccess.Name).Observe(stat.SuccessTotal().Seconds())
		}
		if stat.FailureTotal() != time.Duration(0) {
			bm.bootstrapMetrics.BootstrapTimes.WithLabelValues(scope, metrics.LabelValueOutcomeFail.Name).Observe(stat.FailureTotal().Seconds())
		}
	}
}

func (bm *BootstrapTimes) getMap() map[string]*spanstat.SpanStat {
	return map[string]*spanstat.SpanStat{
		"overall":         bm.overall,
		"earlyInit":       bm.earlyInit,
		"k8sInit":         &bm.k8sInit,
		"restore":         &bm.restore,
		"healthCheck":     &bm.healthCheck,
		"ingressIPAM":     &bm.ingressIPAM,
		"initAPI":         &bm.initAPI,
		"initDaemon":      &bm.initDaemon,
		"cleanup":         &bm.cleanup,
		"bpfBase":         &bm.bpfBase,
		"clusterMeshInit": &bm.clusterMeshInit,
		"ipam":            &bm.ipam,
		"daemonInit":      &bm.daemonInit,
		"mapsInit":        &bm.mapsInit,
		"workloadsInit":   &bm.workloadsInit,
		"proxyStart":      &bm.proxyStart,
		"fqdn":            &bm.fqdn,
		"enableConntrack": &bm.enableConntrack,
		"kvstore":         &bm.kvstore,
	}
}
