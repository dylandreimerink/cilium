// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"time"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/rate"
)

const (
	apiRequestEndpointCreate = "endpoint-create"
	apiRequestEndpointDelete = "endpoint-delete"
	apiRequestEndpointGet    = "endpoint-get"
	apiRequestEndpointPatch  = "endpoint-patch"
	apiRequestEndpointList   = "endpoint-list"
)

var apiRateLimitDefaults = map[string]rate.APILimiterParameters{
	// PUT /endpoint/{id}
	apiRequestEndpointCreate: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Second * 2,
		RateLimit:                   0.5,
		RateBurst:                   4,
		ParallelRequests:            4,
		SkipInitial:                 4,
		MaxWaitDuration:             15 * time.Second,
		Log:                         false,
	},
	// DELETE /endpoint/{id}
	//
	// No maximum wait time is enforced as delete calls should always
	// succeed. Permit a large number of parallel requests to minimize
	// latency of delete calls, if the system performance allows for it,
	// the maximum number of parallel requests will grow to a larger number
	// but it will never shrink below 4. Logging is enabled for visibility
	// as frequency should be low.
	apiRequestEndpointDelete: {
		EstimatedProcessingDuration: 200 * time.Millisecond,
		AutoAdjust:                  true,
		ParallelRequests:            4,
		MinParallelRequests:         4,
		Log:                         false,
	},
	// GET /endpoint/{id}/healthz
	// GET /endpoint/{id}/log
	// GET /endpoint/{id}/labels
	// GET /endpoint/{id}/config
	//
	// All GET calls to endpoint attributes are grouped together and rate
	// limited.
	apiRequestEndpointGet: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Millisecond * 200,
		RateLimit:                   4.0,
		RateBurst:                   4,
		ParallelRequests:            4,
		MinParallelRequests:         2,
		SkipInitial:                 4,
		MaxWaitDuration:             10 * time.Second,
	},
	// PATCH /endpoint/{id}
	// PATCH /endpoint/{id}/config
	// PATCH /endpoint/{id}/labels
	//
	// These calls are similar PUT /endpoint/{id} but put into a separate
	// group as they are less likely to be expensive. They can be expensive
	// though if datapath regenerations are required. Logging is enabled
	// for visibility.
	apiRequestEndpointPatch: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Second,
		RateLimit:                   0.5,
		RateBurst:                   4,
		ParallelRequests:            4,
		SkipInitial:                 4,
		MaxWaitDuration:             15 * time.Second,
		Log:                         false,
	},
	// GET /endpoint
	//
	// Listing endpoints should be relatively quick, even with a large
	// number of endpoints on a node. Always permit two parallel requests
	// and rely on rate limiting to throttle if load becomes high.
	apiRequestEndpointList: {
		AutoAdjust:                  true,
		EstimatedProcessingDuration: time.Millisecond * 300,
		RateLimit:                   1.0,
		RateBurst:                   4,
		ParallelRequests:            2,
		MinParallelRequests:         2,
	},
}

type apiRateLimitingMetrics struct {
	// APILimiterWaitDuration is the gauge of the current mean, min, and
	// max wait duration
	APILimiterWaitDuration metric.Vec[metric.Gauge]
	// APILimiterProcessingDuration is the gauge of the mean and estimated
	// processing duration
	APILimiterProcessingDuration metric.Vec[metric.Gauge]
	// APILimiterRequestsInFlight is the gauge of the current and max
	// requests in flight
	APILimiterRequestsInFlight metric.Vec[metric.Gauge]
	// APILimiterRateLimit is the gauge of the current rate limiting
	// configuration including limit and burst
	APILimiterRateLimit metric.Vec[metric.Gauge]
	// APILimiterWaitHistoryDuration is a histogram that measures the
	// individual wait durations of API limiters
	APILimiterWaitHistoryDuration metric.Vec[metric.Observer]
	// APILimiterAdjustmentFactor is the gauge representing the latest
	// adjustment factor that was applied
	APILimiterAdjustmentFactor metric.Vec[metric.Gauge]
	// APILimiterProcessedRequests is the counter of the number of
	// processed (successful and failed) requests
	APILimiterProcessedRequests metric.Vec[metric.Counter]
}

func newApiRateLimitingMetrics() *apiRateLimitingMetrics {
	return &apiRateLimitingMetrics{
		APILimiterWaitHistoryDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace:        metrics.Namespace,
			Subsystem:        metrics.SubsystemAPILimiter,
			Name:             "wait_history_duration_seconds",
			Help:             "Histogram over duration of waiting period for API calls subjects to rate limiting",
			EnabledByDefault: false,
		}, metric.LabelDescriptions{{Name: "api_call"}}),

		APILimiterWaitDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        metrics.Namespace,
			Subsystem:        metrics.SubsystemAPILimiter,
			Name:             "wait_duration_seconds",
			Help:             "Current wait time for api calls",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			{Name: "value"},
		}),

		APILimiterProcessingDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        metrics.Namespace,
			Subsystem:        metrics.SubsystemAPILimiter,
			Name:             "processing_duration_seconds",
			Help:             "Current processing time of api call",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			{Name: "value"},
		}),

		APILimiterRequestsInFlight: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        metrics.Namespace,
			Subsystem:        metrics.SubsystemAPILimiter,
			Name:             "requests_in_flight",
			Help:             "Current requests in flight",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			{Name: "value"},
		}),

		APILimiterRateLimit: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        metrics.Namespace,
			Subsystem:        metrics.SubsystemAPILimiter,
			Name:             "rate_limit",
			Help:             "Current rate limiting configuration",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			{Name: "value"},
		}),

		APILimiterAdjustmentFactor: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace:        metrics.Namespace,
			Subsystem:        metrics.SubsystemAPILimiter,
			Name:             "adjustment_factor",
			Help:             "Current adjustment factor while auto adjusting",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
		}),

		APILimiterProcessedRequests: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        metrics.Namespace,
			Subsystem:        metrics.SubsystemAPILimiter,
			Name:             "processed_requests_total",
			Help:             "Total number of API requests processed",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "api_call"},
			metrics.LabelOutcome,
		}),
	}
}

func (a *apiRateLimitingMetrics) ProcessedRequest(name string, v rate.MetricsValues) {
	a.APILimiterProcessingDuration.WithLabelValues(name, "mean").Set(v.MeanProcessingDuration)
	a.APILimiterProcessingDuration.WithLabelValues(name, "estimated").Set(v.EstimatedProcessingDuration)
	a.APILimiterWaitDuration.WithLabelValues(name, "mean").Set(v.MeanWaitDuration)
	a.APILimiterWaitDuration.WithLabelValues(name, "max").Set(v.MaxWaitDuration.Seconds())
	a.APILimiterWaitDuration.WithLabelValues(name, "min").Set(v.MinWaitDuration.Seconds())
	a.APILimiterRequestsInFlight.WithLabelValues(name, "in-flight").Set(float64(v.CurrentRequestsInFlight))
	a.APILimiterRequestsInFlight.WithLabelValues(name, "limit").Set(float64(v.ParallelRequests))
	a.APILimiterRateLimit.WithLabelValues(name, "limit").Set(float64(v.Limit))
	a.APILimiterRateLimit.WithLabelValues(name, "burst").Set(float64(v.Burst))
	a.APILimiterAdjustmentFactor.WithLabelValues(name).Set(v.AdjustmentFactor)

	if v.Outcome == "" {
		a.APILimiterWaitHistoryDuration.WithLabelValues(name).Observe(v.WaitDuration.Seconds())
		v.Outcome = metrics.Error2Outcome(v.Error)
	}

	a.APILimiterProcessedRequests.WithLabelValues(name, v.Outcome).Inc()
}
