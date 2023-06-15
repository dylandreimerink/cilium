// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	metricpkg "github.com/cilium/cilium/pkg/metrics/metric"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

var defaultAgentRegistryConfig = AgentRegistryConfig{
	PrometheusServeAddr: ":9962",
}

type AgentRegistryConfig struct {
	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddr string
	// This is a list of metrics to be enabled or disabled, format is `+`/`-` + `{metric name}`
	Metrics []string
}

func (rc AgentRegistryConfig) Flags(flags *pflag.FlagSet) {
	flags.String("prometheus-serve-addr", rc.PrometheusServeAddr, "IP:Port on which to serve prometheus metrics (pass \":Port\" to bind on all interfaces, \"\" is off)")
	flags.StringSlice("metrics", rc.Metrics, "Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo, -metric_bar to disable metric_bar)")
}

func (rc AgentRegistryConfig) GetMetrics() []string {
	return rc.Metrics
}

func (rc AgentRegistryConfig) GetServeAddr() string {
	return rc.PrometheusServeAddr
}

type RegistryConfig interface {
	GetMetrics() []string
	GetServeAddr() string
}

// RegistryParams are the parameters needed to construct a Registry
type RegistryParams struct {
	cell.In

	Logger     logrus.FieldLogger
	Shutdowner hive.Shutdowner
	Lifecycle  hive.Lifecycle

	AutoMetrics []metricpkg.WithMetadata `group:"hive-metrics"`
	Config      RegistryConfig
}

// Registry is a cell around a prometheus registry. This registry starts an HTTP server as part of its lifecycle
// on which all enabled metrics will be available. A reference to this registry can also be used to dynamically
// register or unregister `prometheus.Collector`s.
type Registry struct {
	inner *prometheus.Registry

	params RegistryParams
}

func NewRegistry(params RegistryParams) *Registry {
	reg := &Registry{
		params: params,
	}

	reg.Reinitialize()

	// Resolve the global registry variable for as long as we still have global functions
	registryResolver.Resolve(reg)

	if params.Config.GetServeAddr() != "" {
		// The Handler function provides a default handler to expose metrics
		// via an HTTP server. "/metrics" is the usual endpoint for that.
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg.inner, promhttp.HandlerOpts{}))
		srv := http.Server{
			Addr:    params.Config.GetServeAddr(),
			Handler: mux,
		}

		params.Lifecycle.Append(hive.Hook{
			OnStart: func(hc hive.HookContext) error {
				go func() {
					params.Logger.Infof("Serving prometheus metrics on %s", params.Config.GetServeAddr())
					err := srv.ListenAndServe()
					if err != nil && !errors.Is(err, http.ErrServerClosed) {
						params.Shutdowner.Shutdown(hive.ShutdownWithError(err))
					}
				}()
				return nil
			},
			OnStop: func(hc hive.HookContext) error {
				return srv.Shutdown(hc)
			},
		})
	}

	return reg
}

// Register registers a collector
func (r *Registry) Register(c prometheus.Collector) error {
	return r.inner.Register(c)
}

// Unregister unregisters a collector
func (r *Registry) Unregister(c prometheus.Collector) bool {
	return r.inner.Unregister(c)
}

// goCustomCollectorsRX tracks enabled go runtime metrics.
var goCustomCollectorsRX = regexp.MustCompile(`^/sched/latencies:seconds`)

// Reinitialize creates a new internal registry and re-registers metrics to it.
func (r *Registry) Reinitialize() {
	r.inner = prometheus.NewPedanticRegistry()

	metrics := make(map[string]metricpkg.WithMetadata)
	for i, autoMetric := range r.params.AutoMetrics {
		metrics[autoMetric.Opts().ConfigName] = r.params.AutoMetrics[i]
	}

	metricFlags := r.params.Config.GetMetrics()
	for _, metricFlag := range metricFlags {
		metricFlag = strings.TrimSpace(metricFlag)

		metric := metrics[metricFlag[1:]]
		if metric == nil {
			continue
		}

		switch metricFlag[0] {
		case '+':
			metric.SetEnabled(true)
		case '-':
			metric.SetEnabled(false)
		default:
			r.params.Logger.Warning(
				"--metrics flag contains value which does not start with + or -, '%s', ignoring",
				metricFlag,
			)
		}
	}

	for _, m := range metrics {
		if c, ok := m.(prometheus.Collector); ok {
			r.MustRegister(c)
		}
	}
}

// MustRegister adds the collector to the registry, exposing this metric to
// prometheus scrapes.
// It will panic on error.
func (r *Registry) MustRegister(c ...prometheus.Collector) {
	r.inner.MustRegister(c...)
}

// RegisterList registers a list of collectors. If registration of one
// collector fails, no collector is registered.
func (r *Registry) RegisterList(list []prometheus.Collector) error {
	registered := []prometheus.Collector{}

	for _, c := range list {
		if err := r.Register(c); err != nil {
			for _, c := range registered {
				r.Unregister(c)
			}
			return err
		}

		registered = append(registered, c)
	}

	return nil
}

// DumpMetrics gets the current Cilium metrics and dumps all into a
// models.Metrics structure.If metrics cannot be retrieved, returns an error
func (r *Registry) DumpMetrics() ([]*models.Metric, error) {
	result := []*models.Metric{}
	currentMetrics, err := r.inner.Gather()
	if err != nil {
		return result, err
	}

	for _, val := range currentMetrics {
		metricName := val.GetName()
		metricType := val.GetType()

		for _, metricLabel := range val.Metric {
			labels := map[string]string{}
			for _, label := range metricLabel.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}

			var value float64
			switch metricType {
			case dto.MetricType_COUNTER:
				value = metricLabel.Counter.GetValue()
			case dto.MetricType_GAUGE:
				value = metricLabel.GetGauge().GetValue()
			case dto.MetricType_UNTYPED:
				value = metricLabel.GetUntyped().GetValue()
			case dto.MetricType_SUMMARY:
				value = metricLabel.GetSummary().GetSampleSum()
			case dto.MetricType_HISTOGRAM:
				value = metricLabel.GetHistogram().GetSampleSum()
			default:
				continue
			}

			metric := &models.Metric{
				Name:   metricName,
				Labels: labels,
				Value:  value,
			}
			result = append(result, metric)
		}
	}
	return result, nil
}
