package client

import (
	"context"
	"net/url"
	"strings"
	"time"

	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"

	"github.com/cilium/cilium/pkg/metrics"
)

// k8sMetrics implements the LatencyMetric and ResultMetric interface from
// k8s client-go package
type k8sMetrics struct {
	legacyMetrics *metrics.LegacyMetrics
}

func (k *k8sMetrics) Observe(_ context.Context, verb string, u url.URL, latency time.Duration) {
	k.legacyMetrics.KubernetesAPIInteractions.WithLabelValues(u.Path, verb).Observe(latency.Seconds())
}

func (k *k8sMetrics) Increment(_ context.Context, code string, method string, host string) {
	k.legacyMetrics.KubernetesAPICallsTotal.WithLabelValues(host, method, code).Inc()
	// The 'code' is set to '<error>' in case an error is returned from k8s
	// more info:
	// https://github.com/kubernetes/client-go/blob/v0.18.0-rc.1/rest/request.go#L700-L703
	if code != "<error>" {
		// Consider success only if status code is 2xx
		if strings.HasPrefix(code, "2") {
			k8smetrics.LastSuccessInteraction.Reset()
		}
	}
	k8smetrics.LastInteraction.Reset()
}
