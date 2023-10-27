// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	meta "k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/ipalloc"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_client_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/api/meta"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	client_typed_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// The condition added to services to indicate if a request for IPs could be satisfied or not
	ciliumSvcRequestSatisfiedCondition = "cilium.io/IPAMRequestSatisfied"

	ciliumPoolIPsTotalCondition     = "cilium.io/IPsTotal"
	ciliumPoolIPsAvailableCondition = "cilium.io/IPsAvailable"
	ciliumPoolIPsUsedCondition      = "cilium.io/IPsUsed"
	ciliumPoolConflict              = "cilium.io/PoolConflict"

	// The annotation LB IPAM will look for when searching for requested IPs
	ciliumSvcLBIPSAnnotation = "io.cilium/lb-ipam-ips"
  ciliumSvcLBISKAnnotation = "io.cilium/lb-ipam-sharing-key"

	// The string used in the FieldManager field on update options
	ciliumFieldManager = "cilium-operator-lb-ipam"

	serviceNamespaceLabel = "io.kubernetes.service.namespace"
	serviceNameLabel      = "io.kubernetes.service.name"
)

var (
	// eventsOpts are the options used with resource's Events()
	eventsOpts = resource.WithRateLimiter(
		// This rate limiter will retry in the following pattern
		// 250ms, 500ms, 1s, 2s, 4s, 8s, 16s, 32s, .... max 5m
		workqueue.NewItemExponentialFailureRateLimiter(250*time.Millisecond, 5*time.Minute),
	)
)

func newLBIPAM(params LBIPAMParams) *LBIPAM {
	if !params.Clientset.IsEnabled() {
		return nil
	}

	var lbClasses []string
	if params.DaemonConfig.EnableBGPControlPlane {
		lbClasses = append(lbClasses, cilium_api_v2alpha1.BGPLoadBalancerClass)
	}

	if params.DaemonConfig.EnableL2Announcements {
		lbClasses = append(lbClasses, cilium_api_v2alpha1.L2AnnounceLoadBalancerClass)
	}

	jobGroup := params.JobRegistry.NewGroup(
		params.Scope,
		job.WithLogger(params.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "lbipam")),
	)

	lbIPAM := &LBIPAM{
		logger:       params.Logger,
		poolResource: params.PoolResource,
		svcResource:  params.SvcResource,
		poolClient:   params.Clientset.CiliumV2alpha1().CiliumLoadBalancerIPPools(),
		svcClient:    params.Clientset.Slim().CoreV1(),
		shutdowner:   params.Shutdowner,
		pools:        make(map[string]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool),
		rangesStore:  newRangesStore(),
		serviceStore: NewServiceStore(),
		lbClasses:    lbClasses,
		ipv4Enabled:  option.Config.IPv4Enabled(),
		ipv6Enabled:  option.Config.IPv6Enabled(),
		jobGroup:     jobGroup,
		metrics:      params.Metrics,
	}

	jobGroup.Add(
		job.OneShot("lbipam main", func(ctx context.Context, health cell.HealthReporter) error {
			lbIPAM.Run(ctx, health)
			return nil
		}),
	)

	params.LC.Append(jobGroup)

	return lbIPAM
}

// LBIPAM is the loadbalancer IP address manager, controller which allocates and assigns IP addresses
// to LoadBalancer services from the configured set of LoadBalancerIPPools in the cluster.
type LBIPAM struct {
	logger logrus.FieldLogger

	lbClasses   []string
	ipv4Enabled bool
	ipv6Enabled bool

	poolClient cilium_client_v2alpha1.CiliumLoadBalancerIPPoolInterface
	svcClient  client_typed_v1.ServicesGetter

	poolResource resource.Resource[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]
	svcResource  resource.Resource[*slim_core_v1.Service]

	shutdowner hive.Shutdowner

	pools        map[string]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool
	rangesStore  rangesStore
	serviceStore serviceStore

	jobGroup job.Group

	metrics *ipamMetrics

	// Only used during testing.
	initDoneCallbacks []func()
}

func (ipam *LBIPAM) restart() {
	ipam.logger.Info("Restarting LB IPAM")

	// Reset all stored state
	ipam.pools = make(map[string]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)
	ipam.rangesStore = newRangesStore()
	ipam.serviceStore = NewServiceStore()

	// Re-start the main goroutine
	ipam.jobGroup.Add(
		job.OneShot("lbipam main", func(ctx context.Context, health cell.HealthReporter) error {
			ipam.Run(ctx, health)
			return nil
		}),
	)
}

func (ipam *LBIPAM) Run(ctx context.Context, health cell.HealthReporter) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	poolChan := ipam.poolResource.Events(ctx, eventsOpts)

	ipam.logger.Info("LB-IPAM initializing")

	// Synchronize pools first as we need them before we can satisfy
	// the services. This will also wait for the first pool to appear
	// before we start processing the services, which will save us from
	// unnecessary work when LB-IPAM is not used.
	poolsSynced := false
	for event := range poolChan {
		if event.Kind == resource.Sync {
			err := ipam.settleConflicts(ctx)
			if err != nil {
				ipam.logger.WithError(err).Error("Error while settling pool conflicts")
				// Keep retrying the handling of the sync event until we succeed.
				// During this time we may receive further updates and deletes.
				event.Done(err)
				continue
			}
			poolsSynced = true
			event.Done(nil)
		} else {
			ipam.handlePoolEvent(ctx, event)
		}

		// Pools have been synchronized and we've got more than
		// one pool, continue initialization.
		if poolsSynced && len(ipam.pools) > 0 {
			break
		}
	}

	svcChan := ipam.svcResource.Events(ctx, eventsOpts)

	for event := range svcChan {
		if event.Kind == resource.Sync {
			if err := ipam.satisfyServices(ctx); err != nil {
				ipam.logger.WithError(err).Error("Error while satisfying services")
				// Keep retrying the handling of the sync event until we succeed.
				event.Done(err)
				continue
			}
			if err := ipam.updateAllPoolCounts(ctx); err != nil {
				ipam.logger.WithError(err).Error("Error while updating pool counts")
				event.Done(err)
				continue
			}
			event.Done(nil)
			break
		} else {
			ipam.handleServiceEvent(ctx, event)
		}
	}

	ipam.logger.Info("LB-IPAM done initializing")
	for _, cb := range ipam.initDoneCallbacks {
		if cb != nil {
			cb()
		}
	}

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-poolChan:
			if !ok {
				poolChan = nil
				continue
			}
			ipam.handlePoolEvent(ctx, event)

			// This controller must go back into a dormant state when the last pool has been removed
			if len(ipam.pools) == 0 {
				// Upon return, restart the controller, which will start in pre-init state
				defer ipam.restart()
				return
			}

		case event, ok := <-svcChan:
			if !ok {
				svcChan = nil
				continue
			}
			ipam.handleServiceEvent(ctx, event)
		}
	}
}

func (ipam *LBIPAM) handlePoolEvent(ctx context.Context, event resource.Event[*cilium_api_v2alpha1.CiliumLoadBalancerIPPool]) {
	var err error
	switch event.Kind {
	case resource.Upsert:
		err = ipam.poolOnUpsert(ctx, event.Key, event.Object)
		if err != nil {
			ipam.logger.WithError(err).Error("pool upsert failed")
			err = fmt.Errorf("poolOnUpsert: %w", err)
		}
	case resource.Delete:
		err = ipam.poolOnDelete(ctx, event.Key, event.Object)
		if err != nil {
			ipam.logger.WithError(err).Error("pool delete failed")
			err = fmt.Errorf("poolOnDelete: %w", err)
		}
	}
	event.Done(err)
}

func (ipam *LBIPAM) handleServiceEvent(ctx context.Context, event resource.Event[*slim_core_v1.Service]) {
	var err error
	switch event.Kind {
	case resource.Upsert:
		err = ipam.svcOnUpsert(ctx, event.Key, event.Object)
		if err != nil {
			ipam.logger.WithError(err).Error("service upsert failed")
			err = fmt.Errorf("svcOnUpsert: %w", err)
		}
	case resource.Delete:
		err = ipam.svcOnDelete(ctx, event.Key, event.Object)
		if err != nil {
			ipam.logger.WithError(err).Error("service delete failed")
			err = fmt.Errorf("svcOnDelete: %w", err)
		}
	}
	event.Done(err)
}

// RegisterOnReady registers a callback function which will be invoked when LBIPAM is done initializing.
// Note: mainly used in the integration tests.
func (ipam *LBIPAM) RegisterOnReady(cb func()) {
	ipam.initDoneCallbacks = append(ipam.initDoneCallbacks, cb)
}

func (ipam *LBIPAM) poolOnUpsert(ctx context.Context, k resource.Key, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
	// Deep copy so we get a version we are allowed to update the status
	pool = pool.DeepCopy()

	var err error
	if _, exists := ipam.pools[pool.GetName()]; exists {
		err = ipam.handlePoolModified(ctx, pool)
		if err != nil {
			return fmt.Errorf("handlePoolModified: %w", err)
		}
	} else {
		err = ipam.handleNewPool(ctx, pool)
		if err != nil {
			return fmt.Errorf("handleNewPool: %w", err)
		}
	}
	if err != nil {
		return err
	}

	err = ipam.settleConflicts(ctx)
	if err != nil {
		return fmt.Errorf("settleConflicts: %w", err)
	}

	err = ipam.satisfyAndUpdateCounts(ctx)
	if err != nil {
		return fmt.Errorf("satisfyAndUpdateCounts: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) poolOnDelete(ctx context.Context, k resource.Key, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
	err := ipam.handlePoolDeleted(ctx, pool)
	if err != nil {
		return fmt.Errorf("handlePoolDeleted: %w", err)
	}

	err = ipam.settleConflicts(ctx)
	if err != nil {
		return fmt.Errorf("settleConflicts: %w", err)
	}

	err = ipam.satisfyAndUpdateCounts(ctx)
	if err != nil {
		return fmt.Errorf("satisfyAndUpdateCounts: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) svcOnUpsert(ctx context.Context, k resource.Key, svc *slim_core_v1.Service) error {
	err := ipam.handleUpsertService(ctx, svc)
	if err != nil {
		return fmt.Errorf("handleUpsertService: %w", err)
	}

	err = ipam.satisfyAndUpdateCounts(ctx)
	if err != nil {
		return fmt.Errorf("satisfyAndUpdateCounts: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) svcOnDelete(ctx context.Context, k resource.Key, svc *slim_core_v1.Service) error {
	ipam.logger.Debugf("Deleted service '%s/%s'", svc.GetNamespace(), svc.GetName())

	ipam.handleDeletedService(svc)

	err := ipam.satisfyAndUpdateCounts(ctx)
	if err != nil {
		return fmt.Errorf("satisfyAndUpdateCounts: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) satisfyAndUpdateCounts(ctx context.Context) error {
	err := ipam.satisfyServices(ctx)
	if err != nil {
		return fmt.Errorf("satisfyServices: %w", err)
	}

	err = ipam.updateAllPoolCounts(ctx)
	if err != nil {
		return fmt.Errorf("updateAllPoolCounts: %w", err)
	}

	return nil
}

// handleUpsertService updates the service view in the service store, it removes any allocation and ingress that
// do not belong on the service and will move the service to the satisfied or unsatisfied service view store depending
// on if the service requests are satisfied or not.
func (ipam *LBIPAM) handleUpsertService(ctx context.Context, svc *slim_core_v1.Service) error {
	key := resource.NewKey(svc)
	sv, found, _ := ipam.serviceStore.GetService(key)
	if !found {
		sv = &ServiceView{
			Key: key,
		}
	}

	// Ignore services which are not meant for us
	if !ipam.isResponsibleForSVC(svc) {
		if !found {
			return nil
		}

		// Release allocations
		for _, alloc := range sv.AllocatedIPs {
			alloc.Origin.alloc.Free(alloc.IP)
		}
		ipam.serviceStore.Delete(sv.Key)

		// Remove all ingress IPs
		sv.Status.LoadBalancer.Ingress = nil
		slim_meta.RemoveStatusCondition(&sv.Status.Conditions, ciliumSvcRequestSatisfiedCondition)

		err := ipam.patchSvcStatus(ctx, sv)
		if err != nil {
			return fmt.Errorf("patchSvcStatus: %w", err)
		}

		return nil
	}

	// We are responsible for this service.

	// Update the service view
	sv.Generation = svc.Generation
	sv.Labels = svcLabels(svc)
	sv.RequestedFamilies.IPv4, sv.RequestedFamilies.IPv6 = ipam.serviceIPFamilyRequest(svc)
	sv.RequestedIPs = getSVCRequestedIPs(ipam.logger, svc)
	sv.SharingKey = getSVCSharingKey(ipam.logger, svc)
  sv.ExternalTrafficPolicy = svc.ExternalTrafficPolicy.DeepCopy()
  sv.Ports = svc.Ports.DeepCopy()
  sv.Selector = svc.Selector.DeepCopy()
	sv.Status = svc.Status.DeepCopy()

	// Remove any allocation that are no longer valid due to a change in the service spec
	err := ipam.stripInvalidAllocations(sv)
	if err != nil {
		return fmt.Errorf("stripInvalidAllocations: %w", err)
	}

	// Check for each ingress, if its IP has been allocated by us. If it isn't check if we can allocate that IP.
	// If we can't, strip the ingress from the service.
	svModifiedStatus, err := ipam.stripOrImportIngresses(sv)
	if err != nil {
		return fmt.Errorf("stripOrImportIngresses: %w", err)
	}

	// Attempt to satisfy this service in particular now. We do this now instread of relying on
	// ipam.satisfyServices to avoid updating the service twice in quick succession.
	if !sv.isSatisfied() {
		modified, err := ipam.satisfyService(sv)
		if err != nil {
			return fmt.Errorf("satisfyService: %w", err)
		}
		if modified {
			svModifiedStatus = true
		}
	}

	// If any of the steps above changed the service object, update the object.
	if svModifiedStatus {
		err := ipam.patchSvcStatus(ctx, sv)
		if err != nil {
			return fmt.Errorf("patchSvcStatus: %w", err)
		}
	}

	ipam.serviceStore.Upsert(sv)

	return nil
}

func (ipam *LBIPAM) stripInvalidAllocations(sv *ServiceView) error {
	var errs error
	// Remove bad allocations which are no longer valid
	for allocIdx := len(sv.AllocatedIPs) - 1; allocIdx >= 0; allocIdx-- {
		alloc := sv.AllocatedIPs[allocIdx]

		releaseAllocIP := func() error {
			ipam.logger.Debugf("removing allocation '%s' from '%s'", alloc.IP.String(), sv.Key.String())
			alloc.Origin.alloc.Free(alloc.IP)

			sv.AllocatedIPs = slices.Delete(sv.AllocatedIPs, allocIdx, allocIdx+1)
			return nil
		}

		// If origin pool no longer exists, remove allocation
		pool, found := ipam.pools[alloc.Origin.originPool]
		if !found {
			errs = errors.Join(errs, releaseAllocIP())
			continue
		}

		// If service no longer matches the pool selector, remove allocation
		if pool.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.Spec.ServiceSelector)
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("Making selector from pool '%s' label selector", pool.Name))
				continue
			}

			if !selector.Matches(sv.Labels) {
				errs = errors.Join(errs, releaseAllocIP())
				continue
			}
		}

		// If the service is requesting specific IPs
		if len(sv.RequestedIPs) > 0 {
			found := false
			for _, reqIP := range sv.RequestedIPs {
				if reqIP.Compare(alloc.IP) == 0 {
					found = true
					break
				}
			}
			// If allocated IP has not been requested, remove it
			if !found {
				errs = errors.Join(errs, releaseAllocIP())
				continue
			}
		} else {
			// No specific requests have been made, check if we have ingresses from un-requested families.

			if isIPv6(alloc.IP) {
				// Service has an IPv6 address, but its spec doesn't request it anymore, so take it away
				if !sv.RequestedFamilies.IPv6 {
					errs = errors.Join(errs, releaseAllocIP())
					continue
				}

			} else {
				// Service has an IPv4 address, but its spec doesn't request it anymore, so take it away
				if !sv.RequestedFamilies.IPv4 {
					errs = errors.Join(errs, releaseAllocIP())
					continue
				}
			}
		}
	}

	return errs
}

func (ipam *LBIPAM) stripOrImportIngresses(sv *ServiceView) (statusModified bool, err error) {
	var newIngresses []slim_core_v1.LoadBalancerIngress

	// Only keep valid ingresses.
	for _, ingress := range sv.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}

		ip, err := netip.ParseAddr(ingress.IP)
		if err != nil {
			continue
		}

		// Remove any ingress which is no longer allocated
		var viewIP *ServiceViewIP
		for i, vip := range sv.AllocatedIPs {
			if vip.IP.Compare(ip) == 0 {
				viewIP = &sv.AllocatedIPs[i]
				break
			}
		}
		if viewIP == nil {
			// The ingress is not allocated by LB IPAM, check if we can "import it"

			// If the service has requested IP, the ingress must match one of them.
			if len(sv.RequestedIPs) > 0 {
				found := false
				for _, reqIP := range sv.RequestedIPs {
					if reqIP.Compare(ip) == 0 {
						found = true
						break
					}
				}
				if !found {
					// Don't keep ingress
					continue
				}
			}

			if isIPv6(ip) {
				if !sv.RequestedFamilies.IPv6 {
					continue
				}
			} else {
				if !sv.RequestedFamilies.IPv4 {
					continue
				}
			}

			lbRange, _, err := ipam.findRangeOfIP(sv, ip)
			if err != nil {
				return statusModified, fmt.Errorf("findRangeOfIP: %w", err)
			}
			if lbRange == nil {
				continue
			}

			err = lbRange.alloc.Alloc(ip, true)
			if err != nil {
				if errors.Is(err, ipalloc.ErrInUse) {
					ipam.logger.WithFields(logrus.Fields{
						"ingress-ip": ingress.IP,
						"svc":        sv.Key,
					}).Warningf(
						"Ingress IP '%s' is assigned to multiple services, removing from svc '%s'",
						ingress.IP,
						sv.Key,
					)

					continue
				}

				return statusModified, fmt.Errorf("Error while attempting to allocate IP '%s'", ingress.IP)
			}

			sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
				IP:     ip,
				Origin: lbRange,
			})
		}

		newIngresses = append(newIngresses, ingress)
	}

	// Deduplicate ingress IPs (condition can be created externally before we adopted the service)
	newIngresses = slices.CompactFunc(newIngresses, func(a, b slim_core_v1.LoadBalancerIngress) bool {
		return a.IP == b.IP
	})

	// Check if we have removed any ingresses
	if len(sv.Status.LoadBalancer.Ingress) != len(newIngresses) {
		statusModified = true
	}

	sv.Status.LoadBalancer.Ingress = newIngresses

	return statusModified, nil
}

func getSVCRequestedIPs(log logrus.FieldLogger, svc *slim_core_v1.Service) []netip.Addr {
	var ips []netip.Addr
	if svc.Spec.LoadBalancerIP != "" {
		ip, err := netip.ParseAddr(svc.Spec.LoadBalancerIP)
		if err == nil {
			ips = append(ips, ip)
		} else {
			log.WithError(err).Error("Unable to parse service.spec.LoadBalancerIP")
		}
	}

	if annotation := svc.Annotations[ciliumSvcLBIPSAnnotation]; annotation != "" {
		for _, ipStr := range strings.Split(annotation, ",") {
			ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
			if err == nil {
				ips = append(ips, ip)
			} else {
				log.WithError(err).Error("Unable to parse service.spec.LoadBalancerIP")
			}
		}
	}

	return slices.CompactFunc(ips, func(a, b netip.Addr) bool {
		return a.Compare(b) == 0
	})
}

func getSVCSharingKey(log logrus.FieldLogger, svc *slim_core_v1.Service) string {
	if annotation := svc.Annotations[ciliumSvcLBISKAnnotation]; annotation != "" {
		return annotation
	}
	return ""
}

func (ipam *LBIPAM) handleDeletedService(svc *slim_core_v1.Service) {
	key := resource.NewKey(svc)
	sv, found, _ := ipam.serviceStore.GetService(key)
	if !found {
		return
	}

	for _, alloc := range sv.AllocatedIPs {
		used_by_other := false
		done:
		for _, serviceView := range ipam.serviceStore.satisfied {
			for _, other_alloc := s.AllocatedIPs {
				if other_alloc.IP == alloc.IP {
					used_by_other = true
					break done
				}
			}
		}
		if used_by_other == false {
			alloc.Origin.alloc.Free(alloc.IP)
		}
	}

	ipam.serviceStore.Delete(key)
}

// satisfyServices attempts to satisfy all unsatisfied services by allocating and assigning IP addresses
func (ipam *LBIPAM) satisfyServices(ctx context.Context) error {
	for _, sv := range ipam.serviceStore.unsatisfied {
		statusModified, err := ipam.satisfyService(sv)
		if err != nil {
			return fmt.Errorf("satisfyService: %w", err)
		}

		// If the services status has been modified, update the service.
		if statusModified {
			err := ipam.patchSvcStatus(ctx, sv)
			if err != nil {
				return fmt.Errorf("patchSvcStatus: %w", err)
			}
		}

		ipam.serviceStore.Upsert(sv)
	}

	return nil
}

func (ipam *LBIPAM) satisfyService(sv *ServiceView) (statusModified bool, err error) {
	if len(sv.RequestedIPs) > 0 {
    // We check if the service has a sharing key annotation(cilium version).
    donesharing:
    if sv.SharingKey != "" {
      // If it does, we can see if it exists in the `rangeStore` via the index.
      serviceViewIPPtr, foundServiceViewIP := ipam.rangesStore.GetServiceViewIPForSharingKey(sv.SharingKey)
      if !foundServiceViewIP || serviceViewIPPtr == nil {
        break donesharing
      }
      serviceViewIP := *serviceViewIPPtr
      lbRangePtr := serviceViewIP.Origin
      if lbRangePtr == nil {
        break donesharing
      }
      lbRange := *lbRangePtr
      // If it exists, we go to the `LBRange` and get the list of `ServiceViews`.
      serviceViewsPtr, foundServiceViewsPtr := lbRange.alloc.Get(serviceViewIP.IP)
      if !foundServiceViewsPtr || serviceViewsPtr == nil {
        break donesharing
      }
      serviceViews := *serviceViewsPtr
      // Check if the ports and external traffic policy of the current service is compatible with the existing `ServiceViews`
      compatible := true
      for _, serviceView := range serviceViews {
        if !(serviceView.isCompatible(sv)) {
          compatible = false
          break
        }
      }
      // if it is, add the service view to the list, and satisfy the IP
      if compatible {
        sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
          IP:     serviceViewIP.IP,
          Origin: lbRange,
        })
        append(serviceViews, sv)
      }
    }
		// The service requests specific IPs
		for _, reqIP := range sv.RequestedIPs {
			// if we are able to find the requested IP in the list of allocated IPs
			if slices.IndexFunc(sv.AllocatedIPs, func(sv ServiceViewIP) bool {
				return reqIP.Compare(sv.IP) == 0
			}) != -1 {
				continue
			}

			lbRange, foundPool, err := ipam.findRangeOfIP(sv, reqIP)
			if err != nil {
				return statusModified, fmt.Errorf("findRangeOfIP: %w", err)
			}
			if lbRange == nil {
				msg := fmt.Sprintf("No pool exists with a CIDR containing '%s'", reqIP)
				reason := "no_pool"
				if foundPool {
					msg = fmt.Sprintf("The pool with the CIDR containing '%s', doesn't select this service", reqIP)
					reason = "pool_selector_mismatch"
				}
				if ipam.setSVCSatisfiedCondition(sv, false, reason, msg) {
					statusModified = true
				}

				continue
			}

			if _, exists := lbRange.alloc.Get(reqIP); exists {
			} else {
				ipam.logger.Debugf("Allocate '%s' for '%s'", reqIP.String(), sv.Key.String())
				err = lbRange.alloc.Alloc(reqIP, true)
				if err != nil {
					if errors.Is(err, ipalloc.ErrInUse) {
						return statusModified, fmt.Errorf("ipalloc.Alloc: %w", err)
					}

					ipam.logger.WithError(err).Error("Unable to allocate IP")
					continue
				}
			}

			sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
				IP:     reqIP,
				Origin: lbRange,
			})
		}

	} else {

		hasIPv4 := false
		hasIPv6 := false
		for _, allocated := range sv.AllocatedIPs {
			if isIPv6(allocated.IP) {
				hasIPv6 = true
			} else {
				hasIPv4 = true
			}
		}

		// Missing an IPv4 address, lets attempt to allocate an address
		if sv.RequestedFamilies.IPv4 && !hasIPv4 {
			newIP, lbRange, err := ipam.allocateIPAddress(sv, IPv4Family)
			if err != nil && !errors.Is(err, ipalloc.ErrFull) {
				return statusModified, fmt.Errorf("allocateIPAddress: %w", err)
			}
			if newIP.Compare(netip.Addr{}) != 0 {
				sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
					IP:     newIP,
					Origin: lbRange,
				})
			} else {
				reason := "no_pool"
				message := "There are no enabled CiliumLoadBalancerIPPools that match this service"
				if errors.Is(err, ipalloc.ErrFull) {
					reason = "out_of_ips"
					message = "All enabled CiliumLoadBalancerIPPools that match this service ran out of allocatable IPs"
				}

				if ipam.setSVCSatisfiedCondition(sv, false, reason, message) {
					statusModified = true
				}
			}
		}

		// Missing an IPv6 address, lets attempt to allocate an address
		if sv.RequestedFamilies.IPv6 && !hasIPv6 {
			newIP, lbRange, err := ipam.allocateIPAddress(sv, IPv6Family)
			if err != nil && !errors.Is(err, ipalloc.ErrFull) {
				return statusModified, fmt.Errorf("allocateIPAddress: %w", err)
			}
			if newIP.Compare(netip.Addr{}) != 0 {
				sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
					IP:     newIP,
					Origin: lbRange,
				})
			} else {
				reason := "no_pool"
				message := "There are no enabled CiliumLoadBalancerIPPools that match this service"
				if errors.Is(err, ipalloc.ErrFull) {
					reason = "out_of_ips"
					message = "All enabled CiliumLoadBalancerIPPools that match this service ran out of allocatable IPs"
				}

				if ipam.setSVCSatisfiedCondition(sv, false, reason, message) {
					statusModified = true
				}
			}
		}
	}

	// Sync allocated IPs back to the service
	for _, alloc := range sv.AllocatedIPs {
		// If the allocated IP isn't found in the assigned list, assign it
		if slices.IndexFunc(sv.Status.LoadBalancer.Ingress, func(in slim_core_v1.LoadBalancerIngress) bool {
			addr, err := netip.ParseAddr(in.IP)
			if err != nil {
				return false
			}

			return addr.Compare(alloc.IP) == 0
		}) == -1 {
      // Once we allocated a new IP, and we have a sharing key, check if the sharing key is present in the index (we can reuse the result from earlier)
      serviceViewIPPtr, foundServiceViewIP := ipam.rangesStore.GetServiceViewIPForSharingKey(sv.SharingKey)
      if !foundServiceViewIP || serviceViewIPPtr == nil {
        ipam.rangesStore.SetServiceViewIPForSharingKey(sv.SharingKey, alloc)
      }
      serviceViewIP := *serviceViewIPPtr
      lbRangePtr := serviceViewIP.Origin

			sv.Status.LoadBalancer.Ingress = append(sv.Status.LoadBalancer.Ingress, slim_core_v1.LoadBalancerIngress{
				IP: alloc.IP.String(),
			})
			statusModified = true
		}
	}

	if sv.isSatisfied() {
		if ipam.setSVCSatisfiedCondition(sv, true, "satisfied", "") {
			statusModified = true
		}
	}

	ipam.serviceStore.Upsert(sv)

	return statusModified, err
}

func (ipam *LBIPAM) setSVCSatisfiedCondition(
	sv *ServiceView,
	satisfied bool,
	reason, message string,
) (statusModified bool) {
	status := slim_meta_v1.ConditionFalse
	if satisfied {
		status = slim_meta_v1.ConditionTrue
	}

	if cond := slim_meta.FindStatusCondition(sv.Status.Conditions, ciliumSvcRequestSatisfiedCondition); cond != nil &&
		cond.Status == status &&
		cond.ObservedGeneration == sv.Generation &&
		cond.Reason == reason &&
		cond.Message == message {
		return false
	}

	slim_meta.SetStatusCondition(&sv.Status.Conditions, slim_meta_v1.Condition{
		Type:               ciliumSvcRequestSatisfiedCondition,
		Status:             status,
		ObservedGeneration: sv.Generation,
		LastTransitionTime: slim_meta_v1.Now(),
		Reason:             reason,
		Message:            message,
	})
	return true
}

func (ipam *LBIPAM) findRangeOfIP(sv *ServiceView, ip netip.Addr) (lbRange *LBRange, foundPool bool, err error) {
	for _, r := range ipam.rangesStore.ranges {
		if r.Disabled() {
			continue
		}

		from, to := r.alloc.Range()
		if ip.Compare(from) < 0 || ip.Compare(to) > 0 {
			continue
		}

		pool, found := ipam.pools[r.originPool]
		if !found {
			continue
		}

		foundPool = true

		if pool.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.Spec.ServiceSelector)
			if err != nil {
				return nil, false, fmt.Errorf("Making selector from pool '%s' label selector: %w", pool.Name, err)
			}

			if !selector.Matches(sv.Labels) {
				continue
			}
		}

		return r, false, nil
	}

	return nil, foundPool, nil
}

// isResponsibleForSVC checks if LB IPAM should allocate and assign IPs or some other controller
func (ipam *LBIPAM) isResponsibleForSVC(svc *slim_core_v1.Service) bool {
	// Ignore non-lb services
	if svc.Spec.Type != slim_core_v1.ServiceTypeLoadBalancer {
		return false
	}

	// We will assume that we are the default LB, LB-IPAM shouldn't be enabled clusters that don't support LBClasses
	// and have multiple LBs.
	if svc.Spec.LoadBalancerClass == nil {
		return true
	}

	if !slices.Contains(ipam.lbClasses, *svc.Spec.LoadBalancerClass) {
		return false
	}

	return true
}

type AddressFamily string

const (
	IPv4Family AddressFamily = "IPv4"
	IPv6Family AddressFamily = "IPv6"
)

func (ipam *LBIPAM) allocateIPAddress(
	sv *ServiceView,
	family AddressFamily,
) (
	newIP netip.Addr,
	chosenRange *LBRange,
	err error,
) {
	full := false
	for _, lbRange := range ipam.rangesStore.ranges {
		// If the range is disabled we can't allocate new IPs from it.
		if lbRange.Disabled() {
			continue
		}

		// Skip this range if it doesn't match the requested address family
		if _, to := lbRange.alloc.Range(); isIPv6(to) {
			if family == IPv4Family {
				continue
			}
		} else {
			if family == IPv6Family {
				continue
			}
		}

		pool, found := ipam.pools[lbRange.originPool]
		if !found {
			ipam.logger.WithField("pool-name", lbRange.originPool).
				Warnf("Bad state detected, store contains lbRange for pool '%s' but missing the pool", lbRange.originPool)
			continue
		}

		// If there is no selector, all services match
		if pool.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.Spec.ServiceSelector)
			if err != nil {
				return netip.Addr{}, nil, fmt.Errorf("Making selector from pool '%s' label selector: %w", pool.Name, err)
			}

			if !selector.Matches(sv.Labels) {
				continue
			}
		}

		// Attempt to allocate the next IP from this range.
		newIp, err := lbRange.alloc.AllocAny(true)
		if err != nil {
			// If the range is full, mark it.
			if errors.Is(err, ipalloc.ErrFull) {
				full = true
				continue
			}

			ipam.logger.WithError(err).Error("Allocate next IP from lb range")
			continue
		}

		return newIp, lbRange, nil
	}

	if full {
		return netip.Addr{}, nil, ipalloc.ErrFull
	}

	return netip.Addr{}, nil, nil
}

// serviceIPFamilyRequest checks which families of IP addresses are requested
func (ipam *LBIPAM) serviceIPFamilyRequest(svc *slim_core_v1.Service) (IPv4Requested, IPv6Requested bool) {
	if svc.Spec.IPFamilyPolicy != nil {
		switch *svc.Spec.IPFamilyPolicy {
		case slim_core_v1.IPFamilyPolicySingleStack:
			if len(svc.Spec.IPFamilies) > 0 {
				if svc.Spec.IPFamilies[0] == slim_core_v1.IPFamily(IPv4Family) {
					IPv4Requested = true
				} else {
					IPv6Requested = true
				}
			} else {
				if ipam.ipv4Enabled {
					IPv4Requested = true
				} else if ipam.ipv6Enabled {
					IPv6Requested = true
				}
			}

		case slim_core_v1.IPFamilyPolicyPreferDualStack:
			if len(svc.Spec.IPFamilies) > 0 {
				for _, family := range svc.Spec.IPFamilies {
					if family == slim_core_v1.IPFamily(IPv4Family) {
						IPv4Requested = ipam.ipv4Enabled
					}
					if family == slim_core_v1.IPFamily(IPv6Family) {
						IPv6Requested = ipam.ipv6Enabled
					}
				}
			} else {
				// If no IPFamilies are specified

				IPv4Requested = ipam.ipv4Enabled
				IPv6Requested = ipam.ipv6Enabled
			}

		case slim_core_v1.IPFamilyPolicyRequireDualStack:
			IPv4Requested = ipam.ipv4Enabled
			IPv6Requested = ipam.ipv6Enabled
		}
	} else {
		if len(svc.Spec.IPFamilies) > 0 {
			if svc.Spec.IPFamilies[0] == slim_core_v1.IPFamily(IPv4Family) {
				IPv4Requested = true
			} else {
				IPv6Requested = true
			}
		} else {
			if ipam.ipv4Enabled {
				IPv4Requested = true
			} else if ipam.ipv6Enabled {
				IPv6Requested = true
			}
		}
	}

	return IPv4Requested, IPv6Requested
}

// Handle the addition of a new IPPool
func (ipam *LBIPAM) handleNewPool(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
	// Sanity check that we do not yet know about this pool.
	if _, found := ipam.pools[pool.GetName()]; found {
		ipam.logger.WithField("pool-name", pool.GetName()).
			Warnf("LB IPPool '%s' has been created, but a LB IP Pool with the same name already exists", pool.GetName())
		return nil
	}

	ipam.pools[pool.GetName()] = pool
	blocks := append(pool.Spec.Cidrs, pool.Spec.Blocks...)
	for _, ipBlock := range blocks {
		from, to, fromCidr, err := ipRangeFromBlock(ipBlock)
		if err != nil {
			return fmt.Errorf("Error parsing ip block: %w", err)
		}

		lbRange, err := NewLBRange(from, to, pool)
		if err != nil {
			return fmt.Errorf("Error making LB Range for '%s': %w", ipBlock.Cidr, err)
		}

		// If AllowFirstLastIPs is no or unspecified, mark the first and last IP as allocated upon range creation.
		if fromCidr && pool.Spec.AllowFirstLastIPs != cilium_api_v2alpha1.AllowFirstLastIPYes {
			// TODO: in 1.16 switch from default no to default yes.
			// https://github.com/cilium/cilium/issues/28591
			from, to := lbRange.alloc.Range()

			// If the first and last IPs are the same or adjacent, we would reserve the entire range.
			// Only reserve first and last IPs for ranges /30 or /126 and larger.
			if !(from.Compare(to) == 0 || from.Next().Compare(to) == 0) {
				lbRange.alloc.Alloc(from, true)
				lbRange.alloc.Alloc(to, true)
			}
		}

		ipam.rangesStore.Add(lbRange)
	}

	// Unmark new pools so they get a conflict: False condition set, otherwise kubectl will report a blank field.
	ipam.unmarkPool(ctx, pool)

	return nil
}

func ipRangeFromBlock(block cilium_api_v2alpha1.CiliumLoadBalancerIPPoolIPBlock) (to, from netip.Addr, fromCidr bool, err error) {
	if string(block.Cidr) != "" {
		prefix, err := netip.ParsePrefix(string(block.Cidr))
		if err != nil {
			return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("Error parsing cidr '%s': %w", block.Cidr, err)
		}

		to, from = rangeFromPrefix(prefix)
		return to, from, true, nil
	}

	from, err = netip.ParseAddr(block.Start)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("error parsing start ip '%s': %w", block.Start, err)
	}
	if block.Stop == "" {
		return from, from, false, nil
	}

	to, err = netip.ParseAddr(block.Stop)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false, fmt.Errorf("error parsing stop ip '%s': %w", block.Stop, err)
	}

	return from, to, false, nil
}

func (ipam *LBIPAM) handlePoolModified(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
	changedAllowFirstLastIPs := false
	if existingPool, ok := ipam.pools[pool.GetName()]; ok {
		changedAllowFirstLastIPs = (existingPool.Spec.AllowFirstLastIPs == cilium_api_v2alpha1.AllowFirstLastIPYes) !=
			(pool.Spec.AllowFirstLastIPs == cilium_api_v2alpha1.AllowFirstLastIPYes)
	}

	ipam.pools[pool.GetName()] = pool

	type rng struct {
		from, to netip.Addr
		fromCidr bool
	}
	var newRanges []rng
	blocks := append(pool.Spec.Cidrs, pool.Spec.Blocks...)
	for _, newBlock := range blocks {
		from, to, fromCidr, err := ipRangeFromBlock(newBlock)
		if err != nil {
			return fmt.Errorf("Error parsing ip block: %w", err)
		}

		newRanges = append(newRanges, rng{
			from:     from,
			to:       to,
			fromCidr: fromCidr,
		})
	}

	existingRanges, _ := ipam.rangesStore.GetRangesForPool(pool.GetName())

	// Remove existing ranges that no longer exist
	for _, extRange := range existingRanges {
		found := false
		fromCidr := false
		for _, newRange := range newRanges {
			if extRange.EqualCIDR(newRange.from, newRange.to) {
				found = true
				fromCidr = newRange.fromCidr
				break
			}
		}

		if found {
			// If the AllowFirstLastIPs state changed
			if fromCidr && changedAllowFirstLastIPs {
				// TODO in 1.16 switch from default no to default yes.
				// https://github.com/cilium/cilium/issues/28591
				if pool.Spec.AllowFirstLastIPs == cilium_api_v2alpha1.AllowFirstLastIPYes {
					// If we are allowing first and last IPs again, free them for allocation
					from, to := extRange.alloc.Range()

					if !(from.Compare(to) == 0 || from.Next().Compare(to) == 0) {
						extRange.alloc.Free(from)
						extRange.alloc.Free(to)
					}
				} else {
					// If we are disallowing first and last IPs, alloc the first and last IP if they are not already allocated.
					// Note: This will not revoke IPs that are already allocated to services.
					from, to := extRange.alloc.Range()

					// If the first and last IPs are the same or adjacent, we would reserve the entire range.
					// Only reserve first and last IPs for ranges /30 or /126 and larger.
					if !(from.Compare(to) == 0 || from.Next().Compare(to) == 0) {
						extRange.alloc.Alloc(from, true)
						extRange.alloc.Alloc(to, true)
					}
				}
			}

			continue
		}

		// Remove allocations from services if the ranges no longer exist
		ipam.rangesStore.Delete(extRange)
		err := ipam.deleteRangeAllocations(ctx, extRange)
		if err != nil {
			return fmt.Errorf("deleteRangeAllocations: %w", err)
		}
	}

	// Add new ranges that were added
	for _, newRange := range newRanges {
		found := false
		for _, extRange := range existingRanges {
			if extRange.EqualCIDR(newRange.from, newRange.to) {
				found = true
				break
			}
		}

		if found {
			continue
		}

		newLBRange, err := NewLBRange(newRange.from, newRange.to, pool)
		if err != nil {
			return fmt.Errorf("Error while making new LB range for range '%s - %s': %w", newRange.from, newRange.to, err)
		}

		// If AllowFirstLastIPs is no or default, mark the first and last IP as allocated upon range creation.
		if newRange.fromCidr && pool.Spec.AllowFirstLastIPs != cilium_api_v2alpha1.AllowFirstLastIPYes {
			// TODO: in 1.16 switch from default no to default yes.
			// https://github.com/cilium/cilium/issues/28591
			from, to := newLBRange.alloc.Range()

			// If the first and last IPs are the same or adjacent, we would reserve the entire range.
			// Only reserve first and last IPs for ranges /30 or /126 and larger.
			if !(from.Compare(to) == 0 || from.Next().Compare(to) == 0) {
				newLBRange.alloc.Alloc(from, true)
				newLBRange.alloc.Alloc(to, true)
			}
		}

		ipam.rangesStore.Add(newLBRange)
	}

	existingRanges, _ = ipam.rangesStore.GetRangesForPool(pool.GetName())
	for _, extRange := range existingRanges {
		extRange.externallyDisabled = pool.Spec.Disabled
	}

	// This is a heavy operation, but pool modification should happen rarely
	err := ipam.revalidateAllServices(ctx)
	if err != nil {
		return fmt.Errorf("revalidateAllServices: %w", err)
	}

	return nil
}

func (ipam *LBIPAM) revalidateAllServices(ctx context.Context) error {
	revalidate := func(sv *ServiceView) error {
		err := ipam.stripInvalidAllocations(sv)
		if err != nil {
			return fmt.Errorf("stripInvalidAllocations: %w", err)
		}

		// Check for each ingress, if its IP has been allocated by us. If it isn't check if we can allocate that IP.
		// If we can't, strip the ingress from the service.
		svModifiedStatus, err := ipam.stripOrImportIngresses(sv)
		if err != nil {
			return fmt.Errorf("stripOrImportIngresses: %w", err)
		}

		// Attempt to satisfy this service in particular now. We do this now instread of relying on
		// ipam.satisfyServices to avoid updating the service twice in quick succession.
		if !sv.isSatisfied() {
			modified, err := ipam.satisfyService(sv)
			if err != nil {
				return fmt.Errorf("satisfyService: %w", err)
			}
			if modified {
				svModifiedStatus = true
			}
		}

		// If any of the steps above changed the service object, update the object.
		if svModifiedStatus {
			err := ipam.patchSvcStatus(ctx, sv)
			if err != nil {
				return fmt.Errorf("patchSvcStatus: %w", err)
			}
		}

		ipam.serviceStore.Upsert(sv)

		return nil
	}
	for _, sv := range ipam.serviceStore.unsatisfied {
		if err := revalidate(sv); err != nil {
			return fmt.Errorf("revalidate: %w", err)
		}
	}

	for _, sv := range ipam.serviceStore.satisfied {
		if err := revalidate(sv); err != nil {
			return fmt.Errorf("revalidate: %w", err)
		}
	}

	return nil
}

func (ipam *LBIPAM) updateAllPoolCounts(ctx context.Context) error {
	ipam.logger.Debug("Updating pool counts")
	for _, pool := range ipam.pools {
		if ipam.updatePoolCounts(pool) {
			ipam.logger.Debugf("Pool counts of '%s' changed, patching", pool.Name)
			err := ipam.patchPoolStatus(ctx, pool)
			if err != nil {
				return fmt.Errorf("patchPoolStatus: %w", err)
			}
		}
	}

	ipam.metrics.MatchingServices.Set(float64(len(ipam.serviceStore.satisfied) + len(ipam.serviceStore.unsatisfied)))
	ipam.metrics.UnsatisfiedServices.Set(float64(len(ipam.serviceStore.unsatisfied)))

	return nil
}

func (ipam *LBIPAM) updatePoolCounts(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) (modifiedPoolStatus bool) {
	ranges, _ := ipam.rangesStore.GetRangesForPool(pool.GetName())

	type IPCounts struct {
		// Total is the total amount of allocatable IPs
		Total *big.Int
		// Available is the amount of IPs which can still be allocated
		Available *big.Int
		// Used is the amount of IPs that are currently allocated
		Used uint64
	}

	totalCounts := IPCounts{
		Total:     big.NewInt(0),
		Available: big.NewInt(0),
	}
	for _, lbRange := range ranges {
		used, available := lbRange.alloc.Stats()

		totalCounts.Total = totalCounts.Total.Add(totalCounts.Total, available)

		// big.NewInt wants a int64, we have a uint64, converting like int64(used) could cause overflow
		// to negative numbers. So shift down by 1 bit so the sign bit is always 0, then convert to bigint.
		// Multiply by two once a bigint to reverse the bitshift and possibly add 1 if the last bit is 1.
		// This should give a loss-less conversion.
		half := int64(used >> 1)
		bigUsed := big.NewInt(0).Mul(big.NewInt(half), big.NewInt(2))
		if used%2 == 1 {
			bigUsed.Add(bigUsed, big.NewInt(1))
		}
		totalCounts.Total = totalCounts.Total.Add(totalCounts.Total, bigUsed)

		totalCounts.Available = totalCounts.Available.Add(totalCounts.Available, available)
		totalCounts.Used += used
	}

	if ipam.setPoolCondition(pool, ciliumPoolIPsTotalCondition, meta_v1.ConditionUnknown, "noreason", totalCounts.Total.String()) ||
		ipam.setPoolCondition(pool, ciliumPoolIPsAvailableCondition, meta_v1.ConditionUnknown, "noreason", totalCounts.Available.String()) ||
		ipam.setPoolCondition(pool, ciliumPoolIPsUsedCondition, meta_v1.ConditionUnknown, "noreason", strconv.FormatUint(totalCounts.Used, 10)) {
		modifiedPoolStatus = true
	}

	available, _ := new(big.Float).SetInt(totalCounts.Available).Float64()
	ipam.metrics.AvailableIPs.WithLabelValues(pool.Name).Set(available)
	ipam.metrics.UsedIPs.WithLabelValues(pool.Name).Set(float64(totalCounts.Used))

	return modifiedPoolStatus
}

func (ipam *LBIPAM) setPoolCondition(
	pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool,
	condType string,
	status meta_v1.ConditionStatus,
	reason, message string,
) (statusModified bool) {
	// Don't trigger an update if the condition is already applied

	if cond := meta.FindStatusCondition(pool.Status.Conditions, condType); cond != nil &&
		cond.Status == status &&
		cond.ObservedGeneration == pool.Generation &&
		cond.Reason == reason &&
		cond.Message == message {
		return false
	}

	meta.SetStatusCondition(&pool.Status.Conditions, meta_v1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: pool.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             reason,
		Message:            message,
	})
	return true
}

// deleteRangeAllocations removes allocations from
func (ipam *LBIPAM) deleteRangeAllocations(ctx context.Context, delRange *LBRange) error {
	delAllocs := func(sv *ServiceView) error {
		svModified := false
		for i := len(sv.AllocatedIPs) - 1; i >= 0; i-- {
			alloc := sv.AllocatedIPs[i]

			if alloc.Origin == delRange {
				sv.AllocatedIPs = slices.Delete(sv.AllocatedIPs, i, i+1)
				svModified = true
			}
		}

		if !svModified {
			return nil
		}

		// Check for each ingress, if its IP has been allocated by us. If it isn't check if we can allocate that IP.
		// If we can't, strip the ingress from the service.
		svModifiedStatus, err := ipam.stripOrImportIngresses(sv)
		if err != nil {
			return fmt.Errorf("stripOrImportIngresses: %w", err)
		}

		// Attempt to satisfy this service in particular now. We do this now instread of relying on
		// ipam.satisfyServices to avoid updating the service twice in quick succession.
		if !sv.isSatisfied() {
			statusModified, err := ipam.satisfyService(sv)
			if err != nil {
				return fmt.Errorf("satisfyService: %w", err)
			}
			if statusModified {
				svModifiedStatus = true
			}
		}

		// If any of the steps above changed the service object, update the object.
		if svModifiedStatus {
			err := ipam.patchSvcStatus(ctx, sv)
			if err != nil {
				return fmt.Errorf("patchSvcStatus: %w", err)
			}
		}

		ipam.serviceStore.Upsert(sv)

		return nil
	}
	for _, sv := range ipam.serviceStore.unsatisfied {
		if err := delAllocs(sv); err != nil {
			return fmt.Errorf("delAllocs: %w", err)
		}
	}
	for _, sv := range ipam.serviceStore.satisfied {
		if err := delAllocs(sv); err != nil {
			return fmt.Errorf("delAllocs: %w", err)
		}
	}

	return nil
}

func (ipam *LBIPAM) handlePoolDeleted(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
	delete(ipam.pools, pool.GetName())

	ipam.metrics.AvailableIPs.DeleteLabelValues(pool.Name)
	ipam.metrics.UsedIPs.DeleteLabelValues(pool.Name)

	poolRanges, _ := ipam.rangesStore.GetRangesForPool(pool.GetName())
	for _, poolRange := range poolRanges {
		// Remove allocations from services if the ranges no longer exist
		ipam.rangesStore.Delete(poolRange)
		err := ipam.deleteRangeAllocations(ctx, poolRange)
		if err != nil {
			return fmt.Errorf("deleteRangeAllocations: %w", err)
		}
	}

	return nil
}

func isPoolConflicting(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) bool {
	return meta.IsStatusConditionTrue(pool.Status.Conditions, ciliumPoolConflict)
}

// settleConflicts check if there exist any un-resolved conflicts between the ranges of IP pools and resolve them.
// secondly, it checks if any ranges that are marked as conflicting have been resolved.
// Any found conflicts are reflected in the IP Pool's status.
func (ipam *LBIPAM) settleConflicts(ctx context.Context) error {
	ipam.logger.Debug("Settling pool conflicts")

	// Mark any pools that conflict as conflicting
	for _, poolOuter := range ipam.pools {
		if isPoolConflicting(poolOuter) {
			continue
		}

		outerRanges, _ := ipam.rangesStore.GetRangesForPool(poolOuter.GetName())

		if conflicting, rangeA, rangeB := areRangesInternallyConflicting(outerRanges); conflicting {
			err := ipam.markPoolConflicting(ctx, poolOuter, poolOuter, rangeA, rangeB)
			if err != nil {
				return fmt.Errorf("markPoolConflicting: %w", err)
			}
			continue
		}

		for _, poolInner := range ipam.pools {
			if poolOuter.GetName() == poolInner.GetName() {
				continue
			}

			if isPoolConflicting(poolInner) {
				continue
			}

			innerRanges, _ := ipam.rangesStore.GetRangesForPool(poolInner.GetName())
			if conflicting, outerRange, innerRange := areRangesConflicting(outerRanges, innerRanges); conflicting {
				// If two pools are conflicting, disable/mark the newest pool

				if poolOuter.CreationTimestamp.Before(&poolInner.CreationTimestamp) {
					err := ipam.markPoolConflicting(ctx, poolInner, poolOuter, innerRange, outerRange)
					if err != nil {
						return fmt.Errorf("markPoolConflicting: %w", err)
					}
					break
				}

				err := ipam.markPoolConflicting(ctx, poolOuter, poolInner, outerRange, innerRange)
				if err != nil {
					return fmt.Errorf("markPoolConflicting: %w", err)
				}
				break
			}
		}
	}

	// un-mark pools that no longer conflict
	for _, poolOuter := range ipam.pools {
		if !isPoolConflicting(poolOuter) {
			continue
		}

		outerRanges, _ := ipam.rangesStore.GetRangesForPool(poolOuter.GetName())

		// If the pool is still internally conflicting, don't un-mark
		if conflicting, _, _ := areRangesInternallyConflicting(outerRanges); conflicting {
			continue
		}

		poolConflict := false
		for _, poolInner := range ipam.pools {
			if poolOuter.GetName() == poolInner.GetName() {
				continue
			}

			innerRanges, _ := ipam.rangesStore.GetRangesForPool(poolInner.GetName())
			if conflicting, _, _ := areRangesConflicting(outerRanges, innerRanges); conflicting {
				poolConflict = true
				break
			}
		}

		// The outer pool, which is marked conflicting no longer conflicts
		if !poolConflict {
			err := ipam.unmarkPool(ctx, poolOuter)
			if err != nil {
				return fmt.Errorf("unmarkPool: %w", err)
			}
		}
	}

	return nil
}

// markPoolConflicting marks the targetPool as "Conflicting" in its status and disables all of its ranges internally.
func (ipam *LBIPAM) markPoolConflicting(
	ctx context.Context,
	targetPool, collisionPool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool,
	targetRange, collisionRange *LBRange,
) error {
	// If the target pool is already marked conflicting, than there is no need to re-add a condition
	if isPoolConflicting(targetPool) {
		return nil
	}

	ipam.metrics.ConflictingPools.Inc()

	ipam.logger.WithFields(logrus.Fields{
		"pool1-name":  targetPool.Name,
		"pool1-range": ipNetStr(targetRange),
		"pool2-name":  ipNetStr(collisionRange),
		"pool2-range": collisionPool.Name,
	}).Warnf("Pool '%s' conflicts since range '%s' overlaps range '%s' from IP Pool '%s'",
		targetPool.Name,
		ipNetStr(targetRange),
		ipNetStr(collisionRange),
		collisionPool.Name,
	)

	conflictMessage := fmt.Sprintf(
		"Pool conflicts since range '%s' overlaps range '%s' from IP Pool '%s'",
		ipNetStr(targetRange),
		ipNetStr(collisionRange),
		collisionPool.Name,
	)

	// Mark all ranges of the pool as internally disabled so we will not allocate from them.
	targetPoolRanges, _ := ipam.rangesStore.GetRangesForPool(targetPool.GetName())
	for _, poolRange := range targetPoolRanges {
		poolRange.internallyDisabled = true
	}

	if ipam.setPoolCondition(targetPool, ciliumPoolConflict, meta_v1.ConditionTrue, "cidr_overlap", conflictMessage) {
		err := ipam.patchPoolStatus(ctx, targetPool)
		if err != nil {
			return fmt.Errorf("patchPoolStatus: %w", err)
		}
	}

	return nil
}

// unmarkPool removes the "Conflicting" status from the pool and removes the internally disabled flag from its ranges
func (ipam *LBIPAM) unmarkPool(ctx context.Context, targetPool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
	// Re-enabled all ranges
	targetPoolRanges, _ := ipam.rangesStore.GetRangesForPool(targetPool.GetName())
	for _, poolRange := range targetPoolRanges {
		poolRange.internallyDisabled = false
	}

	ipam.metrics.ConflictingPools.Dec()

	if ipam.setPoolCondition(targetPool, ciliumPoolConflict, meta_v1.ConditionFalse, "resolved", "") {
		err := ipam.patchPoolStatus(ctx, targetPool)
		if err != nil {
			return fmt.Errorf("patchPoolStatus: %w", err)
		}
	}

	return nil
}

func (ipam *LBIPAM) patchSvcStatus(ctx context.Context, sv *ServiceView) error {
	replaceSvcStatus := []k8s.JSONPatch{
		{
			OP:    "replace",
			Path:  "/status",
			Value: sv.Status,
		},
	}

	createStatusPatch, err := json.Marshal(replaceSvcStatus)
	if err != nil {
		return fmt.Errorf("json.Marshal(%v) failed: %w", replaceSvcStatus, err)
	}

	_, err = ipam.svcClient.Services(sv.Key.Namespace).Patch(ctx, sv.Key.Name,
		types.JSONPatchType, createStatusPatch, meta_v1.PatchOptions{
			FieldManager: ciliumFieldManager,
		}, "status")

	return err
}

func (ipam *LBIPAM) patchPoolStatus(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) error {
	replaceSvcStatus := []k8s.JSONPatch{
		{
			OP:    "replace",
			Path:  "/status",
			Value: pool.Status,
		},
	}

	createStatusPatch, err := json.Marshal(replaceSvcStatus)
	if err != nil {
		return fmt.Errorf("json.Marshal(%v) failed: %w", replaceSvcStatus, err)
	}

	_, err = ipam.poolClient.Patch(ctx, pool.Name,
		types.JSONPatchType, createStatusPatch, meta_v1.PatchOptions{
			FieldManager: ciliumFieldManager,
		}, "status")

	return err
}

func isIPv6(ip netip.Addr) bool {
	return ip.BitLen() == 128
}

func rangeFromPrefix(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	prefix = prefix.Masked()
	from := prefix.Addr()
	bitLen := from.BitLen()
	varBits := bitLen - prefix.Bits()
	toSlice := from.AsSlice()

	i := len(toSlice) - 1
	for varBits > 0 {
		if varBits >= 8 {
			toSlice[i] = 0xFF
			varBits -= 8
			i--
			continue
		}

		mask := byte(1) << varBits
		toSlice[i] |= mask
		break
	}

	to, _ := netip.AddrFromSlice(toSlice)
	return from, to
}
