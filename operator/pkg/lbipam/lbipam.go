package lbipam

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/cilium/ipam/service/ipallocator"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	client_core_v1 "k8s.io/client-go/informers/core/v1"
	client_typed_v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	cilium_ext_v2alpha1 "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions/cilium.io/v2alpha1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// The condition added to services to indicate if a request for IPs could be satisfied or not
	ciliumSvcRequestSatisfiedCondition = "io.cilium/lb-ipam-request-satisfied"

	// The load balancer class LB IPAM will look for when .spec.loadBalancerClass is set.
	ciliumSvcBGPControlPlaneLBClass = "io.cilium/bgp-control-plane"

	// The annotation LB IPAM will look for when searching for requested IPs
	ciliumSvcLBIPSAnnotation = "io.cilium/lb-ipam-ips"

	// The string used in the FieldManager field on update options
	ciliumFieldManager = "cilium-operator-lb-ipam"

	serviceNamespaceLabel = "io.kubernetes.service.namespace"
	serviceNameLabel      = "io.kubernetes.service.name"
)

// LBIPPoolClient is the minimal k8s IPPool client needed by LBIPAM
type LBIPPoolClient interface {
	UpdateStatus(ctx context.Context, ciliumLoadBalancerIPPool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool, opts meta_v1.UpdateOptions) (*cilium_api_v2alpha1.CiliumLoadBalancerIPPool, error)
	List(ctx context.Context, opts meta_v1.ListOptions) (*cilium_api_v2alpha1.CiliumLoadBalancerIPPoolList, error)
	Watch(ctx context.Context, opts meta_v1.ListOptions) (watch.Interface, error)
}

type LBIPAMParams struct {
	Logger *logrus.Entry

	PoolClient LBIPPoolClient
	SvcClient  client_typed_v1.ServicesGetter

	PoolInformer cilium_ext_v2alpha1.CiliumLoadBalancerIPPoolInformer
	SvcInformer  client_core_v1.ServiceInformer

	IPv4Enabled bool
	IPv6Enabled bool
}

func NewLBIPAM(params LBIPAMParams) *LBIPAM {
	return &LBIPAM{
		Logger:       params.Logger.WithField(logfields.LogSubsys, "lb-ipam"),
		PoolClient:   params.PoolClient,
		SvcClient:    params.SvcClient,
		PoolInformer: params.PoolInformer,
		SvcInformer:  params.SvcInformer,
		PoolStore:    NewPoolStore(),
		RangesStore:  NewRangesStore(),
		ServiceStore: NewServiceStore(),
		IPv4Enabled:  params.IPv4Enabled,
		IPv6Enabled:  params.IPv6Enabled,
	}
}

// LBIPAM is the loadbalancer IP address manager, watcher/controller which allocates and assigns IP addresses
// to LoadBalancer services from the configured set of LoadBalancerIPPools in the cluster.
type LBIPAM struct {
	Logger *logrus.Entry

	PoolClient LBIPPoolClient
	SvcClient  client_typed_v1.ServicesGetter

	PoolInformer cilium_ext_v2alpha1.CiliumLoadBalancerIPPoolInformer
	SvcInformer  client_core_v1.ServiceInformer

	PoolStore    PoolStore
	RangesStore  RangesStore
	ServiceStore ServiceStore

	IPv4Enabled bool
	IPv6Enabled bool
}

func (ipam *LBIPAM) Run(ctx context.Context, initDone chan struct{}) {
	if initDone == nil {
		initDone = make(chan struct{})
	}

	// The rest of the code assumes there will be no concurrent access, but each informer will call from its own
	// routine. So we need to sync the two.
	var syncMu sync.Mutex

	ipam.PoolInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// Only start processing updates after the initial sync
			select {
			case <-initDone:
			default:
				return
			}

			syncMu.Lock()
			defer syncMu.Unlock()

			pool, ok := obj.(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)
			if !ok {
				ipam.Logger.Warn("pool watcher got Added event with a non pool object")
				return
			}
			// Deep copy so we get a version we are allowed to update
			pool = pool.DeepCopy()

			ipam.Logger.Tracef("Added pool '%s'", pool.GetName())

			ipam.handleNewPool(ctx, pool)
			ipam.settleConflicts(ctx)
			ipam.satisfyServices(ctx)
			ipam.updateAllPoolCounts(ctx)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// Only start processing updates after the initial sync
			select {
			case <-initDone:
			default:
				return
			}

			syncMu.Lock()
			defer syncMu.Unlock()

			oldPool, ok := oldObj.(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)
			if !ok {
				ipam.Logger.Warn("pool watcher got Modified event with a non pool object")
				return
			}

			pool, ok := newObj.(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)
			if !ok {
				ipam.Logger.Warn("pool watcher got Modified event with a non pool object")
				return
			}

			// We are only interested in updates to the spec
			if oldPool.Spec.DeepEqual(&pool.Spec) {
				return
			}

			// Deep copy so we get a version we are allowed to update
			pool = pool.DeepCopy()

			ipam.Logger.Tracef("Updated pool '%s'", pool.GetName())

			ipam.handlePoolModified(ctx, pool)
			ipam.settleConflicts(ctx)
			ipam.satisfyServices(ctx)
			ipam.updateAllPoolCounts(ctx)
		},
		DeleteFunc: func(obj interface{}) {
			// Only start processing updates after the initial sync
			select {
			case <-initDone:
			default:
				return
			}

			syncMu.Lock()
			defer syncMu.Unlock()

			pool, ok := obj.(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)
			if !ok {
				ipam.Logger.Warn("pool watcher got Delete event with a non pool object")
				return
			}
			// Deep copy so we get a version we are allowed to update
			pool = pool.DeepCopy()

			ipam.Logger.Tracef("Deleted pool '%s'", pool.GetName())

			ipam.handlePoolDeleted(ctx, pool)
			ipam.settleConflicts(ctx)
			ipam.satisfyServices(ctx)
			ipam.updateAllPoolCounts(ctx)
		},
	})

	ipam.SvcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// Only start processing updates after the initial sync
			select {
			case <-initDone:
			default:
				return
			}

			syncMu.Lock()
			defer syncMu.Unlock()

			svc, ok := obj.(*core_v1.Service)
			if !ok {
				ipam.Logger.Warn("svc watcher got Added/Modified event with a non service object")
				return
			}
			// Deep copy so we get a version we are allowed to update
			svc = svc.DeepCopy()

			ipam.Logger.Tracef("Added service '%s/%s'", svc.GetNamespace(), svc.GetName())

			ipam.handleUpsertService(ctx, svc)

			ipam.satisfyServices(ctx)
			ipam.updateAllPoolCounts(ctx)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// Only start processing updates after the initial sync
			select {
			case <-initDone:
			default:
				return
			}

			syncMu.Lock()
			defer syncMu.Unlock()

			svc, ok := newObj.(*core_v1.Service)
			if !ok {
				ipam.Logger.Warn("svc watcher got Added/Modified event with a non service object")
				return
			}

			// Deep copy so we get a version we are allowed to update
			svc = svc.DeepCopy()

			ipam.Logger.Tracef("Updated service '%s/%s'", svc.GetNamespace(), svc.GetName())

			ipam.handleUpsertService(ctx, svc)

			ipam.satisfyServices(ctx)
			ipam.updateAllPoolCounts(ctx)
		},
		DeleteFunc: func(obj interface{}) {
			// Only start processing updates after the initial sync
			select {
			case <-initDone:
			default:
				return
			}

			syncMu.Lock()
			defer syncMu.Unlock()

			svc, ok := obj.(*core_v1.Service)
			if !ok {
				ipam.Logger.Warn("svc watcher got Deleted event with a non service object")
				return
			}
			// Deep copy so we get a version we are allowed to update
			svc = svc.DeepCopy()

			ipam.Logger.Tracef("Deleted service '%s/%s'", svc.GetNamespace(), svc.GetName())

			ipam.handleDeletedService(ctx, svc)

			// Removing a service might free up IPs which unsatisfied services are waiting for.
			ipam.satisfyServices(ctx)
			ipam.updateAllPoolCounts(ctx)
		},
	})

	go func() {
		ipam.init(ctx)

		select {
		case <-initDone:
		default:
			close(initDone)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		ipam.PoolInformer.Informer().Run(ctx.Done())
	}()

	go func() {
		defer wg.Done()
		ipam.SvcInformer.Informer().Run(ctx.Done())
	}()

	wg.Wait()
}

// init initializes the stores. Before we can start assigning IP address we need to recreate the current situation
// in our local stores. So we request all IPPools and services from the APIServer and re-populate the pools and ranges
// store. We also need to fix any bad state(conflicting IP ranges, allocations from deleted/modified pools, unallocated
// services) since these may have come about then the operator was down.
func (ipam *LBIPAM) init(ctx context.Context) {
	ipam.Logger.Debug("LB IPAM initializing")

	// Wait for the pool list to be synced
	cache.WaitForCacheSync(ctx.Done(), func() bool {
		return ipam.PoolInformer.Informer().HasSynced()
	})

	poolList, err := ipam.PoolInformer.Lister().List(labels.Everything())
	if err != nil {
		ipam.Logger.WithError(err).Error("error while listing LB IPPools")
		return
	}

	// Add all existing pools to the store
	for _, pool := range poolList {
		ipam.Logger.WithField("name", pool.GetName()).Debug("Import existing pool")
		ipam.handleNewPool(ctx, pool)
	}

	// Settle any conflicts as a result of adding the pools
	ipam.settleConflicts(ctx)

	// Wait for the pool list to be synced
	cache.WaitForCacheSync(ctx.Done(), func() bool {
		return ipam.SvcInformer.Informer().HasSynced()
	})

	svcList, err := ipam.SvcInformer.Lister().List(labels.Everything())
	if err != nil {
		ipam.Logger.WithError(err).Error("error while listing services")
		return
	}

	// Now assign IPs to any service that needs it.
	for _, svc := range svcList {
		ipam.Logger.WithField("name", svc.GetName()).Debug("Import existing service")
		ipam.importService(ctx, svc)
	}

	// Attempt to satisfy any imported services
	ipam.satisfyServices(ctx)

	ipam.Logger.Debug("LB IPAM done initializing")
}

// importService is called on every service when LBIPAM is initialized and should rebuild service and range status.
func (ipam *LBIPAM) importService(ctx context.Context, svc *core_v1.Service) {
	if !ipam.isResponsibleForSVC(svc) {
		return
	}

	if svc.GetUID() == "" {
		// The code keys everything on UIDs, without one we can't function.
		// The APIServer should always assign one, but one tends to forget in tests
		ipam.Logger.Error("Service has no UID!")
		return
	}

	sv := &ServiceView{
		UID:                 svc.GetUID(),
		Namespace:           svc.GetNamespace(),
		Name:                svc.GetName(),
		Labels:              svcLabels(svc),
		LastResourceVersion: svc.ResourceVersion,
	}

	sv.RequestedFamilies.IPv4, sv.RequestedFamilies.IPv6 = ipam.serviceIPFamilyRequest(svc)
	sv.RequestedIPs = getSVCRequestedIPs(svc)

	var (
		newIngresses []core_v1.LoadBalancerIngress
	)

	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		ip := net.ParseIP(ingress.IP)
		if len(sv.RequestedIPs) > 0 {
			found := false
			for _, reqIP := range sv.RequestedIPs {
				if reqIP.Equal(ip) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		lbRange, _ := ipam.findRangeOfIP(sv, ip)
		if lbRange == nil {
			continue
		}

		err := lbRange.allocRange.Allocate(ip)
		if err != nil {
			if errors.Is(err, ipallocator.ErrAllocated) {
				ipam.Logger.Warningf(
					"Ingress IP '%s' is assigned to multiple services, removing from svc '%s'",
					ingress.IP,
					svc.GetUID(),
				)

				continue
			}

			ipam.Logger.WithError(err).Errorf("Error while attempting to allocate IP '%s'", ingress.IP)
			continue
		}

		sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
			IP:     ip,
			Origin: lbRange,
		})
		sv.Assigned = append(sv.Assigned, ip)
		newIngresses = append(newIngresses, ingress)
	}

	if len(svc.Status.LoadBalancer.Ingress) != len(newIngresses) {
		svc.Status.LoadBalancer.Ingress = newIngresses
		_, err := ipam.SvcClient.Services(svc.Namespace).UpdateStatus(ctx, svc, meta_v1.UpdateOptions{
			FieldManager: ciliumFieldManager,
		})
		if err != nil {
			ipam.Logger.WithError(err).Error("Error while updating status (import)")
		}
	}

	if sv.isSatisfied() {
		ipam.setSVCSatisfiedCondition(svc, true, "satisfied", "")
	}

	ipam.ServiceStore.Upsert(sv)
}

// handleUpsertService updates the service view in the service store, it removes any allocation and ingress that
// do not belong on the service and will move the service to the satisfied or unsatisfied service view store depending
// on if the service requests are satisfied or not.
func (ipam *LBIPAM) handleUpsertService(ctx context.Context, svc *core_v1.Service) {
	if svc.GetUID() == "" {
		// The code keys everything on UIDs, without one we can't function.
		// The APIServer should always assign one, but one tends to forget in tests
		ipam.Logger.Error("Service has no UID!")
		return
	}

	sv, _, found := ipam.ServiceStore.GetService(svc.GetUID())
	if !found {
		sv = &ServiceView{
			UID:       svc.GetUID(),
			Namespace: svc.GetNamespace(),
			Name:      svc.GetName(),
		}
	}

	// Ignore services which are not meant for us
	if !ipam.isResponsibleForSVC(svc) {
		if !found {
			return
		}

		// Release allocations
		for _, alloc := range sv.AllocatedIPs {
			alloc.Origin.allocRange.Release(alloc.IP)
		}
		ipam.ServiceStore.Delete(sv.UID)

		// Remove all ingress IPs
		svc.Status.LoadBalancer.Ingress = nil

		_, err := ipam.SvcClient.Services(svc.Namespace).UpdateStatus(ctx, svc, meta_v1.UpdateOptions{
			FieldManager: ciliumFieldManager,
		})
		if err != nil {
			ipam.Logger.WithError(err).Error("Error while updating status (upsert clear)")
		}

		return
	}

	// We are responsible for this service.

	// Update the service view
	sv.Labels = svcLabels(svc)
	sv.LastResourceVersion = svc.ResourceVersion
	sv.RequestedFamilies.IPv4, sv.RequestedFamilies.IPv6 = ipam.serviceIPFamilyRequest(svc)
	sv.RequestedIPs = getSVCRequestedIPs(svc)

	// Remove any allocation that are no longer valid due to a change in the service spec
	ipam.stripInvalidAllocations(sv)

	// Remove any ingresses which were not allocated by us, which can happen when a service is transferred or
	// someone/something edits the status.
	svcModifiedStatus := ipam.stripInvalidIngresses(svc, sv)

	// Attempt to satisfy this service in particular now. We do this now instread of relying on
	// ipam.satisfyServices to avoid updating the service twice in quick succession.
	if !sv.isSatisfied() {
		if ipam.satisfyService(svc, sv) {
			svcModifiedStatus = true
		}
	}

	// If any of the steps above changed the service object, update the object.
	if svcModifiedStatus {
		_, err := ipam.SvcClient.Services(svc.Namespace).UpdateStatus(ctx, svc, meta_v1.UpdateOptions{
			FieldManager: ciliumFieldManager,
		})
		if err != nil {
			ipam.Logger.WithError(err).Error("Error while updating status (upsert)")
		}
	}

	ipam.ServiceStore.Upsert(sv)
}

func (ipam *LBIPAM) stripInvalidAllocations(sv *ServiceView) {
	// Remove bad allocations which are no longer valid
	for allocIdx := len(sv.AllocatedIPs) - 1; allocIdx >= 0; allocIdx-- {
		alloc := sv.AllocatedIPs[allocIdx]

		releaseAllocIP := func() {
			err := alloc.Origin.allocRange.Release(alloc.IP)
			if err != nil {
				ipam.Logger.WithError(err).Errorf("Error while releasing '%s' from '%s'", alloc.IP, alloc.Origin.String())
			}

			sv.AllocatedIPs = slices.Delete(sv.AllocatedIPs, allocIdx, allocIdx+1)
		}

		// If origin pool no longer exists, remove allocation
		pool, found := ipam.PoolStore.GetByUID(alloc.Origin.originPool)
		if !found {
			releaseAllocIP()
			continue
		}

		// If service no longer matches the pool selector, remove allocation
		if pool.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.Spec.ServiceSelector)
			if err != nil {
				ipam.Logger.WithError(err).Errorf("Making selector from pool '%s' label selector", pool.Name)
				continue
			}

			if !selector.Matches(sv.Labels) {
				releaseAllocIP()
				continue
			}
		}

		// If the service is requesting specific IPs
		if len(sv.RequestedIPs) > 0 {
			found := false
			for _, reqIP := range sv.RequestedIPs {
				if reqIP.Equal(alloc.IP) {
					found = true
					break
				}
			}
			// If allocated IP has not been requested, remove it
			if !found {
				releaseAllocIP()
				continue
			}
		} else {
			// No specific requests have been made, check if we have ingresses from un-requested families.

			if alloc.IP.To4() == nil {
				// Service has an IPv6 address, but its spec doesn't request it anymore, so take it away
				if !sv.RequestedFamilies.IPv6 {
					releaseAllocIP()
					continue
				}

			} else {
				// Service has an IPv4 address, but its spec doesn't request it anymore, so take it away
				if !sv.RequestedFamilies.IPv4 {
					releaseAllocIP()

					continue
				}
			}
		}
	}
}

func (ipam *LBIPAM) stripInvalidIngresses(svc *core_v1.Service, sv *ServiceView) (svcModifiedStatus bool) {
	var newIngresses []core_v1.LoadBalancerIngress
	sv.Assigned = nil

	// Only keep valid ingresses.
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP == "" {
			continue
		}

		ip := net.ParseIP(ingress.IP)
		if ip == nil {
			continue
		}

		// Remove any ingress which is no longer allocated
		var viewIP *ServiceViewIP
		for i, vip := range sv.AllocatedIPs {
			if vip.IP.Equal(ip) {
				viewIP = &sv.AllocatedIPs[i]
				break
			}
		}
		if viewIP == nil {
			// The ingress is not allocated by LB IPAM, remove it
			continue
		}

		sv.Assigned = append(sv.Assigned, ip)
		newIngresses = append(newIngresses, ingress)
	}

	// Check if we have removed any ingresses
	if len(svc.Status.LoadBalancer.Ingress) != len(newIngresses) {
		svcModifiedStatus = true
	}

	svc.Status.LoadBalancer.Ingress = newIngresses

	return svcModifiedStatus
}

func getSVCRequestedIPs(svc *core_v1.Service) []net.IP {
	var ips []net.IP
	if svc.Spec.LoadBalancerIP != "" {
		ip := net.ParseIP(svc.Spec.LoadBalancerIP)
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	if annotation := svc.Annotations[ciliumSvcLBIPSAnnotation]; annotation != "" {
		for _, ipStr := range strings.Split(annotation, ",") {
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	return slices.CompactFunc(ips, func(a, b net.IP) bool {
		return a.Equal(b)
	})
}

func (ipam *LBIPAM) handleDeletedService(ctx context.Context, svc *core_v1.Service) {
	sv, found, _ := ipam.ServiceStore.GetService(svc.GetUID())
	if !found {
		return
	}

	for _, alloc := range sv.AllocatedIPs {
		alloc.Origin.allocRange.Release(alloc.IP)
	}

	ipam.ServiceStore.Delete(svc.GetUID())
}

// satisfyServices attempts to satisfy all unsatisfied services by allocating and assigning IP addresses
func (ipam *LBIPAM) satisfyServices(ctx context.Context) {
	for _, sv := range ipam.ServiceStore.unsatisfied {
		svc, err := ipam.SvcInformer.Lister().Services(sv.Namespace).Get(sv.Name)
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error while getting service '%s'", sv.APIName())
			continue
		}
		// Copy so we can modify svc
		svc = svc.DeepCopy()

		svcModifiedStatus := ipam.satisfyService(svc, sv)

		// If the services status has been modified, update the service.
		if svcModifiedStatus {
			_, err := ipam.SvcClient.Services(svc.Namespace).UpdateStatus(ctx, svc, meta_v1.UpdateOptions{
				FieldManager: ciliumFieldManager,
			})
			if err != nil {
				ipam.Logger.WithError(err).Error("Error while updating status (satisfy)")
				continue
			}
		}

		ipam.ServiceStore.Upsert(sv)
	}
}

func (ipam *LBIPAM) satisfyService(svc *core_v1.Service, sv *ServiceView) (svcModifiedStatus bool) {
	if len(sv.RequestedIPs) > 0 {
		// The service requests specific IPs
		for _, reqIP := range sv.RequestedIPs {
			// if we are able to find the requested IP in the list of allocated IPs
			if slices.IndexFunc(sv.AllocatedIPs, func(sv ServiceViewIP) bool {
				return reqIP.Equal(sv.IP)
			}) != -1 {
				continue
			}

			lbRange, foundPool := ipam.findRangeOfIP(sv, reqIP)
			if lbRange == nil {
				msg := fmt.Sprintf("No pool exists with a CIDR containing '%s'", reqIP)
				reason := "no_pool"
				if foundPool {
					msg = fmt.Sprintf("The pool with the CIDR containing '%s', doesn't select this service", reqIP)
					reason = "pool_selector_mismatch"
				}
				if ipam.setSVCSatisfiedCondition(svc, false, reason, msg) {
					svcModifiedStatus = true
				}

				continue
			}

			if lbRange.allocRange.Has(reqIP) {
				msg := fmt.Sprintf("IP '%s' has already been allocated to another service", reqIP)
				if ipam.setSVCSatisfiedCondition(svc, false, "already_allocated", msg) {
					svcModifiedStatus = true
				}
				continue
			}

			err := lbRange.allocRange.Allocate(reqIP)
			if err != nil {
				ipam.Logger.WithError(err).Error("Unable to allocate IP")
				continue
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
			if allocated.IP.To4() == nil {
				hasIPv6 = true
			} else {
				hasIPv4 = true
			}
		}

		// Missing an IPv4 address, lets attempt to allocate an address
		if sv.RequestedFamilies.IPv4 && !hasIPv4 {
			newIP, lbRange, full := ipam.allocateIPAddress(sv, IPv4Family)
			if newIP != nil {
				sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
					IP:     *newIP,
					Origin: lbRange,
				})
			} else {
				reason := "no_pool"
				message := "There are no enabled CiliumLoadBalancerIPPools that match this service"
				if full {
					reason = "out_of_ips"
					message = "All enabled CiliumLoadBalancerIPPools that match this service ran out of allocatable IPs"
				}

				if ipam.setSVCSatisfiedCondition(svc, false, reason, message) {
					svcModifiedStatus = true
				}
			}
		}

		// Missing an IPv6 address, lets attempt to allocate an address
		if sv.RequestedFamilies.IPv6 && !hasIPv6 {
			newIP, lbRange, full := ipam.allocateIPAddress(sv, IPv6Family)
			if newIP != nil {
				sv.AllocatedIPs = append(sv.AllocatedIPs, ServiceViewIP{
					IP:     *newIP,
					Origin: lbRange,
				})
			} else {
				reason := "no_pool"
				message := "There are no enabled CiliumLoadBalancerIPPools that match this service"
				if full {
					reason = "out_of_ips"
					message = "All enabled CiliumLoadBalancerIPPools that match this service ran out of allocatable IPs"
				}

				if ipam.setSVCSatisfiedCondition(svc, false, reason, message) {
					svcModifiedStatus = true
				}
			}
		}
	}

	// Sync allocated IPs back to the service
	for _, alloc := range sv.AllocatedIPs {
		// If the allocated IP isn't found in the assigned list, assign it
		if slices.IndexFunc(sv.Assigned, alloc.IP.Equal) == -1 {
			sv.Assigned = append(sv.Assigned, alloc.IP)
			svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, core_v1.LoadBalancerIngress{
				IP: alloc.IP.String(),
			})
			svcModifiedStatus = true
		}
	}

	if sv.isSatisfied() {
		if ipam.setSVCSatisfiedCondition(svc, true, "satisfied", "") {
			svcModifiedStatus = true
		}
	}

	return svcModifiedStatus
}

func (ipam *LBIPAM) setSVCSatisfiedCondition(
	svc *core_v1.Service,
	satisfied bool,
	reason, message string,
) (svcModifiedStatus bool) {
	status := meta_v1.ConditionFalse
	if satisfied {
		status = meta_v1.ConditionTrue
	}

	for _, cond := range svc.Status.Conditions {
		if cond.Type == ciliumSvcRequestSatisfiedCondition &&
			cond.Status == status &&
			cond.ObservedGeneration == svc.Generation &&
			cond.Reason == reason &&
			cond.Message == message {
			return false
		}
	}

	svc.Status.Conditions = append(svc.Status.Conditions, meta_v1.Condition{
		Type:               ciliumSvcRequestSatisfiedCondition,
		Status:             status,
		ObservedGeneration: svc.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             reason,
		Message:            message,
	})
	return true
}

func (ipam *LBIPAM) findRangeOfIP(sv *ServiceView, ip net.IP) (lbRange *LBRange, foundPool bool) {
	for _, r := range ipam.RangesStore.ranges {
		if r.Disabled() {
			continue
		}

		cidr := r.allocRange.CIDR()
		if !cidr.Contains(ip) {
			continue
		}

		pool, found := ipam.PoolStore.GetByUID(r.originPool)
		if !found {
			continue
		}

		foundPool = true

		if pool.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.Spec.ServiceSelector)
			if err != nil {
				ipam.Logger.WithError(err).Errorf("Making selector from pool '%s' label selector", pool.Name)
				continue
			}

			if !selector.Matches(sv.Labels) {
				continue
			}
		}

		return r, false
	}

	return nil, false
}

// isResponsibleForSVC checks if LB IPAM should allocate and assign IPs or some other controller
func (ipam *LBIPAM) isResponsibleForSVC(svc *core_v1.Service) bool {
	// Ignore non-lb services
	if svc.Spec.Type != core_v1.ServiceTypeLoadBalancer {
		return false
	}

	if svc.Spec.LoadBalancerClass == nil {
		// TODO if a cloud LB exists, it should assign, else we can assign
		// if ipam.CloudLBExists() { return }
	} else if *svc.Spec.LoadBalancerClass != ciliumSvcBGPControlPlaneLBClass {
		// If a load balancer class is set and it is not us, don't handle this service
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
	newIP *net.IP,
	chosenRange *LBRange,
	full bool,
) {
	for _, lbRange := range ipam.RangesStore.ranges {
		// If the range is disabled we can't allocate new IPs from it.
		if lbRange.Disabled() {
			continue
		}

		// Skip this range if it doesn't match the requested address family
		if lbRange.allocRange.CIDR().IP.To4() == nil {
			if family == IPv4Family {
				continue
			}
		} else {
			if family == IPv6Family {
				continue
			}
		}

		pool, found := ipam.PoolStore.GetByUID(lbRange.originPool)
		if !found {
			ipam.Logger.Warnf("Bad state detected, store contains lbRange for pool '%s' but missing the pool", lbRange.originPool)
			continue
		}

		// If there is no selector, all services match
		if pool.Spec.ServiceSelector != nil {
			selector, err := slim_meta_v1.LabelSelectorAsSelector(pool.Spec.ServiceSelector)
			if err != nil {
				ipam.Logger.WithError(err).Error("LB IP Pool service selector to selector conversion")
				continue
			}

			if !selector.Matches(sv.Labels) {
				continue
			}
		}

		// Attempt to allocate the next IP from this range.
		newIp, err := lbRange.allocRange.AllocateNext()
		if err != nil {
			// If the range is full, mark it.
			if errors.Is(err, ipallocator.ErrFull) {
				full = true
				continue
			}

			ipam.Logger.WithError(err).Error("Allocate next IP from lb range")
			continue
		}

		return &newIp, lbRange, false
	}

	return nil, nil, full
}

// serviceIPFamilyRequest checks which families of IP addresses are requested
func (ipam *LBIPAM) serviceIPFamilyRequest(svc *core_v1.Service) (IPv4Requested, IPv6Requested bool) {
	if svc.Spec.IPFamilyPolicy != nil {
		switch *svc.Spec.IPFamilyPolicy {
		case core_v1.IPFamilyPolicySingleStack:
			if len(svc.Spec.IPFamilies) > 0 {
				if svc.Spec.IPFamilies[0] == core_v1.IPFamily(IPv4Family) {
					IPv4Requested = true
				} else {
					IPv6Requested = true
				}
			} else {
				if ipam.IPv4Enabled {
					IPv4Requested = true
				} else if ipam.IPv6Enabled {
					IPv6Requested = true
				}
			}

		case core_v1.IPFamilyPolicyPreferDualStack:
			if len(svc.Spec.IPFamilies) > 0 {
				for _, family := range svc.Spec.IPFamilies {
					if family == core_v1.IPFamily(IPv4Family) {
						IPv4Requested = ipam.IPv4Enabled
					}
					if family == core_v1.IPFamily(IPv6Family) {
						IPv6Requested = ipam.IPv6Enabled
					}
				}
			} else {
				// If no IPFamilies are specified

				IPv4Requested = ipam.IPv4Enabled
				IPv6Requested = ipam.IPv6Enabled
			}

		case core_v1.IPFamilyPolicyRequireDualStack:
			IPv4Requested = ipam.IPv4Enabled
			IPv6Requested = ipam.IPv6Enabled
		}
	} else {
		if len(svc.Spec.IPFamilies) > 0 {
			if svc.Spec.IPFamilies[0] == core_v1.IPFamily(IPv4Family) {
				IPv4Requested = true
			} else {
				IPv6Requested = true
			}
		} else {
			if ipam.IPv4Enabled {
				IPv4Requested = true
			} else if ipam.IPv6Enabled {
				IPv6Requested = true
			}
		}
	}

	return IPv4Requested, IPv6Requested
}

// Handle the addition of a new IPPool
func (ipam *LBIPAM) handleNewPool(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	// Sanity check that we do not yet know about this pool.
	if _, found := ipam.PoolStore.GetByUID(pool.GetUID()); found {
		ipam.Logger.Warnf("LB IPPool with uid '%s' has been created, but a LB IP Pool with the same uid already exists", pool.GetUID())
		return
	}

	ipam.PoolStore.Upsert(pool)
	for _, cidrBlock := range pool.Spec.Cidrs {
		_, cidr, err := net.ParseCIDR(string(cidrBlock.Cidr))
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error parsing cidr '%s'", cidrBlock.Cidr)
			continue
		}

		lbRange, err := NewLBRange(cidr, pool)
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error making LB Range for '%s'", cidrBlock.Cidr)
			continue
		}

		ipam.RangesStore.Add(lbRange)
	}
}

func (ipam *LBIPAM) handlePoolModified(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	ipam.PoolStore.Upsert(pool)

	var newCIDRs []net.IPNet
	for _, newBlock := range pool.Spec.Cidrs {
		_, cidr, err := net.ParseCIDR(string(newBlock.Cidr))
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error parsing cidr '%s'", newBlock.Cidr)
			continue
		}
		newCIDRs = append(newCIDRs, *cidr)
	}

	existingRanges, _ := ipam.RangesStore.GetRangesForPool(pool.GetUID())

	// Remove existing ranges that no longer exist
	for _, extRange := range existingRanges {
		extCIDR := extRange.allocRange.CIDR()
		found := false
		for _, newCIDR := range newCIDRs {
			if newCIDR.IP.Equal(extCIDR.IP) && bytes.Equal(newCIDR.Mask, extCIDR.Mask) {
				found = true
				break
			}
		}

		if found {
			continue
		}

		// Remove allocations from services if the ranges no longer exist
		ipam.RangesStore.Delete(extRange)
		ipam.deleteRangeAllocations(ctx, extRange)
	}

	// Add new ranges that were added
	for _, newCIDR := range newCIDRs {
		found := false
		for _, extRange := range existingRanges {
			extCIDR := extRange.allocRange.CIDR()
			if newCIDR.IP.Equal(extCIDR.IP) && bytes.Equal(newCIDR.Mask, extCIDR.Mask) {
				found = true
				break
			}
		}

		if found {
			continue
		}

		newRange, err := NewLBRange(&newCIDR, pool)
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error while making new LB range for CIDR '%s'", newCIDR.String())
		}

		ipam.RangesStore.Add(newRange)
	}

	existingRanges, _ = ipam.RangesStore.GetRangesForPool(pool.GetUID())
	for _, extRange := range existingRanges {
		extRange.externallyDisabled = pool.Spec.Disabled
	}
}

func (ipam *LBIPAM) updateAllPoolCounts(ctx context.Context) {
	for _, pool := range ipam.PoolStore.pools {
		if ipam.updatePoolCounts(pool) {
			newPool, err := ipam.PoolClient.UpdateStatus(ctx, pool, meta_v1.UpdateOptions{
				FieldManager: ciliumFieldManager,
			})
			if err != nil {
				ipam.Logger.WithError(err).Error("Error while updating pool counts")
				continue
			}

			*pool = *newPool
		}
	}
}

func (ipam *LBIPAM) updatePoolCounts(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) (modifiedPoolStatus bool) {
	ranges, _ := ipam.RangesStore.GetRangesForPool(pool.GetUID())
	curCidrs := make(map[string]bool)
	for _, lbRange := range ranges {
		curCidrs[ipNetStr(lbRange.allocRange.CIDR())] = true
	}

	if pool.Status.CIDRCounts == nil {
		pool.Status.CIDRCounts = make(map[string]cilium_api_v2alpha1.CiliumLoadBalancerIPCounts)
	}

	for cidr := range pool.Status.CIDRCounts {
		if !curCidrs[cidr] {
			delete(pool.Status.CIDRCounts, cidr)
			modifiedPoolStatus = true
		}
	}

	var totalCounts cilium_api_v2alpha1.CiliumLoadBalancerIPCounts
	for _, lbRange := range ranges {
		cidr := ipNetStr(lbRange.allocRange.CIDR())
		cidrCount := pool.Status.CIDRCounts[cidr]

		free := lbRange.allocRange.Free()
		used := lbRange.allocRange.Used()
		newCidrCount := cilium_api_v2alpha1.CiliumLoadBalancerIPCounts{
			Total:     free + used,
			Available: free,
			Used:      used,
		}

		if cidrCount != newCidrCount {
			cidrCount = newCidrCount
			modifiedPoolStatus = true
			pool.Status.CIDRCounts[cidr] = cidrCount
		}

		totalCounts.Total += cidrCount.Total
		totalCounts.Available += cidrCount.Available
		totalCounts.Used += cidrCount.Used
	}

	if pool.Status.TotalCounts != totalCounts {
		modifiedPoolStatus = true
		pool.Status.TotalCounts = totalCounts
	}

	return modifiedPoolStatus
}

// deleteRangeAllocations removes allocations from
func (ipam *LBIPAM) deleteRangeAllocations(ctx context.Context, delRange *LBRange) {
	delAllocs := func(sv *ServiceView) {
		svModified := false
		for i := len(sv.AllocatedIPs) - 1; i >= 0; i-- {
			alloc := sv.AllocatedIPs[i]

			if alloc.Origin == delRange {
				sv.AllocatedIPs = slices.Delete(sv.AllocatedIPs, i, i+1)
				svModified = true
			}
		}

		if !svModified {
			return
		}

		svc, err := ipam.SvcInformer.Lister().Services(sv.Namespace).Get(sv.Name)
		if err != nil {
			ipam.Logger.WithError(err).Errorf("Error while getting service '%s'", sv.APIName())
			return
		}
		// Copy so we can modify svc
		svc = svc.DeepCopy()

		// Trigger an Upsert on the service, which will notice that it has an assigned IP which is no longer
		// allocated and take the proper action.
		ipam.handleUpsertService(ctx, svc)
	}
	for _, sv := range ipam.ServiceStore.unsatisfied {
		delAllocs(sv)
	}
	for _, sv := range ipam.ServiceStore.satisfied {
		delAllocs(sv)
	}
}

func (ipam *LBIPAM) handlePoolDeleted(ctx context.Context, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	ipam.PoolStore.Delete(pool)

	poolRanges, _ := ipam.RangesStore.GetRangesForPool(pool.UID)
	for _, poolRange := range poolRanges {
		// Remove allocations from services if the ranges no longer exist
		ipam.RangesStore.Delete(poolRange)
		ipam.deleteRangeAllocations(ctx, poolRange)
	}
}

// settleConflicts check if there exist any un-resolved conflicts between the ranges of IP pools and resolve them.
// secondly, it checks if any ranges that are marked as conflicting have been resolved.
// Any found conflicts are reflected in the IP Pool's status.
func (ipam *LBIPAM) settleConflicts(ctx context.Context) {
	// Mark any pools that conflict as conflicting
	for _, poolOuter := range ipam.PoolStore.pools {
		if poolOuter.Status.Conflicting {
			continue
		}

		outerRanges, _ := ipam.RangesStore.GetRangesForPool(poolOuter.GetUID())

		if conflicting, rangeA, rangeB := ipam.areRangesInternallyConflicting(outerRanges); conflicting {
			ipam.markPoolConflicting(ctx, poolOuter, poolOuter, rangeA, rangeB)
			continue
		}

		for _, poolInner := range ipam.PoolStore.pools {
			if poolOuter.GetUID() == poolInner.GetUID() {
				continue
			}

			if poolInner.Status.Conflicting {
				continue
			}

			innerRanges, _ := ipam.RangesStore.GetRangesForPool(poolInner.GetUID())
			if conflicting, outerRange, innerRange := ipam.areRangesConflicting(outerRanges, innerRanges); conflicting {
				// If two pools are conflicting, disable/mark the newest pool

				if poolOuter.CreationTimestamp.Before(&poolInner.CreationTimestamp) {
					ipam.markPoolConflicting(ctx, poolInner, poolOuter, innerRange, outerRange)
					break
				}

				ipam.markPoolConflicting(ctx, poolOuter, poolInner, outerRange, innerRange)
				break
			}
		}
	}

	// un-mark pools that no longer conflict
	for _, poolOuter := range ipam.PoolStore.pools {
		if !poolOuter.Status.Conflicting {
			continue
		}

		outerRanges, _ := ipam.RangesStore.GetRangesForPool(poolOuter.GetUID())

		// If the pool is still internally conflicting, don't un-mark
		if conflicting, _, _ := ipam.areRangesInternallyConflicting(outerRanges); conflicting {
			continue
		}

		poolConflict := false
		for _, poolInner := range ipam.PoolStore.pools {
			if poolOuter.GetUID() == poolInner.GetUID() {
				continue
			}

			innerRanges, _ := ipam.RangesStore.GetRangesForPool(poolInner.GetUID())
			if conflicting, _, _ := ipam.areRangesConflicting(outerRanges, innerRanges); conflicting {
				poolConflict = true
				break
			}
		}

		// The outer pool, which is marked conflicting no longer conflicts
		if !poolConflict {
			ipam.unmarkPool(ctx, poolOuter)
		}
	}
}

// areRangesInternallyConflicting checks if any of the ranges within the same list conflict with each other.
func (ipam *LBIPAM) areRangesInternallyConflicting(ranges []*LBRange) (conflicting bool, rangeA, rangeB *LBRange) {
	for i, outer := range ranges {
		for ii, inner := range ranges {
			if i == ii {
				continue
			}

			if !intersect(outer.allocRange.CIDR(), inner.allocRange.CIDR()) {
				continue
			}

			return true, outer, inner
		}
	}

	return false, nil, nil
}

func (ipam *LBIPAM) areRangesConflicting(outerRanges, innerRanges []*LBRange) (conflicting bool, targetRange, conflictingRange *LBRange) {
	for _, outerRange := range outerRanges {
		for _, innerRange := range innerRanges {
			// IPs of dissimilar IP families can't overlap
			outerIsIpv4 := outerRange.allocRange.CIDR().IP.To4() != nil
			innerIsIpv4 := innerRange.allocRange.CIDR().IP.To4() != nil
			if innerIsIpv4 != outerIsIpv4 {
				continue
			}

			// no intersection, no conflict
			if !intersect(outerRange.allocRange.CIDR(), innerRange.allocRange.CIDR()) {
				continue
			}

			return true, outerRange, innerRange
		}
	}

	return false, nil, nil
}

func intersect(n1, n2 net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

// markPoolConflicting marks the targetPool as "Conflicting" in its status and disables all of its ranges internally.
func (ipam *LBIPAM) markPoolConflicting(
	ctx context.Context,
	targetPool, collisionPool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool,
	targetRange, collisionRange *LBRange,
) {
	// If the target pool is already marked conflicting, than there is no need to re-add a condition
	if targetPool.Status.Conflicting {
		return
	}

	ipam.Logger.Warnf("Pool '%s' disables since CIDR '%s' overlaps CIDR '%s' from IP Pool '%s'",
		targetPool.Name,
		ipNetStr(targetRange.allocRange.CIDR()),
		ipNetStr(collisionRange.allocRange.CIDR()),
		collisionPool.Name,
	)
	targetPool.Status.Conflicting = true
	targetPool.Status.ConflictReason = fmt.Sprintf(
		"Pool disables since CIDR '%s' overlaps CIDR '%s' from IP Pool '%s'",
		ipNetStr(targetRange.allocRange.CIDR()),
		ipNetStr(collisionRange.allocRange.CIDR()),
		collisionPool.Name,
	)

	// Mark all ranges of the pool as internally disabled so we will not allocate from them.
	targetPoolRanges, _ := ipam.RangesStore.GetRangesForPool(targetPool.UID)
	for _, poolRange := range targetPoolRanges {
		poolRange.internallyDisabled = true
	}

	updatedPool, err := ipam.PoolClient.UpdateStatus(ctx, targetPool, meta_v1.UpdateOptions{
		FieldManager: ciliumFieldManager,
	})
	if err != nil {
		ipam.Logger.WithError(err).Error("Error while updating IP pool status (mark conflict)")
		return
	}

	// Replace the pool in the store with the updated pool
	*targetPool = *updatedPool
}

// unmarkPool removes the "Conflicting" status from the pool and removes the internally disabled flag from its ranges
func (ipam *LBIPAM) unmarkPool(ctx context.Context, targetPool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	targetPool.Status.Conflicting = false
	targetPool.Status.ConflictReason = ""

	// Re-enabled all ranges
	targetPoolRanges, _ := ipam.RangesStore.GetRangesForPool(targetPool.UID)
	for _, poolRange := range targetPoolRanges {
		poolRange.internallyDisabled = false
	}

	updatedPool, err := ipam.PoolClient.UpdateStatus(ctx, targetPool, meta_v1.UpdateOptions{
		FieldManager: ciliumFieldManager,
	})
	if err != nil {
		ipam.Logger.WithError(err).Error("Error while updating IP pool status (unmark)")
		return
	}

	// Replace the pool in the store with the updated pool
	*targetPool = *updatedPool
}

// svcLabels clones the services labels and adds a number of internal labels which can be used to select
// specific services and/or namespaces using the label selectors.
func svcLabels(svc *core_v1.Service) slim_labels.Set {
	clone := maps.Clone(svc.Labels)
	clone[serviceNameLabel] = svc.Name
	clone[serviceNamespaceLabel] = svc.Namespace
	return clone
}

// PoolStore is a storage structure for IPPools
type PoolStore struct {
	// Map of all IP pools
	pools map[types.UID]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool
}

func NewPoolStore() PoolStore {
	return PoolStore{
		pools: make(map[types.UID]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool),
	}
}

func (ps *PoolStore) Upsert(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	if pool == nil {
		return
	}
	ps.pools[pool.GetUID()] = pool
}

func (ps *PoolStore) Delete(pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) {
	delete(ps.pools, pool.GetUID())
}

func (ps *PoolStore) GetByUID(uid types.UID) (*cilium_api_v2alpha1.CiliumLoadBalancerIPPool, bool) {
	pool, found := ps.pools[uid]
	return pool, found
}

type RangesStore struct {
	ranges       []*LBRange
	poolToRanges map[types.UID][]*LBRange
}

func NewRangesStore() RangesStore {
	return RangesStore{
		poolToRanges: make(map[types.UID][]*LBRange),
	}
}

func (rs *RangesStore) Delete(lbRange *LBRange) {
	idx := slices.Index(rs.ranges, lbRange)
	if idx != -1 {
		rs.ranges = slices.Delete(rs.ranges, idx, idx+1)
	}

	poolRanges := rs.poolToRanges[lbRange.originPool]

	idx = slices.Index(poolRanges, lbRange)
	if idx != -1 {
		poolRanges = slices.Delete(poolRanges, idx, idx+1)
	}

	if len(poolRanges) > 0 {
		rs.poolToRanges[lbRange.originPool] = poolRanges
	} else {
		delete(rs.poolToRanges, lbRange.originPool)
	}
}

func (rs *RangesStore) Add(lbRange *LBRange) {
	rs.ranges = append(rs.ranges, lbRange)
	poolRanges := rs.poolToRanges[lbRange.originPool]
	poolRanges = append(poolRanges, lbRange)
	rs.poolToRanges[lbRange.originPool] = poolRanges
}

func (rs *RangesStore) GetRangesForPool(uid types.UID) ([]*LBRange, bool) {
	ranges, found := rs.poolToRanges[uid]
	return ranges, found
}

type LBRange struct {
	// the actual data of which ips have been allocated or not
	allocRange *ipallocator.Range
	// If true, the LB range has been disabled via the CRD and thus no IPs should be allocated from this range
	externallyDisabled bool
	// If true, the LB range has been disabled by us, because it conflicts with other ranges for example.
	// This range should not be used for allocation.
	internallyDisabled bool
	// The UID of the pool that originated this LB range
	originPool types.UID
}

func NewLBRange(cidr *net.IPNet, pool *cilium_api_v2alpha1.CiliumLoadBalancerIPPool) (*LBRange, error) {
	allocRange, err := ipallocator.NewCIDRRange(cidr)
	if err != nil {
		return nil, fmt.Errorf("new cidr range: %w", err)
	}

	return &LBRange{
		allocRange:         allocRange,
		internallyDisabled: false,
		externallyDisabled: pool.Spec.Disabled,
		originPool:         pool.GetUID(),
	}, nil
}

func (lr *LBRange) Disabled() bool {
	return lr.internallyDisabled || lr.externallyDisabled
}

func (lr *LBRange) String() string {
	cidr := lr.allocRange.CIDR()
	return fmt.Sprintf(
		"%s (free: %d, used: %d, intDis: %v, extDis: %v) - origin %s",
		cidr.String(),
		lr.allocRange.Free(),
		lr.allocRange.Used(),
		lr.internallyDisabled,
		lr.externallyDisabled,
		lr.originPool,
	)
}

func ipNetStr(net net.IPNet) string {
	ptr := &net
	return ptr.String()
}

type ServiceStore struct {
	// List of services which have received all IPs they requested
	satisfied map[types.UID]*ServiceView
	// List of services which have one or more IPs which were requested but not allocated
	unsatisfied map[types.UID]*ServiceView
}

func NewServiceStore() ServiceStore {
	return ServiceStore{
		satisfied:   make(map[types.UID]*ServiceView),
		unsatisfied: make(map[types.UID]*ServiceView),
	}
}

func (ss *ServiceStore) GetService(uid types.UID) (serviceView *ServiceView, found, satisfied bool) {
	serviceView, found = ss.satisfied[uid]
	if found {
		return serviceView, true, true
	}

	serviceView, found = ss.unsatisfied[uid]
	if found {
		return serviceView, true, false
	}

	return nil, false, false
}

func (ss *ServiceStore) Upsert(serviceView *ServiceView) {
	if serviceView.isSatisfied() {
		delete(ss.unsatisfied, serviceView.UID)
		ss.satisfied[serviceView.UID] = serviceView
	} else {
		delete(ss.satisfied, serviceView.UID)
		ss.unsatisfied[serviceView.UID] = serviceView
	}
}

func (ss *ServiceStore) Delete(uid types.UID) {
	delete(ss.satisfied, uid)
	delete(ss.unsatisfied, uid)
}

// ServiceView is the LB IPAM's view of the service, the minimal amount of info we need about it.
type ServiceView struct {
	UID       types.UID
	Namespace string
	Name      string
	Labels    slim_labels.Set

	LastResourceVersion string
	// The specific IPs requested by the service
	RequestedIPs []net.IP
	// The IP families requested by the service
	RequestedFamilies struct {
		IPv4 bool
		IPv6 bool
	}
	// The IPs we have allocated for this IP
	AllocatedIPs []ServiceViewIP
	// The IPs that are assigned to the services stats (doesn't necessarily match the allocation if the object
	// transferred or status changed my someone/something other than LB IPAM)
	Assigned []net.IP
}

func (sv *ServiceView) APIName() string {
	if sv.Namespace != "" {
		return fmt.Sprintf("%s/%s", sv.Namespace, sv.Name)
	}

	return sv.Name
}

func (sv *ServiceView) isSatisfied() bool {
	// If the service requests specific IPs
	if len(sv.RequestedIPs) > 0 {
		for _, reqIP := range sv.RequestedIPs {
			// If reqIP doesn't exist in the list of assigned IPs
			if slices.IndexFunc(sv.Assigned, reqIP.Equal) == -1 {
				return false
			}
		}

		return true
	}

	// No specific requests are made, check that all requested families are assigned
	hasIPv4 := false
	hasIPv6 := false
	for _, assigned := range sv.Assigned {
		if assigned.To4() == nil {
			hasIPv6 = true
		} else {
			hasIPv4 = true
		}
	}

	// We are unsatisfied if we requested IPv4 and didn't get it or we requested IPv6 and didn't get it
	unsatisfied := (sv.RequestedFamilies.IPv4 && !hasIPv4) || (sv.RequestedFamilies.IPv6 && !hasIPv6)
	return !unsatisfied
}

// ServiceViewIP is the IP and from which range it was allocated
type ServiceViewIP struct {
	IP     net.IP
	Origin *LBRange
}
