// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/bgpv2/backend"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type ConfigReconciler interface {
	// Priority is used to sort a slice of reconcilers and will determine execution order.
	Priority() int
	Reconcile(ctx context.Context, thisNode abstractNode, mgr backend.BGPSpeakerManager) error
}

func newSpeakerReconciler(
	vRouterFactory DiffStoreFactory[*cilium_v2alpha1.CiliumBGPVirtualRouter],
	logger logrus.FieldLogger,
) speakerReconcilerOut {
	return speakerReconcilerOut{
		SpeakerReconciler: &speakerReconciler{
			vRouterStore: vRouterFactory.NewStore(),
			logger:       logger,
		},
	}
}

type speakerReconcilerOut struct {
	cell.Out

	SpeakerReconciler ConfigReconciler `group:"config-reconcilers"`
}

// speakerReconciler reconciles the speaker configuration
type speakerReconciler struct {
	vRouterStore DiffStore[*cilium_v2alpha1.CiliumBGPVirtualRouter]
	logger       logrus.FieldLogger
}

func (pfr *speakerReconciler) Priority() int {
	return 0
}

const speakerReconcilerOrigin = "speakerReconciler"

func (pfr *speakerReconciler) Reconcile(ctx context.Context, thisNode abstractNode, mgr backend.BGPSpeakerManager) error {
	upserted, deleted, err := pfr.vRouterStore.Diff()
	if err != nil {
		return fmt.Errorf("vRouter store diff: %w", err)
	}
	for _, vRouter := range upserted {
		if !isRouterApplicable(thisNode, vRouter) {
			continue
		}

		bgpSpeaker := vRouterToBGPSpeaker(thisNode, vRouter, speakerReconcilerOrigin)

		// TODO apply annotation overwrites

		pfr.logger.Debugf("Upserting BGP Speaker '%s/%d'", bgpSpeaker.Key.RouterID, bgpSpeaker.Key.LocalASN)

		err := mgr.UpsertSpeaker(bgpSpeaker)
		if err != nil {
			return fmt.Errorf("UpsertSpeaker: %w", err)
		}
	}

	// Avoid listing speakers if we don't need to delete anything
	if len(deleted) == 0 {
		return nil
	}

	speakers := mgr.ListSpeakers()
	for _, speaker := range speakers {
		for _, deletedKey := range deleted {
			if speaker.Origin.Name != deletedKey.Name {
				continue
			}

			pfr.logger.Debug("Deleting BGP Speaker '%s/%s'", speaker.Key.RouterID, speaker.Key.LocalASN)

			err := mgr.DeleteSpeaker(speaker.Key)
			if err != nil {
				return fmt.Errorf("DeleteSpeaker: %w", err)
			}
			break
		}
	}

	return nil
}

func newPodCidrReconciler(
	vRouterFactory DiffStoreFactory[*cilium_v2alpha1.CiliumBGPVirtualRouter],
) podCidrReconcilerOut {
	return podCidrReconcilerOut{
		PodCidrReconciler: &podCidrReconciler{
			vRouterStore: vRouterFactory.NewStore(),
		},
	}
}

type podCidrReconcilerOut struct {
	cell.Out

	PodCidrReconciler ConfigReconciler `group:"config-reconcilers"`
}

// podCidrReconciler reconciles podCIDR routes
type podCidrReconciler struct {
	vRouterStore DiffStore[*cilium_v2alpha1.CiliumBGPVirtualRouter]
}

func (pfr *podCidrReconciler) Priority() int {
	return 10
}

const podCIDRReconcilerOrigin = "podCIDRReconciler"

func (pfr *podCidrReconciler) Reconcile(ctx context.Context, thisNode abstractNode, mgr backend.BGPSpeakerManager) error {
	upserted, _, err := pfr.vRouterStore.Diff()
	if err != nil {
		return fmt.Errorf("vRouter store diff: %w", err)
	}

	for _, vRouter := range upserted {
		if !isRouterApplicable(thisNode, vRouter) {
			continue
		}

		speakerKey := backend.BGPSpeakerPK{
			RouterID: vRouterRouterID(thisNode, vRouter),
			LocalASN: uint32(vRouter.Spec.LocalASN),
		}

		var routerPodCIDRs []net.IPNet
		if vRouter.Spec.ExportPodCIDR {
			// Only upsert routes for this vRouter if we want to export pod CIDRs
			for _, podCIDR := range thisNode.PodCIDRs {
				_, ipNet, err := net.ParseCIDR(podCIDR)
				if err != nil {
					return fmt.Errorf("ParseCIDR('%s'): %w", podCIDR, err)
				}
				routerPodCIDRs = append(routerPodCIDRs, *ipNet)

				route := &backend.UnicastRoute{
					RouteOrigin: backend.Origin{
						Reconciler: podCIDRReconcilerOrigin,
						Type:       "podCIDR",
					},
					BGPSpeaker: speakerKey,
					Cidr:       *ipNet,
					// TODO add additional attributes based on the vRouters attributes
				}

				setNexthopForUnicastRoute(route)

				err = mgr.UpsertRoute(route)
				if err != nil {
					return fmt.Errorf("UpsertRoute: %w", err)
				}
			}
		}

		// TODO query based on origin and/or speaker key
		for _, route := range mgr.ListRoutes() {
			// Ignore routes managed by other reconcilers
			if route.Origin().Reconciler != podCIDRReconcilerOrigin {
				continue
			}

			// Ignore routes on other speakers
			if route.Speaker() != speakerKey {
				continue
			}

			prefix := route.Attributes()[backend.AttrPrefix]
			cidr := net.IPNet{
				IP: net.ParseIP(prefix),
			}

			prefixLen := route.Attributes()[backend.AttrPrefixLen]
			len, err := strconv.Atoi(prefixLen)
			if err != nil {
				continue
			}

			if cidr.IP.To4() == nil {
				cidr.Mask = net.CIDRMask(len, 128)
			} else {
				cidr.Mask = net.CIDRMask(len, 32)
			}

			// Ignore route if it exists in `routerPodCIDRs`
			if slices.IndexFunc(routerPodCIDRs, func(i net.IPNet) bool {
				return cidrEqual(i, cidr)
			}) != -1 {
				continue
			}

			// Delete any podCIDR route that isn't wanted anymore.
			err = mgr.DeleteRoute(route)
			if err != nil {
				return fmt.Errorf("DeleteRoute: %w", err)
			}
		}
	}

	// Ignore deletes since any routes that we added to the vRouter will also implicitly be deleted.

	return nil
}

func newLBSvcReconciler(
	vRouterFactory DiffStoreFactory[*cilium_v2alpha1.CiliumBGPVirtualRouter],
	svcFactory DiffStoreFactory[*slim_core_v1.Service],
) lbSvcReconcilerOut {
	return lbSvcReconcilerOut{
		LBSvcReconciler: &lbSvcReconciler{
			vRouterStore: vRouterFactory.NewStore(),
			svcStore:     svcFactory.NewStore(),
		},
	}
}

type lbSvcReconcilerOut struct {
	cell.Out

	LBSvcReconciler ConfigReconciler `group:"config-reconcilers"`
}

type lbSvcReconciler struct {
	vRouterStore DiffStore[*cilium_v2alpha1.CiliumBGPVirtualRouter]
	svcStore     DiffStore[*slim_core_v1.Service]
}

func (pfr *lbSvcReconciler) Priority() int {
	return 20
}

const lbSvcReconcilerOrigin = "lbSvcReconciler"

func (pfr *lbSvcReconciler) Reconcile(ctx context.Context, thisNode abstractNode, mgr backend.BGPSpeakerManager) error {
	err := pfr.ReconcileVrouters(thisNode, mgr)
	if err != nil {
		return fmt.Errorf("ReconcileVrouters: %w", err)
	}

	err = pfr.ReconcileServices(thisNode, mgr)
	if err != nil {
		return fmt.Errorf("ReconcileServices: %w", err)
	}

	return nil
}

func (pfr *lbSvcReconciler) ReconcileVrouters(thisNode abstractNode, mgr backend.BGPSpeakerManager) error {
	upserted, _, err := pfr.vRouterStore.Diff()
	if err != nil {
		return fmt.Errorf("vRouter store diff: %w", err)
	}

	for _, vRouter := range upserted {
		if !isRouterApplicable(thisNode, vRouter) {
			continue
		}

		// Don't announce services if selector isn't set.
		if vRouter.Spec.ServiceSelector == nil {
			continue
		}

		speakerKey := backend.BGPSpeakerPK{
			RouterID: vRouterRouterID(thisNode, vRouter),
			LocalASN: uint32(vRouter.Spec.LocalASN),
		}

		svcSelector, err := slimmetav1.LabelSelectorAsSelector(vRouter.Spec.ServiceSelector)
		if err != nil {
			// TODO handle error in a different way?
			return fmt.Errorf("LabelSelectorAsSelector: %w", err)
		}

		// keep track of all of the routes per service
		routes := make(map[resource.Key][]backend.BGPRoute)

		// Make a list of all routes that should exist
		for _, svc := range pfr.svcStore.List() {
			// Ignore non-loadbalancer services
			if svc.Spec.Type != slim_core_v1.ServiceTypeLoadBalancer {
				continue
			}

			// Ignore non matching services
			if !svcSelector.Matches(serviceLabelSet(svc)) {
				continue
			}

			svcKey := resource.NewKey(svc)

			for _, ingress := range svc.Status.LoadBalancer.Ingress {
				// Ignore ingresses without ips
				if ingress.IP == "" {
					continue
				}

				cidr := net.IPNet{
					IP: net.ParseIP(ingress.IP),
				}
				if cidr.IP.To4() == nil {
					cidr.Mask = net.CIDRMask(128, 128)
				} else {
					cidr.Mask = net.CIDRMask(32, 32)
				}

				route := &backend.UnicastRoute{
					RouteOrigin: backend.Origin{
						Reconciler: lbSvcReconcilerOrigin,
						Type:       "service",
						Name:       svc.Name,
						Namespace:  svc.Namespace,
					},
					Cidr:       cidr,
					BGPSpeaker: speakerKey,
					// TODO add additional route attributes from the vRouter.Spec.routeAttributes
				}

				setNexthopForUnicastRoute(route)
				routes[svcKey] = append(routes[svcKey], route)
				err = mgr.UpsertRoute(route)
				if err != nil {
					return fmt.Errorf("UpsertRoute: %w", err)
				}
			}
		}

		// TODO filter by vRouter key
		for _, route := range mgr.ListRoutes() {
			// Ignore routes not for this speaker
			if route.Speaker() != speakerKey {
				continue
			}

			origin := route.Origin()
			// Ignore routes not manages by this reconciler
			if origin.Reconciler != lbSvcReconcilerOrigin {
				continue
			}

			// Get all routes that we want to be announced for the given service.
			key := resource.Key{Namespace: origin.Namespace, Name: origin.Name}
			svcRoutes := routes[key]

			// If the route exists in the list of wanted routes, ignore it
			if slices.IndexFunc(svcRoutes, func(i backend.BGPRoute) bool {
				return maps.Equal(route.Attributes(), i.Attributes())
			}) != -1 {
				continue
			}

			// Delete any route that isn't wanted anymore.
			err := mgr.DeleteRoute(route)
			if err != nil {
				return fmt.Errorf("DeleteRoute: %w", err)
			}
		}
	}

	// vRouter Deletes can be ignored, if the vRouter has been deleted, than the routes are also gone.

	return nil
}

func (pfr *lbSvcReconciler) ReconcileServices(thisNode abstractNode, mgr backend.BGPSpeakerManager) error {
	upserted, deleted, err := pfr.svcStore.Diff()
	if err != nil {
		return fmt.Errorf("svc store diff: %w", err)
	}

	// keep track of all of the routes per service
	routes := make(map[resource.Key][]backend.BGPRoute)

	for _, vRouter := range pfr.vRouterStore.List() {
		if !isRouterApplicable(thisNode, vRouter) {
			continue
		}

		// Don't announce services if selector isn't set.
		if vRouter.Spec.ServiceSelector == nil {
			continue
		}

		speakerKey := backend.BGPSpeakerPK{
			RouterID: vRouterRouterID(thisNode, vRouter),
			LocalASN: uint32(vRouter.Spec.LocalASN),
		}

		svcSelector, err := slimmetav1.LabelSelectorAsSelector(vRouter.Spec.ServiceSelector)
		if err != nil {
			// TODO handle error in a different way?
			return fmt.Errorf("LabelSelectorAsSelector: %w", err)
		}
		for _, svc := range upserted {
			// Ignore non-loadbalancer services
			if svc.Spec.Type != slim_core_v1.ServiceTypeLoadBalancer {
				continue
			}

			// Ignore non matching services
			if !svcSelector.Matches(serviceLabelSet(svc)) {
				continue
			}

			svcKey := resource.NewKey(svc)

			// TODO remove, this is temporary until LB-IPAM is merged into master
			svc.Status.LoadBalancer.Ingress = []slim_core_v1.LoadBalancerIngress{
				{
					IP: "40.30.20.10",
				},
			}

			for _, ingress := range svc.Status.LoadBalancer.Ingress {
				// Ignore ingresses without ips
				if ingress.IP == "" {
					continue
				}

				cidr := net.IPNet{
					IP: net.ParseIP(ingress.IP),
				}
				if cidr.IP.To4() == nil {
					cidr.Mask = net.CIDRMask(128, 128)
				} else {
					cidr.Mask = net.CIDRMask(32, 32)
				}

				route := &backend.UnicastRoute{
					RouteOrigin: backend.Origin{
						Reconciler: lbSvcReconcilerOrigin,
						Type:       "service",
						Name:       svc.Name,
						Namespace:  svc.Namespace,
					},
					Cidr:       cidr,
					BGPSpeaker: speakerKey,
					// TODO add additional route attributes from the vRouter.Spec.routeAttributes
				}

				setNexthopForUnicastRoute(route)
				routes[svcKey] = append(routes[svcKey], route)
				err = mgr.UpsertRoute(route)
				if err != nil {
					return fmt.Errorf("UpsertRoute: %w", err)
				}
			}
		}
	}

routeLoop:
	for _, route := range mgr.ListRoutes() {
		origin := route.Origin()

		// Delete any route that has a origin that has now been deleted
		for _, svcKey := range deleted {
			// TODO filter by svc key.
			// Ignore routes not managed by this reconciler
			if origin.Reconciler != lbSvcReconcilerOrigin {
				continue
			}

			// Ignore routes not for this service
			if origin.Name != svcKey.Name || origin.Namespace != svcKey.Namespace {
				continue
			}

			err := mgr.DeleteRoute(route)
			if err != nil {
				return fmt.Errorf("DeleteRoute: %w", err)
			}

			continue routeLoop
		}

		svcRoutes, found := routes[resource.Key{Namespace: origin.Namespace, Name: origin.Name}]
		if !found {
			// This service hasn't been upserted, so no need to check if now missing announcements
			continue
		}

		// If the route exists in the list of wanted routes, ignore it
		if slices.IndexFunc(svcRoutes, func(i backend.BGPRoute) bool {
			return maps.Equal(route.Attributes(), i.Attributes())
		}) != -1 {
			continue
		}

		// Delete the route if we no longer want it.
		err := mgr.DeleteRoute(route)
		if err != nil {
			return fmt.Errorf("DeleteRoute: %w", err)
		}
	}

	return nil
}

func isRouterApplicable(thisNode abstractNode, router *cilium_v2alpha1.CiliumBGPVirtualRouter) bool {
	// No selector means all nodes match
	if router.Spec.NodeSelector == nil {
		return true
	}

	selector, err := slimmetav1.LabelSelectorAsSelector(router.Spec.NodeSelector)
	if err != nil {
		// TODO handle error in a different way? Set status on vRouter?
		return false
	}

	return selector.Matches(labels.Set(thisNode.Labels))
}

func vRouterToBGPSpeaker(thisNode abstractNode, vRouter *cilium_v2alpha1.CiliumBGPVirtualRouter, reconciler string) backend.BGPSpeaker {
	speaker := backend.BGPSpeaker{
		Key: backend.BGPSpeakerPK{
			RouterID: vRouterRouterID(thisNode, vRouter),
			LocalASN: uint32(vRouter.Spec.LocalASN),
		},
		Origin: backend.Origin{
			Reconciler: reconciler,
			Type:       cilium_v2alpha1.BGPVRouterName,
			Name:       vRouter.Name,
		},
		Config: backend.BGPSpeakerConfig{
			Annotations: vRouter.Annotations,
			LocalASN:    uint32(vRouter.Spec.LocalASN),
			ListenPort:  -1,
			RouterID:    vRouterRouterID(thisNode, vRouter),
		},
	}

	for _, neighbor := range vRouter.Spec.Neighbors {
		addr, _, _ := net.ParseCIDR(neighbor.PeerAddress)
		speaker.Neighbors = append(speaker.Neighbors, backend.BGPNeighbor{
			Address: addr,
			ASN:     uint32(neighbor.PeerASN),
			Config: backend.BGPNeighborConfig{
				// TODO replace with actual per-neighbor annotations
				Annotations: make(map[string]string),
			},
		})
	}

	return speaker
}

func vRouterRouterID(thisNode abstractNode, vRouter *cilium_v2alpha1.CiliumBGPVirtualRouter) string {
	// TODO do proper router ID selection
	return thisNode.IPv4.String()
}

func setNexthopForUnicastRoute(ur *backend.UnicastRoute) {
	if ur.Cidr.IP.To4() != nil {
		// IPv4

		// Currently, we only support advertising locally originated paths (the paths generated in Cilium
		// node itself, not the paths received from another BGP Peer or redistributed from another routing
		// protocol. In this case, the nexthop address should be the address used for peering. That means
		// the nexthop address can be changed depending on the neighbor.
		//
		// For example, when the Cilium node is connected to two subnets 10.0.0.0/24 and 10.0.1.0/24 with
		// local address 10.0.0.1 and 10.0.1.1 respectively, the nexthop should be advertised for 10.0.0.0/24
		// peers is 10.0.0.1. On the other hand, we should advertise 10.0.1.1 as a nexthop for 10.0.1.0/24.
		//
		// By setting the next hop to 0.0.0.0 (or :: for IPv6) we ask the BGP Backend to figure out the correct
		// nexthop on its own.
		//
		// References:
		// - RFC4271 Section 5.1.3 (NEXT_HOP)
		// - RFC4760 Section 3 (Multiprotocol Reachable NLRI - MP_REACH_NLRI (Type Code 14))
		ur.Nexthop = net.ParseIP("0.0.0.0")
		return
	}

	// IPv6

	// See the above explanation for IPv4
	ur.Nexthop = net.ParseIP("::")
}

func cidrEqual(a, b net.IPNet) bool {
	aOnes, aSize := a.Mask.Size()
	bOnes, bSize := b.Mask.Size()
	return a.IP.Equal(b.IP) && aOnes == bOnes && aSize == bSize
}

func serviceLabelSet(svc *slim_core_v1.Service) labels.Labels {
	svcLabels := maps.Clone(svc.Labels)
	svcLabels["io.kubernetes.service.name"] = svc.Name
	svcLabels["io.kubernetes.service.namespace"] = svc.Namespace
	return labels.Set(svcLabels)
}
