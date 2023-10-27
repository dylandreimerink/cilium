// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbipam

import (
	"net"
	"net/netip"
	"slices"

	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_labels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
)

type serviceStore struct {
	// List of services which have received all IPs they requested
	satisfied map[resource.Key]*ServiceView
	// List of services which have one or more IPs which were requested but not allocated
	unsatisfied map[resource.Key]*ServiceView
}

func NewServiceStore() serviceStore {
	return serviceStore{
		satisfied:   make(map[resource.Key]*ServiceView),
		unsatisfied: make(map[resource.Key]*ServiceView),
	}
}

func (ss *serviceStore) GetService(key resource.Key) (serviceView *ServiceView, found, satisfied bool) {
	serviceView, found = ss.satisfied[key]
	if found {
		return serviceView, true, true
	}

	serviceView, found = ss.unsatisfied[key]
	if found {
		return serviceView, true, false
	}

	return nil, false, false
}

func (ss *serviceStore) Upsert(serviceView *ServiceView) {
	if serviceView.isSatisfied() {
		delete(ss.unsatisfied, serviceView.Key)
		ss.satisfied[serviceView.Key] = serviceView
	} else {
		delete(ss.satisfied, serviceView.Key)
		ss.unsatisfied[serviceView.Key] = serviceView
	}
}

func (ss *serviceStore) Delete(key resource.Key) {
	delete(ss.satisfied, key)
	delete(ss.unsatisfied, key)
}

// ServiceView is the LB IPAM's view of the service, the minimal amount of info we need about it.
type ServiceView struct {
	Key    resource.Key
	Labels slim_labels.Set

	Generation int64
	Status     *slim_core_v1.ServiceStatus

  SharingKey string
  // These required to determine if a service conflicts with another for sharing an ip
  ExternalTrafficPolicy *slim_core_v1.ServiceExternalTrafficPolicy
  Ports *[]slim_core_v1.ServicePort
  Selector *map[string]string

	// The specific IPs requested by the service
	RequestedIPs []netip.Addr
	// The IP families requested by the service
	RequestedFamilies struct {
		IPv4 bool
		IPv6 bool
	}
	// The IPs we have allocated for this IP
	AllocatedIPs []ServiceViewIP
}

func (sv *ServiceView) isCompatible(osv *ServiceView) bool {
  // They request the use of different ports (e.g. tcp/80 for one and tcp/443 for the other).
  for _, port1 := sv.Ports {
    for _, port2 := osv.Ports {
      if port1 == port2 {
        return false
      }
    }
  }
  // They both use the Cluster external traffic policy, or they both point to the exact same set of pods (i.e. the pod selectors are identical).
  if !((sv.ExternalTrafficPolicy == slim_core_v1.ServiceExternalTrafficPolicyCluster) && (osv.ExternalTrafficPolicy == sv.ExternalTrafficPolicy)) {
    return reflect.DeepEqual(sv.Selector, osv.Selector)
  }
  return true
}

func (sv *ServiceView) isSatisfied() bool {
	// If the service requests specific IPs
	if len(sv.RequestedIPs) > 0 {
		for _, reqIP := range sv.RequestedIPs {
			// If reqIP doesn't exist in the list of assigned IPs
			if slices.IndexFunc(sv.Status.LoadBalancer.Ingress, func(in slim_core_v1.LoadBalancerIngress) bool {
				addr, err := netip.ParseAddr(in.IP)
				if err != nil {
					return false
				}
				return addr.Compare(reqIP) == 0
			}) == -1 {
				return false
			}
		}

		return true
	}

	// No specific requests are made, check that all requested families are assigned
	hasIPv4 := false
	hasIPv6 := false
	for _, assigned := range sv.Status.LoadBalancer.Ingress {
		if net.ParseIP(assigned.IP).To4() == nil {
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
	IP     netip.Addr
	Origin *LBRange
}

// svcLabels clones the services labels and adds a number of internal labels which can be used to select
// specific services and/or namespaces using the label selectors.
func svcLabels(svc *slim_core_v1.Service) slim_labels.Set {
	clone := maps.Clone(svc.Labels)
	if clone == nil {
		clone = make(map[string]string)
	}
	clone[serviceNameLabel] = svc.Name
	clone[serviceNamespaceLabel] = svc.Namespace
	return clone
}
