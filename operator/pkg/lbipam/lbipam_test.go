package lbipam

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s_testing "k8s.io/client-go/testing"
)

// TestConflictResolution tests that, upon initialization, LB IPAM will detect conflicts between pools,
// internally disables one of the pools, and notifies the user via a status update.
// Next, we update the conflicting pool to remove the offending range, this should re-enable the pool.
func TestConflictResolution(t *testing.T) {
	poolB := mkPool(poolBUID, "pool-b", []string{"10.0.10.0/24", "FF::0/48"})
	poolB.CreationTimestamp = meta_v1.Date(2022, 10, 16, 13, 30, 00, 0, time.UTC)
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
		poolB,
	}, true, false)

	await := fixture.AwaitPool(func(action k8s_testing.Action) bool {
		if action.GetResource() != poolResource || action.GetVerb() != "update" {
			return false
		}

		pool := action.(k8s_testing.UpdateAction).GetObject().(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)

		if pool.Name != "pool-b" {
			return false
		}

		if !pool.Status.Conflicting {
			return false
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Pool B has not been marked conflicting")
	}

	// All ranges of a conflicting pool must be disabled
	poolBRanges, _ := fixture.lbIPAM.RangesStore.GetRangesForPool(poolBUID)
	for _, r := range poolBRanges {
		if !r.internallyDisabled {
			t.Fatalf("Range '%s' from pool B hasn't been disabled", ipNetStr(r.allocRange.CIDR()))
		}
	}

	// Phase 2, resolving the conflict

	await = fixture.AwaitPool(func(action k8s_testing.Action) bool {
		if action.GetResource() != poolResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		pool := action.(k8s_testing.UpdateAction).GetObject().(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)

		if pool.Name != "pool-b" {
			return false
		}

		if pool.Status.Conflicting {
			return false
		}

		return true
	}, time.Second)

	poolB, err := fixture.poolClient.Get(context.Background(), "pool-b", meta_v1.GetOptions{})
	if err != nil {
		t.Fatal(poolB)
	}

	// Remove the conflicting range
	poolB.Spec.Cidrs = []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		{
			Cidr: cilium_api_v2alpha1.IPv4orIPv6CIDR("FF::0/48"),
		},
	}

	_, err = fixture.poolClient.Update(context.Background(), poolB, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Pool b has not de-conflicted")
	}
}

func TestPoolInternalConflict(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24", "10.0.10.64/28"})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, false)

	await := fixture.AwaitPool(func(action k8s_testing.Action) bool {
		if action.GetResource() != poolResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		pool := action.(k8s_testing.UpdateAction).GetObject().(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)

		if !pool.Status.Conflicting {
			return false
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected pool to be marked conflicting")
	}

	await = fixture.AwaitPool(func(action k8s_testing.Action) bool {
		if action.GetResource() != poolResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		pool := action.(k8s_testing.UpdateAction).GetObject().(*cilium_api_v2alpha1.CiliumLoadBalancerIPPool)

		if pool.Status.Conflicting {
			return false
		}

		return true
	}, 2*time.Second)

	pool, err := fixture.poolClient.Get(context.Background(), "pool-a", meta_v1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	pool.Spec.Cidrs = []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		{
			Cidr: "10.0.10.0/24",
		},
	}

	_, err = fixture.poolClient.Update(context.Background(), pool, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected pool to be un-marked conflicting")
	}
}

// TestAllocHappyPath tests that an existing service will first get an IPv4 address assigned, then when they request
// an IPv6 instead, the IPv4 is freed and an IPv6 is allocated for them.
func TestAllocHappyPath(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24", "FF::0/48"}),
	}, true, true)

	// Initially request only an IPv4
	policy := core_v1.IPFamilyPolicySingleStack
	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type:           core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []core_v1.IPFamily{
					core_v1.IPv4Protocol,
				},
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Fatal("Expected service to receive a IPv4 address")
		}

		if len(svc.Status.Conditions) != 1 {
			t.Fatal("Expected service to receive exactly one condition")
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Fatal("Unexpected condition type assigned to service")
		}

		if svc.Status.Conditions[0].Status != meta_v1.ConditionTrue {
			t.Fatal("Unexpected condition status assigned to service")
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service to be updated")
	}

	svc, err := fixture.svcClient.Services("default").Get(context.Background(), "service-a", meta_v1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Switch to requesting an IPv6 address
	svc.Spec.IPFamilies = []core_v1.IPFamily{
		core_v1.IPv6Protocol,
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		// The second update allocates the new IPv6
		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() != nil {
			t.Fatal("Expected service to receive a IPv6 address")
		}

		return true
	}, time.Second)

	_, err = fixture.svcClient.Services("default").Update(context.Background(), svc, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update after update")
	}

	svc, err = fixture.svcClient.Services("default").Get(context.Background(), "service-a", meta_v1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Switch back to requesting an IPv4 address
	svc.Spec.IPFamilies = []core_v1.IPFamily{
		core_v1.IPv4Protocol,
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		// The second update allocates the new IPv4
		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Fatal("Expected service to receive a IPv4 address")
		}

		return true
	}, time.Second)

	_, err = fixture.svcClient.Services("default").Update(context.Background(), svc, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update after update")
	}
}

func TestServiceDelete(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true)

	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type: core_v1.ServiceTypeLoadBalancer,
				IPFamilies: []core_v1.IPFamily{
					core_v1.IPv4Protocol,
				},
			},
		},
	)

	var svcIP string

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Fatal("Expected service to receive a IPv4 address")
		}

		svcIP = svc.Status.LoadBalancer.Ingress[0].IP

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service status to be updated")
	}

	if !fixture.lbIPAM.RangesStore.ranges[0].allocRange.Has(net.ParseIP(svcIP)) {
		t.Fatal("Service IP hasn't been allocated")
	}

	err := fixture.svcClient.Services("default").Delete(context.Background(), "service-a", meta_v1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	if fixture.lbIPAM.RangesStore.ranges[0].allocRange.Has(net.ParseIP(svcIP)) {
		t.Fatal("Service IP hasn't been released")
	}
}

// TestReallocOnInit tests the edge case where an existing service has an IP assigned for which there is no IP Pool.
// LB IPAM should take the unknown IP away and allocate a new and valid IP. This scenario can happen when a service
// passes ownership from on controller to another or when a pool is deleted while the operator is down.
func TestReallocOnInit(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true)

	// Initially request only an IPv4
	policy := core_v1.IPFamilyPolicySingleStack
	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type:           core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []core_v1.IPFamily{
					core_v1.IPv4Protocol,
				},
			},
			Status: core_v1.ServiceStatus{
				LoadBalancer: core_v1.LoadBalancerStatus{
					Ingress: []core_v1.LoadBalancerIngress{
						{
							IP: "192.168.1.12",
						},
					},
				},
			},
		},
	)

	i := 0
	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)
		i++
		if i == 1 {
			// The first update removes the bad IPv4 address
			if len(svc.Status.LoadBalancer.Ingress) != 0 {
				t.Fatal("Expected service to have no ingresses")
			}

			return false
		}

		if i == 2 {
			// The second update allocates the new IPv4
			if len(svc.Status.LoadBalancer.Ingress) != 1 {
				t.Fatal("Expected service to receive exactly one ingress IP")
			}

			if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
				t.Fatal("Expected service to receive a IPv4 address")
			}

			if svc.Status.LoadBalancer.Ingress[0].IP == "192.168.1.12" {
				t.Fatal("Expected ingress IP to not be the initial, bad IP")
			}

			if len(svc.Status.Conditions) != 1 {
				t.Fatal("Expected service to receive exactly one condition")
			}

			if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
				t.Fatal("Expected second condition to be svc-satisfied:true")
			}

			if svc.Status.Conditions[0].Status != meta_v1.ConditionTrue {
				t.Fatal("Expected second condition to be svc-satisfied:true")
			}
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service to be updated")
	}
}

// TestAllocOnInit tests that on init, ingress IPs on services which match configured pools are imported
// and marked as allocated. This is crucial when restarting the operator in a running cluster.
func TestAllocOnInit(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true)

	policy := core_v1.IPFamilyPolicySingleStack
	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type:           core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []core_v1.IPFamily{
					core_v1.IPv4Protocol,
				},
			},
			Status: core_v1.ServiceStatus{
				LoadBalancer: core_v1.LoadBalancerStatus{
					Ingress: []core_v1.LoadBalancerIngress{
						{
							IP: "10.0.10.123",
						},
					},
				},
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		t.Fatal("No service updates expected")

		return false
	}, 100*time.Millisecond)

	initDone := make(chan struct{})
	go fixture.lbIPAM.Run(context.Background(), initDone)

	<-initDone

	await.Block()

	if !fixture.lbIPAM.RangesStore.ranges[0].allocRange.Has(net.ParseIP("10.0.10.123")) {
		t.Fatal("Expected the imported IP to be allocated")
	}
}

// TestPoolSelector tests that an IP Pool will only allocate IPs to services which match its service selector.
// The selector in this case is a very simple label.
func TestPoolSelectorBasic(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	selector := slimv1.LabelSelector{
		MatchLabels: map[string]string{
			"color": "red",
		},
	}
	poolA.Spec.ServiceSelector = &selector

	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true)

	go fixture.lbIPAM.Run(context.Background(), nil)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if svc.Name != "red-service" {
			t.Fatal("Expected update from 'red-service'")
		}

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Fatal("Expected service to receive a IPv4 address")
		}

		if len(svc.Status.Conditions) != 1 {
			t.Fatal("Expected service to receive exactly one condition")
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Fatal("Expected condition to be svc-satisfied:true")
		}

		if svc.Status.Conditions[0].Status != meta_v1.ConditionTrue {
			t.Fatal("Expected condition to be svc-satisfied:true")
		}

		return true
	}, time.Second)

	policy := core_v1.IPFamilyPolicySingleStack
	matchingService := &core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "red-service",
			UID:  serviceAUID,
			Labels: map[string]string{
				"color": "red",
			},
		},
		Spec: core_v1.ServiceSpec{
			Type:           core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}

	_, err := fixture.svcClient.Services("default").Create(context.Background(), matchingService, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if svc.Name != "blue-service" {
			return false
		}

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Fatal("Expected service to not receive any ingress IPs")
		}

		if len(svc.Status.Conditions) != 1 {
			t.Fatal("Expected service to receive exactly one condition")
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Fatal("Expected condition to be svc-satisfied:false")
		}

		if svc.Status.Conditions[0].Status != meta_v1.ConditionFalse {
			t.Fatal("Expected condition to be svc-satisfied:false")
		}

		return true
	}, time.Second)

	nonMatchingService := &core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "blue-service",
			UID:  serviceBUID,
			Labels: map[string]string{
				"color": "blue",
			},
		},
		Spec: core_v1.ServiceSpec{
			Type:           core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}

	_, err = fixture.svcClient.Services("default").Create(context.Background(), nonMatchingService, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestPoolSelectorNamespace tests that an IP Pool with a 'io.kubernetes.service.namespace' selector will only
// assign IPs to services in the given namespace.
func TestPoolSelectorNamespace(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	selector := slimv1.LabelSelector{
		MatchLabels: map[string]string{
			"io.kubernetes.service.namespace": "tenant-one",
		},
	}
	poolA.Spec.ServiceSelector = &selector

	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true)

	go fixture.lbIPAM.Run(context.Background(), nil)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if svc.Name != "red-service" {
			t.Fatal("Expected update from 'red-service'")
		}

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Fatal("Expected service to receive a IPv4 address")
		}

		if len(svc.Status.Conditions) != 1 {
			t.Fatal("Expected service to receive exactly one condition")
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Fatal("Expected condition to be svc-satisfied:true")
		}

		if svc.Status.Conditions[0].Status != meta_v1.ConditionTrue {
			t.Fatal("Expected condition to be svc-satisfied:true")
		}

		return true
	}, time.Second)

	policy := core_v1.IPFamilyPolicySingleStack
	matchingService := &core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "red-service",
			Namespace: "tenant-one",
			UID:       serviceAUID,
		},
		Spec: core_v1.ServiceSpec{
			Type:           core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}

	_, err := fixture.svcClient.Services("tenant-one").Create(context.Background(), matchingService, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if svc.Name != "blue-service" {
			return false
		}

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Fatal("Expected service to not receive any ingress IPs")
		}

		if len(svc.Status.Conditions) != 1 {
			t.Fatal("Expected service to receive exactly one condition")
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Fatal("Expected condition to be svc-satisfied:false")
		}

		if svc.Status.Conditions[0].Status != meta_v1.ConditionFalse {
			t.Fatal("Expected condition to be svc-satisfied:false")
		}

		return true
	}, time.Second)

	nonMatchingService := &core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "blue-service",
			Namespace: "tenant-two",
			UID:       serviceBUID,
			Labels: map[string]string{
				// Setting the same label in an attempt to escalate privileges doesn't work
				"io.kubernetes.service.namespace": "tenant-one",
			},
		},
		Spec: core_v1.ServiceSpec{
			Type:           core_v1.ServiceTypeLoadBalancer,
			IPFamilyPolicy: &policy,
		},
	}

	_, err = fixture.svcClient.Services("tenant-two").Create(context.Background(), nonMatchingService, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestChangeServiceType tests that we don't handle non-LB services, then we update the type and check that we start
// handling the service, then switch the type again and verify that we release the allocated IP.
func TestChangeServiceType(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true)

	// This existing ClusterIP service should be ignored
	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type: core_v1.ServiceTypeClusterIP,
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		t.Fatal("No service updates expected")

		return false
	}, 100*time.Millisecond)

	initDone := make(chan struct{})
	go fixture.lbIPAM.Run(context.Background(), initDone)

	<-initDone

	await.Block()

	var assignedIP string

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if net.ParseIP(svc.Status.LoadBalancer.Ingress[0].IP).To4() == nil {
			t.Fatal("Expected service to receive a IPv4 address")
		}

		assignedIP = svc.Status.LoadBalancer.Ingress[0].IP

		if len(svc.Status.Conditions) != 1 {
			t.Fatal("Expected service to receive exactly one condition")
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Fatal("Expected condition to be svc-satisfied:true")
		}

		if svc.Status.Conditions[0].Status != meta_v1.ConditionTrue {
			t.Fatal("Expected condition to be svc-satisfied:true")
		}

		return true
	}, time.Second)

	updatedService := &core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: core_v1.ServiceSpec{
			Type: core_v1.ServiceTypeLoadBalancer,
		},
	}

	_, err := fixture.svcClient.Services("default").Update(context.Background(), updatedService, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Fatal("Expected service to have no ingress IPs")
		}

		if len(svc.Status.Conditions) != 0 {
			t.Fatal("Expected service to have no conditions")
		}

		return true
	}, time.Second)

	updatedService = &core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "service-a",
			Namespace: "default",
			UID:       serviceAUID,
		},
		Spec: core_v1.ServiceSpec{
			Type: core_v1.ServiceTypeNodePort,
		},
	}

	_, err = fixture.svcClient.Services("default").Update(context.Background(), updatedService, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	if fixture.lbIPAM.RangesStore.ranges[0].allocRange.Has(net.ParseIP(assignedIP)) {
		t.Fatal("Expected assigned IP to be released")
	}
}

// TestRangesFull tests the behavior when all eligible ranges are full.
func TestRangesFull(t *testing.T) {
	// A single /32 can't be used to allocate since we always reserve 2 IPs,
	// the network and broadcast address, which in the case of a /32 means it is always full.
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.123/32", "FF::123/128"}),
	}, true, true)

	policy := core_v1.IPFamilyPolicySingleStack
	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type:           core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []core_v1.IPFamily{
					core_v1.IPv4Protocol,
				},
			},
		},
	)
	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-b",
				Namespace: "default",
				UID:       serviceBUID,
			},
			Spec: core_v1.ServiceSpec{
				Type:           core_v1.ServiceTypeLoadBalancer,
				IPFamilyPolicy: &policy,
				IPFamilies: []core_v1.IPFamily{
					core_v1.IPv6Protocol,
				},
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		// spew.Dump(svc)

		if svc.Name != "service-a" {
			if len(svc.Status.LoadBalancer.Ingress) != 0 {
				t.Error("Expected service to have no ingress IPs")
			}

			if len(svc.Status.Conditions) != 1 {
				t.Fatal("Expected service to have one conditions")
				return true
			}

			if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
				t.Error("Expected condition to be svc-satisfied:false")
			}

			if svc.Status.Conditions[0].Status != meta_v1.ConditionFalse {
				t.Error("Expected condition to be svc-satisfied:false")
			}

			if svc.Status.Conditions[0].Reason != "out_of_ips" {
				t.Error("Expected condition reason to be out of IPs")
			}

			return false
		}

		if svc.Name != "service-b" {

			if len(svc.Status.LoadBalancer.Ingress) != 0 {
				t.Error("Expected service to have no ingress IPs")
			}

			if len(svc.Status.Conditions) != 1 {
				t.Error("Expected service to have one conditions")
				return true
			}

			if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
				t.Error("Expected condition to be svc-satisfied:false")
			}

			if svc.Status.Conditions[0].Status != meta_v1.ConditionFalse {
				t.Error("Expected condition to be svc-satisfied:false")
			}

			if svc.Status.Conditions[0].Reason != "out_of_ips" {
				t.Error("Expected condition reason to be out of IPs")
			}
		}

		return true
	}, time.Second)

	initDone := make(chan struct{})
	go fixture.lbIPAM.Run(context.Background(), initDone)

	<-initDone

	if await.Block() {
		t.Fatal("Expected two service updates")
	}
}

// TestRequestIPs tests that we can request specific IPs
func TestRequestIPs(t *testing.T) {
	// A single /32 can't be used to allocate since we always reserve 2 IPs,
	// the network and broadcast address, which in the case of a /32 means it is always full.
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true)

	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type:           core_v1.ServiceTypeLoadBalancer,
				LoadBalancerIP: "10.0.10.20",
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if svc.Status.LoadBalancer.Ingress[0].IP != "10.0.10.20" {
			t.Fatal("Expected service to receive IP '10.0.10.20'")
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if svc.Name != "service-b" {
			t.Fatal("Expected status update for service-b")
		}

		if len(svc.Status.LoadBalancer.Ingress) != 3 {
			t.Fatal("Expected service to receive exactly three ingress IPs")
		}

		first := false
		second := false
		third := false

		for _, ingress := range svc.Status.LoadBalancer.Ingress {
			switch ingress.IP {
			case "10.0.10.21":
				first = true
			case "10.0.10.22":
				second = true
			case "10.0.10.23":
				third = true
			default:
				t.Fatal("Unexpected ingress IP")
			}
		}

		if !first {
			t.Fatal("Expected service to receive IP '10.0.10.21'")
		}

		if !second {
			t.Fatal("Expected service to receive IP '10.0.10.22'")
		}

		if !third {
			t.Fatal("Expected service to receive IP '10.0.10.23'")
		}

		return true
	}, time.Second)

	serviceB := &core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
			Annotations: map[string]string{
				ciliumSvcLBIPSAnnotation: "10.0.10.22,10.0.10.23",
			},
		},
		Spec: core_v1.ServiceSpec{
			Type:           core_v1.ServiceTypeLoadBalancer,
			LoadBalancerIP: "10.0.10.21",
		},
	}

	_, err := fixture.svcClient.Services("default").Create(context.Background(), serviceB, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if svc.Name != "service-c" {
			t.Fatal("Expected status update for service-b")
		}

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Fatal("Expected service to receive no ingress IPs")
		}

		if len(svc.Status.Conditions) != 1 {
			t.Fatal("Expected service to have one conditions")
		}

		if svc.Status.Conditions[0].Type != ciliumSvcRequestSatisfiedCondition {
			t.Fatal("Expected condition to be request-valid:false")
		}

		if svc.Status.Conditions[0].Status != meta_v1.ConditionFalse {
			t.Fatal("Expected condition to be request-valid:false")
		}

		if svc.Status.Conditions[0].Reason != "already_allocated" {
			t.Fatal("Expected condition reason to be 'already_allocated'")
		}

		return true
	}, time.Second)

	// request an already allocated IP
	serviceC := &core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "service-c",
			Namespace: "default",
			UID:       serviceCUID,
		},
		Spec: core_v1.ServiceSpec{
			Type:           core_v1.ServiceTypeLoadBalancer,
			LoadBalancerIP: "10.0.10.21",
		},
	}

	_, err = fixture.svcClient.Services("default").Create(context.Background(), serviceC, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestAddPool tests that adding a new pool will satisfy services.
func TestAddPool(t *testing.T) {
	// A single /32 can't be used to allocate since we always reserve 2 IPs,
	// the network and broadcast address, which in the case of a /32 means it is always full.
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
	}, true, true)

	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type:           core_v1.ServiceTypeLoadBalancer,
				LoadBalancerIP: "10.0.20.10",
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Fatal("Expected service to receive no ingress IPs")
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if svc.Status.LoadBalancer.Ingress[0].IP != "10.0.20.10" {
			t.Fatal("Expected service to receive IP '10.0.20.10'")
		}

		return true
	}, time.Second)

	twentyPool := mkPool(poolBUID, "pool-b", []string{"10.0.20.0/24"})
	_, err := fixture.poolClient.Create(context.Background(), twentyPool, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestAddRange tests adding a range to a pool will satisfy services which have not been able to get an IP
func TestAddRange(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	// A single /32 can't be used to allocate since we always reserve 2 IPs,
	// the network and broadcast address, which in the case of a /32 means it is always full.
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true)

	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type:           core_v1.ServiceTypeLoadBalancer,
				LoadBalancerIP: "10.0.20.10",
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Fatal("Expected service to receive no ingress IPs")
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	poolA.Spec.Cidrs = append(poolA.Spec.Cidrs, cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		Cidr: "10.0.20.0/24",
	})

	_, err := fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if svc.Status.LoadBalancer.Ingress[0].IP != "10.0.20.10" {
			t.Fatal("Expected service to receive IP '10.0.20.10'")
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestDisablePool tests that disabling a pool will not remove existing allocations but will stop new allocations.
// Then re-enable the pool and see that the pool resumes allocating IPs
func TestDisablePool(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	// A single /32 can't be used to allocate since we always reserve 2 IPs,
	// the network and broadcast address, which in the case of a /32 means it is always full.
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true)

	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type: core_v1.ServiceTypeLoadBalancer,
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		return true
	}, 100*time.Millisecond)

	poolA.Spec.Disabled = true

	_, err := fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !await.Block() {
		t.Fatal("Unexpected service status update")
	}

	if !fixture.lbIPAM.RangesStore.ranges[0].externallyDisabled {
		t.Fatal("The range has not been externally disabled")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if svc.Name != "service-b" {
			t.Fatal("Expected service status update to occur on service-b")
		}

		if len(svc.Status.LoadBalancer.Ingress) != 0 {
			t.Fatal("Expected service to receive no ingress IPs")
		}

		return true
	}, time.Second)

	serviceB := &core_v1.Service{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "service-b",
			Namespace: "default",
			UID:       serviceBUID,
		},
		Spec: core_v1.ServiceSpec{
			Type: core_v1.ServiceTypeLoadBalancer,
		},
	}

	_, err = fixture.svcClient.Services("default").Create(context.Background(), serviceB, meta_v1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if svc.Name != "service-b" {
			return false
		}

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			return false
		}

		return true
	}, time.Second)

	poolA.Spec.Disabled = false

	_, err = fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestPoolDelete tests that when a pool is deleted, all of the IPs from that pool are released and that any effected
// services get a new IP from another pool.
func TestPoolDelete(t *testing.T) {
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"}),
		mkPool(poolBUID, "pool-b", []string{"10.0.20.0/24"}),
	}, true, true)

	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type: core_v1.ServiceTypeLoadBalancer,
			},
		},
	)

	var allocPool string

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if strings.HasPrefix(svc.Status.LoadBalancer.Ingress[0].IP, "10.0.10") {
			allocPool = "pool-a"
		} else {
			allocPool = "pool-b"
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if strings.HasPrefix(svc.Status.LoadBalancer.Ingress[0].IP, "10.0.10") {
			if allocPool == "pool-a" {
				t.Fatal("New IP was allocated from deleted pool")
			}
		} else {
			if allocPool == "pool-b" {
				t.Fatal("New IP was allocated from deleted pool")
			}
		}

		return true
	}, time.Second)

	err := fixture.poolClient.Delete(context.Background(), allocPool, meta_v1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TestRangeDelete tests that when a range is deleted from a pool, all of the IPs from that range are released and
// that any effected services get a new IP from another range.
func TestRangeDelete(t *testing.T) {
	poolA := mkPool(poolAUID, "pool-a", []string{"10.0.10.0/24"})
	fixture := mkTestFixture([]*cilium_api_v2alpha1.CiliumLoadBalancerIPPool{
		poolA,
	}, true, true)

	fixture.coreCS.Tracker().Add(
		&core_v1.Service{
			ObjectMeta: meta_v1.ObjectMeta{
				Name:      "service-a",
				Namespace: "default",
				UID:       serviceAUID,
			},
			Spec: core_v1.ServiceSpec{
				Type: core_v1.ServiceTypeLoadBalancer,
			},
		},
	)

	await := fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		return true
	}, time.Second)

	go fixture.lbIPAM.Run(context.Background(), nil)

	if await.Block() {
		t.Fatal("Expected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		return true
	}, 100*time.Millisecond)

	// Add a new CIDR, this should not have any effect on the existing service.
	poolA.Spec.Cidrs = append(poolA.Spec.Cidrs, cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		Cidr: "10.0.20.0/24",
	})
	_, err := fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if !await.Block() {
		t.Fatal("Unexpected service status update")
	}

	await = fixture.AwaitService(func(action k8s_testing.Action) bool {
		if action.GetResource() != servicesResource || action.GetVerb() != "update" || action.GetSubresource() != "status" {
			return false
		}

		svc := action.(k8s_testing.UpdateAction).GetObject().(*core_v1.Service)

		if len(svc.Status.LoadBalancer.Ingress) != 1 {
			t.Fatal("Expected service to receive exactly one ingress IP")
		}

		if !strings.HasPrefix(svc.Status.LoadBalancer.Ingress[0].IP, "10.0.20") {
			t.Fatal("Expected new ingress to be in the 10.0.20.0/24 range")
		}

		return true
	}, time.Second)

	// Remove the existing range, this should trigger the re-allocation of the existing service
	poolA.Spec.Cidrs = []cilium_api_v2alpha1.CiliumLoadBalancerIPPoolCIDRBlock{
		{
			Cidr: "10.0.20.0/24",
		},
	}
	_, err = fixture.poolClient.Update(context.Background(), poolA, meta_v1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if await.Block() {
		t.Fatal("Expected service status update")
	}
}

// TODO:
// - import svc with requested IPs
// - alloc error on import
// - service no longer matches pool selector
// - Remove requested IP
// - Requesting IP from pool with mismatched selector
// - DualStack
