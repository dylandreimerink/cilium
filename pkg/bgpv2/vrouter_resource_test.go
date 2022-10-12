package bgpv2

import (
	"context"
	"runtime/debug"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/davecgh/go-spew/spew"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type VRouterResourceFixture struct {
	vRouterRes *VRouterResource
	ciliumCS   *cilium_fake.Clientset
	hive       *hive.Hive
}

func newVRouterResourceFixture() *VRouterResourceFixture {
	fixture := &VRouterResourceFixture{}

	// Create a new mocked CRD client set with the pools as initial objects
	fixture.ciliumCS = cilium_fake.NewSimpleClientset()

	// Construct a new Hive with mocked out dependency cells.
	fixture.hive = hive.New(
		// Create a resource from the mocked clients
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy] {
			return resource.New[*cilium_api_v2alpha1.CiliumBGPPeeringPolicy](
				lc, utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPPeeringPolicyList](
					c.CiliumV2alpha1().CiliumBGPPeeringPolicies(),
				),
			)
		}),
		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*cilium_api_v2alpha1.CiliumBGPVirtualRouter] {
			return resource.New[*cilium_api_v2alpha1.CiliumBGPVirtualRouter](
				lc, utils.ListerWatcherFromTyped[*cilium_api_v2alpha1.CiliumBGPVirtualRouterList](
					c.CiliumV2alpha1().CiliumBGPVirtualRouters(),
				),
			)
		}),

		// Provide the mocked client cells directly
		cell.Provide(func() k8sClient.Clientset {
			return &k8sClient.FakeClientset{
				CiliumFakeClientset: fixture.ciliumCS,
			}
		}),

		cell.Invoke(func(vRouterRes *VRouterResource) {
			fixture.vRouterRes = vRouterRes
		}),

		cell.Provide(NewVRouterResource),
	)

	return fixture
}

func TestAddMergeVRouters(t *testing.T) {
	fixture := newVRouterResourceFixture()
	tracker := fixture.ciliumCS.Tracker()

	fixture.hive.Start(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 2)
	eventChan := stream.ToChannel[resource.Event[*cilium_api_v2alpha1.CiliumBGPVirtualRouter]](ctx, errs, fixture.vRouterRes)

	getEvent := func() resource.Event[*cilium_api_v2alpha1.CiliumBGPVirtualRouter] {
		timer := time.NewTimer(time.Second)
		select {
		case event := <-eventChan:
			return event
		case <-timer.C:
			t.Fatal("No event on channel")
			return nil
		}
	}

	event := getEvent()
	_, ok := event.(SyncEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected sync event")
	}

	tracker.Add(&cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		ObjectMeta: v1.ObjectMeta{
			Name: "single-a",
		},
		Spec: cilium_api_v2alpha1.CiliumBGPVirtualRouterSpec{
			LocalASN: 1,
		},
	})
	event = getEvent()
	ue, ok := event.(UpdateEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected update event")
	}
	if ue.Obj.Name != "single-a" {
		t.Fatal("Expected 0th event to be for 'single-a'")
	}

	tracker.Add(&cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		ObjectMeta: v1.ObjectMeta{
			Name: "single-b",
		},
		Spec: cilium_api_v2alpha1.CiliumBGPVirtualRouterSpec{
			LocalASN: 2,
		},
	})
	event = getEvent()
	ue, ok = event.(UpdateEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		spew.Dump(event)
		t.Fatal("Expected update event")
	}
	if ue.Obj.Name != "single-b" {
		t.Fatal("Expected 1st event to be for 'single-a'")
	}

	tracker.Add(&cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-a",
		},
		Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
			VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouterSpec{
				{
					LocalASN: 3,
				},
				{
					LocalASN: 4,
				},
			},
		},
	})
	event = getEvent()
	ue, ok = event.(UpdateEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected update event")
	}
	if ue.Obj.Name != "policy-a-3" {
		t.Fatal("Expected 2nd event to be for 'policy-a-3'")
	}

	event = getEvent()
	ue, ok = event.(UpdateEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected update event")
	}
	if ue.Obj.Name != "policy-a-4" {
		t.Fatal("Expected 3rd event to be for 'policy-a-4'")
	}

	cancel()
	<-errs
	fixture.hive.Stop(context.Background())
}

func TestModifyVRouterPolicy(t *testing.T) {
	fixture := newVRouterResourceFixture()
	tracker := fixture.ciliumCS.Tracker()

	fixture.hive.Start(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 2)
	eventChan := stream.ToChannel[resource.Event[*cilium_api_v2alpha1.CiliumBGPVirtualRouter]](ctx, errs, fixture.vRouterRes)

	getEvent := func() resource.Event[*cilium_api_v2alpha1.CiliumBGPVirtualRouter] {
		timer := time.NewTimer(time.Second)
		select {
		case event := <-eventChan:
			return event
		case <-timer.C:
			debug.PrintStack()
			t.Fatal("No event on channel")
			return nil
		}
	}

	event := getEvent()
	_, ok := event.(SyncEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected sync event")
	}

	tracker.Add(&cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-a",
		},
		Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
			VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouterSpec{
				{
					LocalASN: 1,
				},
				{
					LocalASN: 2,
				},
			},
		},
	})
	event = getEvent()
	ue, ok := event.(UpdateEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected update event")
	}
	if ue.Obj.Name != "policy-a-1" {
		t.Fatal("Expected 0th event to be for 'policy-a-1'")
	}

	event = getEvent()
	ue, ok = event.(UpdateEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected update event")
	}
	if ue.Obj.Name != "policy-a-2" {
		t.Fatal("Expected 2nd event to be for 'policy-a-2'")
	}

	err := tracker.Update(cilium_api_v2alpha1.SchemeGroupVersion.WithResource(cilium_api_v2alpha1.BGPPPluralName),
		&cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name: "policy-a",
			},
			Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
				VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouterSpec{
					{
						LocalASN: 1,
					},
				},
			},
		}, "")
	if err != nil {
		t.Fatal(err)
	}

	event = getEvent()
	de, ok := event.(DeleteEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected delete event")
	}
	if de.Obj.Name != "policy-a-2" {
		t.Fatal("Expected 4th event to be for 'policy-a-2'")
	}

	event = getEvent()
	ue, ok = event.(UpdateEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected update event")
	}
	if ue.Obj.Name != "policy-a-1" {
		t.Fatal("Expected 3rd event to be for 'policy-a-1'")
	}

	cancel()
	<-errs
	fixture.hive.Stop(context.Background())
}

func TestDeleteVRouterPolicy(t *testing.T) {
	fixture := newVRouterResourceFixture()
	tracker := fixture.ciliumCS.Tracker()

	fixture.hive.Start(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 2)
	eventChan := stream.ToChannel[resource.Event[*cilium_api_v2alpha1.CiliumBGPVirtualRouter]](ctx, errs, fixture.vRouterRes)

	getEvent := func() resource.Event[*cilium_api_v2alpha1.CiliumBGPVirtualRouter] {
		timer := time.NewTimer(time.Second)
		select {
		case event := <-eventChan:
			return event
		case <-timer.C:
			debug.PrintStack()
			t.Fatal("No event on channel")
			return nil
		}
	}

	event := getEvent()
	_, ok := event.(SyncEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected sync event")
	}

	tracker.Add(&cilium_api_v2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "policy-a",
		},
		Spec: cilium_api_v2alpha1.CiliumBGPPeeringPolicySpec{
			VirtualRouters: []cilium_api_v2alpha1.CiliumBGPVirtualRouterSpec{
				{
					LocalASN: 1,
				},
				{
					LocalASN: 2,
				},
			},
		},
	})
	event = getEvent()
	ue, ok := event.(UpdateEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected update event")
	}
	if ue.Obj.Name != "policy-a-1" {
		t.Fatal("Expected 0th event to be for 'policy-a-1'")
	}

	event = getEvent()
	ue, ok = event.(UpdateEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected update event")
	}
	if ue.Obj.Name != "policy-a-2" {
		t.Fatal("Expected 2nd event to be for 'policy-a-2'")
	}

	err := tracker.Delete(cilium_api_v2alpha1.SchemeGroupVersion.WithResource(cilium_api_v2alpha1.BGPPPluralName), "", "policy-a")
	if err != nil {
		t.Fatal(err)
	}

	event = getEvent()
	de, ok := event.(DeleteEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected delete event")
	}
	if de.Obj.Name != "policy-a-1" {
		t.Fatal("Expected 3rd event to be for 'policy-a-1'")
	}

	event = getEvent()
	de, ok = event.(DeleteEvent[*cilium_api_v2alpha1.CiliumBGPVirtualRouter])
	if !ok {
		t.Fatal("Expected delete event")
	}
	if de.Obj.Name != "policy-a-2" {
		t.Fatal("Expected 4th event to be for 'policy-a-2'")
	}
	cancel()
	<-errs
	fixture.hive.Stop(context.Background())
}
