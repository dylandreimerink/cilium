package bgpv2

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DiffStoreFixture struct {
	diffFactory DiffStoreFactory[*cilium_api_v2alpha1.CiliumBGPVirtualRouter]
	signaler    *Signaler
	ciliumCS    *cilium_fake.Clientset
	hive        *hive.Hive
}

func newDiffStoreFixture() *DiffStoreFixture {
	fixture := &DiffStoreFixture{}

	// Create a new mocked CRD client set with the pools as initial objects
	fixture.ciliumCS = cilium_fake.NewSimpleClientset()

	// Construct a new Hive with mocked out dependency cells.
	fixture.hive = hive.New(
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

		cell.Provide(newSignaler),

		cell.Invoke(func(
			signaler *Signaler,
			diffFactory DiffStoreFactory[*cilium_api_v2alpha1.CiliumBGPVirtualRouter],
		) {
			fixture.signaler = signaler
			fixture.diffFactory = diffFactory
		}),

		cell.Provide(newDiffStoreFactory[*cilium_api_v2alpha1.CiliumBGPVirtualRouter]),
	)

	return fixture
}

// Test that adding and deleting objects trigger signals
func TestDiffSignal(t *testing.T) {
	fixture := newDiffStoreFixture()
	tracker := fixture.ciliumCS.Tracker()

	// Add an initial object.
	err := tracker.Add(&cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		ObjectMeta: v1.ObjectMeta{
			Name: "router-a",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = fixture.hive.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	diffstore := fixture.diffFactory.NewStore()

	timer := time.NewTimer(time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err := diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Initial upserted not one")
	}

	if len(deleted) != 0 {
		t.Fatal("Initial deleted not zero")
	}

	// Add an object after init

	err = tracker.Add(&cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		ObjectMeta: v1.ObjectMeta{
			Name: "router-b",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	timer = time.NewTimer(time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Runtime upserted not one")
	}

	if len(deleted) != 0 {
		t.Fatal("Runtime deleted not zero")
	}

	// Delete an object after init

	err = tracker.Delete(cilium_api_v2alpha1.SchemeGroupVersion.WithResource(cilium_api_v2alpha1.BGPVrouterPluralName), "", "router-b")
	if err != nil {
		t.Fatal(err)
	}

	timer = time.NewTimer(time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 0 {
		t.Fatal("Runtime upserted not zero")
	}

	if len(deleted) != 1 {
		t.Fatal("Runtime deleted not one")
	}

	err = fixture.hive.Stop(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

// Test that multiple events are correctly combined.
func TestDiffUpsertCoalesce(t *testing.T) {
	fixture := newDiffStoreFixture()
	tracker := fixture.ciliumCS.Tracker()

	err := fixture.hive.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	diffstore := fixture.diffFactory.NewStore()

	// Add first object
	err = tracker.Add(&cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		ObjectMeta: v1.ObjectMeta{
			Name: "router-a",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add second object
	err = tracker.Add(&cilium_api_v2alpha1.CiliumBGPVirtualRouter{
		ObjectMeta: v1.ObjectMeta{
			Name: "router-b",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer := time.NewTimer(time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err := diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 2 {
		t.Fatal("Expected 2 upserted objects")
	}

	if len(deleted) != 0 {
		t.Fatal("Expected 0 deleted objects")
	}

	// Update first object
	err = tracker.Update(
		cilium_api_v2alpha1.SchemeGroupVersion.WithResource(cilium_api_v2alpha1.BGPVrouterPluralName),
		&cilium_api_v2alpha1.CiliumBGPVirtualRouter{
			ObjectMeta: v1.ObjectMeta{
				Name: "router-a",
			},
			Spec: cilium_api_v2alpha1.CiliumBGPVirtualRouterSpec{
				LocalASN: 1,
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	err = tracker.Delete(cilium_api_v2alpha1.SchemeGroupVersion.WithResource(cilium_api_v2alpha1.BGPVrouterPluralName), "", "router-b")
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer = time.NewTimer(time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Expected 1 upserted object")
	}

	if len(deleted) != 1 {
		t.Fatal("Expected 1 deleted object")
	}

	// Update first object once
	err = tracker.Update(
		cilium_api_v2alpha1.SchemeGroupVersion.WithResource(cilium_api_v2alpha1.BGPVrouterPluralName),
		&cilium_api_v2alpha1.CiliumBGPVirtualRouter{
			ObjectMeta: v1.ObjectMeta{
				Name: "router-a",
			},
			Spec: cilium_api_v2alpha1.CiliumBGPVirtualRouterSpec{
				LocalASN: 2,
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Update first object twice
	err = tracker.Update(
		cilium_api_v2alpha1.SchemeGroupVersion.WithResource(cilium_api_v2alpha1.BGPVrouterPluralName),
		&cilium_api_v2alpha1.CiliumBGPVirtualRouter{
			ObjectMeta: v1.ObjectMeta{
				Name: "router-a",
			},
			Spec: cilium_api_v2alpha1.CiliumBGPVirtualRouterSpec{
				LocalASN: 3,
			},
		},
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	// Wait a second for changes to be processed
	time.Sleep(time.Second)

	// Check that we have a signal
	timer = time.NewTimer(time.Second)
	select {
	case <-fixture.signaler.Sig:
		timer.Stop()
	case <-timer.C:
		t.Fatal("No signal sent by diffstore")
	}

	upserted, deleted, err = diffstore.Diff()
	if err != nil {
		t.Fatal(err)
	}

	if len(upserted) != 1 {
		t.Fatal("Expected 1 upserted object")
	}

	if len(deleted) != 0 {
		t.Fatal("Expected 1 deleted object")
	}

	if upserted[0].Spec.LocalASN != 3 {
		t.Fatal("Expected to only see the latest update")
	}

	err = fixture.hive.Stop(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}
