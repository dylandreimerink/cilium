package bgpv2

import (
	"context"
	"testing"

	"github.com/cilium/cilium/pkg/bgpv2/backend"
	"github.com/cilium/cilium/pkg/bgpv2/backend/mock"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_fake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

type SpeakerFixture struct {
	mockManager *mock.Manager
	signaler    *Signaler
	ciliumCS    *cilium_fake.Clientset
	hive        *hive.Hive
}

func newSpeakerFixture() *SpeakerFixture {
	fixture := &SpeakerFixture{}

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

		cell.Provide(func(lc hive.Lifecycle, c k8sClient.Clientset) resource.Resource[*cilium_api_v2.CiliumNode] {
			return resource.New[*cilium_api_v2.CiliumNode](
				lc, utils.ListerWatcherFromTyped[*cilium_api_v2.CiliumNodeList](
					c.CiliumV2().CiliumNodes(),
				),
			)
		}),

		// Provide the mocked client cells directly
		cell.Provide(func() k8sClient.Clientset {
			return &k8sClient.FakeClientset{
				CiliumFakeClientset: fixture.ciliumCS,
			}
		}),

		cell.Provide(func() BGPControlPlaneConfig {
			return BGPControlPlaneConfig{
				Enabled: true,
			}
		}),

		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{
				IPAM: ipamOption.IPAMClusterPoolV2,
			}
		}),

		cell.Provide(newNodeListener),

		cell.Provide(newSignaler),

		mock.Cell,

		cell.Invoke(func(
			signaler *Signaler,
			manager backend.BGPSpeakerManager,
		) {
			fixture.signaler = signaler
			fixture.mockManager = manager.(*mock.Manager)
		}),

		cell.Provide(newDiffStoreFactory[*cilium_api_v2alpha1.CiliumBGPVirtualRouter]),

		cell.Invoke(registerBGPController),

		cell.Provide(newSpeakerReconciler),
	)

	return fixture
}

func TestSpeakerReconciliation(t *testing.T) {
	fixture := newSpeakerFixture()

	err := fixture.hive.Start(context.Background())
	if err != nil {
		t.Fatal(t)
	}

	err = fixture.hive.Stop(context.Background())
	if err != nil {
		t.Fatal(t)
	}
}
