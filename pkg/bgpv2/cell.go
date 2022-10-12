package bgpv2

import (
	"github.com/cilium/cilium/pkg/bgpv2/backend/gobgp"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_typed_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/option"
)

//                                  +--------------+          +------------+
//                                  |Resource[Node]|--+------>|NodeListener|------------------------------------------------------+
//                                  +--------------+  |       +------------+                                                      |
//                                                    |                                                                          \|/
//                            +--------------------+  |                       +-----------------+                           +----------+
//                            |Resource[CiliumNode]|--+   +----------------+->|ReconcileSignaler|-------------------------->|Controller|
//                            +--------------------+      |                |  +-----------------+                           +----------+                                +-------------+
//   +-----------------+                                  |                |                                                     |                                    /-| GoBGPBackend|
//   |Resource[vRouter]--\                                |                |                    +-----------------+              |               +-----------------+ /  +-------------+
//   +-----------------+  \  +---------------+    +------------------+     |                    |                 |------------------------+---->|BGPSpeakerManager|-
//                         - |vRouterResource|--->|DiffStore[vRouter]|---------------+--------->|SpeakerReconciler|<-------------+         |     +-----------------+ \  +-------------+
// +-------------------+  /  +---------------+    +------------------+     |         |          +-----------------+              |         |                          \-| MockBackend |
// |Resource[BGPPolicy]|-/                                                 |         |          +-----------------+              |         |                            +-------------+
// +-------------------+                                    ---------------+         |          |                 |------------------------+
//                                                         /                         |          |PodCIDRReconciler|<-------------+         |
//                                                        /                          |          +-----------------+              |         |
//                                                       /                           |          +-----------------+              |         |
//                        +------------------+    +------------------+               |          |                 |------------------------+
//                        | Resource[Service]|--->|DiffStore[Service]|------------------------->|ServiceReconciler|<-------------+         |
//                        +------------------+    +------------------+               |          +-----------------+              |         |
//                                                                                   |      +-------------------------+          |         |
//                                                                                   |      |                         |--------------------+
//                                                                                   +----->|AdditionalRouteReconciler|<---------+
//                                                                                          +-------------------------+

// Cell ties together all of the different components in the package via dependency injection
var Cell = cell.Module(
	"BGP-Control-Plane",

	// Node listener watches for changes to the current node's settings.
	cell.ProvidePrivate(newNodeListener),

	// Signaler receives a signal every time a DiffStore has pending changes so the controller knows when to
	// trigger reconciliation.
	cell.ProvidePrivate(newSignaler),

	// Service resource provides a stream of events for service objects.
	cell.ProvidePrivate(func(lc hive.Lifecycle, c client.Clientset) (resource.Resource[*slim_core_v1.Service], error) {
		optsModifier, err := utils.GetServiceListOptionsModifier(option.Config)
		if err != nil {
			return nil, err
		}

		var listerWatcher slim_typed_v1.ServiceInterface
		if c.IsEnabled() {
			listerWatcher = c.Slim().CoreV1().Services("")
		}

		return resource.New[*slim_core_v1.Service](
			lc,
			utils.ListerWatcherWithModifier(
				utils.ListerWatcherFromTyped[*slim_core_v1.ServiceList](listerWatcher),
				optsModifier),
			resource.WithErrorHandler(resource.AlwaysRetry),
		), nil
	}),
	// BGPPeeringPolicy resource provides a stream of events for the deprecated BGPPeeringPolicy objects.
	cell.ProvidePrivate(func(lc hive.Lifecycle, c client.Clientset) resource.Resource[*cilium_v2alpha1.CiliumBGPPeeringPolicy] {
		var listerWatcher v2alpha1.CiliumBGPPeeringPolicyInterface
		if c.IsEnabled() {
			listerWatcher = c.CiliumV2alpha1().CiliumBGPPeeringPolicies()
		}

		return resource.New[*cilium_v2alpha1.CiliumBGPPeeringPolicy](
			lc, utils.ListerWatcherFromTyped[*cilium_v2alpha1.CiliumBGPPeeringPolicyList](
				listerWatcher,
			))
	}),
	// BGPVirtualRoute resource provides a stream of events for the new virtual route resources.
	cell.ProvidePrivate(func(lc hive.Lifecycle, c client.Clientset) resource.Resource[*cilium_v2alpha1.CiliumBGPVirtualRouter] {
		var listerWatcher v2alpha1.CiliumBGPVirtualRouterInterface
		if c.IsEnabled() {
			listerWatcher = c.CiliumV2alpha1().CiliumBGPVirtualRouters()
		}

		return resource.New[*cilium_v2alpha1.CiliumBGPVirtualRouter](
			lc, utils.ListerWatcherFromTyped[*cilium_v2alpha1.CiliumBGPVirtualRouterList](
				listerWatcher,
			))
	}),
	// CiliumNode resource provides a stream of events for the cilium node objects.
	cell.ProvidePrivate(func(lc hive.Lifecycle, c client.Clientset) resource.Resource[*cilium_v2.CiliumNode] {
		var listerWatcher v2.CiliumNodeInterface
		if c.IsEnabled() {
			listerWatcher = c.CiliumV2().CiliumNodes()
		}

		return resource.New[*cilium_v2.CiliumNode](
			lc, utils.ListerWatcherFromTyped[*cilium_v2.CiliumNodeList](
				listerWatcher,
			))
	}),
	// TODO k8s node resource

	// Change the vRouter resource with a compatibility layer that translates deprecated policies into
	// the new vRouters, so both can exist at the same time.
	cell.Decorate(func(
		lc hive.Lifecycle,
		vRouterResource resource.Resource[*cilium_v2alpha1.CiliumBGPVirtualRouter],
		policyResource resource.Resource[*cilium_v2alpha1.CiliumBGPPeeringPolicy],
	) resource.Resource[*cilium_v2alpha1.CiliumBGPVirtualRouter] {
		return NewVRouterResource(lc, policyResource, vRouterResource)
	},
		cell.Provide(newDiffStoreFactory[*cilium_v2alpha1.CiliumBGPVirtualRouter]),
	),

	cell.ProvidePrivate(newDiffStoreFactory[*slim_core_v1.Service]),

	// All of our reconcilers
	cell.ProvidePrivate(newSpeakerReconciler),
	cell.ProvidePrivate(newPodCidrReconciler),
	cell.ProvidePrivate(newLBSvcReconciler),

	// The GoBGP speaker backend
	gobgp.Cell,

	// The controller, linchpin of the module
	cell.Config(BGPControlPlaneConfig{}),
	cell.Invoke(registerBGPController),
)
