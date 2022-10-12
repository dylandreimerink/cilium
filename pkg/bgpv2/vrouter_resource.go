package bgpv2

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/stream"
	"golang.org/x/exp/maps"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

// VRouterResource is a compatibility construct which converts the deprecated peering policy and the newer vRouter
// resources into a stream of just vRouter resources. This allows us to implement code as if we no longer have the
// policies which makes it easier to remove that code in the next cilium version while still allowing for backwards
// compatibility for now.
type VRouterResource struct {
	policyResource  resource.Resource[*cilium_v2alpha1.CiliumBGPPeeringPolicy]
	vRouterResource resource.Resource[*cilium_v2alpha1.CiliumBGPVirtualRouter]

	vRouterStore *vRouterStore

	policyMu  lock.Mutex
	policyMap map[resource.Key]*cilium_v2alpha1.CiliumBGPPeeringPolicy

	observersMu    lock.Mutex
	observers      map[uint64]chan resource.Event[*cilium_v2alpha1.CiliumBGPVirtualRouter]
	observerTicket uint64

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// We implement the resource interface so we are essentially a drop in replacement.
var _ resource.Resource[*cilium_v2alpha1.CiliumBGPVirtualRouter] = (*VRouterResource)(nil)

func NewVRouterResource(
	lc hive.Lifecycle,
	policyResource resource.Resource[*cilium_v2alpha1.CiliumBGPPeeringPolicy],
	vRouterResource resource.Resource[*cilium_v2alpha1.CiliumBGPVirtualRouter],
) *VRouterResource {
	vrr := &VRouterResource{
		policyResource:  policyResource,
		vRouterResource: vRouterResource,

		policyMap: make(map[resource.Key]*cilium_v2alpha1.CiliumBGPPeeringPolicy),

		vRouterStore: &vRouterStore{
			m: make(map[resource.Key]*cilium_v2alpha1.CiliumBGPVirtualRouter),
		},

		observers: make(map[uint64]chan resource.Event[*cilium_v2alpha1.CiliumBGPVirtualRouter]),
	}

	lc.Append(vrr)

	return vrr
}

func (vrr *VRouterResource) Start(_ hive.HookContext) error {
	vrr.ctx, vrr.cancel = context.WithCancel(context.Background())
	vrr.done = make(chan struct{})
	go vrr.run()
	return nil
}

func (vrr *VRouterResource) Stop(ctx hive.HookContext) error {
	vrr.cancel()

	select {
	case <-ctx.Done():
	case <-vrr.done:
	}

	return nil
}

func (vrr *VRouterResource) run() {
	defer func() { close(vrr.done) }()

	errChan := make(chan error, 2)
	policyChan := stream.ToChannel[resource.Event[*cilium_v2alpha1.CiliumBGPPeeringPolicy]](vrr.ctx, errChan, vrr.policyResource)
	vrouterChan := stream.ToChannel[resource.Event[*cilium_v2alpha1.CiliumBGPVirtualRouter]](vrr.ctx, errChan, vrr.vRouterResource)

	policyInSync := false
	vrouterInSync := false

	for policyChan != nil || vrouterChan != nil {
		select {
		case policyEvent, ok := <-policyChan:
			if !ok {
				policyChan = nil
				continue
			}

			policyEvent.Handle(
				func() error {
					policyInSync = true
					if policyInSync && vrouterInSync {
						vrr.emitEvent(SyncEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter]{})
					}

					return nil
				},
				vrr.handlePolicyUpdate,
				func(k resource.Key, cbp *cilium_v2alpha1.CiliumBGPPeeringPolicy) error {
					for _, routerSpec := range cbp.Spec.VirtualRouters {
						key := resource.Key{Name: fmt.Sprintf("%s-%d", cbp.Name, routerSpec.LocalASN)}
						vRouter, _, _ := vrr.vRouterStore.GetByKey(key)
						vrr.vRouterStore.delete(key)
						vrr.emitEvent(DeleteEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter]{Key: key, Obj: vRouter})
					}

					delete(vrr.policyMap, k)

					return nil
				})

		case vrouterEvent, ok := <-vrouterChan:
			if !ok {
				vrouterChan = nil
				continue
			}

			vrouterEvent.Handle(
				func() error {
					vrouterInSync = true
					if policyInSync && vrouterInSync {
						vrr.emitEvent(SyncEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter]{})
					}

					return nil
				},
				func(k resource.Key, cbr *cilium_v2alpha1.CiliumBGPVirtualRouter) error {
					vrr.vRouterStore.upsert(cbr)
					vrr.emitEvent(UpdateEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter]{
						Key: k,
						Obj: cbr,
					})
					return nil
				},
				func(k resource.Key, cbr *cilium_v2alpha1.CiliumBGPVirtualRouter) error {
					vrr.vRouterStore.delete(k)
					vrr.emitEvent(DeleteEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter]{
						Key: k,
						Obj: cbr,
					})
					return nil
				},
			)
		}
	}
}

func (vrr *VRouterResource) handlePolicyUpdate(k resource.Key, cbp *cilium_v2alpha1.CiliumBGPPeeringPolicy) error {
	vrr.policyMu.Lock()
	defer vrr.policyMu.Unlock()

	var lastVrouterSpecs []cilium_v2alpha1.CiliumBGPVirtualRouterSpec
	last := vrr.policyMap[k]

	if last != nil {
		lastVrouterSpecs = last.Spec.VirtualRouters

		newRouters := make(map[int]bool, len(cbp.Spec.VirtualRouters))
		for _, vrouter := range cbp.Spec.VirtualRouters {
			newRouters[vrouter.LocalASN] = true
		}

		// Delete events
		for _, vRouterSpec := range lastVrouterSpecs {
			if newRouters[vRouterSpec.LocalASN] {
				continue
			}

			key := resource.Key{Name: fmt.Sprintf("%s-%d", last.Name, vRouterSpec.LocalASN)}
			vRouter, _, _ := vrr.vRouterStore.GetByKey(key)
			vrr.vRouterStore.delete(key)
			vrr.emitEvent(DeleteEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter]{
				Key: key,
				Obj: vRouter,
			})
		}
	}

	// Update events
	for _, vRouterSpec := range cbp.Spec.VirtualRouters {
		vRouter := &cilium_v2alpha1.CiliumBGPVirtualRouter{
			ObjectMeta: v1.ObjectMeta{
				Name:              fmt.Sprintf("%s-%d", cbp.Name, vRouterSpec.LocalASN),
				Labels:            cbp.Labels,
				Annotations:       cbp.Annotations,
				CreationTimestamp: cbp.CreationTimestamp,
				DeletionTimestamp: cbp.DeletionTimestamp,
			},
			Spec: vRouterSpec,
		}
		vrr.vRouterStore.upsert(vRouter)
		vrr.emitEvent(UpdateEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter]{
			Key: resource.NewKey(vRouter),
			Obj: vRouter,
		})
	}

	vrr.policyMap[k] = cbp

	return nil
}

func (vrr *VRouterResource) emitEvent(event resource.Event[*cilium_v2alpha1.CiliumBGPVirtualRouter]) {
	vrr.observersMu.Lock()
	defer vrr.observersMu.Unlock()

	const bailoutAfter = 5 * time.Second
	bailoutTimer := time.NewTimer(bailoutAfter)

	// Write event to all subscribed observers
	for ticket, observer := range vrr.observers {
		// Reset or recreate timer.
		if !bailoutTimer.Reset(bailoutAfter) {
			bailoutTimer = time.NewTimer(bailoutAfter)
		}

		select {
		case observer <- event:
		case <-bailoutTimer.C:
			// If the observer blocks for more than 5 seconds, kick it.
			close(observer)
			delete(vrr.observers, ticket)
		}
	}
}

func (vrr *VRouterResource) Store(context.Context) (resource.Store[*cilium_v2alpha1.CiliumBGPVirtualRouter], error) {
	return vrr.vRouterStore, nil
}

func (vrr *VRouterResource) Observe(ctx context.Context, next func(resource.Event[*cilium_v2alpha1.CiliumBGPVirtualRouter]), complete func(error)) {
	// Get a guaranteed unique number
	ticket := atomic.AddUint64(&vrr.observerTicket, 1) - 1

	const bufSize = 5
	observeChan := make(chan resource.Event[*cilium_v2alpha1.CiliumBGPVirtualRouter], bufSize)

	vrr.observersMu.Lock()
	vrr.observers[ticket] = observeChan
	vrr.observersMu.Unlock()

	go func() {
	loop:
		for {
			select {
			case event := <-observeChan:
				next(event)
			case <-ctx.Done():
				break loop
			}
		}

		vrr.observersMu.Lock()
		delete(vrr.observers, ticket)
		vrr.observersMu.Unlock()

		close(observeChan)

		complete(nil)
	}()
}

type vRouterStore struct {
	mu lock.RWMutex
	m  map[resource.Key]*cilium_v2alpha1.CiliumBGPVirtualRouter
}

func (vrs *vRouterStore) upsert(item *cilium_v2alpha1.CiliumBGPVirtualRouter) {
	vrs.mu.Lock()
	defer vrs.mu.Unlock()

	vrs.m[resource.NewKey(item)] = item
}

func (vrs *vRouterStore) delete(key resource.Key) {
	vrs.mu.Lock()
	defer vrs.mu.Unlock()

	delete(vrs.m, key)
}

// List returns all items currently in the store.
func (vrs *vRouterStore) List() []*cilium_v2alpha1.CiliumBGPVirtualRouter {
	vrs.mu.RLock()
	defer vrs.mu.RUnlock()

	return maps.Values(vrs.m)
}

// IterKeys returns a key iterator.
func (vrs *vRouterStore) IterKeys() resource.KeyIter {
	vrs.mu.RLock()
	defer vrs.mu.RUnlock()

	return &keyIter{list: maps.Keys(vrs.m)}
}

// Get returns the latest version by deriving the key from the given object.
func (vrs *vRouterStore) Get(
	obj *cilium_v2alpha1.CiliumBGPVirtualRouter,
) (
	item *cilium_v2alpha1.CiliumBGPVirtualRouter,
	exists bool,
	err error,
) {
	key := resource.Key{Namespace: obj.Namespace, Name: obj.Name}
	return vrs.GetByKey(key)
}

// GetByKey returns the latest version of the object with given key.
func (vrs *vRouterStore) GetByKey(key resource.Key) (item *cilium_v2alpha1.CiliumBGPVirtualRouter, exists bool, err error) {
	vrs.mu.RLock()
	defer vrs.mu.RUnlock()

	item, exists = vrs.m[key]
	return item, exists, nil
}

type keyIter struct {
	list []resource.Key
}

func (ki *keyIter) Next() bool {
	return len(ki.list) > 0
}

func (ki *keyIter) Key() resource.Key {
	defer func() { ki.list = ki.list[1:] }()
	return ki.list[0]
}

var _ resource.Event[*cilium_v2alpha1.CiliumBGPVirtualRouter] = (*SyncEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter])(nil)

type baseEvent struct{}

func (be baseEvent) Done(err error) {}

type SyncEvent[T k8sRuntime.Object] struct {
	baseEvent
}

func (se SyncEvent[T]) Handle(
	onSync func() error,
	onUpdate func(resource.Key, T) error,
	onDelete func(resource.Key, T) error,
) {
	onSync()
}

var _ resource.Event[*cilium_v2alpha1.CiliumBGPVirtualRouter] = (*UpdateEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter])(nil)

type UpdateEvent[T k8sRuntime.Object] struct {
	baseEvent
	Key resource.Key
	Obj T
}

func (ue UpdateEvent[T]) Handle(
	onSync func() error,
	onUpdate func(resource.Key, T) error,
	onDelete func(resource.Key, T) error,
) {
	onUpdate(ue.Key, ue.Obj)
}

var _ resource.Event[*cilium_v2alpha1.CiliumBGPVirtualRouter] = (*DeleteEvent[*cilium_v2alpha1.CiliumBGPVirtualRouter])(nil)

type DeleteEvent[T k8sRuntime.Object] struct {
	baseEvent
	Key resource.Key
	Obj T
}

func (de DeleteEvent[T]) Handle(
	onSync func() error,
	onUpdate func(resource.Key, T) error,
	onDelete func(resource.Key, T) error,
) {
	onDelete(de.Key, de.Obj)
}
