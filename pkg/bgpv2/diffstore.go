// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/stream"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
)

// DiffStoreFactory creates diffStores. All stores from the same factory share the same underlying store, but each
// diff store tracks the diff since the last time it was checked.
type DiffStoreFactory[T k8sRuntime.Object] interface {
	NewStore() DiffStore[T]
}

var _ DiffStoreFactory[*k8sRuntime.Unknown] = (*diffStoreFactory[*k8sRuntime.Unknown])(nil)

type diffStoreParams[T k8sRuntime.Object] struct {
	cell.In

	LS         hive.Lifecycle
	Shutdowner hive.Shutdowner
	Resource   resource.Resource[T]
	Signaler   *Signaler `optional:"true"`
}

type diffStoreFactory[T k8sRuntime.Object] struct {
	diffStoreParams[T]

	store resource.Store[T]

	ctx      context.Context
	cancel   context.CancelFunc
	doneChan chan struct{}

	initialSync bool

	stores []*diffStore[T]
}

func newDiffStoreFactory[T k8sRuntime.Object](params diffStoreParams[T]) DiffStoreFactory[T] {
	ds := &diffStoreFactory[T]{
		diffStoreParams: params,
	}

	params.LS.Append(ds)

	return ds
}

func (sd *diffStoreFactory[T]) NewStore() DiffStore[T] {
	store := &diffStore[T]{
		updatedKeys: make(map[resource.Key]bool),
	}
	sd.stores = append(sd.stores, store)
	return store
}

func (sd *diffStoreFactory[T]) Start(_ hive.HookContext) error {
	sd.ctx, sd.cancel = context.WithCancel(context.Background())
	sd.doneChan = make(chan struct{})
	go sd.run()
	return nil
}

func (sd *diffStoreFactory[T]) Stop(stopCtx hive.HookContext) error {
	sd.cancel()

	select {
	case <-sd.doneChan:
	case <-stopCtx.Done():
	}

	return nil
}

func (sd *diffStoreFactory[T]) run() {
	defer close(sd.doneChan)

	var err error
	sd.store, err = sd.Resource.Store(sd.ctx)
	if err != nil {
		sd.Shutdowner.Shutdown(hive.ShutdownWithError(err))
		return
	}

	for _, store := range sd.stores {
		store.store = sd.store
	}

	errChan := make(chan error, 2)
	updateChan := stream.ToChannel[resource.Event[T]](sd.ctx, errChan, sd.Resource)

	for {
		select {
		case event, ok := <-updateChan:
			if !ok {
				break
			}

			sd.handleEvent(event)
		case err := <-errChan:
			sd.Shutdowner.Shutdown(hive.ShutdownWithError(err))
			return
		}
	}
}

func (sd *diffStoreFactory[T]) handleEvent(event resource.Event[T]) {
	update := func(k resource.Key, t T) error {
		for _, store := range sd.stores {
			store.mu.Lock()
			store.updatedKeys[k] = true
			store.mu.Unlock()
		}

		if sd.initialSync && sd.Signaler != nil {
			sd.Signaler.Event(struct{}{})
		}
		return nil
	}

	event.Handle(
		func() error {
			sd.initialSync = true
			if sd.Signaler != nil {
				sd.Signaler.Event(struct{}{})
			}
			return nil
		},
		update,
		update,
	)
}

// DiffStore is a super set of the resource.Store. The diffStore tracks all changes made to the diff store since the
// last time the user synced up. This allows a user to get a list of just the changed objects while still being able
// to query the full store for a full sync.
type DiffStore[T k8sRuntime.Object] interface {
	resource.Store[T]

	// Diff returns a list of items that have been upserted(updated or inserted) and deleted since the last call to Diff.
	Diff() (upserted []T, deleted []resource.Key, err error)
}

var _ DiffStore[*k8sRuntime.Unknown] = (*diffStore[*k8sRuntime.Unknown])(nil)

// diffStore takes a resource.Resource[T] and watches for events, it stores all of the keys that have been changed.
// diffStore can still be used as a normal store, but adds the Diff function to get a Diff of all changes.
// The diffStore also takes in Signaler which it will signal after the initial sync and every update thereafter.
type diffStore[T k8sRuntime.Object] struct {
	store resource.Store[T]

	mu          sync.Mutex
	updatedKeys map[resource.Key]bool
}

// Diff returns a list of items that have been upserted(updated or inserted) and deleted since the last call to Diff.
func (sd *diffStore[T]) Diff() (upserted []T, deleted []resource.Key, err error) {
	sd.mu.Lock()
	defer sd.mu.Unlock()

	for k := range sd.updatedKeys {
		item, found, err := sd.store.GetByKey(k)
		if err != nil {
			return nil, nil, err
		}

		if found {
			upserted = append(upserted, item)
		} else {
			deleted = append(deleted, k)
		}
	}

	sd.updatedKeys = make(map[resource.Key]bool, 0)

	return upserted, deleted, err
}

// List returns all items currently in the store.
func (sd *diffStore[T]) List() []T {
	return sd.store.List()
}

// IterKeys returns a key iterator.
func (sd *diffStore[T]) IterKeys() resource.KeyIter {
	return sd.store.IterKeys()
}

// Get returns the latest version by deriving the key from the given object.
func (sd *diffStore[T]) Get(obj T) (item T, exists bool, err error) {
	return sd.store.Get(obj)
}

// GetByKey returns the latest version of the object with given key.
func (sd *diffStore[T]) GetByKey(key resource.Key) (item T, exists bool, err error) {
	return sd.store.GetByKey(key)
}
