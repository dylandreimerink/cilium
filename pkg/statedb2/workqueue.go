// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb2

import (
	"bytes"
	"container/heap"
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/statedb2/index"
	"github.com/cilium/cilium/pkg/stream"
	"golang.org/x/exp/slices"
	"k8s.io/client-go/util/workqueue"
)

type EventKind string

const (
	Sync   EventKind = "sync"
	Upsert EventKind = "upsert"
	Delete EventKind = "delete"
)

type Event[T any] struct {
	Kind     EventKind
	Revision Revision
	Object   T

	// Done marks the event as processed.  If err is non-nil, the
	// key of the object is requeued and the processing retried at
	// a later time with a potentially new version of the object.
	Done func(err error)
}

type WorkQueue[Obj any] interface {
	stream.Observable[Event[Obj]]
}

type wq[Obj any] struct {
	db    *DB
	table *genTable[Obj]
	workqueue.RateLimitingInterface
	dt      *DeleteTracker[Obj]
	indexer anyIndexer
}

func (wq *wq[Obj]) adder(ctx context.Context, minRevision Revision) {
	dt := wq.dt
	defer dt.Close()
	defer wq.ShutDown()
	for {
		txn := wq.db.ReadTxn()

		// Get all new and updated objects with revision number equal or
		// higher than 'minRevision'.
		// The returned watch channel watches the whole table and thus
		// is closed when either insert or delete happens.
		updatedIter, watch := dt.table.LowerBound(txn, ByRevision[Obj](minRevision))

		// Get deleted objects with revision equal or higher than 'minRevision'.
		deletedIter := dt.Deleted(txn.getTxn(), minRevision)

		// Combine the iterators into one. This can be done as insert and delete
		// both assign the object a new fresh monotonically increasing revision
		// number.
		iter := newDualIterator[Obj](deletedIter, updatedIter)

		// Feed in the keys of updated and deleted into the queue in revision
		// order.
		for key, obj, _, ok := iter.Next(); ok; key, obj, _, ok = iter.Next() {
			// key is revision + primary key
			wq.Add(string(key[8:]))
			minRevision = obj.revision
		}
		minRevision += 1

		select {
		case <-watch:
		case <-ctx.Done():
			return
		}
	}
}

func (wq *wq[Obj]) getObject(idKey []byte) (obj object, ok bool) {
	indexTxn := wq.db.ReadTxn().getTxn().indexReadTxn(wq.table.table, wq.table.primaryAnyIndexer.name)
	return indexTxn.Get(idKey)
}

func (wq *wq[Obj]) sender(ctx context.Context, events chan<- Event[Obj]) {
	defer close(events)

	// unprocessedDeletions is a min-heap of the revisions of yet unprocessed deletions.
	// It is used to track the low-watermark for graveyard garbage collection.
	var unprocessedDeletions unprocessedDeletions

	for {
		raw, shutdown := wq.Get()
		if shutdown {
			break
		}
		key := index.Key(raw.(string))

		// First try to find the object from the primary index.
		txn := wq.db.ReadTxn()
		indexTxn := txn.getTxn().indexReadTxn(wq.table.table, wq.table.primaryAnyIndexer.name)
		if obj, ok := indexTxn.Get(key); ok {
			if wasMinimum, minRevision := unprocessedDeletions.RemoveByKey(key); wasMinimum {
				// There was an unprocessed deletion for this key, and it was the lowest revision,
				// mark to let it be garbage collected.
				wq.dt.Mark(txn, minRevision)
			}

			events <- Event[Obj]{
				Kind:     Upsert,
				Revision: obj.revision,
				Object:   obj.data.(Obj),
				Done: func(err error) {
					if err == nil {
						// Clear rate-limiting
						wq.Forget(raw)
					} else {
						wq.AddRateLimited(raw)
					}
					wq.Done(raw)
				},
			}
		} else {
			graveyardTxn := txn.getTxn().indexReadTxn(wq.table.table, GraveyardIndex)
			if obj, ok := graveyardTxn.Get(key); ok {
				// Keep track of the processing of this deletion event in order to
				// update the low watermark once it's processed successfully. We need
				// this as deletion events can be processed and retried out of order
				// in regards to revision number.
				unprocessedDeletions.Insert(key, obj.revision)

				events <- Event[Obj]{
					Kind:     Delete,
					Object:   obj.data.(Obj),
					Revision: obj.revision,
					Done: func(err error) {
						if err != nil {
							wq.AddRateLimited(raw)
						} else {
							// Clear rate-limiting
							wq.Forget(raw)

							// Bump the low watermark.
							if unprocessedDeletions.RemoveByRevision(obj.revision) {
								wq.dt.Mark(txn, obj.revision)
							}
						}
						wq.Done(raw)
					},
				}
			} else {
				// If this happens the graveyard the object has been accidentally
				// garbage collected from the graveyard when it should not have.
				panic(fmt.Sprintf("BUG: WorkQueue contained key for a missing deleted object with key %q", key))
			}
		}
	}

}

func newWorkQueue[Obj any](txn WriteTxn, table *genTable[Obj], ctx context.Context) (<-chan Event[Obj], error) {
	events := make(chan Event[Obj])

	dt, err := table.DeleteTracker(txn, "workqueue")
	if err != nil {
		return nil, err
	}

	wq := &wq[Obj]{
		db:                    txn.getTxn().db,
		RateLimitingInterface: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		dt:                    dt,
		indexer:               table.primaryAnyIndexer,
		table:                 table,
	}

	indexTxn := txn.getTxn().indexReadTxn(table.table, table.primaryAnyIndexer.name)
	if indexTxn == nil {
		panic("BUG: Missing primary index " + table.primaryAnyIndexer.name)
	}
	root := indexTxn.Root()
	iter := root.Iterator()

	// Seed the queue with the keys of all current objects
	for key, _, ok := iter.Next(); ok; key, _, ok = iter.Next() {
		wq.Add(key)
	}

	go wq.adder(ctx, table.Revision(txn))
	go wq.sender(ctx, events)

	return events, nil
}

type revKey struct {
	revision Revision
	key      index.Key
}

type revisionHeap []revKey

func (r revisionHeap) Len() int           { return len(r) }
func (r revisionHeap) Less(i, j int) bool { return r[i].revision < r[j].revision }
func (r revisionHeap) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

func (r *revisionHeap) Push(x any) {
	*r = append(*r, x.(revKey))
}

func (r *revisionHeap) Pop() (rev any) {
	n := len(*r)
	rev = (*r)[n-1]
	*r = (*r)[:n-1]
	return
}

func (r revisionHeap) Min() revKey {
	return r[len(r)-1]
}

func (r *revisionHeap) Remove(key string) {
}

// TODO: this will only perform reasonably well with limited number of unprocessed deletions.
// consider other data structures for better average O().
type unprocessedDeletions struct {
	lock.Mutex // protect concurrent calls from the Done callback
	objects    revisionHeap
}

func (u *unprocessedDeletions) RemoveByKey(key index.Key) (wasMinimum bool, minRevision Revision) {
	u.Lock()
	defer u.Unlock()
	if u.objects.Len() == 0 {
		return false, 0
	}

	minObject := u.objects.Min()
	wasMinimum = bytes.Equal(minObject.key, key)
	minRevision = minObject.revision
	if i := slices.IndexFunc(u.objects, func(other revKey) bool { return bytes.Equal(other.key, key) }); i > 0 {
		heap.Remove(&u.objects, i)
	}
	return
}

func (u *unprocessedDeletions) RemoveByRevision(rev Revision) (wasMinimum bool) {
	u.Lock()
	defer u.Unlock()
	if u.objects.Len() == 0 {
		return false
	}

	wasMinimum = u.objects.Min().revision == rev
	if i := slices.IndexFunc(u.objects, func(other revKey) bool { return other.revision == rev }); i > 0 {
		heap.Remove(&u.objects, i)
	}
	return
}

func (u *unprocessedDeletions) Insert(key index.Key, rev Revision) {
	u.Lock()
	defer u.Unlock()
	heap.Push(&u.objects, revKey{rev, key})
}
