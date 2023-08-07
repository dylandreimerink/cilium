// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb2

import (
	"fmt"

	"github.com/cilium/cilium/pkg/statedb2/index"
)

func Collect[Obj any](iter Iterator[Obj]) []Obj {
	objs := []Obj{}
	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		objs = append(objs, obj)
	}
	return objs
}

// ProcessEach invokes the given function for each object provided by the iterator.
func ProcessEach[Obj any, It Iterator[Obj]](iter It, fn func(Obj, Revision) error) (err error) {
	for obj, rev, ok := iter.Next(); ok; obj, rev, ok = iter.Next() {
		err = fn(obj, rev)
		if err != nil {
			return
		}
	}
	return
}

type objectIterator interface {
	Next() ([]byte, object, bool)
}

// iterator adapts the "any" object iterator to a typed object.
type iterator[Obj any] struct {
	iter objectIterator
}

func (it *iterator[Obj]) next() (key index.Key, obj object, ok bool) {
	return it.iter.Next()
}

func (it *iterator[Obj]) Next() (obj Obj, revision uint64, ok bool) {
	_, iobj, ok := it.iter.Next()
	if ok {
		obj = iobj.data.(Obj)
		revision = iobj.revision
	}
	return
}

func newDualIterator[Obj any](left, right Iterator[Obj]) *dualIterator {
	return &dualIterator{
		left:  iterState{iter: left},
		right: iterState{iter: right},
	}
}

type iterState struct {
	iter interface {
		next() (index.Key, object, bool)
	}
	key index.Key
	obj object
	ok  bool
}

// dualIterator allows iterating over two iterators in revision order.
// Meant to be used for combined iteration of LowerBound(ByRevision)
// and Deleted().
type dualIterator struct {
	left, right iterState
}

func (it *dualIterator) Next() (key index.Key, obj object, fromLeft, ok bool) {
	// Advance the iterators
	if !it.left.ok && it.left.iter != nil {
		it.left.key, it.left.obj, it.left.ok = it.left.iter.next()
		if !it.left.ok {
			it.left.iter = nil
		}
	}
	if !it.right.ok && it.right.iter != nil {
		it.right.key, it.right.obj, it.right.ok = it.right.iter.next()
		if !it.right.ok {
			it.right.iter = nil
		}
	}

	// Find the lowest revision object
	switch {
	case !it.left.ok && !it.right.ok:
		ok = false
		return
	case it.left.ok && !it.right.ok:
		it.left.ok = false
		return it.left.key, it.left.obj, true, true
	case it.right.ok && !it.left.ok:
		it.right.ok = false
		return it.right.key, it.right.obj, false, true
	case it.left.obj.revision <= it.right.obj.revision:
		it.left.ok = false
		return it.left.key, it.left.obj, true, true
	case it.right.obj.revision <= it.left.obj.revision:
		it.right.ok = false
		return it.right.key, it.right.obj, false, true
	default:
		panic(fmt.Sprintf("BUG: Unhandled case: %+v", it))
	}
}
