package main

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb2"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
)

var reconcilerWorkqueueCell = cell.Module(
	"reconciler-workqueue",
	"Backend reconciler",
	cell.Invoke(registerWorkQueueReconciler),
)

type workQueueReconcilerParams struct {
	cell.In

	Backends  statedb2.Table[Backend]
	DB        *statedb2.DB
	Lifecycle hive.Lifecycle
	Log       logrus.FieldLogger
	Registry  job.Registry
	Reporter  cell.HealthReporter
}

func registerWorkQueueReconciler(p reconcilerParams) {
	g := p.Registry.NewGroup()
	r := &workQueueReconciler{
		reconcilerParams: p,
		handle:           &backendsHandle{backends: sets.New[BackendID]()},
	}
	g.Add(job.OneShot("workqueue-reconciler-loop", r.reconcileLoop))
	p.Lifecycle.Append(g)
}

type workQueueReconciler struct {
	reconcilerParams

	handle *backendsHandle
}

func (r *workQueueReconciler) reconcileLoop(ctx context.Context) error {
	defer r.Reporter.Stopped("Stopped")

	wtxn := r.DB.WriteTxn(r.Backends)
	events, err := r.Backends.WorkQueue(wtxn, ctx)
	wtxn.Commit()
	if err != nil {
		return err
	}

	// TODO: WorkQueue should expose health in some way, e.g.
	// number of events being retried.

	for ev := range events {
		be := ev.Object

		switch ev.Kind {
		case statedb2.Delete:
			err := r.handle.Delete(ev.Object)
			if err != nil {
				r.Log.WithError(err).WithField("revision", ev.Revision).WithField("id", be.ID).Warn("Failed to delete backend")
			} else {
				r.validate()
				r.Log.WithField("revision", ev.Revision).WithField("id", be.ID).Info("Deleted")
			}
			ev.Done(err)
		case statedb2.Upsert:
			err := r.handle.Insert(ev.Object)
			if err != nil {
				r.Log.WithError(err).WithField("revision", ev.Revision).WithField("id", be.ID).Warn("Failed to insert backend")
			} else {
				r.Log.WithField("revision", ev.Revision).WithField("id", be.ID).Info("Inserted")
				r.validate()
			}

			ev.Done(err)
		}
	}
	return nil
}

func (r *workQueueReconciler) validate() {
	txn := r.DB.ReadTxn()
	iter, _ := r.Backends.All(txn)
	n := 0
	objs := []Backend{}
	for obj, _, ok := iter.Next(); ok; obj, _, ok = iter.Next() {
		n++
		objs = append(objs, obj)
	}
	if n != r.handle.backends.Len() {
		panic(fmt.Sprintf("validate failed, expected %+v, seeing %+v", objs, r.handle.backends))
	}
}
