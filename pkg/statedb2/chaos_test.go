// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb2_test

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/statedb2"
	"github.com/cilium/cilium/pkg/statedb2/index"
	"golang.org/x/exp/slices"
)

type chaosBase struct {
	id  uint64
	mod uint64
}

func (c chaosBase) ID() uint64 {
	return c.id
}

type chaosIface interface {
	ID() uint64
}

func mkID() uint64 {
	return rand.Uint64() % 100
}

func mkIDIndex[Obj chaosIface]() statedb2.Index[Obj, uint64] {
	return statedb2.Index[Obj, uint64]{
		Name: "id",
		FromObject: func(obj Obj) index.KeySet {
			return index.NewKeySet(index.Uint64(obj.ID()))
		},
		FromKey: func(n uint64) []byte {
			return index.Uint64(n)
		},
		Unique: true,
	}
}

type (
	chaos1 struct{ chaosBase }
	chaos2 struct{ chaosBase }
	chaos3 struct{ chaosBase }
	chaos4 struct{ chaosBase }
	chaos5 struct{ chaosBase }
)

var (
	tableChaos1, _ = statedb2.NewTable[chaos1]("chaos1", mkIDIndex[chaos1]())
	tableChaos2, _ = statedb2.NewTable[chaos2]("chaos2", mkIDIndex[chaos2]())
	tableChaos3, _ = statedb2.NewTable[chaos3]("chaos3", mkIDIndex[chaos3]())
	tableChaos4, _ = statedb2.NewTable[chaos4]("chaos4", mkIDIndex[chaos4]())
	tableChaos5, _ = statedb2.NewTable[chaos5]("chaos5", mkIDIndex[chaos5]())
	chaosTables    = []statedb2.TableMeta{tableChaos1, tableChaos2, tableChaos3, tableChaos4, tableChaos5}
	chaosDB, _     = statedb2.NewDB(chaosTables)
)

func randomSubset[T any](xs []T) []T {
	xs = slices.Clone(xs)
	rand.Shuffle(len(xs), func(i, j int) {
		xs[i], xs[j] = xs[j], xs[i]
	})
	n := 1 + rand.Intn(len(xs)-1)
	return xs[:n]
}

type action func(log *log.Logger, txn statedb2.WriteTxn, target statedb2.TableMeta)

func insertAction(log *log.Logger, txn statedb2.WriteTxn, table statedb2.TableMeta) {
	id := mkID()
	mod := rand.Uint64()
	log.Printf("%s: Insert %d\n", table.Name(), id)
	switch t := table.(type) {
	case statedb2.Table[chaos1]:
		t.Insert(txn, chaos1{chaosBase{id, mod}})
	case statedb2.Table[chaos2]:
		t.Insert(txn, chaos2{chaosBase{id, mod}})
	case statedb2.Table[chaos3]:
		t.Insert(txn, chaos3{chaosBase{id, mod}})
	case statedb2.Table[chaos4]:
		t.Insert(txn, chaos4{chaosBase{id, mod}})
	case statedb2.Table[chaos5]:
		t.Insert(txn, chaos5{chaosBase{id, mod}})
	}
}

func deleteAction(log *log.Logger, txn statedb2.WriteTxn, table statedb2.TableMeta) {
	id := mkID()
	log.Printf("%s: Delete %d\n", table.Name(), id)
	switch t := table.(type) {
	case statedb2.Table[chaos1]:
		t.Delete(txn, chaos1{chaosBase{id, 0}})
	case statedb2.Table[chaos2]:
		t.Delete(txn, chaos2{chaosBase{id, 0}})
	case statedb2.Table[chaos3]:
		t.Delete(txn, chaos3{chaosBase{id, 0}})
	case statedb2.Table[chaos4]:
		t.Delete(txn, chaos4{chaosBase{id, 0}})
	case statedb2.Table[chaos5]:
		t.Delete(txn, chaos5{chaosBase{id, 0}})
	}
}

func deleteAllAction(log *log.Logger, txn statedb2.WriteTxn, table statedb2.TableMeta) {
	log.Printf("%s: DeleteAll\n", table.Name())
	switch t := table.(type) {
	case statedb2.Table[chaos1]:
		t.DeleteAll(txn)
	case statedb2.Table[chaos2]:
		t.DeleteAll(txn)
	case statedb2.Table[chaos3]:
		t.DeleteAll(txn)
	case statedb2.Table[chaos4]:
		t.DeleteAll(txn)
	case statedb2.Table[chaos5]:
		t.DeleteAll(txn)
	}
}

var actions = []action{
	insertAction,
	insertAction,
	insertAction,
	insertAction,
	insertAction,
	deleteAction,
	deleteAction,
	deleteAction,
	deleteAllAction,
}

func randomAction() action {
	return actions[rand.Intn(len(actions))]
}

func tableNames(tables []statedb2.TableMeta) []string {
	names := make([]string, len(tables))
	for i := range tables {
		names[i] = tables[i].Name()
	}
	return names
}

func chaosMonkey(monkey int, iterations int) {
	log := log.New(os.Stdout, fmt.Sprintf("monkey[%03d] | ", monkey), 0)
	for iterations > 0 {
		targets := randomSubset(chaosTables)
		log.Printf("==> %v", tableNames(targets))
		txn := chaosDB.WriteTxn(targets[0], targets[1:]...)
		time.Sleep(time.Nanosecond)
		for _, target := range targets {
			act := randomAction()
			act(log, txn, target)
			time.Sleep(time.Nanosecond)
		}
		time.Sleep(time.Nanosecond)
		log.Printf("<== %v", tableNames(targets))
		if rand.Intn(10) == 0 {
			txn.Abort()
		} else {
			txn.Commit()
		}
		iterations--
	}
}

func TestDB_Chaos(t *testing.T) {
	chaosDB.Start(context.TODO())
	defer chaosDB.Stop(context.TODO())

	var wg sync.WaitGroup
	numMonkeys := 10
	numIterations := 1000
	wg.Add(numMonkeys)
	for i := 0; i < numMonkeys; i++ {
		i := i
		go func() {
			chaosMonkey(i, numIterations)
			wg.Done()
		}()
	}
	wg.Wait()
}
