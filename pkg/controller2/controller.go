// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package controller

import (
	"context"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

type ControllerFunc func(ctx context.Context) error

type ErrorAction int

const (
	ErrorActionNone ErrorAction = iota
	ErrorActionRetry
	ErrorActionShutdown
)

type ErrorHandler func(err error) ErrorAction

type controller struct {
	name       string
	doFunc     ControllerFunc
	shutdowner hive.Shutdowner
	logger     logrus.FieldLogger

	doneFunc func(ctx context.Context, err error)
	stopFunc func()

	trigger chan struct{}
}

func newController(
	name string,
	doFunc ControllerFunc,
	shutdowner hive.Shutdowner,
	logger logrus.FieldLogger,
) *controller {
	return &controller{
		name:       name,
		doFunc:     doFunc,
		shutdowner: shutdowner,
		logger:     logger.WithField("name", name),
		doneFunc:   func(ctx context.Context, err error) {},
		stopFunc:   func() {},
		trigger:    make(chan struct{}, 1),
	}
}

func (c *controller) run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case c.trigger <- struct{}{}:
	default:
	}

	for {
		select {
		case <-ctx.Done():
			c.stopFunc()
			return

		case <-c.trigger:
			var err error

			pprof.Do(ctx, pprof.Labels(
				"controller-name", c.name,
			), func(ctx context.Context) {
				err = c.doFunc(ctx)
			})

			c.doneFunc(ctx, err)
		}
	}
}

type Opt func(c *controller)

func WithStopFunc(fn func()) Opt {
	return func(c *controller) {
		c.stopFunc = fn
	}
}

func WithInterval(interval time.Duration) Opt {
	return func(c *controller) {
		ticker := time.NewTicker(interval)
		stop := make(chan struct{})

		go func() {
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					select {
					case c.trigger <- struct{}{}:
					default:
					}
				}
			}
		}()

		next := c.stopFunc
		c.stopFunc = func() {
			// ensure we call the next link the the cain of responsibility
			defer next()

			ticker.Stop()
			close(stop)
		}
	}
}

func WithRetry(handler ErrorHandler, cadence workqueue.RateLimiter) Opt {
	return func(c *controller) {
		next := c.doneFunc
		c.doneFunc = func(ctx context.Context, err error) {
			// ensure we call the next link the the cain of responsibility
			defer next(ctx, err)

			if err == nil {
				cadence.Forget(c)
				return
			}

			switch handler(err) {
			case ErrorActionNone:
				return
			case ErrorActionRetry:
				timer := time.After(cadence.When(c))
				go func() {
					<-timer

					select {
					case c.trigger <- struct{}{}:
					default:
					}
				}()
			case ErrorActionShutdown:
				c.shutdowner.Shutdown(hive.ShutdownWithError(err))
			}
		}
	}
}
