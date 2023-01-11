// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/go-openapi/runtime/middleware"
	k8sCache "k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/promise"
)

type getIdentity struct {
	d *Daemon
}

func newGetIdentityHandler(d *Daemon) GetIdentityHandler { return &getIdentity{d: d} }

func (h *getIdentity) Handle(params GetIdentityParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /identity request")

	identities := []*models.Identity{}
	if params.Labels == nil {
		// if labels is nil, return all identities from the kvstore
		// This is in response to "identity list" command
		identities = h.d.identityAllocator.GetIdentities()
	} else {
		identity := h.d.identityAllocator.LookupIdentity(params.HTTPRequest.Context(), labels.NewLabelsFromModel(params.Labels))
		if identity == nil {
			return NewGetIdentityIDNotFound()
		}

		identities = append(identities, identitymodel.CreateModel(identity))
	}

	return NewGetIdentityOK().WithPayload(identities)
}

type getIdentityID struct {
	c cache.IdentityAllocator
}

func newGetIdentityIDHandler(c cache.IdentityAllocator) GetIdentityIDHandler {
	return &getIdentityID{c: c}
}

func (h *getIdentityID) Handle(params GetIdentityIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /identity/<ID> request")

	nid, err := identity.ParseNumericIdentity(params.ID)
	if err != nil {
		return NewGetIdentityIDBadRequest()
	}

	identity := h.c.LookupIdentityByID(params.HTTPRequest.Context(), nid)
	if identity == nil {
		return NewGetIdentityIDNotFound()
	}

	return NewGetIdentityIDOK().WithPayload(identitymodel.CreateModel(identity))
}

type getIdentityEndpoints struct{}

func newGetIdentityEndpointsIDHandler(d *Daemon) GetIdentityEndpointsHandler {
	return &getIdentityEndpoints{}
}

func (h *getIdentityEndpoints) Handle(params GetIdentityEndpointsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /identity/endpoints request")

	identities := identitymanager.GetIdentityModels()

	return NewGetIdentityEndpointsOK().WithPayload(identities)
}

type identityAllocatorOwner struct {
	policy        *policy.Repository
	policyUpdater *policy.Updater
}

// UpdateIdentities informs the policy package of all identity changes
// and also triggers policy updates.
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (iao *identityAllocatorOwner) UpdateIdentities(added, deleted cache.IdentityCache) {
	wg := &sync.WaitGroup{}
	iao.policy.GetSelectorCache().UpdateIdentities(added, deleted, wg)
	// Wait for update propagation to endpoints before triggering policy updates
	wg.Wait()
	iao.policyUpdater.TriggerPolicyUpdates(false, "one or more identities created or deleted")
}

// GetNodeSuffix returns the suffix to be appended to kvstore keys of this
// agent
func (iao *identityAllocatorOwner) GetNodeSuffix() string {
	var ip net.IP

	switch {
	case option.Config.EnableIPv4:
		ip = node.GetIPv4()
	case option.Config.EnableIPv6:
		ip = node.GetIPv6()
	}

	if ip == nil {
		log.Fatal("Node IP not available yet")
	}

	return ip.String()
}

func newCacheIdentityAllocatorOwner(lc hive.Lifecycle, policyPromise promise.Promise[*policy.Repository], policyUpdaterPromise promise.Promise[*policy.Updater]) cache.IdentityAllocatorOwner {
	owner := &identityAllocatorOwner{}
	lc.Append(hive.Hook{
		OnStart: func(ctx hive.HookContext) (err error) {
			owner.policy, err = policyPromise.Await(ctx)
			if err != nil {
				return err
			}
			owner.policyUpdater, err = policyUpdaterPromise.Await(ctx)
			if err != nil {
				return err
			}
			return nil
		},
	})
	return owner
}

// CachingIdentityAllocator provides an abstraction over the concrete type in
// pkg/identity/cache so that the underlying implementation can be mocked out
// in unit tests.
type CachingIdentityAllocator interface {
	cache.IdentityAllocator

	InitIdentityAllocator(versioned.Interface, k8sCache.Store) <-chan struct{}
	WatchRemoteIdentities(kvstore.BackendOperations) (*allocator.RemoteCache, error)
	Close()
}

type cachingIdentityAllocator struct {
	*cache.CachingIdentityAllocator
	ipCache *ipcache.IPCache
}

func NewCachingIdentityAllocator(
	owner cache.IdentityAllocatorOwner,
	ipCache *ipcache.IPCache,
	allocResolver promise.Resolver[cache.IdentityAllocator],
) CachingIdentityAllocator {
	alloc := cachingIdentityAllocator{
		CachingIdentityAllocator: cache.NewCachingIdentityAllocator(owner),
		ipCache:                  ipCache,
	}
	allocResolver.Resolve(alloc)
	return alloc
}

func (c cachingIdentityAllocator) AllocateCIDRsForIPs(ips []net.IP, newlyAllocatedIdentities map[netip.Prefix]*identity.Identity) ([]*identity.Identity, error) {
	return c.ipCache.AllocateCIDRsForIPs(ips, newlyAllocatedIdentities)
}

func (c cachingIdentityAllocator) ReleaseCIDRIdentitiesByID(ctx context.Context, identities []identity.NumericIdentity) {
	c.ipCache.ReleaseCIDRIdentitiesByID(ctx, identities)
}
