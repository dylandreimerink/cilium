// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	cidrlabels "github.com/cilium/cilium/pkg/labels/cidr"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

var (
	// ErrLocalIdentityAllocatorUninitialized is an error that's returned when
	// the local identity allocator is uninitialized.
	ErrLocalIdentityAllocatorUninitialized = errors.New("local identity allocator uninitialized")
)

// metadata contains the ipcache metadata. Mainily it holds a map which maps IP
// prefixes (x.x.x.x/32) to a set of information (prefixInfo).
//
// When allocating an identity to associate with each prefix, the
// identity allocation routines will merge this set of labels into the
// complete set of labels used for that local (CIDR) identity,
// thereby associating these labels with each prefix that is 'covered'
// by this prefix. Subsequently these labels may be matched by network
// policy and propagated in monitor output.
//
// ```mermaid
// flowchart
//   subgraph labelsWithSource
//   labels.Labels
//   source.Feature
//   end
//   subgraph prefixInfo
//   UA[UID]-->LA[labelsWithSource]
//   UB[UID]-->LB[labelsWithSource]
//   ...
//   end
//   subgraph identityMetadata
//   IP_Prefix-->prefixInfo
//   end
// ```
type metadata struct {
	// Protects the m map.
	//
	// If this mutex will be held at the same time as the IPCache mutex,
	// this mutex must be taken first and then take the IPCache mutex in
	// order to prevent deadlocks.
	lock.RWMutex

	// m is the actual map containing the mappings.
	m map[string]prefixInfo

	// applyChangesMU protects InjectLabels and RemoveLabelsExcluded from being
	// run in parallel
	applyChangesMU lock.Mutex

	// queued* handle updates into the IPCache. Whenever a label is added
	// or removed from a specific IP prefix, that prefix is added into
	// 'queuedPrefixes'. Each time label injection is triggered, it will
	// process the metadata changes for these prefixes and potentially
	// generate updates into the ipcache, policy engine and datapath.
	queuedChangesMU lock.Mutex
	queuedPrefixes  map[string]struct{}
}

func newMetadata() *metadata {
	return &metadata{
		m:              make(map[string]prefixInfo),
		queuedPrefixes: make(map[string]struct{}),
	}
}

func (m *metadata) dequeuePrefixUpdates() (modifiedPrefixes []string) {
	m.queuedChangesMU.Lock()
	modifiedPrefixes = make([]string, 0, len(m.queuedPrefixes))
	for p := range m.queuedPrefixes {
		modifiedPrefixes = append(modifiedPrefixes, p)
	}
	m.queuedPrefixes = make(map[string]struct{})
	m.queuedChangesMU.Unlock()

	return
}

func (m *metadata) enqueuePrefixUpdates(prefixes []string) {
	m.queuedChangesMU.Lock()
	defer m.queuedChangesMU.Unlock()

	for _, prefix := range prefixes {
		m.queuedPrefixes[prefix] = struct{}{}
	}
}

// UpsertMetadata upserts a given IP and its corresponding labels associated
// with it into the ipcache metadata map. The given labels are not modified nor
// is its reference saved, as they're copied when inserting into the map.
//
// The caller must subsequently call ipc.TriggerLabelInjection() to implement
// these metadata updates into the datapath.
func (ipc *IPCache) UpsertMetadata(prefix string, lbls labels.Labels, src source.Source, uid k8sTypes.UID) {
	ipc.metadata.upsert(prefix, lbls, src, uid)
	ipc.metadata.enqueuePrefixUpdates([]string{prefix})
}

func (m *metadata) upsert(prefix string, lbls labels.Labels, src source.Source, uid k8sTypes.UID) {
	l := labels.NewLabelsFromModel(nil)
	l.MergeLabels(lbls)

	m.Lock()
	if _, ok := m.m[prefix]; !ok {
		m.m[prefix] = make(prefixInfo)
	}
	m.m[prefix][uid] = newLabelsWithSource(l, src)
	m.Unlock()
}

// GetIDMetadataByIP returns the associated labels with an IP. The caller must
// not modifying the returned object as it's a live reference to the underlying
// map.
func (ipc *IPCache) GetIDMetadataByIP(prefix string) labels.Labels {
	if info := ipc.metadata.get(prefix); info != nil {
		return info.ToLabels()
	}
	return nil
}

func (m *metadata) get(prefix string) prefixInfo {
	m.RLock()
	defer m.RUnlock()
	return m.m[prefix]
}

// InjectLabels injects labels from the ipcache metadata (IDMD) map into the
// identities used for the prefixes in the IPCache. The given source is the
// source of the caller, as inserting into the IPCache requires knowing where
// this updated information comes from. Conversely, RemoveLabelsExcluded()
// performs the inverse: removes labels from the IDMD map and releases
// identities allocated by this function.
//
// Note that as this function iterates through the IDMD, if it detects a change
// in labels for a given prefix, then this might allocate a new identity. If a
// prefix was previously associated with an identity, it will get deallocated,
// so a balance is kept, ensuring a one-to-one mapping between prefix and
// identity.
func (ipc *IPCache) InjectLabels(addedCIDRs []string) (remainingAdded []string, err error) {
	if ipc.IdentityAllocator == nil || !ipc.IdentityAllocator.IsLocalIdentityAllocatorInitialized() {
		return addedCIDRs, ErrLocalIdentityAllocatorUninitialized
	}

	if ipc.k8sSyncedChecker != nil &&
		!ipc.k8sSyncedChecker.K8sCacheIsSynced() {
		return addedCIDRs, errors.New("k8s cache not fully synced")
	}

	var (
		// idsToAdd stores the identities that must be updated via the
		// selector cache.
		idsToAdd = make(map[identity.NumericIdentity]labels.LabelArray)
		// toReplace stores the identity to replace in the ipcache.
		toReplace = make(map[string]Identity)
	)

	ipc.metadata.applyChangesMU.Lock()
	defer ipc.metadata.applyChangesMU.Unlock()

	for i, prefix := range addedCIDRs {
		info := ipc.metadata.get(prefix)
		lbls := info.ToLabels()

		// TODO: Check if we need isNew (identity reference counting)
		id, _, err := ipc.injectLabels(prefix, lbls)
		if err != nil {
			return addedCIDRs[i:], fmt.Errorf("failed to allocate new identity for IP %v: %w", prefix, err)
		}

		// If host identity has changed, update its labels.
		newLbls := id.Labels
		if id.ID == identity.ReservedIdentityHost {
			identity.AddReservedIdentityWithLabels(id.ID, newLbls)
		}
		idsToAdd[id.ID] = newLbls.LabelArray()
		toReplace[prefix] = Identity{
			ID:     id.ID,
			Source: info.Source(),
		}
	}

	// Recalculate policy first before upserting into the ipcache.
	ipc.UpdatePolicyMaps(context.TODO(), idsToAdd, nil)

	ipc.mutex.Lock()
	defer ipc.mutex.Unlock()
	for ip, id := range toReplace {
		hIP, key := ipc.getHostIPCache(ip)
		meta := ipc.getK8sMetadata(ip)
		if _, err := ipc.upsertLocked(
			ip,
			hIP,
			key,
			meta,
			id,
			true,
		); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr:   ip,
				logfields.Identity: id,
			}).Error("Failed to replace ipcache entry with new identity after label removal. Traffic may be disrupted.")
		}
	}

	return nil, nil
}

// UpdatePolicyMaps pushes updates for the specified identities into the policy
// engine and ensures that they are propagated into the underlying datapaths.
func (ipc *IPCache) UpdatePolicyMaps(ctx context.Context, addedIdentities, deletedIdentities map[identity.NumericIdentity]labels.LabelArray) {
	// GH-17962: Refactor to call (*Daemon).UpdateIdentities(), instead of
	// re-implementing the same logic here. It will also allow removing the
	// dependencies that are passed into this function.

	var wg sync.WaitGroup
	if deletedIdentities != nil {
		// SelectorCache.UpdateIdentities() asks for callers to avoid
		// handing the same identity in both 'adds' and 'deletes'
		// parameters here, so make two calls. These changes will not
		// be propagated to the datapath until the UpdatePolicyMaps
		// call below.
		ipc.PolicyHandler.UpdateIdentities(nil, deletedIdentities, &wg)
	}
	ipc.PolicyHandler.UpdateIdentities(addedIdentities, nil, &wg)
	policyImplementedWG := ipc.DatapathHandler.UpdatePolicyMaps(ctx, &wg)
	policyImplementedWG.Wait()
}

// injectLabels will allocate an identity for the given prefix and the given
// labels. The caller of this function can expect that an identity is newly
// allocated with reference count of 1 or an identity is looked up and its
// reference count is incremented.
//
// The release of the identity must be managed by the caller, except for the
// case where a CIDR policy exists first and then the kube-apiserver policy is
// applied. This is because the CIDR identities before the kube-apiserver
// policy is applied will need to be converted (released and re-allocated) to
// account for the new kube-apiserver label that will be attached to them. This
// is a known issue, see GH-17962 below.
func (ipc *IPCache) injectLabels(prefix string, lbls labels.Labels) (*identity.Identity, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), option.Config.IPAllocationTimeout)
	defer cancel()

	if lbls.Has(labels.LabelHost[labels.IDNameHost]) {
		// Associate any new labels with the host identity.
		//
		// This case is a bit special, because other parts of Cilium
		// have hardcoded assumptions around the host identity and
		// that it corresponds to identity.ReservedIdentityHost.
		// If additional labels are associated with the IPs of the
		// host, add those extra labels into the host identity here
		// so that policy will match on the identity correctly.
		//
		// We can get away with this because the host identity is only
		// significant within the current agent's view (ie each agent
		// will calculate its own host identity labels independently
		// for itself). For all other identities, we avoid modifying
		// the labels at runtime and instead opt to allocate new
		// identities below.
		identity.AddReservedIdentityWithLabels(identity.ReservedIdentityHost, lbls)
		return identity.LookupReservedIdentity(identity.ReservedIdentityHost), false, nil
	}

	// If no other labels are associated with this IP, we assume that it's
	// outside of the cluster and hence needs a CIDR identity.
	if !(lbls.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode])) {
		// GH-17962: Handle the following case:
		//   1) Apply ToCIDR policy (matching IPs of kube-apiserver)
		//   2) Apply kube-apiserver policy
		//
		// Possible implementation:
		//   Lookup CIDR ID => get all CIDR labels minus kube-apiserver label.
		//   If found, means that ToCIDR policy already applied. Convert CIDR
		//   IDs to include a new identity with kube-apiserver label. We don't
		//   need to remove old entries from ipcache because the caller will
		//   overwrite the ipcache entry anyway.

		return ipc.injectLabelsForCIDR(prefix, lbls)
	}

	return ipc.IdentityAllocator.AllocateIdentity(ctx, lbls, false, identity.InvalidIdentity)
}

// injectLabelsForCIDR will allocate a CIDR identity for the given prefix. The
// release of the identity must be managed by the caller.
func (ipc *IPCache) injectLabelsForCIDR(p string, lbls labels.Labels) (*identity.Identity, bool, error) {
	var prefix string

	ip := net.ParseIP(p)
	if ip == nil {
		return nil, false, fmt.Errorf("Invalid IP inserted into IdentityMetadata: %s", prefix)
	} else if ip.To4() != nil {
		prefix = p + "/32"
	} else {
		prefix = p + "/128"
	}

	_, cidr, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, false, err
	}

	allLbls := cidrlabels.GetCIDRLabels(cidr)
	allLbls.MergeLabels(lbls)

	log.WithFields(logrus.Fields{
		logfields.CIDR:   cidr,
		logfields.Labels: lbls, // omitting allLbls as CIDR labels would make this massive
	}).Debug(
		"Injecting CIDR labels for prefix",
	)

	return ipc.allocate(cidr, allLbls, identity.InvalidIdentity)
}

// RemoveLabelsExcluded removes the given labels from all IPs inside the IDMD
// except for the IPs / prefixes inside the given excluded set. This may cause
// updates to the ipcache, as well as to the identity and policy logic via
// 'updater' and 'triggerer'.
func (ipc *IPCache) RemoveLabelsExcluded(
	lbls labels.Labels,
	toExclude map[string]struct{},
	src source.Source,
	uid k8sTypes.UID,
) {
	ipc.metadata.applyChangesMU.Lock()
	defer ipc.metadata.applyChangesMU.Unlock()

	ipc.metadata.Lock()
	defer ipc.metadata.Unlock()

	oldSet := ipc.metadata.filterByLabels(lbls)
	toRemove := make(map[string]labels.Labels)
	for _, ip := range oldSet {
		if _, ok := toExclude[ip]; !ok {
			toRemove[ip] = lbls
		}
	}

	ipc.removeLabelsFromIPs(toRemove, src, uid)
}

// filterByLabels returns all the prefixes inside the ipcache metadata map
// which contain the given labels. Note that `filter` is a subset match, not a
// full match.
//
// Assumes that the ipcache metadata read lock is taken!
func (m *metadata) filterByLabels(filter labels.Labels) []string {
	var matching []string
	sortedFilter := filter.SortedList()
	for prefix, info := range m.m {
		lbls := info.ToLabels()
		if bytes.Contains(lbls.SortedList(), sortedFilter) {
			matching = append(matching, prefix)
		}
	}
	return matching
}

// removeLabelsFromIPs removes all given prefixes at once. This function will
// trigger policy update and recalculation if necessary on behalf of the
// caller.
//
// A prefix will only be removed from the IDMD if the set of labels becomes
// empty.
//
// Assumes that the ipcache metadata lock is taken!
func (ipc *IPCache) removeLabelsFromIPs(
	m map[string]labels.Labels,
	src source.Source,
	uid k8sTypes.UID,
) {
	var (
		idsToAdd    = make(map[identity.NumericIdentity]labels.LabelArray)
		idsToDelete = make(map[identity.NumericIdentity]labels.LabelArray)
		// toReplace stores the identity to replace in the ipcache.
		toReplace = make(map[string]Identity)
	)

	ipc.Lock()
	defer ipc.Unlock()

	for prefix, lbls := range m {
		id, exists := ipc.LookupByIPRLocked(prefix)
		if !exists {
			continue
		}

		idsToDelete[id.ID] = nil // labels for deletion don't matter to UpdateIdentities()

		// Insert to propagate the updated set of labels after removal.
		l := ipc.removeLabels(prefix, lbls, src, uid)
		if len(l) > 0 {
			// If for example kube-apiserver label is removed from the local
			// host identity (when the kube-apiserver is running within the
			// cluster and it is no longer running on the current local host),
			// then removeLabels() will return a non-empty set representing the
			// new full set of labels to associate with the node (in this
			// example, just the local host label). In order to propagate the
			// new identity, we must emit a delete event for the old identity
			// and then an add event for the new identity.

			// If host identity has changed, update its labels.
			if id.ID == identity.ReservedIdentityHost {
				identity.AddReservedIdentityWithLabels(id.ID, l)
			}

			newID, _, err := ipc.IdentityAllocator.AllocateIdentity(context.TODO(), l, false, identity.InvalidIdentity)
			if err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.IPAddr:         prefix,
					logfields.Identity:       id,
					logfields.IdentityLabels: l,    // new labels
					logfields.Labels:         lbls, // removed labels
				}).Error(
					"Failed to allocate new identity after dissociating labels from existing identity. Traffic may be disrupted.",
				)
				continue
			}
			idsToAdd[newID.ID] = l.LabelArray()
			toReplace[prefix] = Identity{
				ID:     newID.ID,
				Source: sourceByLabels(src, l),
			}
		}
	}
	if len(idsToDelete) > 0 {
		ipc.UpdatePolicyMaps(context.TODO(), idsToAdd, idsToDelete)
	}
	for ip, id := range toReplace {
		hIP, key := ipc.getHostIPCache(ip)
		meta := ipc.getK8sMetadata(ip)
		if _, err := ipc.upsertLocked(
			ip,
			hIP,
			key,
			meta,
			id,
			true, /* force upsert */
		); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.IPAddr:   ip,
				logfields.Identity: id,
			}).Error("Failed to replace ipcache entry with new identity after label removal. Traffic may be disrupted.")
		}
	}
}

// removeLabels removes the given labels association with the given prefix. The
// leftover labels are returned, if any. If there are leftover labels, the
// caller must allocate a new identity and do the following *in order* to avoid
// drops:
//   1) policy recalculation must be implemented into the datapath and
//   2) new identity must have a new entry upserted into the IPCache
// Note: GH-17962, triggering policy recalculation doesn't actually *implement*
// the changes into datapath (because it's an async call), this is a known
// issue. There's a very small window for drops when two policies select the
// same traffic and the identity changes. For example, this is possible if an
// IP is associated with the kube-apiserver and referenced inside a ToCIDR
// policy, and then the IP is no longer associated with the kube-apiserver.
//
// Identities are deallocated and their subequent entry in the IPCache is
// removed if the prefix is no longer associated with any labels.
//
// This function assumes that the ipcache metadata and the IPIdentityCache
// locks are taken!
func (ipc *IPCache) removeLabels(prefix string, lbls labels.Labels, src source.Source, uid k8sTypes.UID) labels.Labels {
	info, ok := ipc.metadata.m[prefix]
	if !ok {
		return nil
	}
	delete(info, uid)

	l := info.ToLabels()
	if len(l) == 0 { // Labels empty, delete
		// No labels left. Example case: when the kube-apiserver is running
		// outside of the cluster, meaning that the IDMD only ever had the
		// kube-apiserver label (CIDR labels are not added) and it's now being
		// removed.
		delete(ipc.metadata.m, prefix)
	} else {
		// TODO: Ensure that CiliumNode updates will populate the 'info'
		// with the information "CIDR X is a remote node".
	}

	// TODO: Delete...?
	id, exists := ipc.LookupByIPRLocked(prefix)
	if !exists {
		log.WithFields(logrus.Fields{
			logfields.CIDR:   prefix,
			logfields.Labels: lbls,
		}).Warn(
			"Identity for prefix was unexpectedly not found in ipcache, unable " +
				"to remove labels from prefix. If a network policy is applied, check " +
				"for any drops. It's possible that insertion or removal from " +
				"the ipcache failed.",
		)
		return nil
	}

	realID := ipc.IdentityAllocator.LookupIdentityByID(context.TODO(), id.ID)
	if realID == nil {
		log.WithFields(logrus.Fields{
			logfields.CIDR:     prefix,
			logfields.Labels:   lbls,
			logfields.Identity: id,
		}).Warn(
			"Identity unexpectedly not found within the identity allocator, " +
				"unable to remove labels from prefix. It's possible that insertion " +
				"or removal from the ipcache failed.",
		)
		return nil
	}
	released, err := ipc.IdentityAllocator.Release(context.TODO(), realID, false)
	if err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.IPAddr:         prefix,
			logfields.Labels:         lbls,
			logfields.Identity:       realID,
			logfields.IdentityLabels: realID.Labels,
		}).Error(
			"Failed to release assigned identity to IP while removing label association, this might be a leak.",
		)
		return nil
	}
	if released {
		ipc.deleteLocked(prefix, sourceByLabels(src, lbls))
		return nil
	}

	// TODO: Is it possible for a CIDR identity to hit this line? Maybe if
	// there is CIDR policy for a kube-apiserver /32 IP, and you add/delete
	// that policy a few times, you leak references to the identity
	// corresponding to "reserved:kube-apiserver","cidr:w.x.y.z/32", ..

	// Generate new identity with the label removed. This should be the case
	// where the existing identity had >1 refcount, meaning that something was
	// referring to it.
	//
	// If kube-apiserver is inside the cluster, this path is always hit
	// (because even if we remove the kube-apiserver from that node, we
	// need to inject the identity corresponding to "host" or "remote-node"
	// (without apiserver label)
	return l
}

func sourceByLabels(d source.Source, lbls labels.Labels) source.Source {
	if lbls.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]) {
		return source.KubeAPIServer
	}
	return d
}

// TriggerLabelInjection triggers the label injection controller to iterate
// through the IDMD and potentially allocate new identities based on any label
// changes.
//
// The following diagram describes the relationship between the label injector
// triggered here and the callers/callees.
//
//      +------------+  (1)        (1)  +-----------------------------+
//      | EP Watcher +-----+      +-----+ CN Watcher / Node Discovery |
//      +-----+------+   W |      | W   +------+----------------------+
//            |            |      |            |
//            |            v      v            |
//            |            +------+            |
//            |            | IDMD |            |
//            |            +------+            |
//            |               ^                |
//            |               |                |
//            |           (3) |R               |
//            | (2)    +------+--------+   (2) |
//            +------->|Label Injector |<------+
//           Trigger   +-------+-------+ Trigger
//                         (4) |W
//                             |
//                             v
//                           +---+
//                           |IPC|
//                           +---+
//      legend:
//      * W means write
//      * R means read
func (ipc *IPCache) TriggerLabelInjection() {
	// GH-17829: Would also be nice to have an end-to-end test to validate
	//           on upgrade that there are no connectivity drops when this
	//           channel is preventing transient BPF entries.

	// This controller is for retrying this operation in case it fails. It
	// should eventually succeed.
	ipc.UpdateController(
		"ipcache-inject-labels",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				var err error

				idsToModify := ipc.metadata.dequeuePrefixUpdates()
				idsToModify, err = ipc.InjectLabels(idsToModify)
				ipc.metadata.enqueuePrefixUpdates(idsToModify)

				return err
			},
		},
	)
}
