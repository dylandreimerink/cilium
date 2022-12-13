// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/allocator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// configNotificationsChannelSize is the size of the channel used to
	// notify a clustermesh of configuration changes
	configNotificationsChannelSize = 512
)

// Configuration is the configuration that must be provided to
// NewClusterMesh()
type Configuration struct {
	// Name is the name of the local cluster. This is used for logging and metrics
	Name string

	// NodeName is the name of the local node. This is used for logging and metrics
	NodeName string

	// ConfigDirectory is the path to the directory that will be watched for etcd
	// configuration files to appear
	ConfigDirectory string

	// NodeKeyCreator is the function used to create node instances as
	// nodes are being discovered in remote clusters
	NodeKeyCreator store.KeyCreator

	// ServiceMerger is the interface responsible to merge service and
	// endpoints into an existing cache
	ServiceMerger ServiceMerger

	// NodeManager is the node manager to manage all discovered remote
	// nodes
	NodeManager *nodemanager.Manager

	nodeObserver store.Observer

	// RemoteIdentityWatcher provides identities that have been allocated on a
	// remote cluster.
	RemoteIdentityWatcher RemoteIdentityWatcher

	IPCache *ipcache.IPCache

	// ServicesSharedKeyDeleteDelay is the delay before a shared service delete
	// event is handled. This parameter is optional.
	ServicesSharedKeyDeleteDelay *time.Duration

	// NodesSharedKeyDeleteDelay is the delay before a shared node delete event
	// is handled. This parameter is optional.
	NodesSharedKeyDeleteDelay *time.Duration

	LegacyMetrics *metrics.LegacyMetrics
}

func SetClusterConfig(clusterName string, config *cmtypes.CiliumClusterConfig, backend kvstore.BackendOperations) error {
	key := path.Join(kvstore.ClusterConfigPrefix, clusterName)

	val, err := json.Marshal(config)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err = kvstore.Client().UpdateIfDifferent(ctx, key, val, true)
	if err != nil {
		return err
	}

	return nil
}

func GetClusterConfig(clusterName string, backend kvstore.BackendOperations) (*cmtypes.CiliumClusterConfig, error) {
	var config cmtypes.CiliumClusterConfig

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	val, err := backend.Get(ctx, path.Join(kvstore.ClusterConfigPrefix, clusterName))
	if err != nil {
		return nil, err
	}

	// Cluster configuration missing, but it's not an error
	if val == nil {
		return nil, nil
	}

	if err := json.Unmarshal(val, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// RemoteIdentityWatcher is any type which provides identities that have been
// allocated on a remote cluster.
type RemoteIdentityWatcher interface {
	// WatchRemoteIdentities starts watching for identities in another kvstore and
	// syncs all identities to the local identity cache.
	WatchRemoteIdentities(backend kvstore.BackendOperations) (*allocator.RemoteCache, error)

	// Close stops the watcher.
	Close()
}

// NodeObserver returns the node store observer of the configuration
func (c *Configuration) NodeObserver() store.Observer {
	if c.nodeObserver != nil {
		return c.nodeObserver
	}

	return nodeStore.NewNodeObserver(c.NodeManager)
}

// ClusterMesh is a cache of multiple remote clusters
type ClusterMesh struct {
	// conf is the configuration, it is immutable after NewClusterMesh()
	conf Configuration

	mutex         lock.RWMutex
	clusters      map[string]*remoteCluster
	controllers   *controller.Manager
	configWatcher *configDirectoryWatcher

	ipcache *ipcache.IPCache

	// globalServices is a list of all global services. The datastructure
	// is protected by its own mutex inside the structure.
	globalServices *globalServiceCache
}

// NewClusterMesh creates a new remote cluster cache based on the
// provided configuration
func NewClusterMesh(c Configuration) (*ClusterMesh, error) {
	cm := &ClusterMesh{
		conf:           c,
		clusters:       map[string]*remoteCluster{},
		controllers:    controller.NewManager(),
		globalServices: newGlobalServiceCache(c.Name, c.NodeName, c.LegacyMetrics),
		ipcache:        c.IPCache,
	}

	w, err := createConfigDirectoryWatcher(c.ConfigDirectory, cm)
	if err != nil {
		return nil, fmt.Errorf("unable to create config directory watcher: %s", err)
	}

	cm.configWatcher = w

	if err := cm.configWatcher.watch(); err != nil {
		return nil, err
	}

	return cm, nil
}

// Close stops watching for remote cluster configuration files to appear and
// will close all connections to remote clusters
func (cm *ClusterMesh) Close() {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.configWatcher != nil {
		cm.configWatcher.close()
	}

	for name, cluster := range cm.clusters {
		cluster.onRemove()
		delete(cm.clusters, name)
	}
	cm.controllers.RemoveAllAndWait()
}

func (cm *ClusterMesh) newRemoteCluster(name, path string) *remoteCluster {
	rc := &remoteCluster{
		name:        name,
		configPath:  path,
		mesh:        cm,
		changed:     make(chan bool, configNotificationsChannelSize),
		controllers: controller.NewManager(),
		swg:         lock.NewStoppableWaitGroup(),
	}

	return rc
}

func (cm *ClusterMesh) add(name, path string) {
	if name == option.Config.ClusterName {
		log.WithField(fieldClusterName, name).Debug("Ignoring configuration for own cluster")
		return
	}

	inserted := false
	cm.mutex.Lock()
	cluster, ok := cm.clusters[name]
	if !ok {
		cluster = cm.newRemoteCluster(name, path)
		cm.clusters[name] = cluster
		inserted = true
	}

	cm.conf.LegacyMetrics.TotalRemoteClusters.WithLabelValues(cm.conf.Name, cm.conf.NodeName).Set(float64(len(cm.clusters)))
	cm.mutex.Unlock()

	log.WithField(fieldClusterName, name).Debug("Remote cluster configuration added")

	if inserted {
		cluster.onInsert(cm.conf.RemoteIdentityWatcher)
	} else {
		// signal a change in configuration
		cluster.changed <- true
	}
}

func (cm *ClusterMesh) remove(name string) {
	cm.mutex.Lock()
	if cluster, ok := cm.clusters[name]; ok {
		cluster.onRemove()
		delete(cm.clusters, name)
		cm.conf.LegacyMetrics.TotalRemoteClusters.WithLabelValues(cm.conf.Name, cm.conf.NodeName).Set(float64(len(cm.clusters)))
		cm.globalServices.onClusterDelete(name)
	}
	cm.mutex.Unlock()

	log.WithField(fieldClusterName, name).Debug("Remote cluster configuration removed")
}

// NumReadyClusters returns the number of remote clusters to which a connection
// has been established
func (cm *ClusterMesh) NumReadyClusters() int {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	nready := 0
	for _, cm := range cm.clusters {
		if cm.isReady() {
			nready++
		}
	}

	return nready
}

func (cm *ClusterMesh) canConnect(name string, config *cmtypes.CiliumClusterConfig) error {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	for n, rc := range cm.clusters {
		if err := func() error {
			rc.mutex.RLock()
			defer rc.mutex.RUnlock()

			if rc.name == name || !rc.isReadyLocked() || rc.config == nil {
				return nil
			}

			if err := rc.config.IsCompatible(config); err != nil {
				return err
			}

			return nil
		}(); err != nil {
			return fmt.Errorf("configuration of %s is not compatible with %s: %w", name, n, err)
		}
	}

	return nil
}

// ClustersSynced returns after all clusters were synchronized with the bpf
// datapath.
func (cm *ClusterMesh) ClustersSynced(ctx context.Context) error {
	cm.mutex.RLock()
	swgs := make([]*lock.StoppableWaitGroup, 0, len(cm.clusters))
	for _, cluster := range cm.clusters {
		swgs = append(swgs, cluster.swg)
	}
	cm.mutex.RUnlock()

	for _, swg := range swgs {
		select {
		case <-swg.WaitChannel():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Status returns the status of the ClusterMesh subsystem
func (cm *ClusterMesh) Status() (status *models.ClusterMeshStatus) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	status = &models.ClusterMeshStatus{
		NumGlobalServices: int64(cm.globalServices.size()),
	}

	for _, cm := range cm.clusters {
		status.Clusters = append(status.Clusters, cm.status())
	}

	return
}
