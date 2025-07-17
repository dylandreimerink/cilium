package reconciler

import (
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/lock"
)

type DesiredRouteManager struct {
	tbl statedb.RWTable[*DesiredRoute]

	mu         lock.Mutex
	ownerIDCnt uint32
}

func (m *DesiredRouteManager) RegisterOwner(name string, adminDistance int) *RouteOwner {
	m.mu.Lock()
	defer m.mu.Unlock()

	owner := &RouteOwner{
		name:          name,
		id:            m.ownerIDCnt,
		adminDistance: adminDistance,
	}
	m.ownerIDCnt++
	return owner
}

func (m *DesiredRouteManager) RemoveOwner(owner *RouteOwner) error {
	// TODO delete all desired routes for this owner
	return nil
}

func (m *DesiredRouteManager) UpsertRoutes(routes ...DesiredRoute) error {
	// TODO add route to table, ensure only one is selected per prefix+table
	return nil
}

func (m *DesiredRouteManager) UpsertRoutesWait(routes ...DesiredRoute) error {
	// TODO add route to table, ensure only one is selected per prefix+table
	// wait for added routes to be processed by the reconciler
	return nil
}

func (m *DesiredRouteManager) DeleteRoutes(routes ...DesiredRoute) error {
	// TODO remove route from table
	return nil
}
