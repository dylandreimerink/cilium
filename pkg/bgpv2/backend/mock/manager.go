package mock

import (
	"fmt"

	"github.com/cilium/cilium/pkg/bgpv2/backend"
	"github.com/cilium/cilium/pkg/hive/cell"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

var Cell = cell.Module(
	"Mock-Speaker-Backend",

	cell.Provide(newManager),
)

var _ backend.BGPSpeakerManager = (*Manager)(nil)

type speaker struct {
	backend.BGPSpeaker
	Routes []backend.BGPRoute
}

type Manager struct {
	Speakers map[backend.BGPSpeakerPK]speaker
}

func newManager() backend.BGPSpeakerManager {
	return &Manager{
		Speakers: make(map[backend.BGPSpeakerPK]speaker),
	}
}

func (m *Manager) ListSpeakers() []backend.BGPSpeaker {
	speakers := make([]backend.BGPSpeaker, 0, len(m.Speakers))
	for _, speaker := range m.Speakers {
		speakers = append(speakers, speaker.BGPSpeaker)
	}
	return speakers
}

func (m *Manager) UpsertSpeaker(bgpSpeaker backend.BGPSpeaker) error {
	m.Speakers[bgpSpeaker.Key] = speaker{
		BGPSpeaker: bgpSpeaker,
	}

	return nil
}

func (m *Manager) DeleteSpeaker(key backend.BGPSpeakerPK) error {
	delete(m.Speakers, key)
	return nil
}

func (m *Manager) SpeakerInfo() ([]backend.BGPSpeakerInfo, error) {
	infos := make([]backend.BGPSpeakerInfo, 0, len(m.Speakers))
	for _, speaker := range m.Speakers {
		info := backend.BGPSpeakerInfo{
			Key:    speaker.Key,
			Origin: speaker.Origin,
			Info: map[string]string{
				"pod_cidr_announcements": "0",
				"lb_svc_announcements":   "0",
			},
		}

		for _, neighbor := range speaker.Neighbors {
			info.Neighbors = append(info.Neighbors, backend.BGPNeighborInfo{
				Address: neighbor.Address,
				ASN:     neighbor.ASN,
				Info: map[string]string{
					"state":  "ESTABLISHED",
					"uptime": "1h2m3s",
				},
			})
		}
		infos = append(infos, info)
	}

	return infos, nil
}

func (m *Manager) ListRoutes() []backend.BGPRoute {
	var routes []backend.BGPRoute
	for _, speaker := range m.Speakers {
		routes = append(routes, speaker.Routes...)
	}
	return routes
}

func (m *Manager) UpsertRoute(route backend.BGPRoute) error {
	speaker, found := m.Speakers[route.Speaker()]
	if !found {
		return fmt.Errorf("No speaker matching the route")
	}

	speaker.Routes = append(speaker.Routes, route)
	m.Speakers[route.Speaker()] = speaker

	return nil
}

func (m *Manager) DeleteRoute(route backend.BGPRoute) error {
	speaker, found := m.Speakers[route.Speaker()]
	if !found {
		return fmt.Errorf("No speaker matching the route")
	}

	for i, existingRoute := range speaker.Routes {
		match := existingRoute.AFI() == route.AFI() &&
			existingRoute.SAFI() == route.SAFI() &&
			maps.Equal(existingRoute.Attributes(), route.Attributes())

		if match {
			speaker.Routes = slices.Delete(speaker.Routes, i, i+1)
			break
		}
	}

	m.Speakers[route.Speaker()] = speaker

	return nil
}
