package gobgp

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/bgpv2/backend"

	"github.com/davecgh/go-spew/spew"
	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	bgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"golang.org/x/exp/slices"
)

type ServerMap map[backend.BGPSpeakerPK]*ServerWithConfig

type ServerWithConfig struct {
	// a gobgp backed BgpServer configured in accordance to the accompanying
	// CiliumBGPVirtualRouter configuration.
	Server  *server.BgpServer
	Speaker backend.BGPSpeaker

	Advertisements AdvertisementMap
	ReceivedRoutes []*gobgp.Path
}

func newServerWithConfig() *ServerWithConfig {
	return &ServerWithConfig{
		Advertisements: newAdvertisementMap(),
	}
}

func (m *Manager) ListSpeakers() []backend.BGPSpeaker {
	var speakers []backend.BGPSpeaker
	for _, server := range m.serverMap {
		speakers = append(speakers, server.Speaker)
	}
	return speakers
}

func (m *Manager) UpsertSpeaker(bgpSpeaker backend.BGPSpeaker) error {
	sc, found := m.serverMap[bgpSpeaker.Key]
	if !found {
		sc = newServerWithConfig()
	}

	sc.Speaker = bgpSpeaker
	defer func() { m.serverMap[bgpSpeaker.Key] = sc }()

	config := bgpSpeaker.Config

	startReq := &gobgp.StartBgpRequest{
		Global: &gobgp.Global{
			Asn:        config.LocalASN,
			RouterId:   config.RouterID,
			ListenPort: config.ListenPort,
			RouteSelectionOptions: &gobgp.RouteSelectionOptionsConfig{
				AdvertiseInactiveRoutes: true,
			},
		},
	}

	// TODO apply host annotation overwrites

	// If the server already exists, this is an update.
	if sc.Server != nil {
		bgpInfo, err := sc.Server.GetBgp(context.TODO(), &gobgp.GetBgpRequest{})
		if err != nil {
			return fmt.Errorf("failed to retrieve BgpServer info for virtual router with ASN %v: %w", config.LocalASN, err)
		}

		var shouldRecreate bool
		if config.ListenPort != bgpInfo.Global.ListenPort {
			shouldRecreate = true
			m.logger.Infof("Virtual router with ASN %v local port has changed from %v to %v", config.LocalASN, bgpInfo.Global.ListenPort, config.ListenPort)
		}

		if config.RouterID != bgpInfo.Global.RouterId {
			shouldRecreate = true
			m.logger.Infof("Virtual router with ASN %v router ID has changed from %v to %v", config.LocalASN, bgpInfo.Global.RouterId, config.RouterID)
		}

		if !shouldRecreate {
			m.logger.Debugf("No preflight reconciliation necessary for virtual router with local ASN %v", config.LocalASN)

			err = m.reconcileNeighbors(sc)
			if err != nil {
				return fmt.Errorf("Reconcile neighbors: %w", err)
			}

			return nil
		}

		m.logger.Infof("Recreating virtual router with ASN %v for changes to take effect", config.LocalASN)

		// stop the old BgpServer
		sc.Server.Stop()

		// Continue with the "new" path to make the new server
	}

	logger := NewServerLogger(m.logger, sc.Speaker.Config.LocalASN)
	sc.Server = bgpserver.NewBgpServer(bgpserver.LoggerOption(logger))
	go sc.Server.Serve()

	if err := sc.Server.StartBgp(context.TODO(), startReq); err != nil {
		return fmt.Errorf("failed starting BGP server: %w", err)
	}

	// will log out any peer changes.
	// TODO update statistics on events?
	watchRequest := &gobgp.WatchEventRequest{
		Peer: &gobgp.WatchEventRequest_Peer{},
	}
	err := sc.Server.WatchEvent(context.TODO(), watchRequest, func(r *gobgp.WatchEventResponse) {
		if p := r.GetPeer(); p != nil && p.Type == gobgp.WatchEventResponse_PeerEvent_STATE {
			logger.l.Info(p)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to configure logging for virtual router with local-asn %v: %w", startReq.Global.Asn, err)
	}

	err = m.reconcileNeighbors(sc)
	if err != nil {
		return fmt.Errorf("Reconcile neighbors: %w", err)
	}

	return nil
}

var (
	// GoBGPIPv6Family is a read-only pointer to a gobgp.Family structure
	// representing IPv6 address family.
	GoBGPIPv6Family = &gobgp.Family{
		Afi:  gobgp.Family_AFI_IP6,
		Safi: gobgp.Family_SAFI_UNICAST,
	}
	// GoBGPIPv4Family is a read-only pointer to a gobgp.Family structure
	// representing IPv4 address family.
	GoBGPIPv4Family = &gobgp.Family{
		Afi:  gobgp.Family_AFI_IP,
		Safi: gobgp.Family_SAFI_UNICAST,
	}
)

func (m *Manager) reconcileNeighbors(sc *ServerWithConfig) error {
	m.logger.Debugf("Reconciling neighbors for '%s/%d'", sc.Speaker.Key.RouterID, sc.Speaker.Config.LocalASN)

	existingPeers := make(map[string]*gobgp.Peer, 0)
	sc.Server.ListPeer(context.TODO(), &gobgp.ListPeerRequest{}, func(p *gobgp.Peer) {
		existingPeers[p.Conf.NeighborAddress] = p
	})

	requestedPeers := make(map[string]backend.BGPNeighbor)
	for _, n := range sc.Speaker.Neighbors {
		addr := n.Address.String()
		requestedPeers[addr] = n

		requested := requestedPeer(sc, n)

		existing := existingPeers[n.Address.String()]
		if existing != nil {
			// Update

			if peerEqual(existing, requested) {
				m.logger.Debugf("Neighbor '%s' is up-to-date", addr)
				spew.Dump(existing)
				continue
			}

			m.logger.Debugf("Updating neighbor '%s'", addr)
			_, err := sc.Server.UpdatePeer(context.TODO(), &gobgp.UpdatePeerRequest{
				Peer:          requested,
				DoSoftResetIn: true,
			})
			if err != nil {
				return fmt.Errorf("Update peer: %w", err)
			}

			continue
		}

		// New
		m.logger.Debugf("Creating neighbor '%s'", addr)

		err := sc.Server.AddPeer(context.TODO(), &gobgp.AddPeerRequest{
			Peer: requested,
		})
		if err != nil {
			return fmt.Errorf("Add peer: %w", err)
		}
	}

	for _, p := range existingPeers {
		_, found := requestedPeers[p.Conf.NeighborAddress]
		if !found {
			continue
		}

		// Delete peer
		m.logger.Debugf("Deleting neighbor '%s'", p.Conf.NeighborAddress)
		sc.Server.DeletePeer(context.TODO(), &gobgp.DeletePeerRequest{
			Address: p.Conf.NeighborAddress,
		})
	}

	return nil
}

func requestedPeer(sc *ServerWithConfig, n backend.BGPNeighbor) *gobgp.Peer {
	peer := &gobgp.Peer{
		Conf: &gobgp.PeerConf{
			LocalAsn:        sc.Speaker.Config.LocalASN,
			PeerAsn:         n.ASN,
			NeighborAddress: n.Address.String(),
		},
		AfiSafis: peerAfiSafis(),
	}

	// TODO apply neighbor annotations

	return peer
}

func peerEqual(p1, p2 *gobgp.Peer) bool {
	return peerConfEqual(p1.Conf, p2.Conf) &&
		peerTimersEqual(p1.Timers.Config, p2.Timers.Config) &&
		peerAfiSafiEqual(p1.AfiSafis, p2.AfiSafis)
}

func peerConfEqual(p1, p2 *gobgp.PeerConf) bool {
	if p1 == nil || p2 == nil {
		return p1 == nil && p2 == nil
	}

	return p1.AuthPassword == p2.AuthPassword &&
		p1.Description == p2.Description &&
		p1.LocalAsn == p2.LocalAsn &&
		p1.NeighborAddress == p2.NeighborAddress &&
		p1.PeerAsn == p2.PeerAsn &&
		p1.PeerGroup == p2.PeerGroup &&
		p1.Type == p2.Type &&
		p1.RemovePrivate == p2.RemovePrivate &&
		p1.RouteFlapDamping == p2.RouteFlapDamping &&
		p1.SendCommunity == p2.SendCommunity &&
		p1.NeighborInterface == p2.NeighborInterface &&
		p1.Vrf == p2.Vrf &&
		p1.AllowOwnAsn == p2.AllowOwnAsn &&
		p1.ReplacePeerAsn == p2.ReplacePeerAsn &&
		p1.AdminDown == p2.AdminDown
}

func peerTimersEqual(p1, p2 *gobgp.TimersConfig) bool {
	if p1 == nil || p2 == nil {
		return p1 == nil && p2 == nil
	}

	return p1.ConnectRetry == p2.ConnectRetry &&
		p1.HoldTime == p2.HoldTime &&
		p1.KeepaliveInterval == p2.KeepaliveInterval &&
		p1.MinimumAdvertisementInterval == p2.MinimumAdvertisementInterval &&
		p1.IdleHoldTimeAfterReset == p2.IdleHoldTimeAfterReset
}

func peerAfiSafiEqual(p1, p2 []*gobgp.AfiSafi) bool {
	if len(p1) != len(p2) {
		return false
	}

	for _, as1 := range p1 {
		if slices.IndexFunc(p2, func(as2 *gobgp.AfiSafi) bool {
			return as1.Config.Enabled == as2.Config.Enabled &&
				as1.Config.Family.Afi == as2.Config.Family.Afi &&
				as1.Config.Family.Safi == as2.Config.Family.Safi
		}) == -1 {
			return false
		}
	}

	return true
}

// TODO make dynamic/based on config?
func peerAfiSafis() []*gobgp.AfiSafi {
	return []*gobgp.AfiSafi{
		{
			Config: &gobgp.AfiSafiConfig{
				Family: GoBGPIPv4Family,
			},
		},
		{
			Config: &gobgp.AfiSafiConfig{
				Family: GoBGPIPv6Family,
			},
		},
	}
}

func (m *Manager) DeleteSpeaker(key backend.BGPSpeakerPK) error {
	sc, found := m.serverMap[key]
	if !found {
		return nil
	}

	sc.Server.Stop()

	delete(m.serverMap, key)

	return nil
}

func (m *Manager) SpeakerInfo() ([]backend.BGPSpeakerInfo, error) {
	// TODO implement
	return nil, nil
}
