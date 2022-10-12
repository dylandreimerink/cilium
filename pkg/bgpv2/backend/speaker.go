// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package backend

import (
	"net"
)

// BGPSpeakerManager manages the backend implementation of one or more BGPSpeakers.
type BGPSpeakerManager interface {
	ListSpeakers() []BGPSpeaker
	UpsertSpeaker(BGPSpeaker) error
	DeleteSpeaker(BGPSpeakerPK) error
	SpeakerInfo() ([]BGPSpeakerInfo, error)

	ListRoutes() []BGPRoute
	UpsertRoute(BGPRoute) error
	DeleteRoute(BGPRoute) error
}

// BGPSpeakerPK is the primary key of a speaker and can be used to refer to it.
type BGPSpeakerPK struct {
	RouterID string
	LocalASN uint32
}

// BGPSpeaker represents a single BGP Speaker instance which can have a set of routes.
type BGPSpeaker struct {
	Key BGPSpeakerPK

	Origin Origin

	Config    BGPSpeakerConfig
	Neighbors []BGPNeighbor
}

// BGPSpeakerConfig is the speaker-wide config and holds settings which can't be changed on a per neighbor basis
type BGPSpeakerConfig struct {
	LocalASN   uint32
	ListenPort int32
	RouterID   string

	// A KV pair with no pre-defined schema, used for backend specific speaker configuration.
	Annotations map[string]string
}

// BGPNeighbor represents a BGP Neighbor connection/configuration.
type BGPNeighbor struct {
	Address net.IP
	ASN     uint32

	Config BGPNeighborConfig
}

// BGPNeighborConfig is the neighbor specific configuration
type BGPNeighborConfig struct {
	// A KV pair with no pre-defined schema, used for backend specific peer configuration.
	Annotations map[string]string
}

// BGPSpeakerInfo contains information about the runtime status of a speaker
type BGPSpeakerInfo struct {
	Key BGPSpeakerPK

	Origin Origin

	// Info contains backend specific info
	Info      map[string]string
	Neighbors []BGPNeighborInfo
}

type BGPNeighborInfo struct {
	Address net.IP
	ASN     uint32

	// Backend specific info about the neighbor
	Info map[string]string
}

type Origin struct {
	Reconciler string
	Type       string
	Namespace  string
	Name       string
}
