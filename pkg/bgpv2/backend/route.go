// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package backend

import (
	"net"
	"strconv"

	"golang.org/x/exp/maps"
)

const (
	AFI_IPv4 = 1
	AFI_IPv6 = 2
)

const (
	SAFI_UNICAST = 1
)

type BGPRoute interface {
	// Address Family Identifiers, together with the SAFI determines what kind of route information this is.
	AFI() int32
	// Subsequent Address Family Identifiers
	SAFI() int32
	// The speaker to which this route should be added
	Speaker() BGPSpeakerPK
	// Resource that originated the route (not to be confused with the BGP Origin Attribute)
	Origin() Origin

	// Attributes describe the actual route, not all route types have the same attributes.
	// Not all backends might implement all attributes, in which case a backend should make a best effort.
	Attributes() map[BGPAttribute]string
}

type BGPAttribute int

const (
	// Start of IPv4/IPv6 unicast attributes

	// AttrPrefix is a IPv4 or IPv6 address
	AttrPrefix BGPAttribute = iota
	// AttrPrefixLen is the prefix mask size (0-32) for IPv4, (0-128) for IPv6
	AttrPrefixLen
	// AttrNextHop is an IPv4 or IPv6 address
	AttrNextHop
	// AttrMed is an 32-bit unsigned value
	AttrMed
	// AttrASPath is a comma-separated list of 32-bit unsigned ASN's e.g. (65001,65002,65003)
	AttrASPath
	// AttrCommunity is a comma-separated list of BGP Communities (65001:0,65002:1)
	AttrCommunity
	// AttrLargeCommunity is a comma-separated list of BGP large communities (65001:500:1,65002:502:2)
	AttrLargeCommunity
	// AttrLocalPreference is a 32-bit unsigned value
	AttrLocalPreference

	// End of IPv4/IPv6 unicast attributes
)

var _ BGPRoute = (*UnicastRoute)(nil)

type UnicastRoute struct {
	RouteOrigin Origin
	Cidr        net.IPNet
	Nexthop     net.IP
	BGPSpeaker  BGPSpeakerPK
	Additional  map[BGPAttribute]string
}

func (ur *UnicastRoute) AFI() int32 {
	if ur.Cidr.IP.To4() == nil {
		return AFI_IPv6
	}

	return AFI_IPv4
}

func (ur *UnicastRoute) SAFI() int32 {
	return SAFI_UNICAST
}

func (ur *UnicastRoute) Origin() Origin {
	return ur.RouteOrigin
}

func (ur *UnicastRoute) Speaker() BGPSpeakerPK {
	return ur.BGPSpeaker
}

func (ur *UnicastRoute) Attributes() map[BGPAttribute]string {
	attr := maps.Clone(ur.Additional)
	attr[AttrPrefix] = ur.Cidr.IP.String()
	attr[AttrPrefixLen] = strconv.Itoa(simpleMaskLength(ur.Cidr.Mask))
	attr[AttrNextHop] = ur.Nexthop.String()
	return attr
}

// If mask is a sequence of 1 bits followed by 0 bits,
// return the number of 1 bits.
func simpleMaskLength(mask net.IPMask) int {
	var n int
	for i, v := range mask {
		if v == 0xff {
			n += 8
			continue
		}
		// found non-ff byte
		// count 1 bits
		for v&0x80 != 0 {
			n++
			v <<= 1
		}
		// rest must be 0 bits
		if v != 0 {
			return -1
		}
		for i++; i < len(mask); i++ {
			if mask[i] != 0 {
				return -1
			}
		}
		break
	}
	return n
}
