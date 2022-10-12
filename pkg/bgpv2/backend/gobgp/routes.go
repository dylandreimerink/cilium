package gobgp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/bgpv2/backend"

	"github.com/davecgh/go-spew/spew"
	gobgp "github.com/osrg/gobgp/v3/api"
	"golang.org/x/exp/maps"
	apb "google.golang.org/protobuf/types/known/anypb"
)

type AdvertisementMap struct {
	outer map[afiSafi]map[routeKey]*Advertisement
}

func newAdvertisementMap() AdvertisementMap {
	return AdvertisementMap{
		outer: make(map[afiSafi]map[routeKey]*Advertisement),
	}
}

func (am *AdvertisementMap) inner(afiSafi afiSafi) map[routeKey]*Advertisement {
	inner, found := am.outer[afiSafi]
	if !found {
		inner = make(map[routeKey]*Advertisement)
		am.outer[afiSafi] = inner
	}
	return inner
}

func (am *AdvertisementMap) GetByKey(afiSafi afiSafi, key routeKey) *Advertisement {
	inner := am.inner(afiSafi)
	return inner[key]
}

func (am *AdvertisementMap) Set(advert *Advertisement) {
	inner := am.inner(routeAfiSafi(advert.Route))
	inner[genRouteKey(advert.Route)] = advert
}

func (am *AdvertisementMap) Delete(advert *Advertisement) {
	inner := am.inner(routeAfiSafi(advert.Route))
	delete(inner, genRouteKey(advert.Route))
}

func (am *AdvertisementMap) ForEach(fn func(advert *Advertisement) error) error {
	for _, inner := range am.outer {
		for _, advert := range inner {
			if err := fn(advert); err != nil {
				return err
			}
		}
	}

	return nil
}

type Advertisement struct {
	Route backend.BGPRoute
	Path  *gobgp.Path
}

func (m *Manager) ListRoutes() []backend.BGPRoute {
	// TODO replace with a query based function, this is inefficient
	var routes []backend.BGPRoute
	for _, speaker := range m.serverMap {
		speaker.Advertisements.ForEach(func(advert *Advertisement) error {
			routes = append(routes, advert.Route)
			return nil
		})
	}
	return routes
}

func (m *Manager) UpsertRoute(route backend.BGPRoute) error {
	spew.Dump(route)

	speakerKey := route.Speaker()
	server := m.serverMap[speakerKey]
	if server == nil {
		return fmt.Errorf("no speaker for route")
	}

	key := genRouteKey(route)
	if key == "" {
		return fmt.Errorf("Unable to generate route key")
	}

	advert := server.Advertisements.GetByKey(routeAfiSafi(route), key)
	if advert != nil {
		// The existing route and the given are the same, no work is needed
		if maps.Equal(advert.Route.Attributes(), route.Attributes()) {
			return nil
		}

		// Delete existing path before adding the new path
		err := server.Server.DeletePath(context.TODO(), &gobgp.DeletePathRequest{
			Family: &gobgp.Family{
				Afi:  gobgp.Family_Afi(route.AFI()),
				Safi: gobgp.Family_Safi(route.SAFI()),
			},
			Path: advert.Path,
		})
		if err != nil {
			return fmt.Errorf("delete path: %w", err)
		}
	}

	path, err := parseRoute(route)
	if err != nil {
		return fmt.Errorf("parseRoute: %w", err)
	}

	if advert == nil {
		advert = &Advertisement{
			Route: route,
			Path:  path,
		}
	}

	resp, err := server.Server.AddPath(context.TODO(), &gobgp.AddPathRequest{
		Path: path,
	})
	if err != nil {
		return fmt.Errorf("add path: %w", err)
	}

	advert.Path.Uuid = resp.GetUuid()

	server.Advertisements.Set(advert)

	return nil
}

func (m *Manager) DeleteRoute(route backend.BGPRoute) error {
	speakerKey := route.Speaker()
	server := m.serverMap[speakerKey]
	if server == nil {
		return fmt.Errorf("no speaker for route")
	}

	key := genRouteKey(route)
	if key == "" {
		return fmt.Errorf("Unable to generate route key")
	}

	advert := server.Advertisements.GetByKey(routeAfiSafi(route), key)
	if advert == nil {
		// Can't find given route, nothing to do.
		return nil
	}

	// Delete existing path before adding the new path
	err := server.Server.DeletePath(context.TODO(), &gobgp.DeletePathRequest{
		Family: &gobgp.Family{
			Afi:  gobgp.Family_Afi(route.AFI()),
			Safi: gobgp.Family_Safi(route.SAFI()),
		},
		Path: advert.Path,
	})
	if err != nil {
		return fmt.Errorf("delete path: %w", err)
	}

	server.Advertisements.Delete(advert)

	return nil
}

type afiSafi struct {
	afi  int32
	safi int32
}

var (
	IPv4Unicast = afiSafi{afi: int32(gobgp.Family_AFI_IP), safi: int32(gobgp.Family_SAFI_UNICAST)}
	IPv6Unicast = afiSafi{afi: int32(gobgp.Family_AFI_IP6), safi: int32(gobgp.Family_SAFI_UNICAST)}
)

func routeAfiSafi(route backend.BGPRoute) afiSafi {
	return afiSafi{afi: route.AFI(), safi: route.SAFI()}
}

type routeParser func(route backend.BGPRoute) (*gobgp.Path, error)

var routeParsers = map[afiSafi]routeParser{
	IPv4Unicast: ipv4UnicastParser,
	IPv6Unicast: ipv6UnicastParser,
}

func parseRoute(route backend.BGPRoute) (*gobgp.Path, error) {
	afiSafi := routeAfiSafi(route)
	parser, found := routeParsers[afiSafi]
	if !found {
		return nil, fmt.Errorf("No parser for AFI: %d, SAFI: %d", afiSafi.afi, afiSafi.safi)
	}
	return parser(route)
}

func ipv4UnicastParser(route backend.BGPRoute) (*gobgp.Path, error) {
	attr := route.Attributes()
	prefix := attr[backend.AttrPrefix]
	if prefix == "" {
		return nil, fmt.Errorf("Prefix attribute is required for IPv4 Unicast route")
	}

	prefixLenStr := attr[backend.AttrPrefixLen]
	if prefixLenStr == "" {
		return nil, fmt.Errorf("Prefix attribute is required for IPv4 Unicast route")
	}
	prefixLen, err := strconv.Atoi(prefixLenStr)
	if err != nil {
		return nil, fmt.Errorf("PrefixLen Atoi: %w", err)
	}

	nextHop := attr[backend.AttrNextHop]
	if nextHop == "" {
		return nil, fmt.Errorf("NextHop attribute is required for IPv4 Unicast route")
	}

	nlri, _ := apb.New(&gobgp.IPAddressPrefix{
		PrefixLen: uint32(prefixLen),
		Prefix:    prefix,
	})

	var pattrs []*apb.Any

	// Origin communicates that this is a route we made ourself, not one received from another peer.
	origin, _ := apb.New(&gobgp.OriginAttribute{
		Origin: 0,
	})
	pattrs = append(pattrs, origin)

	extraAttrs, err := parseRouteAttributes(IPv4Unicast, attr)
	if err != nil {
		return nil, fmt.Errorf("parseRouteAttributes: %w", err)
	}
	pattrs = append(pattrs, extraAttrs...)

	path := &gobgp.Path{
		Family: GoBGPIPv4Family,
		Nlri:   nlri,
		Pattrs: pattrs,
	}

	return path, nil
}

func ipv6UnicastParser(route backend.BGPRoute) (*gobgp.Path, error) {
	attr := route.Attributes()
	prefix := attr[backend.AttrPrefix]
	if prefix == "" {
		return nil, fmt.Errorf("Prefix attribute is required for IPv6 Unicast route")
	}

	prefixLenStr := attr[backend.AttrPrefixLen]
	if prefixLenStr == "" {
		return nil, fmt.Errorf("Prefix attribute is required for IPv6 Unicast route")
	}
	prefixLen, err := strconv.Atoi(prefixLenStr)
	if err != nil {
		return nil, fmt.Errorf("PrefixLen Atoi: %w", err)
	}

	nextHop := attr[backend.AttrNextHop]
	if nextHop == "" {
		return nil, fmt.Errorf("NextHop attribute is required for IPv6 Unicast route")
	}

	nlri, _ := apb.New(&gobgp.IPAddressPrefix{
		PrefixLen: uint32(prefixLen),
		Prefix:    prefix,
	})

	var pattrs []*apb.Any

	// Origin communicates that this is a route we made ourself, not one received from another peer.
	origin, _ := apb.New(&gobgp.OriginAttribute{
		Origin: 0,
	})
	pattrs = append(pattrs, origin)

	nlriAttrs, _ := apb.New(&gobgp.MpReachNLRIAttribute{ // MP BGP NLRI
		Family:   GoBGPIPv6Family,
		NextHops: []string{nextHop},
		Nlris:    []*apb.Any{nlri},
	})
	pattrs = append(pattrs, nlriAttrs)

	extraAttrs, err := parseRouteAttributes(IPv4Unicast, attr)
	if err != nil {
		return nil, fmt.Errorf("parseRouteAttributes: %w", err)
	}
	pattrs = append(pattrs, extraAttrs...)

	path := &gobgp.Path{
		Family: GoBGPIPv6Family,
		Nlri:   nlri,
		Pattrs: pattrs,
	}

	return path, nil
}

type routeAttributeParser = func(value string) (*apb.Any, error)

var routeAttributeParsers = map[afiSafi]map[backend.BGPAttribute]routeAttributeParser{
	IPv4Unicast: {
		backend.AttrNextHop:         parseNextHop,
		backend.AttrMed:             parseMed,
		backend.AttrASPath:          parseASPath,
		backend.AttrCommunity:       parseCommunity,
		backend.AttrLargeCommunity:  parseLargeCommunity,
		backend.AttrLocalPreference: parseLocalPreference,
	},
	IPv6Unicast: {
		backend.AttrMed:             parseMed,
		backend.AttrASPath:          parseASPath,
		backend.AttrCommunity:       parseCommunity,
		backend.AttrLargeCommunity:  parseLargeCommunity,
		backend.AttrLocalPreference: parseLocalPreference,
	},
}

func parseRouteAttributes(afiSafi afiSafi, attr map[backend.BGPAttribute]string) ([]*apb.Any, error) {
	parsers := routeAttributeParsers[afiSafi]
	if parsers == nil {
		return nil, fmt.Errorf("No parsers for given AFI-SAFI")
	}

	var result []*apb.Any

	for k, v := range attr {
		parser, found := parsers[k]
		if !found {
			// Ignore missing parsers
			continue
		}

		parserRes, err := parser(v)
		if err != nil {
			return nil, fmt.Errorf("Attribute '%d': %w", k, err)
		}
		result = append(result, parserRes)
	}
	return result, nil
}

func parseNextHop(v string) (*apb.Any, error) {
	if net.ParseIP(v) == nil {
		return nil, fmt.Errorf("Next hop: '%v' is not an IP address", v)
	}

	nextHop, _ := apb.New(&gobgp.NextHopAttribute{
		NextHop: v,
	})

	return nextHop, nil
}

func parseMed(v string) (*apb.Any, error) {
	medValue, err := strconv.Atoi(v)
	if err != nil {
		return nil, fmt.Errorf("Med atoi: %w", err)
	}

	medAttr, _ := apb.New(&gobgp.MultiExitDiscAttribute{
		Med: uint32(medValue),
	})
	return medAttr, nil
}

func parseASPath(v string) (*apb.Any, error) {
	// The AS-PATH attributes is a comma separated list of ASN's (65000,65001,65002)
	// For now, we will only allow a user to input a single sequence.

	segment := &gobgp.AsSegment{
		Type: gobgp.AsSegment_AS_SEQUENCE,
	}
	for i, strSeg := range strings.Split(v, ",") {
		segNum, err := strconv.Atoi(strSeg)
		if err != nil {
			return nil, fmt.Errorf("ASPath seg '%d' atoi: %w", i, err)
		}

		segment.Numbers = append(segment.Numbers, uint32(segNum))
	}

	attr, _ := apb.New(&gobgp.AsPathAttribute{
		Segments: []*gobgp.AsSegment{segment},
	})
	return attr, nil
}

func parseCommunity(v string) (*apb.Any, error) {
	// The community attributes is formatted as a comma separated string containing BGP communities
	// which are two numbers separated by a colon, these are the upper and lower 16 bits of the
	// full 32 bit community (65001:0,65002:1).
	var communities []uint32
	for i, commStr := range strings.Split(v, ",") {
		commParts := strings.Split(commStr, ":")
		if len(commParts) != 2 {
			return nil, fmt.Errorf("Community index '%d': bad format, missing colon", i)
		}

		upper, err := strconv.Atoi(commParts[0])
		if err != nil {
			return nil, fmt.Errorf("Community index '%d' atoi: %w", i, err)
		}

		lower, err := strconv.Atoi(commParts[1])
		if err != nil {
			return nil, fmt.Errorf("Community index '%d' atoi: %w", i, err)
		}

		communities = append(communities, (uint32(upper)<<16)|uint32(lower))
	}

	attr, _ := apb.New(&gobgp.CommunitiesAttribute{
		Communities: communities,
	})
	return attr, nil
}

func parseLargeCommunity(v string) (*apb.Any, error) {
	// The large community attributes is formatted as a comma separated string containing BGP large communities
	// which are three numbers separated by a colons, the first is the "global administrator", second and
	// third the local data part 1 and 2. The first number is 32 bit, the second and last are 16 bit, together
	// making a 64 bit number. (64497:1:528,64497:1:392)
	var communities []*gobgp.LargeCommunity
	for i, commStr := range strings.Split(v, ",") {
		commParts := strings.Split(commStr, ":")
		if len(commParts) != 3 {
			return nil, fmt.Errorf("Community index '%d': bad format, missing colon", i)
		}

		admin, err := strconv.Atoi(commParts[0])
		if err != nil {
			return nil, fmt.Errorf("Community index '%d' atoi: %w", i, err)
		}

		part1, err := strconv.Atoi(commParts[1])
		if err != nil {
			return nil, fmt.Errorf("Community index '%d' atoi: %w", i, err)
		}

		part2, err := strconv.Atoi(commParts[2])
		if err != nil {
			return nil, fmt.Errorf("Community index '%d' atoi: %w", i, err)
		}

		communities = append(communities, &gobgp.LargeCommunity{
			GlobalAdmin: uint32(admin),
			LocalData1:  uint32(part1),
			LocalData2:  uint32(part2),
		})
	}

	attr, _ := apb.New(&gobgp.LargeCommunitiesAttribute{
		Communities: communities,
	})
	return attr, nil
}

func parseLocalPreference(v string) (*apb.Any, error) {
	localPref, err := strconv.Atoi(v)
	if err != nil {
		return nil, fmt.Errorf("Local pref atoi: %w", err)
	}

	attr, _ := apb.New(&gobgp.LocalPrefAttribute{
		LocalPref: uint32(localPref),
	})
	return attr, nil
}

type routeKey string

type routeKeyGen func(attr map[backend.BGPAttribute]string) routeKey

var routeKeyGenerators = map[afiSafi]routeKeyGen{
	IPv4Unicast: unicastKeyGen,
	IPv6Unicast: unicastKeyGen,
}

// genRouteKey returns a key that uniquely identifies this route within its route family(AFI-SAFI)
func genRouteKey(route backend.BGPRoute) routeKey {
	gen := routeKeyGenerators[routeAfiSafi(route)]
	if gen == nil {
		return ""
	}

	return gen(route.Attributes())
}

func unicastKeyGen(attr map[backend.BGPAttribute]string) routeKey {
	return routeKey(attr[backend.AttrPrefix] + "/" + attr[backend.AttrPrefixLen])
}
