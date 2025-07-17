package reconciler

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

type RouteOwner struct {
	name          string
	id            uint32
	adminDistance int
}

type TableID uint32

const (
	TableMain  TableID = 254
	TableLocal TableID = 255
)

type Scope uint8

const (
	SCOPE_UNIVERSE Scope = 0
	SCOPE_SITE     Scope = 200
	SCOPE_LINK     Scope = 253
	SCOPE_HOST     Scope = 254
	SCOPE_NOWHERE  Scope = 255
)

func (s Scope) String() string {
	switch s {
	case SCOPE_UNIVERSE:
		return "universe"
	case SCOPE_SITE:
		return "site"
	case SCOPE_LINK:
		return "link"
	case SCOPE_HOST:
		return "host"
	case SCOPE_NOWHERE:
		return "nowhere"
	default:
		return "unknown"
	}
}

type Type uint8

const (
	RTN_UNSPEC      Type = 0x0
	RTN_UNICAST     Type = 0x1
	RTN_LOCAL       Type = 0x2
	RTN_BROADCAST   Type = 0x3
	RTN_ANYCAST     Type = 0x4
	RTN_MULTICAST   Type = 0x5
	RTN_BLACKHOLE   Type = 0x6
	RTN_UNREACHABLE Type = 0x7
	RTN_PROHIBIT    Type = 0x8
	RTN_THROW       Type = 0x9
	RTN_NAT         Type = 0xa
	RTN_XRESOLVE    Type = 0xb
)

type Proto uint8

const (
	RTPROT_KERNEL  Proto = 2
	RTPROT_ENCRYPT Proto = 192
)

var _ statedb.TableWritable = &DesiredRoute{}

type DesiredRouteKey struct {
	Owner  *RouteOwner
	Table  TableID
	Prefix netip.Prefix
}

func (k DesiredRouteKey) Key() index.Key {
	key := index.Uint32(k.Owner.id)
	key = append(key, index.Uint32(uint32(k.Table))...)
	key = append(key, index.NetIPAddr(k.Prefix.Addr())...)
	key = append(key, uint8(k.Prefix.Bits()))
	return key
}

func (k DesiredRouteKey) TablePrefixKey() index.Key {
	key := index.Uint32(uint32(k.Table))
	key = append(key, index.NetIPAddr(k.Prefix.Addr())...)
	key = append(key, uint8(k.Prefix.Bits()))
	return key
}

type DesiredRoute struct {
	// Composite primary key for the route.
	Owner  *RouteOwner
	Table  TableID
	Prefix netip.Prefix

	// If true, the route is selected for installation, a calculated property.
	selected bool

	// Optional, if [netip.Addr.IsZero] then no nexthop is specified.
	Nexthop netip.Addr
	// Optional, if [netip.Addr.IsZero] then no source address is specified.
	Src netip.Addr
	// Required
	DeviceIfIndex uint32
	// Optional, if 0 no MTU is specified.
	MTU uint32
	// Optional, if 0 no priority is specified.
	Priority uint32
	// Optional, if 0 no protocol is specified.
	Proto Proto
	// Optional, if 0 no scope is specified.
	Scope Scope
	// Optional, if 0 no type is specified.
	Type Type

	status reconciler.Status
}

func (dr *DesiredRoute) TableHeader() []string {
	return []string{"Owner", "Table", "Prefix", "Selected"}
}

func (dr *DesiredRoute) TableRow() []string {
	return []string{
		dr.Owner.name,
		strconv.FormatUint(uint64(dr.Table), 10),
		dr.Prefix.String(),
		strconv.FormatBool(dr.selected),
	}
}

func (dr *DesiredRoute) GetStatus() reconciler.Status {
	return dr.status
}

func (dr *DesiredRoute) SetStatus(s reconciler.Status) *DesiredRoute {
	dr.status = s
	return dr
}

func (dr *DesiredRoute) Clone() *DesiredRoute {
	dr2 := *dr
	return &dr2
}

var (
	DesiredRouteIndex = statedb.Index[*DesiredRoute, DesiredRouteKey]{
		Name: "id",
		FromObject: func(d *DesiredRoute) index.KeySet {
			return index.NewKeySet(DesiredRouteKey{
				Owner:  d.Owner,
				Table:  d.Table,
				Prefix: d.Prefix,
			}.Key())
		},
		FromKey: DesiredRouteKey.Key,
		Unique:  true,
	}

	DesiredRouteOwnerIndex = statedb.Index[*DesiredRoute, *RouteOwner]{
		Name: "owner",
		FromObject: func(d *DesiredRoute) index.KeySet {
			return index.NewKeySet(index.Uint32(d.Owner.id))
		},
		FromKey: func(o *RouteOwner) index.Key {
			return index.Uint32(o.id)
		},
		FromString: index.Uint32String,
		Unique:     false,
	}

	DesiredRouteTablePrefixIndex = statedb.Index[*DesiredRoute, DesiredRouteKey]{
		Name: "table-prefix",
		FromObject: func(d *DesiredRoute) index.KeySet {
			return index.NewKeySet(DesiredRouteKey{
				Table:  d.Table,
				Prefix: d.Prefix,
			}.TablePrefixKey())
		},
		FromKey: DesiredRouteKey.TablePrefixKey,
		FromString: func(s string) (index.Key, error) {
			// The string is expected to be in the format "table:prefix"
			first, second, found := strings.Cut(s, ":")
			if !found {
				return nil, fmt.Errorf("bad key, expected \"table:prefix\", got %s", s)
			}

			table, err := strconv.ParseUint(first, 10, 32)
			if err != nil {
				return nil, err
			}

			prefix, err := netip.ParsePrefix(second)
			if err != nil {
				return nil, err
			}

			return DesiredRouteKey{
				Table:  TableID(table),
				Prefix: prefix,
			}.TablePrefixKey(), nil
		},
		Unique: false,
	}
)

func newDesiredRouteTable(db *statedb.DB) (*DesiredRouteManager, statedb.Table[*DesiredRoute], error) {
	tbl, err := statedb.NewTable(
		"desired-route",
		DesiredRouteIndex,
		DesiredRouteOwnerIndex,
		DesiredRouteTablePrefixIndex,
	)
	if err != nil {
		return nil, nil, err
	}

	return &DesiredRouteManager{
		tbl:        tbl,
		ownerIDCnt: 1,
	}, tbl, db.RegisterTable(tbl)
}
