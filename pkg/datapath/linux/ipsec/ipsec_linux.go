// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package ipsec

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/fswatcher"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/encrypt"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/nodediscovery"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

var Cell = cell.Module("ipsec", "IPSec",
	cell.Provide(NewManager),
)

type IPSecDir string

const (
	IPSecDirIn      IPSecDir = "IPSEC_IN"
	IPSecDirOut     IPSecDir = "IPSEC_OUT"
	IPSecDirBoth    IPSecDir = "IPSEC_BOTH"
	IPSecDirOutNode IPSecDir = "IPSEC_OUT_NODE"

	// Constants used to decode the IPsec secret in both formats:
	// 1. [spi] aead-algo aead-key icv-len
	// 2. [spi] auth-algo auth-key enc-algo enc-key [IP]
	offsetSPI      = 0
	offsetAeadAlgo = 1
	offsetAeadKey  = 2
	offsetICV      = 3
	offsetAuthAlgo = 1
	offsetAuthKey  = 2
	offsetEncAlgo  = 3
	offsetEncKey   = 4
	offsetIP       = 5
	maxOffset      = offsetIP

	// ipSecXfrmMarkSPIShift defines how many bits the SPI is shifted when
	// encoded in a XfrmMark
	ipSecXfrmMarkSPIShift = 12
)

type ipSecKey struct {
	Spi   uint8
	ReqID int
	Auth  *netlink.XfrmStateAlgo
	Crypt *netlink.XfrmStateAlgo
	Aead  *netlink.XfrmStateAlgo
}

type ManagerInterface interface {
	GetAuthKeySize() int
	GetCurrentKeySPI() uint8
	IpSecReplacePolicyFwd(dst *net.IPNet, tmplDst net.IP) error
	UpsertIPsecEndpoint(local *net.IPNet, remote *net.IPNet, outerLocal net.IP, outerRemote net.IP, dir IPSecDir, outputMark bool) (uint8, error)
	UpsertIPsecEndpointPolicy(local *net.IPNet, remote *net.IPNet, localTmpl net.IP, remoteTmpl net.IP, dir IPSecDir) error
}

func NewManager(
	lifecycle hive.Lifecycle,
	config *option.DaemonConfig,
	localNode node.LocalNodeStore,
	dpPromise promise.Promise[datapath.Datapath],
	nodeDiscovery promise.Promise[*nodediscovery.NodeDiscovery],
) (ManagerInterface, error) {
	return newManager(lifecycle, config, localNode, dpPromise, nodeDiscovery)
}

type Manager struct {
	ipSecLock lock.RWMutex

	// ipSecKeysGlobal can be accessed by multiple subsystems concurrently,
	// so it should be accessed only through the getIPSecKeys and
	// loadIPSecKeys functions, which will ensure the proper lock is held
	ipSecKeysGlobal map[string]*ipSecKey

	// ipSecCurrentKeySPI is the SPI of the IPSec currently in use
	ipSecCurrentKeySPI uint8

	// ipSecCurrentAuthKeySize is the size of the current key
	ipSecCurrentAuthKeySize int

	// ipSecKeysRemovalTime is used to track at which time a given key is
	// replaced with a newer one, allowing to reclaim old keys only after
	// enough time has passed since their replacement
	ipSecKeysRemovalTime map[uint8]time.Time
}

func newManager(
	lifecycle hive.Lifecycle,
	config *option.DaemonConfig,
	localNode node.LocalNodeStore,
	dpPromise promise.Promise[datapath.Datapath],
	nodeDiscovery promise.Promise[*nodediscovery.NodeDiscovery],
) (*Manager, error) {
	mgr := &Manager{
		ipSecKeysGlobal:      make(map[string]*ipSecKey),
		ipSecKeysRemovalTime: make(map[uint8]time.Time),
	}

	if !config.EncryptNode {
		lifecycle.Append(hive.Hook{
			OnStart: func(hc hive.HookContext) error {
				DeleteIPsecEncryptRoute()
				return nil
			},
		})
	}

	if !config.EnableIPSec {
		return mgr, nil
	}

	authKeySize, spi, err := mgr.loadIPSecKeysFile(config.IPSecKeyFile)
	if err != nil {
		return nil, err
	}
	mgr.ipSecCurrentAuthKeySize = authKeySize

	localNode.Update(func(n *node.LocalNode) {
		n.EncryptionKey = spi
	})

	reclaimerCtx, reclaimerCancel := context.WithCancel(context.Background())
	lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			go mgr.startStaleKeysReclaimer(reclaimerCtx)
			return nil
		},
		OnStop: func(hc hive.HookContext) error {
			reclaimerCancel()
			return nil
		},
	})

	watcherCtx, watcherCancel := context.WithCancel(context.Background())
	lifecycle.Append(hive.Hook{
		OnStart: func(hc hive.HookContext) error {
			go func() {
				ctx := context.Background()
				nd, err := nodeDiscovery.Await(ctx)
				if err != nil {
					return
				}

				dp, err := dpPromise.Await(ctx)
				if err != nil {
					return
				}

				mgr.startKeyfileWatcher(watcherCtx, config.IPSecKeyFile, nd, dp.Node())
			}()
			return nil
		},
		OnStop: func(hc hive.HookContext) error {
			watcherCancel()
			return nil
		},
	})

	return mgr, err
}

func (m *Manager) GetAuthKeySize() int {
	return m.ipSecCurrentAuthKeySize
}

func (m *Manager) GetCurrentKeySPI() uint8 {
	return m.ipSecCurrentKeySPI
}

func (m *Manager) getIPSecKeys(ip net.IP) *ipSecKey {
	m.ipSecLock.RLock()
	defer m.ipSecLock.RUnlock()

	key, scoped := m.ipSecKeysGlobal[ip.String()]
	if scoped == false {
		key, _ = m.ipSecKeysGlobal[""]
	}
	return key
}

func ipSecNewState() *netlink.XfrmState {
	state := netlink.XfrmState{
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Proto: netlink.XFRM_PROTO_ESP,
		ESN:   false,
	}
	return &state
}

func ipSecNewPolicy() *netlink.XfrmPolicy {
	policy := netlink.XfrmPolicy{}
	return &policy
}

func ipSecAttachPolicyTempl(policy *netlink.XfrmPolicy, keys *ipSecKey, srcIP, dstIP net.IP, spi bool, optional int) {
	tmpl := netlink.XfrmPolicyTmpl{
		Proto:    netlink.XFRM_PROTO_ESP,
		Mode:     netlink.XFRM_MODE_TUNNEL,
		Reqid:    keys.ReqID,
		Dst:      dstIP,
		Src:      srcIP,
		Optional: optional,
	}

	if spi {
		tmpl.Spi = int(keys.Spi)
	}

	policy.Tmpls = append(policy.Tmpls, tmpl)
}

func ipSecJoinState(state *netlink.XfrmState, keys *ipSecKey) {
	if keys.Aead != nil {
		state.Aead = keys.Aead
	} else {
		state.Crypt = keys.Crypt
		state.Auth = keys.Auth
	}
	state.Spi = int(keys.Spi)
	state.Reqid = keys.ReqID
}

func (m *Manager) ipSecReplaceStateIn(localIP, remoteIP net.IP, zeroMark bool) (uint8, error) {
	key := m.getIPSecKeys(remoteIP)
	if key == nil {
		return 0, fmt.Errorf("IPSec key missing")
	}
	state := ipSecNewState()
	ipSecJoinState(state, key)
	state.Src = remoteIP
	state.Dst = localIP
	state.Mark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkDecrypt,
		Mask:  linux_defaults.IPsecMarkMaskIn,
	}
	if !zeroMark {
		state.OutputMark = &netlink.XfrmMark{
			Value: linux_defaults.RouteMarkDecrypt,
			Mask:  linux_defaults.RouteMarkMask,
		}
	} else {
		state.OutputMark = &netlink.XfrmMark{
			Value: 0,
			Mask:  linux_defaults.RouteMarkMask,
		}
	}

	return key.Spi, netlink.XfrmStateAdd(state)
}

func (m *Manager) ipSecReplaceStateOut(localIP, remoteIP net.IP) (uint8, error) {
	key := m.getIPSecKeys(localIP)
	if key == nil {
		return 0, fmt.Errorf("IPSec key missing")
	}
	state := ipSecNewState()
	ipSecJoinState(state, key)
	state.Src = localIP
	state.Dst = remoteIP
	state.Mark = &netlink.XfrmMark{
		Value: ipSecXfrmMarkSetSPI(linux_defaults.RouteMarkEncrypt, key.Spi),
		Mask:  linux_defaults.IPsecMarkMask,
	}
	state.OutputMark = &netlink.XfrmMark{
		Value: linux_defaults.RouteMarkEncrypt,
		Mask:  linux_defaults.RouteMarkMask,
	}
	return key.Spi, netlink.XfrmStateAdd(state)
}

func (m *Manager) _ipSecReplacePolicyInFwd(src, dst *net.IPNet, tmplSrc, tmplDst net.IP, proxyMark bool, dir netlink.Dir) error {
	optional := int(0)
	key := m.getIPSecKeys(dst.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}

	policy := ipSecNewPolicy()
	policy.Dir = dir
	policy.Dst = dst
	if dir == netlink.XFRM_DIR_IN {
		policy.Src = src
		policy.Mark = &netlink.XfrmMark{
			Mask: linux_defaults.IPsecMarkMaskIn,
		}
		if proxyMark {
			// We require a policy to match on packets going to the proxy which are
			// therefore carrying the proxy mark. We however don't need a policy
			// for the encrypted packets because there is already a state matching
			// them.
			policy.Mark.Value = linux_defaults.RouteMarkToProxy
			// We must mark the IN policy for the proxy optional simply because it
			// is lacking a corresponding state.
			optional = 1
			// We set the source tmpl address to 0/0 to explicit that it
			// doesn't matter.
			tmplSrc = net.ParseIP("0.0.0.0")
		} else {
			policy.Mark.Value = linux_defaults.RouteMarkDecrypt
		}
	}
	// We always make forward rules optional. The only reason we have these
	// at all is to appease the XFRM route hooks, we don't really care about
	// policy because Cilium BPF programs do that.
	if dir == netlink.XFRM_DIR_FWD {
		optional = 1
		policy.Priority = linux_defaults.IPsecFwdPriority
		// In case of fwd policies, we should tell the kernel the tmpl src
		// doesn't matter; we want all fwd packets to go through.
		tmplSrc = net.ParseIP("0.0.0.0")
		policy.Src = &net.IPNet{IP: tmplSrc, Mask: net.IPv4Mask(0, 0, 0, 0)}
	}
	ipSecAttachPolicyTempl(policy, key, tmplSrc, tmplDst, false, optional)
	return netlink.XfrmPolicyUpdate(policy)
}

func (m *Manager) ipSecReplacePolicyIn(src, dst *net.IPNet, tmplSrc, tmplDst net.IP) error {
	if err := m._ipSecReplacePolicyInFwd(src, dst, tmplSrc, tmplDst, true, netlink.XFRM_DIR_IN); err != nil {
		return err
	}
	return m._ipSecReplacePolicyInFwd(src, dst, tmplSrc, tmplDst, false, netlink.XFRM_DIR_IN)
}

func (m *Manager) IpSecReplacePolicyFwd(dst *net.IPNet, tmplDst net.IP) error {
	// The source CIDR and IP aren't used in the case of FWD policies.
	return m._ipSecReplacePolicyInFwd(nil, dst, net.IP{}, tmplDst, false, netlink.XFRM_DIR_FWD)
}

// ipSecXfrmMarkSetSPI takes a XfrmMark base value, an SPI, returns the mark
// value with the SPI value encoded in it
func ipSecXfrmMarkSetSPI(markValue uint32, spi uint8) uint32 {
	return markValue | (uint32(spi) << ipSecXfrmMarkSPIShift)
}

// ipSecXfrmMarkGetSPI extracts from a XfrmMark value the encoded SPI
func ipSecXfrmMarkGetSPI(markValue uint32) uint8 {
	return uint8(markValue >> ipSecXfrmMarkSPIShift & 0xF)
}

func getSPIFromXfrmPolicy(policy *netlink.XfrmPolicy) uint8 {
	if policy.Mark == nil {
		return 0
	}

	return ipSecXfrmMarkGetSPI(policy.Mark.Value)
}

func (m *Manager) ipSecReplacePolicyOut(src, dst *net.IPNet, tmplSrc, tmplDst net.IP, dir IPSecDir) error {
	// TODO: Remove old policy pointing to target net

	key := m.getIPSecKeys(dst.IP)
	if key == nil {
		return fmt.Errorf("IPSec key missing")
	}

	policy := ipSecNewPolicy()
	if dir == IPSecDirOutNode {
		wildcardIP := net.ParseIP("0.0.0.0")
		wildcardMask := net.IPv4Mask(0, 0, 0, 0)
		policy.Src = &net.IPNet{IP: wildcardIP, Mask: wildcardMask}
	} else {
		policy.Src = src
	}
	policy.Dst = dst
	policy.Dir = netlink.XFRM_DIR_OUT
	policy.Mark = &netlink.XfrmMark{
		Value: ipSecXfrmMarkSetSPI(linux_defaults.RouteMarkEncrypt, key.Spi),
		Mask:  linux_defaults.IPsecMarkMask,
	}
	ipSecAttachPolicyTempl(policy, key, tmplSrc, tmplDst, true, 0)
	return netlink.XfrmPolicyUpdate(policy)
}

func ipsecDeleteXfrmState(ip net.IP) {
	scopedLog := log.WithFields(logrus.Fields{
		"remote-ip": ip,
	})

	xfrmStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		scopedLog.WithError(err).Warning("deleting xfrm state, xfrm state list error")
		return
	}
	for _, s := range xfrmStateList {
		if ip.Equal(s.Dst) {
			if err := netlink.XfrmStateDel(&s); err != nil {
				scopedLog.WithError(err).Warning("deleting xfrm state failed")
			}
		}
	}
}

func ipsecDeleteXfrmPolicy(ip net.IP) {
	scopedLog := log.WithFields(logrus.Fields{
		"remote-ip": ip,
	})

	xfrmPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		scopedLog.WithError(err).Warning("deleting policy state, xfrm policy list error")
	}
	for _, p := range xfrmPolicyList {
		if ip.Equal(p.Dst.IP) {
			if err := netlink.XfrmPolicyDel(&p); err != nil {
				scopedLog.WithError(err).Warning("deleting xfrm policy failed")
			}
		}
	}
}

/* UpsertIPsecEndpoint updates the IPSec context for a new endpoint inserted in
 * the ipcache. Currently we support a global crypt/auth keyset that will encrypt
 * all traffic between endpoints. An IPSec context consists of two pieces a policy
 * and a state, the security policy database (SPD) and security association
 * database (SAD). These are implemented using the Linux kernels XFRM implementation.
 *
 * For all traffic that matches a policy, the policy tuple used is
 * (sip/mask, dip/mask, dev) with an optional mark field used in the Cilium implementation
 * to ensure only expected traffic is encrypted. The state hashtable is searched for
 * a matching state associated with that flow. The Linux kernel will do a series of
 * hash lookups to find the most specific state (xfrm_dst) possible. The hash keys searched are
 * the following, (daddr, saddr, reqid, encap_family), (daddr, wildcard, reqid, encap),
 * (mark, daddr, spi, proto, encap). Any "hits" in the hash table will subsequently
 * have the SPI checked to ensure it also matches. Encap is ignored in our case here
 * and can be used with UDP encap if wanted.
 *
 * The implications of the (inflexible!) hash key implementation is that in-order
 * to have a policy/state match we _must_ insert a state for each daddr. For Cilium
 * this translates to a state entry per node. We learn the nodes/endpoints by
 * listening to ipcache events. Finally, because IPSec is unidirectional a state
 * is needed for both ingress and egress. Denoted by the DIR on the xfrm cmd line
 * in the policy lookup. In the Cilium case, where we have IPSec between all
 * endpoints this results in two policy rules per node, one for ingress
 * and one for egress.
 *
 * For a concrete example consider two cluster nodes using transparent mode e.g.
 * without an IPSec tunnel IP. Cluster Node A has host_ip 10.156.0.1 with an
 * endpoint assigned to IP 10.156.2.2 and cluster Node B has host_ip 10.182.0.1
 * with an endpoint using IP 10.182.3.3. Then on Node A there will be a two policy
 * entries and a set of State entries,
 *
 * Policy1(src=10.182.0.0/16,dst=10.156.0.1/16,dir=in,tmpl(spi=#spi,reqid=#reqid))
 * Policy2(src=10.156.0.0/16,dst=10.182.0.1/16,dir=out,tmpl(spi=#spi,reqid=#reqid))
 * State1(src=*,dst=10.182.0.1,spi=#spi,reqid=#reqid,...)
 * State2(src=*,dst=10.156.0.1,spi=#spi,reqid=#reqid,...)
 *
 * Design Note: For newer kernels a BPF xfrm interface would greatly simplify the
 * state space. Basic idea would be to reference a state using any key generated
 * from BPF program allowing for a single state per security ctx.
 */
func (m *Manager) UpsertIPsecEndpoint(local, remote *net.IPNet, outerLocal, outerRemote net.IP, dir IPSecDir, outputMark bool) (uint8, error) {
	var spi uint8
	var err error

	/* TODO: state reference ID is (dip,spi) which can be duplicated in the current global
	 * mode. The duplication is on _all_ ingress states because dst_ip == host_ip in this
	 * case and only a single spi entry is in use. Currently no check is done to avoid
	 * attempting to add duplicate (dip,spi) states and we get 'file exist' error. These
	 * errors are expected at the moment but perhaps it would be better to avoid calling
	 * netlink API at all when we "know" an entry is a duplicate. To do this the xfer
	 * state would need to be cached in the ipcache.
	 */
	if !outerLocal.Equal(outerRemote) {
		if dir == IPSecDirIn || dir == IPSecDirBoth {
			if spi, err = m.ipSecReplaceStateIn(outerLocal, outerRemote, outputMark); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace local state: %s", err)
				}
			}
			if err = m.ipSecReplacePolicyIn(remote, local, outerRemote, outerLocal); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy in: %s", err)
				}
			}
			if err = m.IpSecReplacePolicyFwd(local, outerLocal); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy fwd: %s", err)
				}
			}
		}

		if dir == IPSecDirOut || dir == IPSecDirOutNode || dir == IPSecDirBoth {
			if spi, err = m.ipSecReplaceStateOut(outerLocal, outerRemote); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace remote state: %s", err)
				}
			}

			if err = m.ipSecReplacePolicyOut(local, remote, outerLocal, outerRemote, dir); err != nil {
				if !os.IsExist(err) {
					return 0, fmt.Errorf("unable to replace policy out: %s", err)
				}
			}
		}
	}
	return spi, nil
}

// UpsertIPsecEndpointPolicy adds a policy to the xfrm rules. Used to add a policy when the state
// rule is already available.
func (m *Manager) UpsertIPsecEndpointPolicy(local, remote *net.IPNet, localTmpl, remoteTmpl net.IP, dir IPSecDir) error {
	if err := m.ipSecReplacePolicyOut(local, remote, localTmpl, remoteTmpl, dir); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("unable to replace templated policy out: %s", err)
		}
	}
	return nil
}

// DeleteIPsecEndpoint deletes a endpoint associated with the remote IP address
func DeleteIPsecEndpoint(remote net.IP) {
	ipsecDeleteXfrmState(remote)
	ipsecDeleteXfrmPolicy(remote)
}

func isXfrmPolicyCilium(policy netlink.XfrmPolicy) bool {
	if policy.Mark == nil {
		// Check if its our fwd rule, we don't have a mark
		// on this rule so use priority.
		if policy.Dir == netlink.XFRM_DIR_FWD &&
			policy.Priority == linux_defaults.IPsecFwdPriority {
			return true
		}
		return false
	}

	if (policy.Mark.Value & linux_defaults.RouteMarkDecrypt) != 0 {
		return true
	}
	if (policy.Mark.Value & linux_defaults.RouteMarkEncrypt) != 0 {
		return true
	}
	return false
}

func isXfrmStateCilium(state netlink.XfrmState) bool {
	if state.Mark == nil {
		return false
	}
	if (state.Mark.Value & linux_defaults.RouteMarkDecrypt) != 0 {
		return true
	}
	if (state.Mark.Value & linux_defaults.RouteMarkEncrypt) != 0 {
		return true
	}
	return false
}

// DeleteXfrm remove any remaining XFRM policy or state from tables
func DeleteXfrm() {
	xfrmPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err == nil {
		for _, p := range xfrmPolicyList {
			if isXfrmPolicyCilium(p) {
				if err := netlink.XfrmPolicyDel(&p); err != nil {
					log.WithError(err).Warning("deleting xfrm policy failed")
				}
			}
		}
	}
	xfrmStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err == nil {
		for _, s := range xfrmStateList {
			if isXfrmStateCilium(s) {
				if err := netlink.XfrmStateDel(&s); err != nil {
					log.WithError(err).Warning("deleting old xfrm state failed")
				}
			}
		}
	}
}

func decodeIPSecKey(keyRaw string) (int, []byte, error) {
	// As we have released the v1.4.0 docs telling the users to write the
	// k8s secret with the prefix "0x" we have to remove it if it is present,
	// so we can decode the secret.
	if keyRaw == "\"\"" {
		return 0, nil, nil
	}
	keyTrimmed := strings.TrimPrefix(keyRaw, "0x")
	key, err := hex.DecodeString(keyTrimmed)
	return len(keyTrimmed), key, err
}

// loadIPSecKeysFile imports IPSec auth and crypt keys from a file. The format
// is to put a key per line as follows, (auth-algo auth-key enc-algo enc-key)
// Returns the authentication overhead in bytes, the key ID, and an error.
func (m *Manager) loadIPSecKeysFile(path string) (int, uint8, error) {
	log.WithField(logfields.Path, path).Info("Loading IPsec keyfile")

	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	return m.loadIPSecKeys(file)
}

func (m *Manager) loadIPSecKeys(r io.Reader) (int, uint8, error) {
	var spi uint8
	var keyLen int
	scopedLog := log

	m.ipSecLock.Lock()
	defer m.ipSecLock.Unlock()

	if err := encrypt.MapCreate(); err != nil {
		return 0, 0, fmt.Errorf("Encrypt map create failed: %v", err)
	}

	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		var oldSpi uint8
		var aeadKey, authKey []byte
		offsetBase := 0

		ipSecKey := &ipSecKey{
			ReqID: 1,
		}

		// Scanning IPsec keys with one of the following formats:
		// 1. [spi] aead-algo aead-key icv-len
		// 2. [spi] auth-algo auth-key enc-algo enc-key [IP]
		s := strings.Split(scanner.Text(), " ")
		if len(s) < 3 {
			// Regardless of the format used, the IPsec secret should have at
			// least 3 fields separated by white spaces.
			return 0, 0, fmt.Errorf("missing IPSec key or invalid format")
		}

		spiI, err := strconv.Atoi(s[offsetSPI])
		if err != nil {
			// If no version info is provided assume using key format without
			// versioning and assign SPI.
			log.Warning("IPsec secrets without an SPI as the first argument are deprecated and will be unsupported in v1.13.")
			spiI = 1
			offsetBase = -1
		}
		if spiI > linux_defaults.IPsecMaxKeyVersion {
			return 0, 0, fmt.Errorf("encryption key space exhausted. ID must be nonzero and less than %d. Attempted %q", linux_defaults.IPsecMaxKeyVersion+1, s[offsetSPI])
		}
		if spiI == 0 {
			return 0, 0, fmt.Errorf("zero is not a valid key ID. ID must be nonzero and less than %d. Attempted %q", linux_defaults.IPsecMaxKeyVersion+1, s[offsetSPI])
		}
		spi = uint8(spiI)

		if len(s) > offsetBase+maxOffset+1 {
			return 0, 0, fmt.Errorf("invalid format: too many fields in the IPsec secret")
		} else if len(s) == offsetBase+offsetICV+1 {
			// We're in the first case, with "[spi] aead-algo aead-key icv-len".
			aeadName := s[offsetBase+offsetAeadAlgo]
			if !strings.HasPrefix(aeadName, "rfc") {
				return 0, 0, fmt.Errorf("invalid AEAD algorithm %q", aeadName)
			}

			_, aeadKey, err = decodeIPSecKey(s[offsetBase+offsetAeadKey])
			if err != nil {
				return 0, 0, fmt.Errorf("unable to decode AEAD key string %q", s[offsetBase+offsetAeadKey])
			}

			icvLen, err := strconv.Atoi(s[offsetICV+offsetBase])
			if err != nil {
				return 0, 0, fmt.Errorf("ICV length is invalid or missing")
			}

			if icvLen != 96 && icvLen != 128 && icvLen != 256 {
				return 0, 0, fmt.Errorf("only ICV lengths 96, 128, and 256 are accepted")
			}

			ipSecKey.Aead = &netlink.XfrmStateAlgo{
				Name:   aeadName,
				Key:    aeadKey,
				ICVLen: icvLen,
			}
			keyLen = icvLen / 8
		} else {
			// We're in the second case, with "[spi] auth-algo auth-key enc-algo enc-key [IP]".
			authAlgo := s[offsetBase+offsetAuthAlgo]
			keyLen, authKey, err = decodeIPSecKey(s[offsetBase+offsetAuthKey])
			if err != nil {
				return 0, 0, fmt.Errorf("unable to decode authentication key string %q", s[offsetBase+offsetAuthKey])
			}

			encAlgo := s[offsetBase+offsetEncAlgo]
			_, encKey, err := decodeIPSecKey(s[offsetBase+offsetEncKey])
			if err != nil {
				return 0, 0, fmt.Errorf("unable to decode encryption key string %q", s[offsetBase+offsetEncKey])
			}

			ipSecKey.Auth = &netlink.XfrmStateAlgo{
				Name: authAlgo,
				Key:  authKey,
			}
			ipSecKey.Crypt = &netlink.XfrmStateAlgo{
				Name: encAlgo,
				Key:  encKey,
			}
		}

		ipSecKey.Spi = spi

		if len(s) == offsetBase+offsetIP+1 {
			// The IPsec secret has the optional IP address field at the end.
			log.Warning("IPsec secrets with an IP address as the last argument are deprecated and will be unsupported in v1.13.")
			if m.ipSecKeysGlobal[s[offsetBase+offsetIP]] != nil {
				oldSpi = m.ipSecKeysGlobal[s[offsetBase+offsetIP]].Spi
			}
			m.ipSecKeysGlobal[s[offsetBase+offsetIP]] = ipSecKey
		} else {
			if m.ipSecKeysGlobal[""] != nil {
				oldSpi = m.ipSecKeysGlobal[""].Spi
			}
			m.ipSecKeysGlobal[""] = ipSecKey
		}

		m.ipSecKeysRemovalTime[oldSpi] = time.Now()
		m.ipSecCurrentKeySPI = spi
	}
	if err := encrypt.MapUpdateContext(0, spi); err != nil {
		scopedLog.WithError(err).Warn("cilium_encrypt_state map updated failed:")
		return 0, 0, err
	}
	return keyLen, spi, nil
}

// DeleteIPsecEncryptRoute removes nodes in main routing table by walking
// routes and matching route protocol type.
func DeleteIPsecEncryptRoute() {
	filter := &netlink.Route{
		Protocol: route.EncryptRouteProtocol,
	}

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_PROTOCOL)
		if err != nil {
			log.WithError(err).Error("Unable to list direct routes")
			return
		}

		for _, rt := range routes {
			if err := netlink.RouteDel(&rt); err != nil {
				log.WithError(err).Warningf("Unable to delete direct node route %s", rt.String())
			}
		}
	}
}

func (m *Manager) keyfileWatcher(ctx context.Context, watcher *fswatcher.Watcher, keyfilePath string, nodediscovery *nodediscovery.NodeDiscovery, nodeHandler datapath.NodeHandler) {
	for {
		select {
		case event := <-watcher.Events:
			if !event.Op.Has(fsnotify.Create) || !event.Op.Has(fsnotify.Write) {
				continue
			}

			_, spi, err := m.loadIPSecKeysFile(keyfilePath)
			if err != nil {
				log.WithError(err).Errorf("Failed to load IPsec keyfile")
				continue
			}

			// Update the IPSec key identity in the local node.
			// This will set addrs.ipsecKeyIdentity in the node
			// package
			node.SetIPsecKeyIdentity(spi)

			// NodeValidateImplementation will eventually call
			// nodeUpdate(), which is responsible for updating the
			// IPSec policies and states for all the different EPs
			// with ipsec.UpsertIPsecEndpoint()
			nodeHandler.NodeValidateImplementation(*nodediscovery.LocalNode())

			// Publish the updated node information to k8s/KVStore
			nodediscovery.UpdateLocalNode()

		case err := <-watcher.Errors:
			log.WithError(err).WithField(logfields.Path, keyfilePath).
				Warning("Error encountered while watching file with fsnotify")

		case <-ctx.Done():
			watcher.Close()
			return
		}
	}
}

func (m *Manager) startKeyfileWatcher(ctx context.Context, keyfilePath string, nodediscovery *nodediscovery.NodeDiscovery, nodeHandler datapath.NodeHandler) error {
	watcher, err := fswatcher.New([]string{keyfilePath})
	if err != nil {
		return err
	}

	go m.keyfileWatcher(ctx, watcher, keyfilePath, nodediscovery, nodeHandler)

	return nil
}

// ipSecSPICanBeReclaimed is used to test whether a given SPI can be reclaimed
// or not (i.e. if it's not in use, and if not, if enough time has passed since
// when it was replaced by a newer one).
//
// In addition to the SPI, this function takes also a reclaimTimestamp
// parameter which represents the time at which we started reclaiming old keys.
// This is needed as we need to test the same SPI multiple times (since for any
// given SPI there are multiple policies and states associated with it), and we
// don't want to get inconsistent results because we are calling time.Now()
// directly in this function.
func (m *Manager) ipSecSPICanBeReclaimed(spi uint8, reclaimTimestamp time.Time) bool {
	// The SPI associated with the key currently in use should not be reclaimed
	if spi == m.ipSecCurrentKeySPI {
		return false
	}

	// Otherwise retrieve the time at which the key for the given SPI was removed
	keyRemovalTime, ok := m.ipSecKeysRemovalTime[spi]
	if !ok {
		// If not found in the keyRemovalTime map, assume the key was
		// deleted just now.
		// In this way if the agent gets restarted before an old key is
		// removed we will always wait at least IPsecKeyDeleteDelay time
		// before reclaiming it
		m.ipSecKeysRemovalTime[spi] = time.Now()

		return false
	}

	// If the key was deleted less than the IPSec key deletion delay
	// time ago, it should not be reclaimed
	if reclaimTimestamp.Sub(keyRemovalTime) < linux_defaults.IPsecKeyDeleteDelay {
		return false
	}

	return true
}

func (m *Manager) deleteStaleXfrmStates(reclaimTimestamp time.Time) {
	scopedLog := log.WithField(logfields.SPI, m.ipSecCurrentKeySPI)

	xfrmStateList, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		scopedLog.WithError(err).Warning("Failed to list XFRM states")
		return
	}

	for _, s := range xfrmStateList {
		stateSPI := uint8(s.Spi)

		if !m.ipSecSPICanBeReclaimed(stateSPI, reclaimTimestamp) {
			continue
		}

		scopedLog = log.WithField(logfields.OldSPI, stateSPI)

		scopedLog.Info("Deleting stale XFRM state")
		if err := netlink.XfrmStateDel(&s); err != nil {
			scopedLog.WithError(err).Warning("Deleting stale XFRM state failed")
		}
	}
}

func (m *Manager) deleteStaleXfrmPolicies(reclaimTimestamp time.Time) {
	scopedLog := log.WithField(logfields.SPI, m.ipSecCurrentKeySPI)

	xfrmPolicyList, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		scopedLog.WithError(err).Warning("Failed to list XFRM policies")
		return
	}

	for _, p := range xfrmPolicyList {
		policySPI := getSPIFromXfrmPolicy(&p)

		if !m.ipSecSPICanBeReclaimed(policySPI, reclaimTimestamp) {
			continue
		}

		// Only OUT XFRM policies depend on the SPI
		if p.Dir != netlink.XFRM_DIR_OUT {
			continue
		}

		scopedLog = log.WithField(logfields.OldSPI, policySPI)

		scopedLog.Info("Deleting stale XFRM policy")
		if err := netlink.XfrmPolicyDel(&p); err != nil {
			scopedLog.WithError(err).Warning("Deleting stale XFRM policy failed")
		}
	}
}

func (m *Manager) doReclaimStaleKeys() {
	m.ipSecLock.Lock()
	defer m.ipSecLock.Unlock()

	// In case no IPSec key has been loaded yet, don't try to reclaim any
	// old key
	if m.ipSecCurrentKeySPI == 0 {
		return
	}

	reclaimTimestamp := time.Now()

	m.deleteStaleXfrmStates(reclaimTimestamp)
	m.deleteStaleXfrmPolicies(reclaimTimestamp)
}

func (m *Manager) startStaleKeysReclaimer(ctx context.Context) {
	timer, timerDone := inctimer.New()

	go func() {
		for {
			select {
			case <-timer.After(1 * time.Minute):
				m.doReclaimStaleKeys()
			case <-ctx.Done():
				timerDone()
				return
			}
		}
	}()
}
