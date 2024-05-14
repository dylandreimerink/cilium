// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"io"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	loader "github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
)

var _ datapath.Datapath = (*FakeDatapath)(nil)

type FakeDatapath struct {
	node           *FakeNodeHandler
	nodeAddressing datapath.NodeAddressing
	lbmap          *mockmaps.LBMockMap
}

// NewDatapath returns a new fake datapath
func NewDatapath() *FakeDatapath {
	return NewDatapathWithNodeAddressing(NewNodeAddressing())
}

func NewDatapathWithNodeAddressing(na datapath.NodeAddressing) *FakeDatapath {
	return &FakeDatapath{
		node:           NewNodeHandler(),
		nodeAddressing: na,
		lbmap:          mockmaps.NewLBMockMap(),
	}
}

// Node returns a fake handler for node events
func (f *FakeDatapath) Node() datapath.NodeHandler {
	return f.node
}

func (f *FakeDatapath) NodeIDs() datapath.NodeIDHandler {
	return f.node
}

func (f *FakeDatapath) NodeNeighbors() datapath.NodeNeighbors {
	return f.node
}

func (f *FakeDatapath) FakeNode() *FakeNodeHandler {
	return f.node
}

// LocalNodeAddressing returns a fake node addressing implementation of the
// local node
func (f *FakeDatapath) LocalNodeAddressing() datapath.NodeAddressing {
	return f.nodeAddressing
}

// WriteNodeConfig pretends to write the datapath configuration to the writer.
func (f *FakeDatapath) WriteNodeConfig(io.Writer, *datapath.LocalNodeConfiguration) error {
	return nil
}

// WriteNetdevConfig pretends to write the netdev configuration to a writer.
func (f *FakeDatapath) WriteNetdevConfig(io.Writer, *option.IntOptions) error {
	return nil
}

// WriteTemplateConfig pretends to write the endpoint configuration to a writer.
func (f *FakeDatapath) WriteTemplateConfig(io.Writer, datapath.EndpointConfiguration) error {
	return nil
}

// WriteEndpointConfig pretends to write the endpoint configuration to a writer.
func (f *FakeDatapath) WriteEndpointConfig(io.Writer, datapath.EndpointConfiguration) error {
	return nil
}

func (f *FakeDatapath) InstallProxyRules(uint16, bool, string) {
}

func (f *FakeDatapath) SupportsOriginalSourceAddr() bool {
	return false
}

func (m *FakeDatapath) GetProxyPort(name string) uint16 {
	return 0
}

func (m *FakeDatapath) InstallNoTrackRules(ip netip.Addr, port uint16) {
}

func (m *FakeDatapath) RemoveNoTrackRules(ip netip.Addr, port uint16) {
}

func (f *FakeDatapath) WireguardAgent() datapath.WireguardAgent {
	return nil
}

func (f *FakeDatapath) LBMap() datapath.LBMap {
	return f.lbmap
}

func (f *FakeDatapath) LBMockMap() *mockmaps.LBMockMap {
	return f.lbmap
}

func (f *FakeDatapath) BandwidthManager() datapath.BandwidthManager {
	return &BandwidthManager{}
}

func (f *FakeDatapath) Orchestrator() datapath.Orchestrator {
	return &FakeOrchestrator{}
}

// Loader is an interface to abstract out loading of datapath programs.
type FakeLoader struct {
}

var _ loader.Loader = &FakeLoader{}

func (f *FakeLoader) CompileOrLoad(ctx context.Context, ep datapath.Endpoint, lctx loader.LoaderContext, stats *metrics.SpanStat) error {
	panic("implement me")
}

func (f *FakeLoader) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, lctx loader.LoaderContext, stats *metrics.SpanStat) error {
	panic("implement me")
}

func (f *FakeLoader) ReinitializeXDP(ctx context.Context, extraCArgs []string, lctx loader.LoaderContext) error {
	panic("implement me")
}

func (f *FakeLoader) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	panic("implement me")
}

func (f *FakeLoader) Unload(ep datapath.Endpoint) {
}

func (f *FakeLoader) CallsMapPath(id uint16) string {
	return ""
}

func (f *FakeLoader) CustomCallsMapPath(id uint16) string {
	return ""
}

func (f *FakeLoader) DetachXDP(iface netlink.Link, bpffsBase, progName string) error {
	return nil
}

func (f *FakeLoader) ELFSubstitutions(ep datapath.Endpoint) (map[string]uint64, map[string]string) {
	return nil, nil
}

// Reinitialize does nothing.
func (f *FakeLoader) Reinitialize(ctx context.Context, tunnelConfig tunnel.Config, deviceMTU int, iptMgr datapath.IptablesManager, p datapath.Proxy, lctx loader.LoaderContext) error {
	return nil
}

func (f *FakeLoader) HostDatapathInitialized() <-chan struct{} {
	return nil
}

func (f *FakeLoader) RestoreTemplates(stateDir string) error {
	return nil
}

type FakeOrchestrator struct{}

func (f *FakeOrchestrator) Reinitialize(ctx context.Context) error {
	return nil
}

func (f *FakeOrchestrator) CompileAndLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	return nil
}

func (f *FakeOrchestrator) CompileOrLoad(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	return nil
}

func (f *FakeOrchestrator) ReloadDatapath(ctx context.Context, ep datapath.Endpoint, stats *metrics.SpanStat) error {
	return nil
}

func (f *FakeOrchestrator) ReinitializeXDP(ctx context.Context, extraCArgs []string) error {
	return nil
}

func (f *FakeOrchestrator) EndpointHash(cfg datapath.EndpointConfiguration) (string, error) {
	return "", nil
}

func (f *FakeOrchestrator) Unload(ep datapath.Endpoint) {
}
