// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/elf"
	"github.com/cilium/cilium/pkg/maps/callsmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	contextTimeout = 10 * time.Second
	benchTimeout   = 5*time.Minute + 5*time.Second

	bpfDir = filepath.Join("..", "..", "..", "bpf")
)

func initEndpoint(tb testing.TB, ep *testutils.TestEndpoint) {
	testutils.PrivilegedTest(tb)

	require.Nil(tb, rlimit.RemoveMemlock())

	ep.State = tb.TempDir()
	for _, iface := range []string{ep.InterfaceName(), defaults.SecondHostDevice} {
		link := netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: iface,
			},
		}
		if err := netlink.LinkAdd(&link); err != nil {
			if !os.IsExist(err) {
				tb.Fatalf("Failed to add link: %s", err)
			}
		}
		tb.Cleanup(func() {
			if err := netlink.LinkDel(&link); err != nil {
				tb.Fatalf("Failed to delete link: %s", err)
			}
		})
	}

	tb.Cleanup(func() {
		files, err := filepath.Glob("/sys/fs/bpf/tc/globals/test_*")
		require.Nil(tb, err)
		for _, f := range files {
			assert.Nil(tb, os.Remove(f))
		}
	})
}

func getDirs(tb testing.TB) *directoryInfo {
	return &directoryInfo{
		Library: bpfDir,
		Runtime: bpfDir,
		State:   bpfDir,
		Output:  tb.TempDir(),
	}
}

func getEpDirs(ep *testutils.TestEndpoint) *directoryInfo {
	return &directoryInfo{
		Library: bpfDir,
		Runtime: bpfDir,
		State:   ep.StateDir(),
		Output:  ep.StateDir(),
	}
}

func testCompileOrLoad(t *testing.T, ep *testutils.TestEndpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()
	stats := &metrics.SpanStat{}

	lctx := testLoaderContext()
	l := newTestLoader(t, lctx)
	err := l.compileOrLoad(ctx, ep, getEpDirs(ep), lctx, stats)
	require.NoError(t, err)
}

// TestCompileOrLoadDefaultEndpoint checks that the datapath can be compiled
// and loaded.
func TestCompileOrLoadDefaultEndpoint(t *testing.T) {
	ep := testutils.NewTestEndpoint()
	initEndpoint(t, &ep)
	testCompileOrLoad(t, &ep)
}

// TestCompileOrLoadHostEndpoint is the same as
// TestCompileAndLoadDefaultEndpoint, but for the host endpoint.
func TestCompileOrLoadHostEndpoint(t *testing.T) {

	callsmap.HostMapName = fmt.Sprintf("test_%s", callsmap.MapName)
	callsmap.NetdevMapName = fmt.Sprintf("test_%s", callsmap.MapName)

	hostEp := testutils.NewTestHostEndpoint()
	initEndpoint(t, &hostEp)

	testCompileOrLoad(t, &hostEp)
}

// TestReload compiles and attaches the datapath multiple times.
func TestReload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	ep := testutils.NewTestEndpoint()
	initEndpoint(t, &ep)

	dirInfo := getEpDirs(&ep)
	err := compileDatapath(ctx, dirInfo, false, log)
	require.NoError(t, err)

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	progs := []progDefinition{
		{progName: symbolFromEndpoint, direction: dirIngress},
		{progName: symbolToEndpoint, direction: dirEgress},
	}
	opts := replaceDatapathOptions{
		device:   ep.InterfaceName(),
		elf:      objPath,
		programs: progs,
		linkDir:  testutils.TempBPFFS(t),
		tcx:      true,
	}
	finalize, err := replaceDatapath(ctx, opts)
	require.NoError(t, err)
	finalize()

	finalize, err = replaceDatapath(ctx, opts)

	require.NoError(t, err)
	finalize()
}

func testCompileFailure(t *testing.T, ep *testutils.TestEndpoint) {
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	exit := make(chan struct{})
	defer close(exit)
	go func() {
		select {
		case <-time.After(100 * time.Millisecond):
			cancel()
		case <-exit:
			break
		}
	}()

	lctx := testLoaderContext()
	l := newTestLoader(t, lctx)
	timeout := time.Now().Add(contextTimeout)
	var err error
	stats := &metrics.SpanStat{}
	for err == nil && time.Now().Before(timeout) {
		err = l.compileOrLoad(ctx, ep, getEpDirs(ep), lctx, stats)
	}
	require.Error(t, err)
}

// TestCompileFailureDefaultEndpoint attempts to compile then cancels the
// context and ensures that the failure paths may be hit.
func TestCompileFailureDefaultEndpoint(t *testing.T) {
	ep := testutils.NewTestEndpoint()
	initEndpoint(t, &ep)
	testCompileFailure(t, &ep)
}

// TestCompileFailureHostEndpoint is the same as
// TestCompileFailureDefaultEndpoint, but for the host endpoint.
func TestCompileFailureHostEndpoint(t *testing.T) {
	hostEp := testutils.NewTestHostEndpoint()
	initEndpoint(t, &hostEp)
	testCompileFailure(t, &hostEp)
}

func TestBPFMasqAddrs(t *testing.T) {
	old4 := option.Config.EnableIPv4Masquerade
	option.Config.EnableIPv4Masquerade = true
	old6 := option.Config.EnableIPv4Masquerade
	option.Config.EnableIPv6Masquerade = true
	t.Cleanup(func() {
		option.Config.EnableIPv4Masquerade = old4
		option.Config.EnableIPv6Masquerade = old6
	})

	// Test without any addresses
	{
		lctx := testLoaderContext()
		l := newTestLoader(t, lctx)

		masq4, masq6 := l.bpfMasqAddrs(lctx, "test")
		require.Equal(t, masq4.IsValid(), false)
		require.Equal(t, masq6.IsValid(), false)
	}

	// Test with addresses
	{
		lctx := testLoaderContext()
		lctx.NodeAddrs = []tables.NodeAddress{
			{
				Addr:       netip.MustParseAddr("1.0.0.1"),
				NodePort:   true,
				Primary:    true,
				DeviceName: "test",
			},
			{
				Addr:       netip.MustParseAddr("1000::1"),
				NodePort:   true,
				Primary:    true,
				DeviceName: "test",
			},
			{
				Addr:       netip.MustParseAddr("2.0.0.2"),
				NodePort:   false,
				Primary:    true,
				DeviceName: tables.WildcardDeviceName,
			},
			{
				Addr:       netip.MustParseAddr("2000::2"),
				NodePort:   false,
				Primary:    true,
				DeviceName: tables.WildcardDeviceName,
			},
		}
		l := newTestLoader(t, lctx)

		masq4, masq6 := l.bpfMasqAddrs(lctx, "test")
		require.Equal(t, masq4.String(), "1.0.0.1")
		require.Equal(t, masq6.String(), "1000::1")

		masq4, masq6 = l.bpfMasqAddrs(lctx, "unknown")
		require.Equal(t, masq4.String(), "2.0.0.2")
		require.Equal(t, masq6.String(), "2000::2")
	}
}

// BenchmarkCompileOnly benchmarks the just the entire compilation process.
func BenchmarkCompileOnly(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	dirInfo := getDirs(b)
	option.Config.Debug = true

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := compileDatapath(ctx, dirInfo, false, log); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReplaceDatapath compiles the datapath program, then benchmarks only
// the loading of the program into the kernel.
func BenchmarkReplaceDatapath(b *testing.B) {
	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	ep := testutils.NewTestEndpoint()
	initEndpoint(b, &ep)

	dirInfo := getEpDirs(&ep)

	if err := compileDatapath(ctx, dirInfo, false, log); err != nil {
		b.Fatal(err)
	}

	objPath := fmt.Sprintf("%s/%s", dirInfo.Output, endpointObj)
	linkDir := testutils.TempBPFFS(b)
	progs := []progDefinition{{progName: symbolFromEndpoint, direction: dirIngress}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		finalize, err := replaceDatapath(ctx,
			replaceDatapathOptions{
				device:   ep.InterfaceName(),
				elf:      objPath,
				programs: progs,
				linkDir:  linkDir,
				tcx:      true,
			},
		)
		if err != nil {
			b.Fatal(err)
		}
		finalize()
	}
}

func TestSubstituteConfiguration(t *testing.T) {
	testutils.PrivilegedTest(t)

	ignorePrefixes := append(ignoredELFPrefixes, "test_cilium_policy")
	for _, p := range ignoredELFPrefixes {
		if strings.HasPrefix(p, "cilium_") {
			testPrefix := fmt.Sprintf("test_%s", p)
			ignorePrefixes = append(ignorePrefixes, testPrefix)
		}
	}
	elf.IgnoreSymbolPrefixes(ignorePrefixes)

	setupCompilationDirectories(t)

	ctx, cancel := context.WithTimeout(context.Background(), benchTimeout)
	defer cancel()

	ep := testutils.NewTestEndpoint()
	initEndpoint(t, &ep)

	option.Config.DryMode = true
	defer func() {
		option.Config.DryMode = false
	}()

	lctx := testLoaderContext()
	l := newTestLoader(t, lctx)
	stats := &metrics.SpanStat{}
	if err := l.CompileOrLoad(ctx, &ep, lctx, stats); err != nil {
		t.Fatal(err)
	}
}
