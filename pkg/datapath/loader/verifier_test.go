// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/defaults"
)

var (
	flagCiliumRoot    = flag.String("cilium-root", "", "Cilium root path")
	flagKernelVersion = flag.String("kernel-version", kernelVersionNetNext.String(), "Kernel version to assume for verifier tests")
	flagResultFile    = flag.String("result-file", "verifier-complexity.json", "File to write the verifier results to")
)

func TestVerifier(t *testing.T) {
	if *flagKernelVersion == "" {
		t.Fatal("Kernel version must be specified")
	}
	kv, err := kernelVersionFromString(*flagKernelVersion)
	if err != nil {
		t.Fatalf("Invalid kernel version '%s': %v", *flagKernelVersion, err)
	}
	t.Logf("Using kernel version: %s", *flagKernelVersion)

	if *flagCiliumRoot == "" {
		t.Fatal("Cilium root path must be specified")
	}

	logLevel := slog.LevelInfo
	if testing.Verbose() {
		logLevel = slog.LevelDebug
	}

	var records verifierComplexityRecords

	t.Cleanup(func() {
		if *flagResultFile != "" {
			t.Logf("Writing verifier complexity records to %s", *flagResultFile)
			records.WriteToFile(*flagResultFile)
		}
	})

	t.Run("LXC", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range lxcBuildPermutations(kv) {
			t.Run(strconv.Itoa(i), compileAndLoad(logLevel, perm, "lxc", endpointProg, endpointObj, i, &records))
			i++
		}
	})

	t.Run("Host", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range hostBuildPermutations(kv) {
			t.Run(strconv.Itoa(i), compileAndLoad(logLevel, perm, "host", hostEndpointProg, hostEndpointObj, i, &records))
			i++
		}
	})

	t.Run("Network", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range networkBuildPermutations(kv) {
			t.Run(strconv.Itoa(i), compileAndLoad(logLevel, perm, "network", networkProg, networkObj, i, &records))
			i++
		}
	})

	t.Run("Overlay", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range overlayBuildPermutations(kv) {
			t.Run(strconv.Itoa(i), compileAndLoad(logLevel, perm, "overlay", overlayProg, overlayObj, i, &records))
			i++
		}
	})

	t.Run("Sock", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range sockBuildPermutations(kv) {
			t.Run(strconv.Itoa(i), compileAndLoad(logLevel, perm, "sock", "bpf_sock.c", "bpf_sock.o", i, &records))
			i++
		}
	})

	t.Run("Wireguard", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range wireguardBuildPermutations(kv) {
			t.Run(strconv.Itoa(i), compileAndLoad(logLevel, perm, "wireguard", wireguardProg, wireguardObj, i, &records))
			i++
		}
	})

	t.Run("XDP", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range xdpBuildPermutations(kv) {
			t.Run(strconv.Itoa(i), compileAndLoad(logLevel, perm, "xdp", xdpProg, xdpObj, i, &records))
			i++
		}
	})
}

func compileAndLoad[T any](logLevel slog.Level, perm buildPermutation[T], collection, source, output string, build int, records *verifierComplexityRecords) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		stateDir := t.TempDir()
		t.Logf("Using state directory: %s", stateDir)

		dirInfo := &directoryInfo{
			Library: path.Join(*flagCiliumRoot, defaults.BpfDir),
			Runtime: stateDir,
			State:   stateDir,
			Output:  stateDir,
		}

		log := hivetest.Logger(t, hivetest.LogLevel(logLevel))

		objFileName, err := compile(t.Context(), log, &progInfo{
			Source:     source,
			Output:     output,
			OutputType: outputObject,
			Options:    perm.options,
		}, dirInfo)
		if err != nil {
			t.Fatalf("Failed to compile %s program: %v", collection, err)
		}

		t.Logf("Compiled %s program: %s", collection, objFileName)

		spec, err := bpf.LoadCollectionSpec(log, objFileName)
		if err != nil {
			t.Fatalf("Failed to load BPF collection spec: %v", err)
		}
		// Do not attempt to pin maps
		for _, m := range spec.Maps {
			m.Pinning = ebpf.PinNone
		}

		ii := 0
		for constants := range perm.loadPermutations {
			t.Run(strconv.Itoa(ii), loadAndRecordComplexity(
				logLevel,
				spec,
				constants,
				collection,
				build, ii,
				records,
			))
			ii++
		}
	}
}

func loadAndRecordComplexity(
	logLevel slog.Level,
	spec *ebpf.CollectionSpec,
	constants any,
	collection string,
	build, load int,
	records *verifierComplexityRecords,
) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		log := hivetest.Logger(t, hivetest.LogLevel(logLevel))

		coll, _, err := bpf.LoadCollection(log, spec, &bpf.CollectionOptions{
			Constants: constants,
			CollectionOptions: ebpf.CollectionOptions{
				Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
				// Enable verifier logs for successful loads.
				// Use log level 1 since it's known by all target kernels.
				Programs: ebpf.ProgramOptions{
					LogLevel: ebpf.LogLevelBranch,
				},
			},
		})

		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Write full verifier log to a path on disk for offline analysis.
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "%+v", ve)
			fullLogFile := fmt.Sprintf("%s_%d_%d_verifier.log", collection, build, load)
			_ = os.WriteFile(fullLogFile, buf.Bytes(), 0444)
			t.Log("Full verifier log at", fullLogFile)

			// Print unverified instruction count.
			t.Log("BPF unverified instruction count per program:")
			for n, p := range spec.Programs {
				t.Logf("\t%s: %d insns", n, len(p.Instructions))
			}

			// Include the original err in the output since it contains the name
			// of the program that triggered the verifier error.
			// ebpf.VerifierError only contains the return code and verifier log
			// buffer.
			t.Logf("Error: %v\nVerifier error tail: %-10v", err, ve)
			t.Fail()
			return
		}
		if err != nil {
			t.Log(err)
			t.Fail()
			return
		}
		defer coll.Close()

		// Print verifier stats appearing on the last line of the log, e.g.
		// 'processed 12248 insns (limit 1000000) ...'.
		// Sort by program names for stable output.
		for _, n := range slices.Sorted(maps.Keys(coll.Programs)) {
			p := coll.Programs[n]
			p.VerifierLog = strings.TrimRight(p.VerifierLog, "\n")
			// Offset points at the last newline, increment by 1 to skip it.
			// Turn a -1 into a 0 if there are no newlines in the log.
			lastOff := strings.LastIndex(p.VerifierLog, "\n") + 1

			r := verifierComplexityRecord{
				Collection: collection,
				Build:      strconv.Itoa(build),
				Load:       strconv.Itoa(load),
				Program:    n,
			}
			_, err := fmt.Sscanf(p.VerifierLog[lastOff:], "processed %d insns (limit %d) max_states_per_insn %d total_states %d peak_states %d mark_read %d",
				&r.InsnsProcessed, &r.InsnsLimit, &r.MaxStatesPerInsn, &r.TotalStates, &r.PeakStates, &r.MarkRead)
			if err != nil {
				t.Fatalf("Failed to parse verifier log for program %s: %v", n, err)
			}

			records.Add(r)
		}
	}
}

type verifierComplexityRecord struct {
	Collection string `json:"collection"`
	Build      string `json:"build"`
	Load       string `json:"load"`
	Program    string `json:"program"`

	InsnsProcessed   int `json:"insns_processed"`
	InsnsLimit       int `json:"insns_limit"`
	MaxStatesPerInsn int `json:"max_states_per_insn"`
	TotalStates      int `json:"total_states"`
	PeakStates       int `json:"peak_states"`
	MarkRead         int `json:"mark_read"`
}

type verifierComplexityRecords struct {
	mu      sync.Mutex
	Records []verifierComplexityRecord
}

func (v *verifierComplexityRecords) Add(r verifierComplexityRecord) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.Records = append(v.Records, r)
}

func (ve *verifierComplexityRecords) WriteToFile(filename string) error {
	ve.mu.Lock()
	defer ve.mu.Unlock()

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create result file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ve.Records); err != nil {
		return fmt.Errorf("failed to write result file: %w", err)
	}
	return nil
}

type kernelVersion int

const (
	kernelVersion54 kernelVersion = iota
	kernelVersion510
	kernelVersion61
	kernelVersionNetNext
	_kernelVersionMax
)

func (kv kernelVersion) String() string {
	switch kv {
	case kernelVersion54:
		return "54"
	case kernelVersion510:
		return "510"
	case kernelVersion61:
		return "61"
	case kernelVersionNetNext:
		return "netnext"
	default:
		return "unknown"
	}
}

func kernelVersionFromString(s string) (kernelVersion, error) {
	switch s {
	case "54":
		return kernelVersion54, nil
	case "510":
		return kernelVersion510, nil
	case "61":
		return kernelVersion61, nil
	case "netnext":
		return kernelVersionNetNext, nil
	default:
		return _kernelVersionMax, fmt.Errorf("unknown kernel version: %s", s)
	}
}

func commonBaseOptions() map[string]string {
	options := map[string]string{}

	options["SKIP_DEBUG"] = "1"
	options["ENABLE_IPV4"] = "1"
	options["ENABLE_IPV6"] = "1"
	options["ENABLE_MASQUERADE_IPV4"] = "1"
	options["ENABLE_MASQUERADE_IPV6"] = "1"
	options["ENABLE_SRC_RANGE_CHECK"] = "1"
	options["POLICY_VERDICT_NOTIFY"] = "1"
	options["ALLOW_ICMP_FRAG_NEEDED"] = "1"
	options["ENABLE_IDENTITY_MARK"] = "1"
	options["MONITOR_AGGREGATION"] = "3"
	options["CT_REPORT_FLAGS"] = "0x0002"
	options["ENABLE_HOST_FIREWALL"] = "1"
	options["ENABLE_ICMP_RULE"] = "1"
	options["ENABLE_DSR"] = "1"
	options["ENABLE_DSR_ICMP_ERRORS"] = "1"
	options["ENABLE_SCTP"] = "1"
	options["ENABLE_CUSTOM_CALLS"] = "1"
	options["ENABLE_SRV6"] = "1"
	options["ENABLE_NODEPORT"] = "1"
	options["ENABLE_NODEPORT_ACCELERATION"] = "1"
	options["ENABLE_IPV4_FRAGMENTS"] = "1"
	options["ENABLE_IPV6_FRAGMENTS"] = "1"
	options["ENABLE_BANDWIDTH_MANAGER"] = "1"
	options["ENABLE_SESSION_AFFINITY"] = "1"

	return options
}

type buildPermutation[T any] struct {
	options          []string
	loadPermutations iter.Seq[T]
}

type lxcPermutation = buildPermutation[*config.BPFLXC]

func lxcBuildPermutations(kernel kernelVersion) iter.Seq[lxcPermutation] {
	return func(yield func(lxcPermutation) bool) {
		options := commonBaseOptions()

		options["ENABLE_ROUTING"] = "1"
		options["ENCAP_IFINDEX"] = "1"
		options["TUNNEL_MODE"] = "1"
		options["ENABLE_VTEP"] = "1"
		options["ENABLE_IPSEC"] = "1"
		options["EVENTS_MAP_RATE_LIMIT"] = "1000"
		options["ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION"] = "1"

		for i := 1; i <= 6; i++ {

			switch i {
			case 1:
				if kernel >= kernelVersion510 {
					options["ENABLE_HOST_ROUTING"] = "1"
					options["ENABLE_TPROXY"] = "1"
					options["ENABLE_LOCAL_REDIRECT_POLICY"] = "1"
				}

				if kernel >= kernelVersion61 {
					options["ENABLE_CLUSTER_AWARE_ADDRESSING"] = "1"
				}

			case 2:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"

			case 3:
				delete(options, "ENABLE_IPV6")
				delete(options, "ENABLE_MASQUERADE_IPV6")
				delete(options, "DSR_ENCAP_MODE")
				delete(options, "DSR_ENCAP_GENEVE")
				delete(options, "DSR_ENCAP_IPIP")

			case 4:
				if kernel <= kernelVersion510 {
					delete(options, "ENABLE_SCTP")
				}

				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"
				options["SERVICE_NO_BACKEND_RESPONSE"] = "1"

			case 5:
				options["ENABLE_IPV6"] = "1"
				options["ENABLE_MASQUERADE_IPV6"] = "1"

				delete(options, "ENABLE_IPV4")
				delete(options, "DSR_ENCAP_MODE")
				delete(options, "DSR_ENCAP_GENEVE")
				delete(options, "DSR_ENCAP_IPIP")
				delete(options, "ENABLE_CLUSTER_AWARE_ADDRESSING")

			case 6:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"

				if kernel >= kernelVersion510 {
					options["ENABLE_ACTIVE_CONNECTION_TRACKING"] = "1"
				}
			}

			optionsSlice := make([]string, 0, len(options))
			for _, k := range slices.Sorted(maps.Keys(options)) {
				optionsSlice = append(optionsSlice, fmt.Sprintf("-D%s=%s", k, options[k]))
			}

			if !yield(lxcPermutation{
				options:          optionsSlice,
				loadPermutations: lxcLoadPermutations(kernel),
			}) {
				return
			}
		}
	}
}

func lxcLoadPermutations(kernel kernelVersion) iter.Seq[*config.BPFLXC] {
	return func(yield func(*config.BPFLXC) bool) {
		for permutation := range permute(1) {
			cfg := config.NewBPFLXC(*config.NewNode())
			cfg.SecctxFromIPCache = permutation[0]
			if !yield(cfg) {
				return
			}
		}
	}
}

type hostPermutation = buildPermutation[*config.BPFHost]

func hostBuildPermutations(kernel kernelVersion) iter.Seq[hostPermutation] {
	return func(yield func(hostPermutation) bool) {
		options := commonBaseOptions()

		options["ENABLE_ROUTING"] = "1"
		options["ENABLE_DSR_HYBRID"] = "1"
		options["ENCAP_IFINDEX"] = "1"
		options["TUNNEL_MODE"] = "1"
		options["ENABLE_EGRESS_GATEWAY"] = "1"
		options["ENABLE_VTEP"] = "1"
		options["ENABLE_IPSEC"] = "1"
		options["EVENTS_MAP_RATE_LIMIT"] = "1000"
		options["ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION"] = "1"

		for i := 1; i <= 7; i++ {
			switch i {
			case 1:
				if kernel >= kernelVersion54 {
					options["ENABLE_HOST_ROUTING"] = "1"
					options["ENABLE_TPROXY"] = "1"
					options["ENABLE_LOCAL_REDIRECT_POLICY"] = "1"
				}

			case 2:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"

			case 3:
				delete(options, "ENABLE_IPV6")
				delete(options, "ENABLE_MASQUERADE_IPV6")
				delete(options, "DSR_ENCAP_MODE")
				delete(options, "DSR_ENCAP_GENEVE")
				delete(options, "DSR_ENCAP_IPIP")

			case 4:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"
				delete(options, "ENABLE_IPSEC")
				options["SERVICE_NO_BACKEND_RESPONSE"] = "1"
				options["ENABLE_WIREGUARD"] = "1"
				options["ENCRYPTION_STRICT_MODE"] = "1"

			case 5:
				delete(options, "ENABLE_IPV4")
				options["ENABLE_IPV6"] = "1"
				options["ENABLE_MASQUERADE_IPV6"] = "1"
				delete(options, "DSR_ENCAP_MODE")
				delete(options, "DSR_ENCAP_GENEVE")
				delete(options, "DSR_ENCAP_IPIP")
				delete(options, "ENABLE_EGRESS_GATEWAY")
				delete(options, "ENABLE_WIREGUARD")
				delete(options, "ENCRYPTION_STRICT_MODE")
				options["ENABLE_IPSEC"] = "1"

			case 6:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"
				if kernel >= kernelVersion510 && kernel <= kernelVersion61 {
					options["ENABLE_ACTIVE_CONNECTION_TRACKING"] = "1"
				}

			case 7:
				if kernel != kernelVersionNetNext {
					continue
				}

				delete(options, "SKIP_DEBUG")
				options["ENABLE_IPV4"] = "1"
				delete(options, "DSR_ENCAP_MODE")
				delete(options, "DSR_ENCAP_GENEVE")
				delete(options, "DSR_ENCAP_IPIP")
				options["ENABLE_EGRESS_GATEWAY"] = "1"
				delete(options, "SERVICE_NO_BACKEND_RESPONSE")
				delete(options, "ENABLE_IPSEC")
				delete(options, "EVENTS_MAP_RATE_LIMIT")
				delete(options, "ENABLE_ACTIVE_CONNECTION_TRACKING")
			}

			optionsSlice := make([]string, 0, len(options))
			for _, k := range slices.Sorted(maps.Keys(options)) {
				optionsSlice = append(optionsSlice, fmt.Sprintf("-D%s=%s", k, options[k]))
			}

			if !yield(hostPermutation{
				options:          optionsSlice,
				loadPermutations: hostLoadPermutations(kernel),
			}) {
				return
			}
		}
	}
}

func hostLoadPermutations(kernel kernelVersion) iter.Seq[*config.BPFHost] {
	return func(yield func(*config.BPFHost) bool) {
		for permutation := range permute(1) {
			cfg := config.NewBPFHost(*config.NewNode())
			cfg.SecctxFromIPCache = permutation[0]
			if !yield(cfg) {
				return
			}
		}
	}
}

func networkLoadPermutations(kernel kernelVersion) iter.Seq[*config.BPFNetwork] {
	return func(yield func(*config.BPFNetwork) bool) {
		cfg := config.NewBPFNetwork(*config.NewNode())
		if !yield(cfg) {
			return
		}
	}
}

type networkPermutation = buildPermutation[*config.BPFNetwork]

func networkBuildPermutations(kernel kernelVersion) iter.Seq[networkPermutation] {
	return func(yield func(networkPermutation) bool) {
		options := make(map[string]string)

		options["ENABLE_IPV4"] = "1"
		options["ENABLE_IPV6"] = "1"
		options["ENABLE_ICMP_RULE"] = "1"
		options["ENABLE_IDENTITY_MARK"] = "1"
		options["ENABLE_IPSEC"] = "1"
		options["ENABLE_IPV4_FRAGMENTS"] = "1"
		options["ENABLE_IPV6_FRAGMENTS"] = "1"
		options["TRACE_NOTIFY"] = "1"
		options["ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION"] = "1"

		optionsSlice := make([]string, 0, len(options))
		for _, k := range slices.Sorted(maps.Keys(options)) {
			optionsSlice = append(optionsSlice, fmt.Sprintf("-D%s=%s", k, options[k]))
		}

		if !yield(networkPermutation{
			options:          optionsSlice,
			loadPermutations: networkLoadPermutations(kernel),
		}) {
			return
		}
	}
}

type overlayPermutation = buildPermutation[*config.BPFOverlay]

func overlayBuildPermutations(kernel kernelVersion) iter.Seq[overlayPermutation] {
	return func(yield func(overlayPermutation) bool) {
		options := commonBaseOptions()

		options["ENABLE_DSR_HYBRID"] = "1"
		options["ENCAP_IFINDEX"] = "1"
		options["TUNNEL_MODE"] = "1"
		options["ENABLE_EGRESS_GATEWAY"] = "1"
		options["LB_SELECTION"] = "1"
		options["LB_SELECTION_MAGLEV"] = "1"
		options["ENABLE_VTEP"] = "1"
		options["ENABLE_IPSEC"] = "1"
		options["EVENTS_MAP_RATE_LIMIT"] = "1000"
		options["ENABLE_LOCAL_REDIRECT_POLICY"] = "1"
		options["ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION"] = "1"
		options["ENABLE_CLUSTER_AWARE_ADDRESSING"] = "1"
		options["ENABLE_INTER_CLUSTER_SNAT"] = "1"

		for i := 1; i <= 2; i++ {
			switch i {
			case 1:
				if kernel == kernelVersion54 {
					delete(options, "ENABLE_CLUSTER_AWARE_ADDRESSING")
					delete(options, "ENABLE_INTER_CLUSTER_SNAT")
				}

				if kernel >= kernelVersion54 {
					options["ENABLE_TPROXY"] = "1"
					options["ENABLE_HOST_ROUTING"] = "1"
					options["ENABLE_LOCAL_REDIRECT_POLICY"] = "1"
				}

			case 2:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"
			}

			optionsSlice := make([]string, 0, len(options))
			for _, k := range slices.Sorted(maps.Keys(options)) {
				optionsSlice = append(optionsSlice, fmt.Sprintf("-D%s=%s", k, options[k]))
			}

			if !yield(overlayPermutation{
				options:          optionsSlice,
				loadPermutations: overlayLoadPermutations(kernel),
			}) {
				return
			}
		}
	}
}

func overlayLoadPermutations(kernel kernelVersion) iter.Seq[*config.BPFOverlay] {
	return func(yield func(*config.BPFOverlay) bool) {
		for permutation := range permute(1) {
			cfg := config.NewBPFOverlay(*config.NewNode())
			cfg.SecctxFromIPCache = permutation[0]
			if !yield(cfg) {
				return
			}
		}
	}
}

type sockConfig struct {
}

func sockBuildPermutations(kernel kernelVersion) iter.Seq[buildPermutation[*sockConfig]] {
	return func(yield func(buildPermutation[*sockConfig]) bool) {
		options := commonBaseOptions()

		options["HAVE_SET_RETVAL"] = "1"
		options["ENABLE_DSR_HYBRID"] = "1"
		options["ENABLE_NAT_46X64"] = "1"
		options["ENCAP_IFINDEX"] = "1"
		options["TUNNEL_MODE"] = "1"
		options["LB_SELECTION"] = "1"
		options["LB_SELECTION_MAGLEV"] = "1"
		options["ENABLE_NAT_46X64_GATEWAY"] = "1"
		options["EVENTS_MAP_RATE_LIMIT"] = "1000"
		options["ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION"] = "1"

		for i := 1; i <= 2; i++ {
			switch i {
			case 1:
				if kernel >= kernelVersion510 {
					options["ENABLE_TPROXY"] = "1"
					options["ENABLE_HOST_ROUTING"] = "1"
					options["ENABLE_LOCAL_REDIRECT_POLICY"] = "1"
				}
				if kernel >= kernelVersion61 {
					options["HAVE_SET_RETVAL"] = "1"
				}

			case 2:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"
				options["ENABLE_ACTIVE_CONNECTION_TRACKING"] = "1"
			}

			optionsSlice := make([]string, 0, len(options))
			for _, k := range slices.Sorted(maps.Keys(options)) {
				optionsSlice = append(optionsSlice, fmt.Sprintf("-D%s=%s", k, options[k]))
			}

			if !yield(buildPermutation[*sockConfig]{
				options:          optionsSlice,
				loadPermutations: sockLoadPermutations(kernel),
			}) {
				return
			}
		}
	}
}

func sockLoadPermutations(kernel kernelVersion) iter.Seq[*sockConfig] {
	return func(yield func(*sockConfig) bool) {
		yield(&sockConfig{}) // No load time config for sock programs
	}
}

func wireguardBuildPermutations(kernel kernelVersion) iter.Seq[buildPermutation[*config.BPFWireguard]] {
	return func(yield func(buildPermutation[*config.BPFWireguard]) bool) {
		options := commonBaseOptions()

		options["ENABLE_DSR_HYBRID"] = "1"
		options["ENCAP_IFINDEX"] = "1"
		options["TUNNEL_MODE"] = "1"
		options["ENABLE_EGRESS_GATEWAY"] = "1"
		options["ENABLE_VTEP"] = "1"
		options["ENABLE_WIREGUARD"] = "1"
		options["ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION"] = "1"

		for i := 1; i <= 7; i++ {
			switch i {
			case 1:
				if kernel >= kernelVersion510 {
					options["ENABLE_TPROXY"] = "1"
					options["ENABLE_HOST_ROUTING"] = "1"
				}

			case 2:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"

			case 3:
				delete(options, "ENABLE_IPV6")
				delete(options, "ENABLE_MASQUERADE_IPV6")
				delete(options, "DSR_ENCAP_MODE")
				delete(options, "DSR_ENCAP_GENEVE")
				delete(options, "DSR_ENCAP_IPIP")

			case 4:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"
				options["SERVICE_NO_BACKEND_RESPONSE"] = "2"
				options["ENCYPTION_STRICT_MODE"] = "1"

			case 5:
				delete(options, "ENABLE_IPV4")
				options["ENABLE_IPV6"] = "1"
				options["ENABLE_MASQUERADE_IPV6"] = "1"
				delete(options, "DSR_ENCAP_MODE")
				delete(options, "DSR_ENCAP_GENEVE")
				delete(options, "DSR_ENCAP_IPIP")
				delete(options, "ENABLE_EGRESS_GATEWAY")
				delete(options, "ENCYPTION_STRICT_MODE")

			case 6:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"

			case 7:
				if kernel != kernelVersionNetNext {
					continue
				}

				delete(options, "SKIP_DEBUG")
				options["ENABLE_IPV4"] = "1"
				delete(options, "DSR_ENCAP_MODE")
				delete(options, "DSR_ENCAP_GENEVE")
				delete(options, "DSR_ENCAP_IPIP")
				options["ENABLE_EGRESS_GATEWAY"] = "1"
				delete(options, "SERVICE_NO_BACKEND_RESPONSE")
			}

			optionsSlice := make([]string, 0, len(options))
			for _, k := range slices.Sorted(maps.Keys(options)) {
				optionsSlice = append(optionsSlice, fmt.Sprintf("-D%s=%s", k, options[k]))
			}

			if !yield(buildPermutation[*config.BPFWireguard]{
				options:          optionsSlice,
				loadPermutations: wireguardLoadPermutations(kernel),
			}) {
				return
			}
		}
	}
}

func wireguardLoadPermutations(kernel kernelVersion) iter.Seq[*config.BPFWireguard] {
	return func(yield func(*config.BPFWireguard) bool) {
		for permutation := range permute(1) {
			cfg := config.NewBPFWireguard(*config.NewNode())
			cfg.SecctxFromIPCache = permutation[0]
			if !yield(cfg) {
				return
			}
		}
	}
}

func xdpBuildPermutations(kernel kernelVersion) iter.Seq[buildPermutation[*config.BPFXDP]] {
	return func(yield func(buildPermutation[*config.BPFXDP]) bool) {
		options := commonBaseOptions()

		options["ENABLE_DSR_HYBRID"] = "1"
		options["ENABLE_PREFILTER"] = "1"
		options["LB_SELECTION"] = "1"
		options["LB_SELECTION_MAGLEV"] = "1"
		options["EVENTS_MAP_RATE_LIMIT"] = "1000"

		for i := 1; i <= 7; i++ {
			switch i {
			case 1:
				if kernel >= kernelVersion510 {
					options["ENABLE_TPROXY"] = "1"
					options["ENABLE_HOST_ROUTING"] = "1"
					options["ENABLE_LOCAL_REDIRECT_POLICY"] = "1"
				}
				if kernel >= kernelVersion61 {
					options["HAVE_XDP_GET_BUFF_LEN"] = "1"
					options["HAVE_XDP_LOAD_BYTES"] = "1"
					options["HAVE_XDP_STORE_BYTES"] = "1"
				}

			case 2:
				options["TUNNEL_MODE"] = "1"

			case 3:
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"
				delete(options, "TUNNEL_MODE")
				options["TUNNEL_PROTOCOL"] = "TUNNEL_PROTOCOL_GENEVE"

			case 4:
				options["TUNNEL_MODE"] = "1"

			case 5:
				delete(options, "ENABLE_HOST_FIREWALL")
				delete(options, "ENABLE_CUSTOM_CALLS")
				delete(options, "ENABLE_SRV6")
				delete(options, "ENABLE_DSR_ICMP_ERRORS")
				delete(options, "ENABLE_DSR")
				delete(options, "ENABLE_DSR_HYBRID")
				delete(options, "DSR_ENCAP_MODE")
				delete(options, "DSR_ENCAP_GENEVE")
				delete(options, "DSR_ENCAP_IPIP")
				delete(options, "ENABLE_BANDWIDTH_MANAGER")
				delete(options, "ENABLE_PREFILTER")
				delete(options, "ENABLE_SCTP")
				delete(options, "EVENTS_MAP_RATE_LIMIT")

				options["CT_REPORT_FLAGS"] = "0x00ff"
				options["TUNNEL_PROTOCOL"] = "TUNNEL_PROTOCOL_VXLAN"
				options["ENABLE_L7_LB"] = "1"
				options["ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION"] = "1"
				options["ENABLE_EGRESS_GATEWAY"] = "1"
				options["SERVICE_NO_BACKEND_RESPONSE"] = "1"
				options["TRACE_NOTIFY"] = "1"

				if kernel >= kernelVersion61 {
					delete(options, "LB_SELECTION")
					delete(options, "LB_SELECTION_MAGLEV")
					delete(options, "TUNNEL_PROTOCOL")
					delete(options, "TUNNEL_MODE")
					delete(options, "ENABLE_L7_LB")
					delete(options, "ENABLE_SERVICE_PROTOCOL_DIFFERENTIATION")
					delete(options, "ENABLE_EGRESS_GATEWAY")
					delete(options, "TRACE_NOTIFY")

					options["CT_REPORT_FLAGS"] = "0x0002"
					options["ENABLE_DSR_ICMP_ERRORS"] = "1"
					options["ENABLE_DSR"] = "1"
					options["ENABLE_DSR_HYBRID"] = "1"
					options["ENABLE_DSR_BYUSER"] = "1"
					options["DSR_ENCAP_MODE"] = "2"
					options["DSR_ENCAP_GENEVE"] = "1"
					options["DSR_ENCAP_IPIP"] = "2"
					options["LB_SELECTION"] = "1"
					options["LB_SELECTION_MAGLEV"] = "1"
					options["ENABLE_TPROXY"] = "1"
					options["ENABLE_BANDWIDTH_MANAGER"] = "1"
					options["EVENTS_MAP_RATE_LIMIT"] = "1000"
				}

			case 6:
				options["ENABLE_HOST_FIREWALL"] = "1"
				options["ENABLE_CUSTOM_CALLS"] = "1"
				options["ENABLE_SRV6"] = "1"
				options["ENABLE_DSR_ICMP_ERRORS"] = "1"
				options["ENABLE_DSR"] = "1"
				options["ENABLE_DSR_HYBRID"] = "1"
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"
				options["ENABLE_BANDWIDTH_MANAGER"] = "1"
				options["ENABLE_PREFILTER"] = "1"
				options["ENABLE_SCTP"] = "1"

				if kernel >= kernelVersion510 {
					options["ENABLE_ACTIVE_CONNECTION_TRACKING"] = "1"
				}

				if kernel >= kernelVersion61 {
					delete(options, "ENABLE_HOST_FIREWALL")
					delete(options, "ENABLE_CUSTOM_CALLS")
					delete(options, "ENABLE_SRV6")
					delete(options, "ENABLE_DSR_ICMP_ERRORS")
					delete(options, "ENABLE_DSR")
					delete(options, "ENABLE_DSR_HYBRID")
					delete(options, "DSR_ENCAP_MODE")
					delete(options, "DSR_ENCAP_GENEVE")
					delete(options, "DSR_ENCAP_IPIP")
					delete(options, "ENABLE_TPROXY")
					delete(options, "ENABLE_BANDWIDTH_MANAGER")
					delete(options, "ENABLE_PREFILTER")
					delete(options, "ENABLE_SCTP")
					delete(options, "ENABLE_LOCAL_REDIRECT_POLICY")
					delete(options, "ENABLE_ACTIVE_CONNECTION_TRACKING")
				}

			case 7:
				if kernel != kernelVersionNetNext {
					continue
				}

				options["ENABLE_HOST_FIREWALL"] = "1"
				options["ENABLE_CUSTOM_CALLS"] = "1"
				options["ENABLE_SRV6"] = "1"
				options["ENABLE_DSR_ICMP_ERRORS"] = "1"
				options["ENABLE_DSR"] = "1"
				options["ENABLE_DSR_HYBRID"] = "1"
				options["DSR_ENCAP_MODE"] = "1"
				options["DSR_ENCAP_GENEVE"] = "1"
				options["DSR_ENCAP_IPIP"] = "2"
				options["ENABLE_TPROXY"] = "1"
				options["ENABLE_BANDWIDTH_MANAGER"] = "1"
				options["ENABLE_PREFILTER"] = "1"
				options["ENABLE_SCTP"] = "1"
				options["ENABLE_LOCAL_REDIRECT_POLICY"] = "1"
				options["ENABLE_ACTIVE_CONNECTION_TRACKING"] = "1"
			}

			optionsSlice := make([]string, 0, len(options))
			for _, k := range slices.Sorted(maps.Keys(options)) {
				optionsSlice = append(optionsSlice, fmt.Sprintf("-D%s=%s", k, options[k]))
			}

			if !yield(buildPermutation[*config.BPFXDP]{
				options:          optionsSlice,
				loadPermutations: xdpLoadPermutations(kernel),
			}) {
				return
			}
		}
	}
}

func xdpLoadPermutations(kernel kernelVersion) iter.Seq[*config.BPFXDP] {
	return func(yield func(*config.BPFXDP) bool) {
		for permutation := range permute(1) {
			cfg := config.NewBPFXDP(*config.NewNode())
			cfg.SecctxFromIPCache = permutation[0]
			if !yield(cfg) {
				return
			}
		}
	}
}
func permute(n int) iter.Seq[[]bool] {
	permutation := make([]bool, n)
	return func(yield func([]bool) bool) {
		for i := uint64(0); i < (1 << n); i++ {
			for j := 0; j < n; j++ {
				permutation[j] = (i & (1 << j)) != 0
			}
			if !yield(permutation) {
				return
			}
		}
	}
}
