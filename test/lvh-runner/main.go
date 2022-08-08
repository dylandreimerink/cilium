package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/lvhrunner"
	"github.com/cilium/little-vm-helper/pkg/images"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func main() {
	var (
		rcnf lvhrunner.RunConf

		mounts []string
		ports []string
		scriptPath string
		scriptOutput string
	)

	// Remove "mmdebstrap" from the list of required binaries since we don't need it to run or modify images
	images.Binaries = []string{
		images.QemuImg,
		images.VirtCustomize,
		images.GuestFish,
	}

	cmd := &cobra.Command{
		Use:          "lvh-runner",
		Short:        "lvh-runner: helper to run Cilium tests on VMs",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			tmpDir, err := os.MkdirTemp("", "cilium-vmtests-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmpDir)

			rcnf.Logger = logrus.New()
			if err := images.CheckEnvironment(); err != nil {
				return err
			}

			rcnf.Filesystems, err = parseMounts(mounts)
			if err != nil {
				return fmt.Errorf("Mount flags: %w", err)
			}

			rcnf.ForwardedPorts, err = parsePorts(ports)
			if err != nil {
				return fmt.Errorf("Port flags: %w", err)
			}

			if scriptPath != "" {
				testActions, err := BuildTesterService(&rcnf, tmpDir, scriptPath, scriptOutput)
				if err != nil {
					return fmt.Errorf("Tester service: %w", err)
				}
				rcnf.ExtraActions = append(rcnf.ExtraActions, testActions...)
			}

			t0 := time.Now()

			ctx := context.Background()
			ctx, cancel := signal.NotifyContext(ctx, unix.SIGINT, unix.SIGTERM)
			defer cancel()

			err = lvhrunner.StartQemu(ctx, rcnf, tmpDir)
			dur := time.Since(t0).Round(time.Millisecond)
			fmt.Printf("Execution took %v\n", dur)
			if err != nil {
				return fmt.Errorf("Qemu exited with an error: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&rcnf.BaseFname, "base", "", "base image filename")
	cmd.MarkFlagRequired("base")
	cmd.Flags().StringVar(&rcnf.TestImage, "name", "cilium", "new vm (and basis for the image name). New vm image will be in the directory of the base image")
	cmd.Flags().StringVar(&rcnf.KernelFname, "kernel", "", "kernel filename to boot with. (if empty no -kernel option will be passed to qemu)")
	cmd.Flags().StringVar(&scriptPath, "script-path", "", "A 'test' script to be executed on startup")
	cmd.Flags().StringVar(&scriptOutput, "script-output", "", "Path to file where the output of the test script would be outputted to")
	cmd.Flags().BoolVar(&rcnf.DontRebuildImage, "dont-rebuild-image", false, "dont rebuild image")
	cmd.Flags().BoolVar(&rcnf.QemuPrint, "qemu-cmd-print", false, "Do not run the qemu command, just print it")
	cmd.Flags().BoolVar(&rcnf.DisableKVM, "qemu-disable-kvm", false, "Do not use KVM acceleration, even if /dev/kvm exists")
	cmd.Flags().BoolVar(&rcnf.JustBoot, "just-boot", false, "Do not actually run any tests. Just setup everything and start the VM. User will be able to login to the VM.")
	cmd.Flags().BoolVar(&rcnf.Daemonize, "daemonize", false, "daemonize QEMU after initializing")
	cmd.Flags().StringArrayVarP(&mounts, "mount", "m", nil, "Mount a directory (id:path[:vmpath])")
	cmd.Flags().StringArrayVarP(&ports, "port", "p", nil, "Forward a port (hostport[:vmport[:tcp|udp]])")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func parseMounts(flags []string) ([]lvhrunner.QemuFS, error) {
	var qfs []lvhrunner.QemuFS
	for _, flag := range flags {
		id, paths, found := strings.Cut(flag, ":")
		if !found {
			return nil, fmt.Errorf(
				"mount flag '%s' doesn't contain a id, must be <id>:<hostpath> or <id>:<hostpath>:<vmpath>",
				flag,
			)
		}

		hostPath, vmPath, found := strings.Cut(paths, ":")
		if !found {
			hostPath = paths
			vmPath = paths
		}

		if strings.HasPrefix(hostPath, "~") || strings.HasPrefix(vmPath, "~") {
			homedir, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}

			hostPath = strings.Replace(hostPath, "~", homedir, 1)
			vmPath = strings.Replace(vmPath, "~", homedir, 1)
		}

		var err error
		hostPath, err = filepath.Abs(hostPath)
		if err != nil {
			return nil, fmt.Errorf(
				"mount flag '%s': %w",
				flag,
				err,
			)
		}

		vmPath, err = filepath.Abs(vmPath)
		if err != nil {
			return nil, fmt.Errorf(
				"mount flag '%s': %w",
				flag,
				err,
			)
		}

		qfs = append(qfs, &lvhrunner.VirtIOFilesystem{
			ID:      id,
			Hostdir: hostPath,
			VMdir:   vmPath,
		})
	}

	return qfs, nil
}

func parsePorts(flags []string) ([]lvhrunner.PortForward, error) {
	var forwards []lvhrunner.PortForward
	for _, flag := range flags {
		hostPortStr, vmPortAndProto, found := strings.Cut(flag, ":")
		if !found {
			hostPort, err := strconv.Atoi(flag)
			if err != nil {
				return nil, fmt.Errorf("'%s' is not a valid port number", flag)
			}
			forwards = append(forwards, lvhrunner.PortForward{
				HostPort: hostPort,
				VMPort: hostPort,
				Protocol: "tcp",
			})
			continue
		}

		hostPort, err := strconv.Atoi(hostPortStr)
		if err != nil {
			return nil, fmt.Errorf("'%s' is not a valid port number", hostPortStr)
		}

		vmPortStr, proto, found := strings.Cut(vmPortAndProto, ":")
		if !found {
			vmPort, err := strconv.Atoi(vmPortAndProto)
			if err != nil {
				return nil, fmt.Errorf("'%s' is not a valid port number", vmPortAndProto)
			}
			forwards = append(forwards, lvhrunner.PortForward{
				HostPort: hostPort,
				VMPort: vmPort,
				Protocol: "tcp",
			})
			continue
		}

		vmPort, err := strconv.Atoi(vmPortStr)
		if err != nil {
			return nil, fmt.Errorf("'%s' is not a valid port number", vmPortStr)
		}

		proto = strings.ToLower(proto)
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("port forward protocol must be tcp or udp")
		}

		forwards = append(forwards, lvhrunner.PortForward{
			HostPort: hostPort,
			VMPort: vmPort,
			Protocol: proto,
		})
	}

	return forwards, nil
}

var ciliumTesterService = `
[Unit]
Description=Cilium tester
After=network.target docker.service

[Service]
ExecStart=%s
Type=oneshot
# https://www.freedesktop.org/software/systemd/man/systemd.exec.html
StandardOutput=file:%s
# StandardOutput=tty
# StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
`

const CiliumTestExecPath = "/usr/bin/cilium-test"

func BuildTesterService(rcnf *lvhrunner.RunConf, tmpDir, scriptPath, scriptOutput string) ([]images.Action, error) {
	service := fmt.Sprintf(ciliumTesterService, CiliumTestExecPath, scriptOutput)
	tmpFile := filepath.Join(tmpDir, "cilium-tester.service")
	err := os.WriteFile(tmpFile, []byte(service), 0722)
	if err != nil {
		return nil, err
	}

	actions := []images.Action{
		{Op: &images.UploadCommand{
			File: scriptPath,
			Dest: CiliumTestExecPath,
		}},
		{Op: &images.ChmodCommand{
			File: CiliumTestExecPath,
			Permissions: "0755",
		}},
		/*
			{Op: &images.RunCommand{
				Cmd: "sed -i  's/^#LogColor=yes/LogColor=no/' /etc/systemd/system.conf",
			}},
		*/
	}

	if !rcnf.JustBoot {
		actions = append(actions, images.Action{Op: &images.CopyInCommand{
			LocalPath: tmpFile,
			RemoteDir: "/etc/systemd/system",
		}})

		enableTester := images.Action{Op: &images.RunCommand{Cmd: "systemctl enable cilium-tester.service"}}
		actions = append(actions, enableTester)
	}

	return actions, nil
}
