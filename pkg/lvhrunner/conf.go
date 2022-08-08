package lvhrunner

import (
	"path/filepath"

	"github.com/cilium/little-vm-helper/pkg/images"
	"github.com/sirupsen/logrus"
)

type RunConf struct {
	// Base image filename
	BaseFname string
	// new vm (and basis for the image name). New vm image will be in the directory of the base image
	TestImage string
	// kernel filename to boot with. (if empty no -kernel option will be passed to qemu)
	KernelFname string
	// dont rebuild image
	DontRebuildImage bool
	// use cilium-vmtests-init as init process in the VM
	UseCiliumTesterInit bool
	// Do not run the qemu command, just print it
	QemuPrint bool
	// Do not actually run any tests. Just setup everything and start the VM. User will be able to login to the VM.
	JustBoot bool
	// Do not use KVM acceleration, even if /dev/kvm exists
	DisableKVM bool
	// Daemonize QEMU after initializing
	Daemonize bool

	// Disable the network connection to the VM
	DisableNetwork bool
	ForwardedPorts []PortForward

	Logger *logrus.Logger

	Filesystems []QemuFS

	ExtraActions []images.Action
}

func (rc *RunConf) testImageFname() string {
	imagesDir := filepath.Dir(rc.BaseFname)
	return filepath.Join(imagesDir, rc.TestImage)
}

type PortForward struct {
	HostPort int
	VMPort   int
	Protocol string
}
