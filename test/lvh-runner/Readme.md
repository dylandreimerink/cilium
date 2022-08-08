# Little VM Helper - Runner

This "runner" modifies a given basic VM ad hoc, adding resources used to test the currently checked out cilium brach.

## Usage

```
lvh-runner: helper to run Cilium tests on VMs

Usage:
  lvh-runner [flags]

Flags:
      --base string            base image filename
      --daemonize              daemonize QEMU after initializing
      --dont-rebuild-image     dont rebuild image
  -h, --help                   help for lvh-runner
      --just-boot              Do not actually run any tests. Just setup everything and start the VM. User will be able to login to the VM.
      --kernel string          kernel filename to boot with. (if empty no -kernel option will be passed to qemu)
  -m, --mount stringArray      Mount a directory (id:path[:vmpath])
      --name string            new vm (and basis for the image name). New vm image will be in the directory of the base image (default "cilium")
  -p, --port stringArray       Forward a port (hostport[:vmport[:tcp|udp]])
      --qemu-cmd-print         Do not run the qemu command, just print it
      --qemu-disable-kvm       Do not use KVM acceleration, even if /dev/kvm exists
      --script-output string   Path to file where the output of the test script would be outputted to
      --script-path string     A 'test' script to be executed on startup
```

## Examples
### Kind connectivity test

The following is an example starts a VM from the 'kind' base image, it mounts the whole cilium directory at the same
location as on the host. It creates a port forward from the hosts port 2222 to the ssh port 22 which allows us to monitor
the VM in development. We request the execution of the `kind-connectivity-test.sh` script, which will run as soon as the
VM is up and running, the output generated is sent to `$(pwd)/out.txt` which is a path within the VM. We can use the pwd
since we have mounted the cilium dir at the same location. This will write the test output to the `out.txt` file. 
Out test script triggers a shutdown of the VM once it has ran to completion.

`go run . --base images/kind.qcow2 --mount cilium:~/go/src/github.com/cilium/cilium --port 2222:22 --script-path kind-connectivity-test.sh --script-output $(pwd)/out.txt`
