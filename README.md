# Go tcpconnlat

An attempt to implement a Go frontend for
[tcpconnlat](https://github.com/iovisor/bcc/blob/master/libbpf-tools/tcpconnlat.c) BPF tool.

Start a virtual machine, install Clang and Go.

```sh
$ vagrant up
$ vagrant ssh
$ sudo apt-get update
$ sudo apt-get install clang
$ sudo snap install go --classic
$ uname -nr
ubuntu-groovy 5.8.0-53-generic
$ clang -v
Ubuntu clang version 11.0.0-2
```

Compile C BPF program into BPF bytecode and generate Go files
with [bpf2go](https://github.com/cilium/ebpf/blob/master/cmd/bpf2go/doc.go) tool.

```sh
$ cd /vagrant/
$ BPF_CFLAGS='-D__TARGET_ARCH_x86' go generate ./cmd/tcpconnlat/
$ sudo go run ./cmd/tcpconnlat/
```

Note, the headers were copied from the following sources.

```sh
$ git clone git://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/groovy
$ cp ./groovy/tools/lib/bpf/bpf_helpers.h ./headers/bpf
$ cp ./groovy/tools/lib/bpf/bpf_core_read.h ./headers/bpf
$ cp ./groovy/tools/lib/bpf/bpf_tracing.h ./headers/bpf
$ git clone https://github.com/libbpf/libbpf.git
$ cp ./libbpf/src/bpf_helper_defs.h ./headers/bpf
```

`vmlinux.h` was generated as follows.

```sh
$ sudo apt-get install linux-tools-common linux-tools-5.8.0-53-generic
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./headers/vmlinux.h
```

Set `#define BPF_NO_PRESERVE_ACCESS_INDEX 0` before importing `vmlinux.h`
in `tcpconnlat.bpf.c` to resolve
`CO-RE relocations: relocate pt_regs: relocation byte_off: not supported` error.
