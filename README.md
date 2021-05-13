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
$ go generate
$ sudo go run .
2021/05/13 16:57:02 failed to load objects: field TcpV6Connect: program tcp_v6_connect: instruction 0: reference to missing symbol "PT_REGS_PARM1"
exit status 1
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

`vmlinux.h` was generated as follows, though I also tried:

- https://raw.githubusercontent.com/iovisor/bcc/master/libbpf-tools/x86/vmlinux_505.h
- https://github.com/cilium/ebpf/commit/34f664db5ce5c6227f0afd64c4272666687c7cde

```sh
$ sudo apt-get install linux-tools-common linux-tools-5.8.0-53-generic
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./headers/vmlinux.h
```
