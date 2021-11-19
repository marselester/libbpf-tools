//go:build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS -cc clang-11 TCPLife ./bpf/tcplife.bpf.c -- -I../../headers

func main() {}
