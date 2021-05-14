// +build linux

package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS -cc clang-11 TCPConnLat ./bpf/tcpconnlat.bpf.c -- -I./headers

func main() {
	// Increase the rlimit of the current process to provide sufficient space
	// for locking memory for the eBPF map.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	objs := TCPConnLatObjects{}
	if err := LoadTCPConnLatObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and
	// attach the pre-compiled program.
	kp, err := link.Kprobe("tcp_v6_connect", objs.TCPConnLatPrograms.TcpV6Connect)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	log.Println("Waiting for events...")
	var key uint64
	for {
		var value piddata
		if err := objs.TCPConnLatMaps.Start.Lookup(key, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("tcp_v6_connect called: %v\n", value)
		time.Sleep(time.Second)
	}
}

type piddata struct {
	comm [16]byte
	ts   uint64
	tgid uint32
}
