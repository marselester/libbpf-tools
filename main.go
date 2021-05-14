// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
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

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// defined in the BPF C program.
	rd, err := perf.NewReader(objs.TCPConnLatMaps.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	for {
		var v event

		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			log.Printf("reading from perf event reader: %v", err)
		}

		if record.LostSamples != 0 {
			log.Printf("rind event perf buffer is full, dropped %d samples", record.LostSamples)
			continue
		}

		err = binary.Read(
			bytes.NewBuffer(record.RawSample),
			binary.LittleEndian,
			&v,
		)
		if err != nil {
			log.Printf("failed to parse perf event: %v", err)
			continue
		}

		log.Println(v)
	}
}

// event represents a perf event sent to userspace from the BPF program running in the kernel.
// Note, that it must match the C event struct, and both C and Go structs must be aligned the same way.
type event struct {
	saddrV4 uint32
	saddrV6 [16]byte
	daddrV4 uint32
	daddrV6 [16]byte
	comm    [16]byte
	deltaUs uint64
	tsUs    uint64
	tgid    uint32
	af      int
	dport   uint16
}
