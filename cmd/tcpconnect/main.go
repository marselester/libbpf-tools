// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS -cc clang-11 TCPConnect ./bpf/tcpconnect.bpf.c -- -I../../headers

func main() {
	// Increase the rlimit of the current process to provide sufficient space
	// for locking memory for the eBPF map.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	objs := TCPConnectObjects{}
	if err := LoadTCPConnectObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load objects: %v", err)
	}
	defer objs.Close()

	tcpv4kp, err := link.Kprobe("tcp_v4_connect", objs.TCPConnectPrograms.TcpV4Connect)
	if err != nil {
		log.Fatalf("opening tcp_v4_connect kprobe: %s", err)
	}
	defer tcpv4kp.Close()

	tcpv4krp, err := link.Kretprobe("tcp_v4_connect", objs.TCPConnectPrograms.TcpV4ConnectRet)
	if err != nil {
		log.Fatalf("opening tcp_v4_connect kretprobe: %s", err)
	}
	defer tcpv4krp.Close()

	tcpv6kp, err := link.Kprobe("tcp_v6_connect", objs.TCPConnectPrograms.TcpV6Connect)
	if err != nil {
		log.Fatalf("opening tcp_v6_connect kprobe: %s", err)
	}
	defer tcpv6kp.Close()

	tcpv6krp, err := link.Kretprobe("tcp_v6_connect", objs.TCPConnectPrograms.TcpV6ConnectRet)
	if err != nil {
		log.Fatalf("opening tcp_v6_connect kretprobe: %s", err)
	}
	defer tcpv6krp.Close()

	log.Println("Waiting for events...")

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// defined in the BPF C program.
	rd, err := perf.NewReader(objs.TCPConnectMaps.Events, os.Getpagesize())
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
			log.Printf("ring event perf buffer is full, dropped %d samples", record.LostSamples)
			continue
		}

		err = binary.Read(
			bytes.NewBuffer(record.RawSample),
			binary.LittleEndian,
			&v,
		)
		if err != nil {
			log.Printf("failed to parse perf event: %#+v", err)
			continue
		}

		var (
			srcAddr, dstAddr net.IP
			ipVer            byte
		)
		switch v.AddrFam {
		case 2:
			srcAddr = net.IP(v.SrcAddr[:4])
			dstAddr = net.IP(v.DstAddr[:4])
			ipVer = 4
		case 10:
			srcAddr = net.IP(v.SrcAddr[:])
			dstAddr = net.IP(v.DstAddr[:])
			ipVer = 6
		}
		log.Printf("PID %d COMM %s IP %d SADDR %s DADDR %s DPORT %d\n", v.PID, v.Comm, ipVer, srcAddr, dstAddr, binary.BigEndian.Uint16(v.DstPort[:]))
	}
}

// event represents a perf event sent to userspace from the BPF program running in the kernel.
// Note, that it must match the C event struct, and both C and Go structs must be aligned the same way.
type event struct {
	SrcAddr [16]byte
	DstAddr [16]byte
	Comm    [16]byte
	// Timestamp is a timestamp in microseconds.
	Timestamp uint64
	// AddrFam is an address family, 2 is AF_INET (IPv4), 10 is AF_INET6 (IPv6).
	AddrFam uint32
	// PID is a process ID.
	PID uint32
	// UID is a process's user ID.
	UID uint32
	// DstPort is a destination port (uint16 in C struct).
	// Note, network byte order is big endian.
	DstPort [2]byte
}
