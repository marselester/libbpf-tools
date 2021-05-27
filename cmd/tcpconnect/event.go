package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// event represents a perf event sent to userspace from the BPF program running in the kernel.
// Note, that it must match the C event struct, and both C and Go structs must be aligned the same way.
type event struct {
	// SrcAddr is the source address.
	SrcAddr [16]byte
	// DstAddr is the destination address.
	DstAddr [16]byte
	// Comm is the process name that opened the connection.
	Comm [16]byte
	// Timestamp is the timestamp in microseconds.
	Timestamp uint64
	// AddrFam is the address family, 2 is AF_INET (IPv4), 10 is AF_INET6 (IPv6).
	AddrFam uint32
	// PID is the process ID that opened the connection.
	PID uint32
	// UID is the process user ID.
	UID uint32
	// DstPort is the destination port (uint16 in C struct).
	// Note, network byte order is big endian.
	DstPort [2]byte
}

func printEvents(ctx context.Context, events *ebpf.Map, printTimestamp, printUID bool) {
	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// defined in the BPF C program.
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Printf("creating perf event reader: %s", err)
		return
	}
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	printHeader(os.Stdout, printTimestamp, printUID)

	var startTimestamp float64
	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				break
			}
			log.Printf("reading from perf event reader: %v", err)
		}

		if record.LostSamples != 0 {
			log.Printf("ring event perf buffer is full, dropped %d samples", record.LostSamples)
			continue
		}

		var e event
		err = binary.Read(
			bytes.NewBuffer(record.RawSample),
			binary.LittleEndian,
			&e,
		)
		if err != nil {
			log.Printf("failed to parse perf event: %#+v", err)
			continue
		}

		if startTimestamp == 0 {
			startTimestamp = float64(e.Timestamp)
		}

		printEvent(os.Stdout, &e, startTimestamp, printTimestamp, printUID)
	}
}

func printHeader(w io.Writer, printTimestamp, printUID bool) {
	if printTimestamp {
		fmt.Fprintf(w, "%-9s", "TIME(s)")
	}
	if printUID {
		fmt.Fprintf(w, "%-6s", "UID")
	}
	fmt.Fprintf(w, "%-6s %-12s %-2s %-16s %-16s %s\n", "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT")
}

func printEvent(w io.Writer, e *event, startTimestamp float64, printTimestamp, printUID bool) {
	var (
		srcAddr, dstAddr net.IP
		ipVer            byte
	)
	switch e.AddrFam {
	case 2:
		srcAddr = net.IP(e.SrcAddr[:4])
		dstAddr = net.IP(e.DstAddr[:4])
		ipVer = 4
	case 10:
		srcAddr = net.IP(e.SrcAddr[:])
		dstAddr = net.IP(e.DstAddr[:])
		ipVer = 6
	}

	if printTimestamp {
		fmt.Fprintf(w, "%-9.3f", (float64(e.Timestamp)-startTimestamp)/1e6)
	}
	if printUID {
		fmt.Fprintf(w, "%-6d", e.UID)
	}

	fmt.Fprintf(
		w,
		"%-6d %-12s %-2d %-16s %-16s %d\n",
		e.PID,
		bytes.TrimRight(e.Comm[:], "\x00"),
		ipVer,
		srcAddr,
		dstAddr,
		binary.BigEndian.Uint16(e.DstPort[:]),
	)
}
