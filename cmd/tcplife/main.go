//go:build linux

/*
Program tcplife is a BCC tool created by Brendan Gregg to
summarize TCP sessions that open and close while tracing,
see https://github.com/iovisor/bcc/blob/master/tools/tcplife.py.
It traces the lifespan of TCP sessions showing their duration, address details,
throughput, the responsible process ID and name.

	TIME: The time of the session in seconds (timestamp), counting from the first event seen.
	PID: The process ID responsible for the connection.
	COMM: The process name responsible for the connection.
	LADDR: Local address.
	LPORT: Local port.
	RADDR: Remote address.
	RPORT: Remote port.
	TX_KB: Number of kilobytes transmitted during the connection.
	RX_KB: Number of kilobytes received during the connection.
	MS: Duration of the connection in milliseconds, i.e.,
		the time from the first state transition seen for the socket, to TCP_CLOSE.

This tool is useful for workload characterisation and flow accounting:
identifying what connections are happening, with the bytes transferred.
This works by tracing TCP socket state change events (sock:inet_sock_set_state tracepoint),
and prints the summary details when the state changes to TCP_CLOSE.
*/

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS -cc clang-11 TCPLife ./bpf/tcplife.bpf.c -- -I../../headers

func main() {
	// By default an exit code is set to indicate a failure since
	// there are more failure scenarios to begin with.
	exitCode := 1
	defer func() { os.Exit(exitCode) }()

	var (
		printTimestamp = flag.Bool("timestamp", false, "include the time of the session in seconds on output, counting from the first event seen")
	)
	flag.Parse()

	// Increase the resource limit of the current process to provide sufficient space
	// for locking memory for the BPF maps.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Printf("failed to set temporary RLIMIT_MEMLOCK: %v", err)
		return
	}

	objs := TCPLifeObjects{}
	if err := LoadTCPLifeObjects(&objs, nil); err != nil {
		log.Printf("failed to load BPF programs and maps: %v", err)
		return
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TCPLifePrograms.TraceInetSockSetState)
	if err != nil {
		log.Printf("failed to attach the BPF program to inet_sock_set_state tracepoint: %v", err)
		return
	}
	defer tp.Close()

	// Open a perf event reader from user space on the PERF_EVENT_ARRAY map
	// defined in the BPF C program.
	rd, err := perf.NewReader(objs.TCPLifeMaps.Events, os.Getpagesize())
	if err != nil {
		log.Printf("failed to create perf event reader: %v", err)
		return
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	printHeader(os.Stdout, *printTimestamp)

	var startTimestamp float64
	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				break
			}
			log.Printf("failed to read from perf ring buffer: %v", err)
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

		printEvent(os.Stdout, &e, startTimestamp, *printTimestamp)
	}

	// The program terminates successfully if it received INT/TERM signal.
	exitCode = 0
}

// event represents a perf event sent to user space from the BPF program running in the kernel.
// Note, that it must match the C event struct, and both C and Go structs must be aligned the same way.
type event struct {
	// SrcAddr is the local address.
	SrcAddr [16]byte
	// DstAddr is the remote address.
	DstAddr [16]byte
	// Comm is the process name responsible for the connection.
	Comm [16]byte
	// BytesReceived is the number of bytes transmitted during the connection.
	BytesReceived uint64
	// BytesAcked is the number of bytes received during the connection.
	BytesAcked uint64
	// Delta is the session duration in microseconds.
	Delta uint64
	// Timestamp is the timestamp in microseconds.
	Timestamp uint64
	// PID is the process ID responsible for the connection.
	PID uint32
	// AddrFam is the address family, 2 is AF_INET (IPv4), 10 is AF_INET6 (IPv6).
	AddrFam uint32
	// SrcPort is the local port (uint16 in C struct).
	// Note, network byte order is big-endian.
	SrcPort [2]byte
	// DstPort is the remote port (uint16 in C struct).
	// Note, network byte order is big-endian.
	DstPort [2]byte
}

func printHeader(w io.Writer, printTimestamp bool) {
	if printTimestamp {
		fmt.Fprintf(w, "%-9s", "TIME(s)")
	}
	fmt.Fprintf(w, "%-5s %-10s %-15s %-5s %-15s %-5s %5s %5s %s\n", "PID", "COMM", "LADDR", "LPORT", "RADDR", "RPORT", "TX_KB", "RX_KB", "MS")
}

func printEvent(w io.Writer, e *event, startTimestamp float64, printTimestamp bool) {
	var (
		srcAddr, dstAddr net.IP
	)
	switch e.AddrFam {
	case 2:
		srcAddr = net.IP(e.SrcAddr[:4])
		dstAddr = net.IP(e.DstAddr[:4])
	case 10:
		srcAddr = net.IP(e.SrcAddr[:])
		dstAddr = net.IP(e.DstAddr[:])
	}

	if printTimestamp {
		fmt.Fprintf(w, "%-9.3f", (float64(e.Timestamp)-startTimestamp)/1e6)
	}

	fmt.Fprintf(
		w,
		"%-5d %-10s %-15s %-5d %-15s %-5d %5d %5d %.2f\n",
		e.PID,
		bytes.TrimRight(e.Comm[:], "\x00"),
		srcAddr,
		binary.BigEndian.Uint16(e.SrcPort[:]),
		dstAddr,
		binary.BigEndian.Uint16(e.DstPort[:]),
		e.BytesReceived/1024,
		e.BytesAcked/1024,
		float64(e.Delta)/1000,
	)
}
