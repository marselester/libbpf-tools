//go:build linux

/*
Program tcpconnlat is a BCC tool created by Brendan Gregg and Wenbo Zhang
to trace TCP active connection latency (via a connect() syscall),
see https://github.com/iovisor/bcc/blob/master/libbpf-tools.

	TIME: The time of the connect in seconds, counting from the first event seen.
	PID: The process ID that opened the connection.
	COMM: The process name that opened the connection, e.g., via a connect() syscall.
	IP: IP address protocol.
	SADDR: Source address.
	DADDR: Destination address.
	DPORT: Destination port.
	LAT(ms): The latency for the connection in milliseconds as measured locally: the time from SYN sent to the response packet.

TCP connection latency is a useful performance measure showing the time taken to establish a connection.
This typically involves kernel TCP/IP processing
and the network round trip time, and not application runtime.

tcpconnlat measures the time from any connection to the response packet,
even if the response is a RST (port closed).
This works by tracing the tcp_v4_connect(), tcp_v6_connect(),
and tcp_rcv_state_process() kernel functions.
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS -cc clang-11 TCPConnLat ./bpf/tcpconnlat.bpf.c -- -I../../headers

func main() {
	// By default an exit code is set to indicate a failure since
	// there are more failure scenarios to begin with.
	exitCode := 1
	defer func() { os.Exit(exitCode) }()

	var (
		printTimestamp = flag.Bool("timestamp", false, "include the time of the connect in seconds on output, counting from the first event seen")
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

	objs := TCPConnLatObjects{}
	if err := LoadTCPConnLatObjects(&objs, nil); err != nil {
		log.Printf("failed to load BPF programs and maps: %v", err)
		return
	}
	defer objs.Close()

	// AttachTrace links a tracing fentry BPF program to a BPF hook defined in kernel modules.
	// Fentry is similar to kprobe, but has improved performance and usability,
	// see https://github.com/libbpf/libbpf-bootstrap/blob/master/README.md#fentry.
	tcpv4fe, err := link.AttachTrace(link.TraceOptions{
		objs.TCPConnLatPrograms.TcpV4Connect,
	})
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_v4_connect fentry: %s", err)
		return
	}
	defer tcpv4fe.Close()

	tcpv6kp, err := link.Kprobe("tcp_v6_connect", objs.TCPConnLatPrograms.TcpV6Connect)
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_v6_connect kprobe: %s", err)
		return
	}
	defer tcpv6kp.Close()

	tcprcvfe, err := link.AttachTrace(link.TraceOptions{
		objs.TCPConnLatPrograms.TcpRcvStateProcess,
	})
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_rcv_state_process fentry: %s", err)
		return
	}
	defer tcprcvfe.Close()

	// Open a perf event reader from user space on the PERF_EVENT_ARRAY map
	// defined in the BPF C program.
	rd, err := perf.NewReader(objs.TCPConnLatMaps.Events, os.Getpagesize())
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
	// SrcAddr is the source address.
	SrcAddr [16]byte
	// DstAddr is the destination address.
	DstAddr [16]byte
	// Comm is the process name that opened the connection.
	Comm [16]byte
	// Delta is the latency in microseconds.
	Delta uint64
	// Timestamp is the timestamp in microseconds.
	Timestamp uint64
	// PID is the process ID that opened the connection.
	PID uint32
	// AddrFam is the address family, 2 is AF_INET (IPv4), 10 is AF_INET6 (IPv6).
	AddrFam uint32
	// DstPort is the destination port (uint16 in C struct).
	// Note, network byte order is big-endian.
	DstPort [2]byte
}

func printHeader(w io.Writer, printTimestamp bool) {
	if printTimestamp {
		fmt.Fprintf(w, "%-9s", "TIME(s)")
	}
	fmt.Fprintf(w, "%-6s %-12s %-2s %-16s %-16s %-5s %s\n", "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT", "LAT(ms)")
}

func printEvent(w io.Writer, e *event, startTimestamp float64, printTimestamp bool) {
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

	fmt.Fprintf(
		w,
		"%-6d %-12s %-2d %-16s %-16s %-5d %.2f\n",
		e.PID,
		bytes.TrimRight(e.Comm[:], "\x00"),
		ipVer,
		srcAddr,
		dstAddr,
		binary.BigEndian.Uint16(e.DstPort[:]),
		float64(e.Delta)/1000,
	)
}
