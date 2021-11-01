//go:build linux

/*
Program tcpconnect is a BCC tool created by Brendan Gregg and Anton Protopopov
to trace new TCP active connections,
see https://github.com/iovisor/bcc/blob/master/libbpf-tools.
It is useful for determining who is connecting to whom.

	TIME: The time of the connect in seconds, counting from the first event seen.
	UID: The process user ID.
	PID: The process ID that opened the connection.
	COMM: The process name that opened the connection, e.g., via a connect() syscall.
	IP: IP address protocol.
	SADDR: Source address.
	DADDR: Destination address.
	DPORT: Destination port.

This works by tracing the tcp_v4_connect() and tcp_v6_connect() kernel functions.
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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS -cc clang-11 TCPConnect ./bpf/tcpconnect.bpf.c -- -I../../headers

func main() {
	// By default an exit code is set to indicate a failure since
	// there are more failure scenarios to begin with.
	exitCode := 1
	defer func() { os.Exit(exitCode) }()

	var (
		printTimestamp = flag.Bool("timestamp", false, "include the time of the connect in seconds on output, counting from the first event seen")
		printUID       = flag.Bool("print-uid", false, "include UID on output")
		filterUID      = flag.Int("uid", -1, "trace this UID only")
		filterPID      = flag.Int("pid", 0, "trace this PID only")
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

	// Replace constants in the BPF C program to filter connections by PID or UID.
	spec, err := LoadTCPConnect()
	if err != nil {
		log.Printf("failed to load collection spec: %v", err)
		return
	}
	bpfConst := make(map[string]interface{})
	if *filterUID > -1 {
		bpfConst["filter_uid"] = uint32(*filterUID)
	}
	if *filterPID > 0 {
		bpfConst["filter_pid"] = int32(*filterPID)
	}
	if err := spec.RewriteConstants(bpfConst); err != nil {
		log.Printf("failed to rewrite constants: %v", err)
		return
	}

	// Load the BPF program into the kernel from an ELF.
	// TCPConnectObjects contains all objects (BPF programs and maps) after they have been loaded into the kernel:
	// - TcpV4Connect, TcpV4ConnectRet, TcpV6Connect, TcpV6ConnectRet BPF programs,
	// - Events, Ipv4Count, Ipv6Count, Sockets BPF maps.
	objs := TCPConnectObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Printf("failed to load BPF programs and maps: %v", err)
		return
	}
	defer objs.Close()

	tcpv4kp, err := link.Kprobe("tcp_v4_connect", objs.TCPConnectPrograms.TcpV4Connect)
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_v4_connect kprobe: %s", err)
		return
	}
	defer tcpv4kp.Close()

	tcpv4krp, err := link.Kretprobe("tcp_v4_connect", objs.TCPConnectPrograms.TcpV4ConnectRet)
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_v4_connect kretprobe: %s", err)
		return
	}
	defer tcpv4krp.Close()

	tcpv6kp, err := link.Kprobe("tcp_v6_connect", objs.TCPConnectPrograms.TcpV6Connect)
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_v6_connect kprobe: %s", err)
		return
	}
	defer tcpv6kp.Close()

	tcpv6krp, err := link.Kretprobe("tcp_v6_connect", objs.TCPConnectPrograms.TcpV6ConnectRet)
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_v6_connect kretprobe: %s", err)
		return
	}
	defer tcpv6krp.Close()

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// defined in the BPF C program.
	rd, err := perf.NewReader(objs.TCPConnectMaps.Events, os.Getpagesize())
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

	printHeader(os.Stdout, *printTimestamp, *printUID)

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

		printEvent(os.Stdout, &e, startTimestamp, *printTimestamp, *printUID)
	}

	// The program terminates successfully if it received INT/TERM signal.
	exitCode = 0
}

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
	// Note, network byte order is big-endian.
	DstPort [2]byte
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
