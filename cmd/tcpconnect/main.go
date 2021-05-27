// +build linux

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
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
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
		printCount     = flag.Bool("count", false, "count connects per source IP and destination IP/port")
		filterUID      = flag.Int("uid", -1, "trace this UID only")
		filterPID      = flag.Int("pid", 0, "trace this PID only")
	)
	flag.Parse()

	// Increase the rlimit of the current process to provide sufficient space
	// for locking memory for the eBPF map.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Printf("failed to set temporary rlimit: %v", err)
		return
	}

	spec, err := LoadTCPConnect()
	if err != nil {
		log.Printf("failed to load collection spec: %v", err)
		return
	}

	// Replace constants in the BPF C program to filter connections by PID or UID.
	bpfConst := make(map[string]interface{})
	if *printCount {
		bpfConst["do_count"] = *printCount
	}
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

	objs := TCPConnectObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Printf("failed to load objects: %v", err)
		return
	}
	defer objs.Close()

	tcpv4kp, err := link.Kprobe("tcp_v4_connect", objs.TCPConnectPrograms.TcpV4Connect)
	if err != nil {
		log.Printf("opening tcp_v4_connect kprobe: %s", err)
		return
	}
	defer tcpv4kp.Close()

	tcpv4krp, err := link.Kretprobe("tcp_v4_connect", objs.TCPConnectPrograms.TcpV4ConnectRet)
	if err != nil {
		log.Printf("opening tcp_v4_connect kretprobe: %s", err)
		return
	}
	defer tcpv4krp.Close()

	tcpv6kp, err := link.Kprobe("tcp_v6_connect", objs.TCPConnectPrograms.TcpV6Connect)
	if err != nil {
		log.Printf("opening tcp_v6_connect kprobe: %s", err)
		return
	}
	defer tcpv6kp.Close()

	tcpv6krp, err := link.Kretprobe("tcp_v6_connect", objs.TCPConnectPrograms.TcpV6ConnectRet)
	if err != nil {
		log.Printf("opening tcp_v6_connect kretprobe: %s", err)
		return
	}
	defer tcpv6krp.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *printCount {
		var (
			ipv4key   ipv4FlowKey
			ipv4value uint64
		)
		entries := objs.TCPConnectMaps.Ipv4Count.Iterate()
		for entries.Next(&ipv4key, &ipv4value) {
			log.Println(ipv4key, ipv4value)
		}
		if err := entries.Err(); err != nil {
			panic(err)
		}

		var (
			ipv6key   ipv6FlowKey
			ipv6value uint64
		)
		entries = objs.TCPConnectMaps.Ipv6Count.Iterate()
		for entries.Next(&ipv6key, &ipv6value) {
			log.Println(ipv6key, ipv6value)
		}
		if err := entries.Err(); err != nil {
			panic(err)
		}
		// if err := objs.TCPConnectMaps.Ipv4Count.Lookup(&key, &value); err != nil {
		// 	log.Printf("failed to read IP v4 map: %s", err)
		// 	return
		// }
	} else {
		printEvents(ctx, objs.TCPConnectMaps.Events, *printTimestamp, *printUID)
	}

	// The program terminates successfully if it received INT/TERM signal.
	exitCode = 0
}
