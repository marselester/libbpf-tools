//go:build linux

package main

import (
	"log"
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

	// Open a Kprobe at the entry point of the kernel function and
	// attach the pre-compiled program.
	tcpv4kp, err := link.Kprobe("tcp_v4_connect", objs.TCPConnLatPrograms.TcpV4Connect)
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_v4_connect kprobe: %s", err)
		return
	}
	defer tcpv4kp.Close()

	tcpv6kp, err := link.Kprobe("tcp_v6_connect", objs.TCPConnLatPrograms.TcpV6Connect)
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_v6_connect kprobe: %s", err)
		return
	}
	defer tcpv6kp.Close()

	tcprcvkp, err := link.Kprobe("tcp_rcv_state_process", objs.TCPConnLatPrograms.TcpRcvStateProcess)
	if err != nil {
		log.Printf("failed to attach the BPF program to tcp_rcv_state_process kprobe: %s", err)
		return
	}
	defer tcprcvkp.Close()

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

		log.Printf("received from perf ring buffer: %s", record.RawSample)
	}

	// The program terminates successfully if it received INT/TERM signal.
	exitCode = 0
}
