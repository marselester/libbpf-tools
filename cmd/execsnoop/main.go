//go:build linux

/*
Program execsnoop is a BCC tool created by Brendan Gregg and others
to trace new process execution via execve() syscalls,
see https://github.com/iovisor/bcc/blob/master/libbpf-tools.
It can find issues of short-lived processes that consume CPU resources and
can also be used to debug software execution, including application start scripts.
For example, perturbations from background jobs, slow of failing application startup,
slow or failing container startup.
Check out examples https://github.com/iovisor/bcc/blob/master/tools/execsnoop_example.txt.

	PCOMM: The parent process/command name, e.g., bash.
	PID: The process ID.
	RET: The return value of the execve().
	ARGS: The filename with arguments.
	TIME: The time of the event (HH:MM:SS).
	TIME(s): The time of the event in seconds, counting from the first event seen.
	UID: The process user ID.

The tool catches new processes that follow the fork->exec sequence,
as well as processes that re-exec() themselves.
Some applications fork() but do not exec(), e.g., for worker processes,
which won't be included in the execsnoop output.

Since the rate of process execution is expected to be low (<1000/second),
the overhead is negligible.
*/
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS -cc clang-11 ExecSnoop ./bpf/execsnoop.bpf.c -- -I../../headers

func main() {
	// By default an exit code is set to indicate a failure since
	// there are more failure scenarios to begin with.
	exitCode := 1
	defer func() { os.Exit(exitCode) }()

	var (
		printTime      = flag.Bool("time", false, "include the time of the event on output (HH:MM:SS)")
		printTimestamp = flag.Bool("timestamp", false, "include the time of the event in seconds on output, counting from the first event seen")
		printUID       = flag.Bool("print-uid", false, "include UID on output")
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

	// Load the BPF program into the kernel from an ELF.
	// ExecSnoopObjects contains all objects (BPF programs and maps) after they have been loaded into the kernel:
	// TracepointSyscallsSysEnterExecve and TracepointSyscallsSysExitExecve BPF programs,
	// Events and Execs BPF maps.
	objs := ExecSnoopObjects{}
	if err := LoadExecSnoopObjects(&objs, nil); err != nil {
		log.Printf("failed to load BPF programs and maps: %v", err)
		return
	}
	defer objs.Close()

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.ExecSnoopPrograms.TracepointSyscallsSysEnterExecve)
	if err != nil {
		log.Printf("failed to attach the BPF program to sys_enter_execve tracepoint: %v", err)
		return
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.ExecSnoopPrograms.TracepointSyscallsSysExitExecve)
	if err != nil {
		log.Printf("failed to attach the BPF program to sys_exit_execve tracepoint: %v", err)
		return
	}
	defer tpExit.Close()

	// Open a perf event reader from user space on the PERF_EVENT_ARRAY map
	// defined in the BPF C program.
	rd, err := perf.NewReader(objs.ExecSnoopMaps.Events, os.Getpagesize())
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

	printHeader(os.Stdout, *printTime, *printTimestamp, *printUID)

	startTime := time.Now()
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
			log.Printf("failed to parse perf event: %v", err)
			continue
		}

		printEvent(os.Stdout, &e, record.RawSample[eventSize:], startTime, *printTime, *printTimestamp, *printUID)
	}

	// The program terminates successfully if it received INT/TERM signal.
	exitCode = 0
}
