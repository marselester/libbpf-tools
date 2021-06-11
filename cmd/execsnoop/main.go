package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	// Increase the rlimit of the current process to provide sufficient space
	// for locking memory for the eBPF map.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Printf("failed to set temporary rlimit: %v", err)
		return
	}

	objs := ExecSnoopObjects{}
	if err := LoadExecSnoopObjects(&objs, nil); err != nil {
		log.Printf("failed to load objects: %v", err)
		return
	}
	defer objs.Close()

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.ExecSnoopPrograms.TracepointSyscallsSysEnterExecve)
	if err != nil {
		log.Printf("failed to open tracepoint: %v", err)
		return
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.ExecSnoopPrograms.TracepointSyscallsSysExitExecve)
	if err != nil {
		log.Printf("failed to open tracepoint: %v", err)
		return
	}
	defer tpExit.Close()

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// defined in the BPF C program.
	rd, err := perf.NewReader(objs.ExecSnoopMaps.Events, os.Getpagesize())
	if err != nil {
		log.Printf("creating perf event reader: %s", err)
		return
	}
	defer rd.Close()

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
			log.Printf("failed to parse perf event: %v", err)
			continue
		}

		fmt.Println(e)
	}

	// The program terminates successfully if it received INT/TERM signal.
	exitCode = 0
}

// pahole -C 'event' ./cmd/execsnoop/execsnoop_bpfel.o
// struct event {
// 	char                       comm[16];             /*     0    16 */
// 	pid_t                      pid;                  /*    16     4 */
// 	pid_t                      tgid;                 /*    20     4 */
// 	pid_t                      ppid;                 /*    24     4 */
// 	uid_t                      uid;                  /*    28     4 */
// 	int                        retval;               /*    32     4 */
// 	int                        args_count;           /*    36     4 */
// 	unsigned int               args_size;            /*    40     4 */
// 	char                       args[7680];           /*    44  7680 */
// 	/* size: 7724, cachelines: 121, members: 9 */
// 	/* last cacheline: 44 bytes */
// };
type event struct {
	Comm      [16]byte
	PID       int32
	TGID      int32
	PPID      int32
	UID       uint32
	Retval    int32
	ArgsCount int32
	ArgsSize  uint32
	// TOTAL_MAX_ARGS * ARGSIZE
	Args [7680]byte
}
