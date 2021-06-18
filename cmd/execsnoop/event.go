package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
)

// The event struct size in bytes, i.e., unsafe.Sizeof(e).
// It's used to obtain the variable length args from the perf record.
const eventSize = 44

// event represents a perf event sent to userspace from the BPF program running in the kernel.
// Note, that it must match the C event struct, and both C and Go structs must be aligned the same way.
type event struct {
	// Comm is the parent process/command name, e.g., bash.
	Comm [16]byte
	// PID is the process ID.
	PID int32
	// TGID is thread group ID.
	TGID int32
	// PPID is the process ID of the parent of this process.
	PPID int32
	// UID is the process user ID, e.g., 1000.
	UID uint32
	// Retval is the return value of the execve().
	Retval int32
	// ArgsCount is a number of arguments.
	ArgsCount int32
	// ArgSize is a size of arguments in bytes.
	ArgsSize uint32
}

func printHeader(w io.Writer, printTime, printTimestamp, printUID bool) {
	if printTime {
		fmt.Fprintf(w, "%-9s", "TIME")
	}
	if printTimestamp {
		fmt.Fprintf(w, "%-9s", "TIME(s)")
	}
	if printUID {
		fmt.Fprintf(w, "%-7s", "UID")
	}
	fmt.Fprintf(w, "%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS")
}

func printEvent(w io.Writer, e *event, args []byte, startTime time.Time, printTime, printTimestamp, printUID bool) {
	now := time.Now()
	if printTime {
		fmt.Fprintf(w, "%-9s", now.Format("15:04:05"))
	}
	if printTimestamp {
		fmt.Fprintf(w, "%-9.3f", now.Sub(startTime).Seconds())
	}
	if printUID {
		fmt.Fprintf(w, "%-7d", e.UID)
	}

	fmt.Fprintf(
		w,
		"%-16s %-6d %-6d %3d %s\n",
		bytes.TrimRight(e.Comm[:], "\x00"),
		e.PID,
		e.PPID,
		e.Retval,
		strings.ReplaceAll(
			string(bytes.Trim(args, "\x00")),
			"\x00",
			" ",
		),
	)
}
