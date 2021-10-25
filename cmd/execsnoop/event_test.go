package main

import (
	"bytes"
	"testing"
	"time"
)

func TestPrintHeader(t *testing.T) {
	b := bytes.Buffer{}
	printHeader(&b, true, true, true)

	want := "TIME     TIME(s)  UID    PCOMM            PID    PPID   RET ARGS\n"
	got := b.String()
	if got != want {
		t.Errorf("expected %q got %q", want, got)
	}
}

func TestPrintEvent(t *testing.T) {
	b := bytes.Buffer{}
	e := event{
		PID:       573609,
		PPID:      46917,
		UID:       1000,
		Retval:    0,
		ArgsCount: 3,
		ArgsSize:  30,
		Comm:      [16]byte{108, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	args := []byte{108, 115, 0, 45, 45, 99, 111, 108, 111, 114, 61, 97, 117, 116, 111, 0, 45, 108, 97, 104, 0, 0, 0}
	printEvent(&b, &e, args, time.Now(), false, false, true)

	want := "1000   ls               573609 46917    0 ls --color=auto -lah\n"
	got := b.String()
	if got != want {
		t.Errorf("expected %q got %q", want, got)
	}
}
