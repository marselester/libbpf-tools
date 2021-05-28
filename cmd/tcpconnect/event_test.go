// +build linux

package main

import (
	"bytes"
	"testing"
)

func TestPrintHeader(t *testing.T) {
	b := bytes.Buffer{}
	printHeader(&b, true, true)

	want := "TIME(s)  UID   PID    COMM         IP SADDR            DADDR            DPORT\n"
	got := b.String()
	if got != want {
		t.Errorf("expected %q got %q", want, got)
	}
}

func TestPrintEvent(t *testing.T) {
	b := bytes.Buffer{}
	e := event{
		SrcAddr:   [16]byte{127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		DstAddr:   [16]byte{127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Comm:      [16]byte{99, 117, 114, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Timestamp: 266732620282,
		AddrFam:   2,
		PID:       238454,
		UID:       1000,
		DstPort:   [2]byte{31, 64},
	}
	printEvent(&b, &e, float64(e.Timestamp), true, true)

	want := "0.000    1000  238454 curl         4  127.0.0.1        127.0.0.1        8000\n"
	got := b.String()
	if got != want {
		t.Errorf("expected %q got %q", want, got)
	}
}
