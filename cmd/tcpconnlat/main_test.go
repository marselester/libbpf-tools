package main

import (
	"bytes"
	"testing"
)

func TestPrintHeader(t *testing.T) {
	b := bytes.Buffer{}
	printHeader(&b, true)

	want := "TIME(s)  PID    COMM         IP SADDR            DADDR            DPORT LAT(ms)\n"
	got := b.String()
	if got != want {
		t.Errorf("expected %q got %q", want, got)
	}
}

func TestPrintEvent(t *testing.T) {
	b := bytes.Buffer{}
	e := event{
		SrcAddr:   [16]byte{10, 0, 2, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		DstAddr:   [16]byte{93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Comm:      [16]byte{99, 117, 114, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		Delta:     47802,
		Timestamp: 21615007854,
		PID:       21500,
		AddrFam:   2,
		DstPort:   [2]byte{0, 80},
	}
	printEvent(&b, &e, float64(e.Timestamp), true)

	want := "0.000    21500  curl         4  10.0.2.15        93.184.216.34    80    47.80\n"
	got := b.String()
	if got != want {
		t.Errorf("expected %q got %q", want, got)
	}
}
