package main

type ipv4FlowKey struct {
	// SrcAddr is the source address.
	SrcAddr [4]byte
	// DstAddr is the destination address.
	DstAddr [4]byte
	// DstPort is the destination port (uint16 in C struct).
	// Note, network byte order is big endian.
	DstPort [2]byte
	// The struct size is 12 bytes due to 2 bytes padding: pahole -C 'ipv4_flow_key' ./cmd/tcpconnect/tcpconnect_bpfel.o
	_ [2]byte
}

type ipv6FlowKey struct {
	// SrcAddr is the source address.
	SrcAddr [16]byte
	// DstAddr is the destination address.
	DstAddr [16]byte
	// DstPort is the destination port (uint16 in C struct).
	// Note, network byte order is big endian.
	DstPort [2]byte
}
