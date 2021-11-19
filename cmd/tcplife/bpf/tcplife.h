#ifndef __TCPLIFE_H
#define __TCPLIFE_H

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

#define TASK_COMM_LEN 16

struct event {
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	char task[TASK_COMM_LEN];
    __u64 ports;
	__u64 rx_b;
	__u64 tx_b;
	__u64 span_us;
	__u64 ts_us;
	__u32 pid;
	__u16 dport;
};

#endif /* __TCPLIFE_H_ */
