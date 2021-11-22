#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "tcplife.h"

#define AF_INET 2
#define AF_INET6 10

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct sock *);
    __type(value, u64);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} birth SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct id_t {
    u32 pid;
    char task[TASK_COMM_LEN];
};

struct inet_sock_state_ctx {
    u64 __pad; // First 8 bytes are not accessible by bpf code.
    const void * skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct sock *);
    __type(value, struct id_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} whoami SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct inet_sock_state_ctx *args)
{
    if (args->protocol != IPPROTO_TCP)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // sk is mostly used as a UUID, and for two tcp stats:
    struct sock *sk = (struct sock *)args->skaddr;

    // lport is either used in a filter here, or later
    u16 lport = args->sport;
    // FILTER_LPORT
    // if (lport != 8000 && lport != 9000) { birth.delete(&sk); return 0; }

    // dport is either used in a filter here, or later
    u16 dport = args->dport;
    // FILTER_DPORT
    // if (dport != 8000 && dport != 9000) { birth.delete(&sk); return 0; }

    /*
     * This tool includes PID and comm context. It's best effort, and may
     * be wrong in some situations. It currently works like this:
     * - record timestamp on any state < TCP_FIN_WAIT1
     * - cache task context on:
     *       TCP_SYN_SENT: tracing from client
     *       TCP_LAST_ACK: client-closed from server
     * - do output on TCP_CLOSE:
     *       fetch task context if cached, or use current task
     */

    // capture birth time
    if (args->newstate < TCP_FIN_WAIT1) {
        /*
         * Matching just ESTABLISHED may be sufficient, provided no code-path
         * sets ESTABLISHED without a tcp_set_state() call. Until we know
         * that for sure, match all early states to increase chances a
         * timestamp is set.
         * Note that this needs to be set before the PID filter later on,
         * since the PID isn't reliable for these early stages, so we must
         * save all timestamps and do the PID filter later when we can.
         */
        u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&birth, &sk, &ts, 0);
    }

    // record PID & comm on SYN_SENT
    if (args->newstate == TCP_SYN_SENT || args->newstate == TCP_LAST_ACK) {
        // now we can PID filter, both here and a little later on for CLOSE
        // FILTER_PID
        // if (pid != 123) { return 0; }

        struct id_t me = {.pid = pid};
        bpf_get_current_comm(&me.task, sizeof(me.task));
        bpf_map_update_elem(&whoami, &sk, &me, 0);
    }

    if (args->newstate != TCP_CLOSE)
        return 0;

    // calculate lifespan
    u64 *tsp, delta_us;
    tsp = bpf_map_lookup_elem(&birth, &sk);
    if (tsp == 0) {
        bpf_map_delete_elem(&whoami, &sk);
        return 0;               // missed create
    }
    delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    bpf_map_delete_elem(&birth, &sk);

    // fetch possible cached data, and filter
    struct id_t *mep;
    mep = bpf_map_lookup_elem(&whoami, &sk);
    if (mep != 0)
        pid = mep->pid;
    // FILTER_PID
    // if (pid != 123) { return 0; }

    u16 family = args->family;
    // FILTER_FAMILY
    // if (family != AF_INET) { return 0; }
    // if (family != AF_INET6) { return 0; }

    // get throughput stats. see tcp_get_info().
    u64 rx_b = 0, tx_b = 0, sport = 0;
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    bpf_probe_read_kernel(&rx_b, sizeof(rx_b), (void *)&tp->bytes_received);
    bpf_probe_read_kernel(&tx_b, sizeof(tx_b), (void *)&tp->bytes_acked);

    struct event e = {};
    e.span_us = delta_us;
    e.rx_b = rx_b;
    e.tx_b = tx_b;
    e.ts_us = bpf_ktime_get_ns() / 1000;
    e.pid = pid;
    e.af = args->family;
    e.lport = lport;
    e.dport = dport;
    if (args->family == AF_INET) {
        BPF_CORE_READ_INTO(&e.saddr_v4, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&e.daddr_v4, sk, __sk_common.skc_daddr);
    } else {
        BPF_CORE_READ_INTO(&e.saddr_v6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&e.daddr_v6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
    if (mep == 0) {
        bpf_get_current_comm(e.task, sizeof(e.task));
    } else {
        bpf_probe_read_kernel(&e.task, sizeof(e.task), (void *)mep->task);
    }
    bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    if (mep != 0)
        bpf_map_delete_elem(&whoami, &sk);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
