// SPDX-License-Identifier: GPL-2.0
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16

enum event_type {
    EVENT_TYPE_PROCESS_EXEC,
    EVENT_TYPE_PROCESS_EXIT,
    EVENT_TYPE_CONN_OPEN,
    EVENT_TYPE_CONN_CLOSE,
};

// Struct to hold connection information
struct connection {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

// The single event struct sent to user-space
struct event {
    enum event_type type;
    __u32 pid;
    __u32 ppid;
    char comm[TASK_COMM_LEN];
    struct connection conn;
};

// Ring buffer for sending events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// Hash map to store command name for a given PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, char[TASK_COMM_LEN]);
} exec_map SEC(".maps");

// Hash map to track active connections and their owning PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct connection);
    __type(value, __u32);
} active_conns SEC(".maps");

// Map to store socket and PID between kprobe and kretprobe
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32); // key is tgid
    __type(value, struct sock *);
} connect_sockets SEC(".maps");


static __always_inline void submit_event(struct event *e) {
    struct event *task_event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!task_event) {
        return;
    }
    *task_event = *e;
    bpf_ringbuf_submit(task_event, 0);
}

// Tracepoint for process execution
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(void *ctx) {
    struct event e = {};
    e.type = EVENT_TYPE_PROCESS_EXEC;
    e.pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e.ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_map_update_elem(&exec_map, &e.pid, &e.comm, BPF_ANY);
    
    submit_event(&e);
    return 0;
}

// Tracepoint for process exit
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx) {
    struct event e = {};
    e.type = EVENT_TYPE_PROCESS_EXIT;
    e.pid = bpf_get_current_pid_tgid() >> 32;

    char *comm = bpf_map_lookup_elem(&exec_map, &e.pid);
    if (comm) {
        __builtin_memcpy(e.comm, comm, TASK_COMM_LEN);
    }

    bpf_map_delete_elem(&exec_map, &e.pid);
    submit_event(&e);
    return 0;
}

// Kprobe for tcp_v4_connect: stores socket pointer for the exit hook
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock *sk) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&connect_sockets, &tgid, &sk, BPF_ANY);
    return 0;
}

// Kretprobe for tcp_v4_connect: sends the final CONN_OPEN event
SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct sock **skpp = bpf_map_lookup_elem(&connect_sockets, &tgid);
    if (!skpp) return 0;

    bpf_map_delete_elem(&connect_sockets, &tgid);

    if (ret != 0) return 0; // Connection failed

    struct sock *sk = *skpp;
    struct event e = {};
    e.type = EVENT_TYPE_CONN_OPEN;
    e.pid = tgid;
    
    char *comm = bpf_map_lookup_elem(&exec_map, &e.pid);
    if (comm) {
        __builtin_memcpy(e.comm, comm, TASK_COMM_LEN);
    }

    e.conn.saddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    e.conn.daddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
    e.conn.sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    e.conn.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_map_update_elem(&active_conns, &e.conn, &e.pid, BPF_ANY);
    submit_event(&e);

    return 0;
}

// Kretprobe for TCP accept
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_ret, struct sock *newsk) {
    if (!newsk) return 0;
    
    __u32 saddr = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
    if (saddr == bpf_htonl(0x7f000001)) return 0; 
    
    struct event e = {};
    e.type = EVENT_TYPE_CONN_OPEN;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    e.conn.saddr = bpf_ntohl(saddr);
    e.conn.daddr = bpf_ntohl(BPF_CORE_READ(newsk, __sk_common.skc_daddr));
    e.conn.sport = BPF_CORE_READ(newsk, __sk_common.skc_num);
    e.conn.dport = bpf_ntohs(BPF_CORE_READ(newsk, __sk_common.skc_dport));

    bpf_map_update_elem(&active_conns, &e.conn, &e.pid, BPF_ANY);
    submit_event(&e);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk) {
    struct connection conn = {};
    conn.saddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    conn.daddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
    conn.sport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    conn.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    __u32 *pid = bpf_map_lookup_elem(&active_conns, &conn);
    if (pid != NULL) {
        struct event e = {};
        e.type = EVENT_TYPE_CONN_CLOSE;
        e.pid = *pid;
        e.conn = conn;
        
        char *comm = bpf_map_lookup_elem(&exec_map, pid);
        if (comm) {
            __builtin_memcpy(e.comm, comm, TASK_COMM_LEN);
        }

        submit_event(&e);
        bpf_map_delete_elem(&active_conns, &conn);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
