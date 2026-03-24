#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* ============================================================
 * Feature flags — all enabled by default.
 * Disable at compile time: clang ... -UMONITOR_EXEC
 * ============================================================ */
#ifndef MONITOR_EXEC
#define MONITOR_EXEC
#endif
#ifndef MONITOR_SUDO
#define MONITOR_SUDO
#endif
#ifndef MONITOR_PASSWD
#define MONITOR_PASSWD
#endif
#ifndef MONITOR_CONNECT
#define MONITOR_CONNECT
#endif
#ifndef MONITOR_PTRACE
#define MONITOR_PTRACE
#endif
#ifndef MONITOR_OPENAT
#define MONITOR_OPENAT
#endif
#ifndef MONITOR_SETUID
#define MONITOR_SETUID
#endif
#ifndef MONITOR_FORK
#define MONITOR_FORK
#endif
#ifndef MONITOR_EXIT
#define MONITOR_EXIT
#endif
#ifndef MONITOR_BIND
#define MONITOR_BIND
#endif
#ifndef MONITOR_DNS
#define MONITOR_DNS
#endif
#ifndef MONITOR_CAPSET
#define MONITOR_CAPSET
#endif

/* ============================================================
 * Suspicious C2 ports for connect() monitoring
 * ============================================================ */
#define PORT_4444  4444
#define PORT_1337  1337
#define PORT_5555  5555
#define PORT_6666  6666
#define PORT_8443  8443
#define PORT_1234  1234
#define PORT_31337 31337

/* ============================================================
 * Event types for ringbuf
 * ============================================================ */
#define EVENT_EXEC      1
#define EVENT_CONNECT   2
#define EVENT_PTRACE    3
#define EVENT_OPENAT    4
#define EVENT_SETUID    5
#define EVENT_SETGID    6
#define EVENT_FORK      7
#define EVENT_EXIT      8
#define EVENT_BIND      9
#define EVENT_DNS       10
#define EVENT_CAPSET    11

/* Event flags */
#define FLAG_SUDO              (1 << 0)
#define FLAG_SUSPICIOUS_PORT   (1 << 1)
#define FLAG_SENSITIVE_FILE    (1 << 2)
#define FLAG_PASSWD_READ       (1 << 3)

/* ============================================================
 * Structured event for ringbuf (48 bytes)
 * ============================================================ */
struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u64 cgroup_id;
    __u8  event_type;
    __u8  flags;
    __u16 dest_port;
    __u32 dest_ip;
    char  comm[16];
};

/* ============================================================
 * RingBuf for rich events to userspace
 * ============================================================ */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* ============================================================
 * Per-CPU counter maps (retained for backward compat)
 * ============================================================ */

#ifdef MONITOR_EXEC
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} exec_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sudo_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} passwd_read_counter SEC(".maps");
#endif

#ifdef MONITOR_CONNECT
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} connect_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} suspicious_connect_counter SEC(".maps");
#endif

#ifdef MONITOR_PTRACE
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ptrace_counter SEC(".maps");
#endif

#ifdef MONITOR_OPENAT
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sensitive_file_counter SEC(".maps");
#endif

#ifdef MONITOR_SETUID
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} setuid_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} setgid_counter SEC(".maps");
#endif

#ifdef MONITOR_FORK
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} fork_counter SEC(".maps");
#endif

#ifdef MONITOR_BIND
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} bind_counter SEC(".maps");
#endif

#ifdef MONITOR_DNS
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dns_counter SEC(".maps");
#endif

#ifdef MONITOR_CAPSET
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} capset_counter SEC(".maps");
#endif

/* ============================================================
 * Helper: increment a per-CPU counter map
 * ============================================================ */
static __always_inline void inc_counter(void *map)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
}

/* ============================================================
 * Helper: emit a structured event to the ringbuf
 * ============================================================ */
static __always_inline void emit_event(__u8 event_type, __u8 flags,
                                       __u16 dest_port, __u32 dest_ip)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->event_type = event_type;
    e->flags = flags;
    e->dest_port = dest_port;
    e->dest_ip = dest_ip;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
}

/* ============================================================
 * Helper: check if path ends with a given suffix
 * ============================================================ */
static __always_inline int ends_with(char *path, long len, const char *suffix, int suffix_len)
{
    long idx = len - suffix_len - 1;
    if (idx < 0 || idx >= 256)
        return 0;
    for (int i = 0; i < suffix_len; i++) {
        if (path[idx + i] != suffix[i])
            return 0;
    }
    return 1;
}

/* ============================================================
 * Helper: exact string match
 * ============================================================ */
static __always_inline int str_eq(char *buf, const char *target, int target_len)
{
    for (int i = 0; i < target_len; i++) {
        if (buf[i] != target[i])
            return 0;
    }
    return 1;
}

/* ============================================================
 * Helper: check if port is suspicious (common C2 ports)
 * ============================================================ */
#ifdef MONITOR_CONNECT
static __always_inline int is_suspicious_port(__u16 port)
{
    switch (port) {
    case PORT_4444:
    case PORT_1337:
    case PORT_5555:
    case PORT_6666:
    case PORT_8443:
    case PORT_1234:
    case PORT_31337:
        return 1;
    default:
        return 0;
    }
}
#endif

/* ============================================================
 * TRACEPOINT: sys_enter_execve
 * ============================================================ */
#ifdef MONITOR_EXEC
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx)
{
    char filename[128] = {0};
    char arg_buf[16] = {0};
    __u8 flags = 0;

    inc_counter(&exec_counter);

    long ret = bpf_probe_read_user_str(filename, sizeof(filename) - 1, (void *)ctx->args[0]);
    if (ret <= 0) {
        emit_event(EVENT_EXEC, 0, 0, 0);
        return 0;
    }

    if (ret >= (long)sizeof(filename))
        filename[sizeof(filename) - 1] = '\0';
    else
        filename[ret] = '\0';

    int is_sudo = ends_with(filename, ret, "/sudo", 5);
    if (is_sudo) {
        inc_counter(&sudo_counter);
        flags |= FLAG_SUDO;
    }

    int is_cat = ends_with(filename, ret, "/cat", 4);

#ifdef MONITOR_PASSWD
    if (is_cat || is_sudo) {
        char **argv_array = (char **)ctx->args[1];
        char *arg_ptr = NULL;

        if (is_cat) {
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_array[1]) == 0 && arg_ptr) {
                long arg_ret = bpf_probe_read_user_str(arg_buf, sizeof(arg_buf) - 1, arg_ptr);
                if (arg_ret == 12 && str_eq(arg_buf, "/etc/passwd", 11)) {
                    inc_counter(&passwd_read_counter);
                    flags |= FLAG_PASSWD_READ;
                }
            }
        } else if (is_sudo) {
            char *arg1_ptr = NULL, *arg2_ptr = NULL;
            if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), &argv_array[1]) != 0)
                goto done;
            if (bpf_probe_read_user(&arg2_ptr, sizeof(arg2_ptr), &argv_array[2]) != 0)
                goto done;
            if (arg1_ptr && arg2_ptr) {
                long a1 = bpf_probe_read_user_str(arg_buf, 5, arg1_ptr);
                if (a1 == 5 && arg_buf[0] == 'c' && arg_buf[1] == 'a' && arg_buf[2] == 't' && arg_buf[3] == '\0') {
                    long a2 = bpf_probe_read_user_str(arg_buf, sizeof(arg_buf) - 1, arg2_ptr);
                    if (a2 == 12 && str_eq(arg_buf, "/etc/passwd", 11)) {
                        inc_counter(&passwd_read_counter);
                        flags |= FLAG_PASSWD_READ;
                    }
                }
            }
        }
    }
#endif /* MONITOR_PASSWD */

done:
    emit_event(EVENT_EXEC, flags, 0, 0);
    return 0;
}
#endif /* MONITOR_EXEC */

/* ============================================================
 * TRACEPOINT: sys_enter_connect
 * ============================================================ */
#ifdef MONITOR_CONNECT
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr = {0};
    __u8 flags = 0;
    __u16 port = 0;
    __u32 ip = 0;

    inc_counter(&connect_counter);

    int addrlen = (int)ctx->args[2];
    if (addrlen < (int)sizeof(struct sockaddr_in))
        goto done;

    if (bpf_probe_read_user(&addr, sizeof(addr), (void *)ctx->args[1]) != 0)
        goto done;

    if (addr.sin_family != 2) /* AF_INET */
        goto done;

    port = __builtin_bswap16(addr.sin_port);
    ip = addr.sin_addr.s_addr;

    if (is_suspicious_port(port)) {
        inc_counter(&suspicious_connect_counter);
        flags |= FLAG_SUSPICIOUS_PORT;
    }

done:
    emit_event(EVENT_CONNECT, flags, port, ip);
    return 0;
}
#endif /* MONITOR_CONNECT */

/* ============================================================
 * TRACEPOINT: sys_enter_ptrace
 * ============================================================ */
#ifdef MONITOR_PTRACE
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    inc_counter(&ptrace_counter);
    emit_event(EVENT_PTRACE, 0, 0, 0);
    return 0;
}
#endif /* MONITOR_PTRACE */

/* ============================================================
 * TRACEPOINT: sys_enter_openat
 * ============================================================ */
#ifdef MONITOR_OPENAT
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    char path[64] = {0};
    __u8 flags = 0;

    long ret = bpf_probe_read_user_str(path, sizeof(path) - 1, (void *)ctx->args[1]);
    if (ret <= 0)
        return 0;

    if (ret == 13 && str_eq(path, "/etc/shadow", 11)) {
        inc_counter(&sensitive_file_counter);
        flags |= FLAG_SENSITIVE_FILE;
    } else if (ret == 14 && str_eq(path, "/etc/sudoers", 12)) {
        inc_counter(&sensitive_file_counter);
        flags |= FLAG_SENSITIVE_FILE;
    } else if (ret >= 17 && ends_with(path, ret, "/authorized_keys", 16)) {
        inc_counter(&sensitive_file_counter);
        flags |= FLAG_SENSITIVE_FILE;
    }

    if (flags)
        emit_event(EVENT_OPENAT, flags, 0, 0);

    return 0;
}
#endif /* MONITOR_OPENAT */

/* ============================================================
 * TRACEPOINT: sys_enter_setuid / sys_enter_setgid
 * ============================================================ */
#ifdef MONITOR_SETUID
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    inc_counter(&setuid_counter);
    emit_event(EVENT_SETUID, 0, 0, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
    inc_counter(&setgid_counter);
    emit_event(EVENT_SETGID, 0, 0, 0);
    return 0;
}
#endif /* MONITOR_SETUID */

/* ============================================================
 * TRACEPOINT: sched_process_fork
 * ============================================================ */
#ifdef MONITOR_FORK
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    inc_counter(&fork_counter);
    emit_event(EVENT_FORK, 0, 0, 0);
    return 0;
}
#endif /* MONITOR_FORK */

/* ============================================================
 * TRACEPOINT: sched_process_exit
 * ============================================================ */
#ifdef MONITOR_EXIT
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    emit_event(EVENT_EXIT, 0, 0, 0);
    return 0;
}
#endif /* MONITOR_EXIT */

/* ============================================================
 * TRACEPOINT: sys_enter_bind
 * ============================================================ */
#ifdef MONITOR_BIND
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr = {0};
    __u16 port = 0;

    inc_counter(&bind_counter);

    int addrlen = (int)ctx->args[2];
    if (addrlen < (int)sizeof(struct sockaddr_in))
        goto done;

    if (bpf_probe_read_user(&addr, sizeof(addr), (void *)ctx->args[1]) != 0)
        goto done;

    if (addr.sin_family != 2)
        goto done;

    port = __builtin_bswap16(addr.sin_port);

done:
    emit_event(EVENT_BIND, 0, port, 0);
    return 0;
}
#endif /* MONITOR_BIND */

/* ============================================================
 * TRACEPOINT: sys_enter_sendto (DNS on port 53)
 * ============================================================ */
#ifdef MONITOR_DNS
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr = {0};

    void *addr_ptr = (void *)ctx->args[4];
    if (!addr_ptr)
        return 0;

    int addrlen = (int)ctx->args[5];
    if (addrlen < (int)sizeof(struct sockaddr_in))
        return 0;

    if (bpf_probe_read_user(&addr, sizeof(addr), addr_ptr) != 0)
        return 0;

    if (addr.sin_family != 2)
        return 0;

    __u16 port = __builtin_bswap16(addr.sin_port);
    if (port == 53) {
        inc_counter(&dns_counter);
        emit_event(EVENT_DNS, 0, 53, addr.sin_addr.s_addr);
    }

    return 0;
}
#endif /* MONITOR_DNS */

/* ============================================================
 * TRACEPOINT: sys_enter_capset
 * ============================================================ */
#ifdef MONITOR_CAPSET
SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
    inc_counter(&capset_counter);
    emit_event(EVENT_CAPSET, 0, 0, 0);
    return 0;
}
#endif /* MONITOR_CAPSET */
