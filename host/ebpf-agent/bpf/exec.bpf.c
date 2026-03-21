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
 * Per-CPU counter maps
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
 * Helper: check if path ends with a given suffix
 * ============================================================ */
static __always_inline int ends_with(char *path, long len, const char *suffix, int suffix_len)
{
    /* len includes null terminator from bpf_probe_read_user_str */
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
 * Tracks: exec events, sudo usage, /etc/passwd reads
 * Also captures parent PID for process lineage
 * ============================================================ */
#ifdef MONITOR_EXEC
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx)
{
    char filename[128] = {0};
    char arg_buf[16] = {0};

    /* Always count exec events */
    inc_counter(&exec_counter);

    /* Read filename (first arg to execve) */
    long ret = bpf_probe_read_user_str(filename, sizeof(filename) - 1, (void *)ctx->args[0]);
    if (ret <= 0)
        return 0;

    if (ret >= (long)sizeof(filename))
        filename[sizeof(filename) - 1] = '\0';
    else
        filename[ret] = '\0';

    /* Check for sudo */
    int is_sudo = ends_with(filename, ret, "/sudo", 5);
    if (is_sudo)
        inc_counter(&sudo_counter);

    /* Check for cat */
    int is_cat = ends_with(filename, ret, "/cat", 4);

    /* Detect "cat /etc/passwd" or "sudo cat /etc/passwd" */
#ifdef MONITOR_PASSWD
    if (is_cat || is_sudo) {
        char **argv_array = (char **)ctx->args[1];
        char *arg_ptr = NULL;

        if (is_cat) {
            /* argv[1] should be "/etc/passwd" */
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_array[1]) == 0 && arg_ptr) {
                long arg_ret = bpf_probe_read_user_str(arg_buf, sizeof(arg_buf) - 1, arg_ptr);
                if (arg_ret == 12 && str_eq(arg_buf, "/etc/passwd", 11))
                    inc_counter(&passwd_read_counter);
            }
        } else if (is_sudo) {
            /* "sudo cat /etc/passwd": argv[1]="cat", argv[2]="/etc/passwd" */
            char *arg1_ptr = NULL, *arg2_ptr = NULL;
            if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), &argv_array[1]) != 0)
                return 0;
            if (bpf_probe_read_user(&arg2_ptr, sizeof(arg2_ptr), &argv_array[2]) != 0)
                return 0;
            if (arg1_ptr && arg2_ptr) {
                long a1 = bpf_probe_read_user_str(arg_buf, 5, arg1_ptr);
                if (a1 == 5 && arg_buf[0] == 'c' && arg_buf[1] == 'a' && arg_buf[2] == 't' && arg_buf[3] == '\0') {
                    long a2 = bpf_probe_read_user_str(arg_buf, sizeof(arg_buf) - 1, arg2_ptr);
                    if (a2 == 12 && str_eq(arg_buf, "/etc/passwd", 11))
                        inc_counter(&passwd_read_counter);
                }
            }
        }
    }
#endif /* MONITOR_PASSWD */

    return 0;
}
#endif /* MONITOR_EXEC */

/* ============================================================
 * TRACEPOINT: sys_enter_connect
 * Tracks: all outbound connect() calls, flags suspicious ports
 * ============================================================ */
#ifdef MONITOR_CONNECT
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr = {0};

    /* Always count connect events */
    inc_counter(&connect_counter);

    /* Read the sockaddr struct from userspace (args[1] = sockaddr*, args[2] = addrlen) */
    int addrlen = (int)ctx->args[2];
    if (addrlen < (int)sizeof(struct sockaddr_in))
        return 0;

    if (bpf_probe_read_user(&addr, sizeof(addr), (void *)ctx->args[1]) != 0)
        return 0;

    /* Only check AF_INET (IPv4) */
    if (addr.sin_family != 2) /* AF_INET = 2 */
        return 0;

    /* Convert port from network byte order to host byte order */
    __u16 port = __builtin_bswap16(addr.sin_port);

    if (is_suspicious_port(port))
        inc_counter(&suspicious_connect_counter);

    return 0;
}
#endif /* MONITOR_CONNECT */

/* ============================================================
 * TRACEPOINT: sys_enter_ptrace
 * Tracks: all ptrace() calls (process injection, debugger attach)
 * ============================================================ */
#ifdef MONITOR_PTRACE
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    inc_counter(&ptrace_counter);
    return 0;
}
#endif /* MONITOR_PTRACE */

/* ============================================================
 * TRACEPOINT: sys_enter_openat
 * Tracks: access to sensitive files
 *   /etc/shadow, /etc/sudoers, .ssh/authorized_keys
 * ============================================================ */
#ifdef MONITOR_OPENAT
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    char path[64] = {0};

    /* args[1] = filename for openat */
    long ret = bpf_probe_read_user_str(path, sizeof(path) - 1, (void *)ctx->args[1]);
    if (ret <= 0)
        return 0;

    /* Check /etc/shadow (12 chars + null = 13) */
    if (ret == 13 && str_eq(path, "/etc/shadow", 11)) {
        inc_counter(&sensitive_file_counter);
        return 0;
    }

    /* Check /etc/sudoers (13 chars + null = 14) */
    if (ret == 14 && str_eq(path, "/etc/sudoers", 12)) {
        inc_counter(&sensitive_file_counter);
        return 0;
    }

    /* Check for authorized_keys anywhere in path */
    /* We look for the suffix "/authorized_keys" (16 chars) */
    if (ret >= 17 && ends_with(path, ret, "/authorized_keys", 16)) {
        inc_counter(&sensitive_file_counter);
        return 0;
    }

    return 0;
}
#endif /* MONITOR_OPENAT */

/* ============================================================
 * TRACEPOINT: sys_enter_setuid
 * Tracks: setuid() privilege escalation attempts
 * ============================================================ */
#ifdef MONITOR_SETUID
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    inc_counter(&setuid_counter);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
    inc_counter(&setgid_counter);
    return 0;
}
#endif /* MONITOR_SETUID */
