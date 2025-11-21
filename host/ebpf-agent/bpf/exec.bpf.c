#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Map to count exec events (global events)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} exec_counter SEC(".maps");

// Map to count sudo privilege escalation events
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sudo_counter SEC(".maps");

// Map to count /etc/passwd read attempts
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} passwd_read_counter SEC(".maps");

// Helper function to check if path ends with "/sudo"
// bpf_probe_read_user_str returns length including null terminator
static __always_inline int is_sudo_path(char *path, long len)
{
    // Must be at least 6 chars to contain "/sudo" (5 chars + null terminator)
    if (len < 6)
        return 0;
    
    // Check for "/sudo" at the end: len includes null, so "/sudo" is at len-6 to len-2
    // For "/usr/bin/sudo" (len=14): check positions 8-12
    long idx = len - 6;  // Position of '/' before "sudo"
    if (idx < 0 || idx >= 256)
        return 0;
        
    return (path[idx] == '/' &&
            path[idx + 1] == 's' &&
            path[idx + 2] == 'u' &&
            path[idx + 3] == 'd' &&
            path[idx + 4] == 'o');
}

// Helper function to check if path ends with "/cat"
static __always_inline int is_cat_path(char *path, long len)
{
    // Must be at least 5 chars to contain "/cat" (4 chars + null terminator)
    if (len < 5)
        return 0;
    
    // Check for "/cat" at the end
    long idx = len - 5;  // Position of '/' before "cat"
    if (idx < 0 || idx >= 256)
        return 0;
        
    return (path[idx] == '/' &&
            path[idx + 1] == 'c' &&
            path[idx + 2] == 'a' &&
            path[idx + 3] == 't');
}

// Helper function to check if argument is "/etc/passwd"
static __always_inline int is_passwd_file(char *arg, long len)
{
    // Must be exactly 12 chars for "/etc/passwd" (11 chars + null terminator)
    if (len != 12)
        return 0;
    
    const char *passwd = "/etc/passwd";
    for (int i = 0; i < 11; i++) {
        if (arg[i] != passwd[i])
            return 0;
    }
    return 1;
}

// Trace execve syscall
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    __u64 *val;
    char filename[128] = {0};  // Reduced from 256
    char *argv_ptr = NULL;
    char arg_buf[16] = {0};  // Just enough for "/etc/passwd" (12 bytes)

    // Always increment exec counter
    val = bpf_map_lookup_elem(&exec_counter, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }

    // Read filename from args[0] (first argument to execve)
    long ret = bpf_probe_read_user_str(filename, sizeof(filename) - 1, (void *)ctx->args[0]);
    if (ret < 0 || ret == 0)
        return 0;

    // Ensure null termination
    if (ret >= sizeof(filename))
        filename[sizeof(filename) - 1] = '\0';
    else
        filename[ret] = '\0';

    // Check if filename contains "sudo"
    if (is_sudo_path(filename, ret)) {
        val = bpf_map_lookup_elem(&sudo_counter, &key);
        if (val) {
            __sync_fetch_and_add(val, 1);
        }
    }

    // Check for "cat /etc/passwd" or "sudo cat /etc/passwd"
    int is_cat = is_cat_path(filename, ret);
    int is_sudo_cmd = is_sudo_path(filename, ret);
    
    if (is_cat || is_sudo_cmd) {
        // args[1] is the argv array (char**), read it directly
        char **argv_array = (char **)ctx->args[1];
        char *arg_ptr = NULL;
        
        if (is_cat) {
            // Direct "cat /etc/passwd": argv[1] should be "/etc/passwd"
            // Read argv[1] from the array
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_array[1]) != 0)
                return 0;
            
            if (arg_ptr != NULL) {
                // Read just enough to check for "/etc/passwd"
                long arg_ret = bpf_probe_read_user_str(arg_buf, sizeof(arg_buf) - 1, arg_ptr);
                if (arg_ret > 0 && arg_ret <= sizeof(arg_buf)) {
                    if (is_passwd_file(arg_buf, arg_ret)) {
                        val = bpf_map_lookup_elem(&passwd_read_counter, &key);
                        if (val) {
                            __sync_fetch_and_add(val, 1);
                        }
                    }
                }
            }
        } else if (is_sudo_cmd) {
            // "sudo cat /etc/passwd": argv[1] should be "cat", argv[2] should be "/etc/passwd"
            char *arg1_ptr = NULL;
            char *arg2_ptr = NULL;
            
            // Read argv[1] (should be "cat")
            if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), &argv_array[1]) != 0)
                return 0;
            
            // Read argv[2] (should be "/etc/passwd")
            if (bpf_probe_read_user(&arg2_ptr, sizeof(arg2_ptr), &argv_array[2]) != 0)
                return 0;
            
            if (arg1_ptr != NULL && arg2_ptr != NULL) {
                // Check if argv[1] is "cat" (4 chars + null = 5 bytes)
                long arg1_ret = bpf_probe_read_user_str(arg_buf, 5, arg1_ptr);
                if (arg1_ret == 5 && arg_buf[0] == 'c' && arg_buf[1] == 'a' && 
                    arg_buf[2] == 't' && arg_buf[3] == '\0') {
                    // Check if argv[2] is "/etc/passwd"
                    long arg2_ret = bpf_probe_read_user_str(arg_buf, sizeof(arg_buf) - 1, arg2_ptr);
                    if (arg2_ret > 0 && arg2_ret <= sizeof(arg_buf) && is_passwd_file(arg_buf, arg2_ret)) {
                        val = bpf_map_lookup_elem(&passwd_read_counter, &key);
                        if (val) {
                            __sync_fetch_and_add(val, 1);
                        }
                    }
                }
            }
        }
    }

    return 0;
}

