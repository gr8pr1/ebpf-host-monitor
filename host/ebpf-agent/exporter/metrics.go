package exporter

import "github.com/prometheus/client_golang/prometheus"

var ExecEvents = prometheus.NewCounter(
    prometheus.CounterOpts{
        Name: "ebpf_exec_events_total",
        Help: "Total execve events recorded by eBPF",
    })

var SudoEvents = prometheus.NewCounter(
    prometheus.CounterOpts{
        Name: "ebpf_sudo_events_total",
        Help: "Total sudo privilege escalation events recorded by eBPF",
    })

var PasswdReadEvents = prometheus.NewCounter(
    prometheus.CounterOpts{
        Name: "ebpf_passwd_read_events_total",
        Help: "Total /etc/passwd read attempts (cat /etc/passwd or sudo cat /etc/passwd) recorded by eBPF",
    })

