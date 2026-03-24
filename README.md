# eBPF Adaptive Security Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org/)
[![Kernel](https://img.shields.io/badge/Kernel-5.8+-orange)](https://www.kernel.org/)
[![eBPF](https://img.shields.io/badge/eBPF-Powered-blue)](https://ebpf.io/)

A host-adapting security monitoring agent that uses eBPF to learn normal system behavior and detect anomalies. The agent operates in two phases: it first establishes per-host baselines through statistical analysis, then monitors for deviations using z-score anomaly detection.

## How It Works

The agent attaches eBPF programs to kernel tracepoints to observe syscalls at the kernel level. Events flow through a structured pipeline:

1. **Kernel**: Tracepoint programs capture syscall metadata (pid, uid, cgroup, process name) and push structured events to a ringbuf, while also incrementing per-CPU counters for backward-compatible Prometheus metrics.
2. **Enrichment**: The Go agent drains the ringbuf, resolves pids to binaries, uids to usernames, and cgroup IDs to container names.
3. **Aggregation**: Events are bucketed into 1-minute windows per dimension (user, process, container, metric type).
4. **Baselining**: A 168-bucket seasonal model (24 hours x 7 days) learns per-dimension means and standard deviations, with EWMA for drift adaptation.
5. **Scoring**: Each window is scored against the baseline. Z-scores above the threshold are flagged as anomalies and exposed as Prometheus gauges.

### Two-Phase Operation

**Phase 1 — Learning** (default: 7 days): The agent collects events and builds per-dimension, per-time-of-day baselines. Static fallback alerts remain active during this phase.

**Phase 2 — Monitoring**: Each aggregation window is scored against the learned baseline. Anomalies are exposed as `ebpf_anomaly_score` metrics. The baseline slowly adapts via EWMA recalibration.

## MITRE ATT&CK Coverage

| Technique | Name | Detection |
|---|---|---|
| T1059 | Command and Scripting Interpreter | `execve` tracing with per-user/per-process baselining |
| T1548 | Abuse Elevation Control Mechanism | `sudo` detection, `setuid()`/`setgid()`, `capset()` |
| T1003 | OS Credential Dumping | `openat()` on `/etc/shadow`, `/etc/passwd` reads |
| T1055 | Process Injection | `ptrace()` monitoring |
| T1071 | Application Layer Protocol (C2) | `connect()` with C2 port flagging, DNS query monitoring |
| T1078 | Valid Accounts | `openat()` on `/etc/sudoers`, `authorized_keys` |
| T1036 | Masquerading | Per-process syscall profiling detects unusual behavior per binary |
| T1046 | Network Service Discovery | `bind()` monitoring for unexpected listening ports |

## What It Monitors

| Dimension | Tracepoints | Baseline Granularity |
|---|---|---|
| **Process Activity** | `sys_enter_execve`, `sched_process_fork`, `sched_process_exit` | per-host, per-user, per-hour |
| **Network** | `sys_enter_connect`, `sys_enter_bind`, `sys_enter_sendto` (DNS) | per-host, per-user, per-hour |
| **Privilege Escalation** | `sys_enter_setuid`, `sys_enter_setgid`, `sys_enter_capset` | per-host, per-user |
| **Sensitive Files** | `sys_enter_openat` (shadow, sudoers, authorized_keys) | per-host, per-hour |
| **Process Injection** | `sys_enter_ptrace` | per-host |
| **Per-User Profiling** | All above, keyed by UID | per-uid, per-hour |
| **Per-Process Profiling** | All above, keyed by comm | per-comm, per-day |
| **Container** | All above, keyed by cgroup ID | per-cgroup, per-hour |

## Prerequisites

- Linux kernel 5.8+ with eBPF support
- Go 1.24+
- clang and llvm
- Kernel headers installed

## Quick Start

```bash
cd host/ebpf-agent

# Build eBPF programs and Go binary
make all

# Run (requires root)
sudo ./ebpf-agent

# Or install as a systemd service
sudo make install
```

The agent exposes metrics on `http://localhost:9110/metrics`.

## Configuration

The agent is configured via `config.yaml`:

```yaml
server:
  port: 9110
  metrics_path: /metrics

poll_interval: 1s

host:
  id: ""  # auto-detected from /etc/machine-id

baseline:
  learning_duration: 168h      # 7 days
  aggregation_window: 1m
  recalibration_interval: 24h
  ewma_alpha: 0.01
  state_file: /var/lib/ebpf-agent/baseline.db

scoring:
  zscore_threshold: 3.0
  minimum_samples: 60

dimensions:
  per_user: true
  per_process: true
  per_container: false
  network: true
  filesystem: true
  scheduling: true
```

### Feature Flags

Disable detection modules at compile time:

```bash
make bpf MONITOR_CONNECT=0 MONITOR_PTRACE=0 MONITOR_DNS=0
```

Available flags: `MONITOR_EXEC`, `MONITOR_SUDO`, `MONITOR_PASSWD`, `MONITOR_CONNECT`, `MONITOR_PTRACE`, `MONITOR_OPENAT`, `MONITOR_SETUID`, `MONITOR_FORK`, `MONITOR_EXIT`, `MONITOR_BIND`, `MONITOR_DNS`, `MONITOR_CAPSET`.

## Metrics

### Raw Counters (with host label)

| Metric | Description |
|---|---|
| `ebpf_exec_events_total` | Total execve syscalls |
| `ebpf_sudo_events_total` | Total sudo executions |
| `ebpf_passwd_read_events_total` | Total /etc/passwd reads |
| `ebpf_connect_events_total` | Total outbound connect() |
| `ebpf_suspicious_connect_events_total` | Connections to C2 ports |
| `ebpf_ptrace_events_total` | Total ptrace() calls |
| `ebpf_sensitive_file_access_total` | Sensitive file openat() |
| `ebpf_setuid_events_total` | Total setuid() calls |
| `ebpf_setgid_events_total` | Total setgid() calls |
| `ebpf_fork_events_total` | Total fork events |
| `ebpf_bind_events_total` | Total bind() calls |
| `ebpf_dns_events_total` | Total DNS queries |
| `ebpf_capset_events_total` | Total capset() calls |

### Baseline & Anomaly Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `ebpf_baseline_phase` | Gauge | `host` | 1=learning, 2=monitoring |
| `ebpf_baseline_progress` | Gauge | `host` | 0.0-1.0 during learning |
| `ebpf_baseline_mean` | Gauge | `host`, `metric`, `dimension` | Baseline mean |
| `ebpf_baseline_stddev` | Gauge | `host`, `metric`, `dimension` | Baseline standard deviation |
| `ebpf_baseline_upper_bound` | Gauge | `host`, `metric`, `dimension` | mean + threshold * stddev |
| `ebpf_anomaly_score` | Gauge | `host`, `metric`, `dimension` | Latest z-score |
| `ebpf_anomaly_total` | Counter | `host`, `metric`, `dimension`, `severity` | Cumulative anomaly count |

## Prometheus Integration

Example alert rules and scrape configuration are in `examples/prometheus/`. See:

- `examples/prometheus/alerts.yml` — Adaptive baseline alerts plus static fallbacks
- `examples/prometheus/scrape.yml` — Scrape config snippet

## Architecture

```
host/ebpf-agent/
├── bpf/
│   ├── exec.bpf.c              # eBPF programs (all tracepoints + ringbuf)
│   ├── bpf_helpers.h            # BPF helper definitions
│   └── vmlinux.h               # Kernel type definitions
├── cmd/agent/
│   ├── main.go                 # Entry point, wires all components
│   └── bpf/exec.bpf.o          # Embedded BPF object (generated by make bpf)
├── internal/
│   ├── config/                  # YAML config parsing + validation
│   ├── poller/                  # Per-CPU map counter poller
│   ├── ringbuf/                 # Ringbuf consumer + event parsing
│   ├── enricher/                # PID/UID/cgroup enrichment
│   ├── aggregator/              # Time-window bucketing
│   ├── baseline/                # 168-bucket seasonal model + EWMA
│   ├── scorer/                  # Z-score anomaly detection
│   ├── store/                   # SQLite state persistence
│   └── phase/                   # Learning/monitoring phase management
├── examples/prometheus/         # Alert rules and scrape config
├── config.yaml
├── Makefile
├── ebpf-agent.service
├── go.mod
└── go.sum
```

## Development

```bash
cd host/ebpf-agent

# Build just the BPF object
make bpf

# Build just the Go binary
make build

# Run tests
make test

# Inspect eBPF maps at runtime
sudo bpftool map list
sudo bpftool map dump name exec_counter
```

## What This Doesn't Detect

- **Packet payload inspection** — sees destination port/IP but not data content
- **Fileless malware** — `memfd_create` + `execveat` bypasses the `execve` tracepoint
- **Cross-host correlation** — each agent is independent
- **Kernel rootkits** — malicious kernel modules can hide events from eBPF
- **DNS tunneling** — counts DNS queries but does not inspect query content
- **LD_PRELOAD injection** — shared library hijacking does not trigger `ptrace()` or `execve()`

## Security Considerations

- Requires root privileges for tracepoint attachment
- Baseline state file (`/var/lib/ebpf-agent/baseline.db`) must be root-owned (0600) to prevent baseline poisoning
- EWMA drift adaptation means an attacker slowly escalating over weeks could shift the baseline — set absolute ceiling alerts alongside relative ones
- During the learning phase, only static fallback alerts are active
- Enable TLS and basic auth on the metrics endpoint in production

## Additional Documentation

- **[ADAPTIVE_BASELINE_ARCHITECTURE.md](ADAPTIVE_BASELINE_ARCHITECTURE.md)**: Detailed architecture design
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: Contribution guidelines

## License

MIT License — see [LICENSE](LICENSE).
