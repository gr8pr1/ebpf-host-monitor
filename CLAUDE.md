# CLAUDE.md — eBPF Adaptive Security Agent

## Change Documentation Rule
**All changes made to this project must be documented in [state.md](state.md).** Every implementation task, bug fix, refactor, or architectural decision gets an entry: what changed, why, and any caveats. This is the project's living changelog — keep it current.

## Pre-Implementation Verification Rule
**Before implementing any change, CLAUDE.md must be verified against state.md.**

Steps:
1. Read `state.md` in full — check every logged change since the last time CLAUDE.md was updated
2. Cross-reference those changes against the "Current Implementation State", "Known Issues", and "Roadmap" sections of this file
3. Update any stale or inaccurate information in CLAUDE.md to reflect the actual current state
4. Only after CLAUDE.md is confirmed accurate may implementation begin

This prevents acting on an outdated picture of the codebase. If state.md and CLAUDE.md conflict, state.md is the authoritative record of what has actually changed — fix CLAUDE.md accordingly.

---

## Project Overview
An eBPF-based host security monitoring agent that learns normal system behavior over a configurable period (default 7 days), then shifts to monitoring phase and flags statistical anomalies using z-score analysis. Events are tagged with MITRE ATT&CK technique IDs.

- **Language:** Go 1.24+ (userspace), C (eBPF kernel programs)
- **Kernel requirement:** Linux 5.8+ (BPF ringbuf support)
- **Dependencies:** cilium/ebpf, prometheus/client_golang, OpenTelemetry OTLP exporters, go.yaml.in/yaml/v2, modernc.org/sqlite

---

## Repository Layout
```
host/ebpf-agent/
├── cmd/agent/main.go          # Entry point; wires all components
├── bpf/exec.bpf.c             # eBPF kernel programs (C)
├── internal/
│   ├── aggregator/            # 1-minute time-window bucketing
│   ├── baseline/              # 168-bucket seasonal model + EWMA
│   ├── config/                # YAML config parsing + validation
│   ├── enricher/              # PID/UID/cgroup enrichment (LRU cache)
│   ├── mitre/                 # MITRE ATT&CK technique mapping + chain placeholder
│   ├── otelexport/            # OpenTelemetry OTLP (traces, metrics, logs)
│   ├── phase/                 # Learning ↔ monitoring state machine
│   ├── ringbuf/               # BPF ringbuf consumer + event parsing
│   ├── scorer/                # Z-score anomaly detection
│   └── store/                 # SQLite persistence (baseline + metadata)
├── Makefile                   # Build system with compile-time feature flags
├── config.yaml                # Full configuration template
└── examples/                  # prometheus/ alerts + otel-collector/ sample
```

---

## Current Implementation State

### Working
- Core pipeline: ringbuf → enricher → aggregator → baseline → scorer
- Two-phase lifecycle (learning 7d → monitoring) with SQLite persistence (`learning_started_at` metadata, shutdown persist, ringbuf drain on SIGTERM)
- 12 eBPF tracepoints: execve, connect, ptrace, openat, setuid, setgid, fork, exit, bind, sendto, capset
- **IPv4 + IPv6** for connect, bind, DNS (sendto): 64-byte event struct with `ip_version` + `dest_ip[16]`
- **openat** behavioral baselining: rate-limited generic `file_open` + `sensitive_file` / `passwd_read` metrics
- MITRE ATT&CK mapping in `internal/mitre/mitre.go` (incl. T1036.003 masquerade fix, T1106 fallback for generic exec, EventExit mapping)
- Z-score and optional **MAD** (median/MAD from last 8 samples per seasonal bucket) when `scoring.mad_enabled: true`
- **Absolute ceiling thresholds** per metric via `scoring.ceilings`
- **unique_dest_ips** metric (distinct IPs per window via aggregator)
- Seasonal 168-bucket baseline (24h × 7 days-of-week)
- EWMA drift adaptation (α=0.01 default)
- LRU cache for PID/UID enrichment (4096 entries, 10s TTL); dimension keys use `bin:` / `comm:` prefixes to limit baseline mixing
- Dimension toggles: `dimensions.network`, `filesystem`, `scheduling` filter aggregation
- Prometheus `/metrics` health-only (incl. `ebpf_enrichment_failures_total`, `ebpf_otel_export_errors_total`)
- **OpenTelemetry** OTLP (`otel:` config): traces (anomalies + security events as spans), metrics + log providers
- Cold-start flagging for unseen dimensions post-learning
- YAML config validation with unit tests (`config_test.go`)
- Compile-time feature flags per tracepoint (`MONITOR_*`)

### Not Implemented (Planned)
- Temporal MITRE kill-chain correlation (stub `internal/mitre/chain.go`)
- Per-dimension automatic skewness-based MAD/z-score selection
- Remaining ARCHITECTURE metrics: `/tmp` create rate, file write rate, OOM kill, fork bomb score, short-lived process lifetime, bytes_tx/rx
- Bytes transmitted/received metrics
- Container network metrics (per_container disabled by default)
- BPF `BPF_PROG_TEST_RUN` harness (placeholder test with `bpf_test` tag)

---

## Known Issues / Technical Debt

| Issue | Location | Severity |
|---|---|---|
| PID resolution TOCTOU race | `internal/enricher/enricher.go` | Medium — short-lived processes may miss binary path |
| Cold-start fast-track window | `baseline` / `phase` | Medium — `new_dimension_learn_window` config reserved, not fully wired |
| EWMA evasion risk | `internal/baseline/baseline.go` | Medium — slow drift can shift baseline over weeks (mitigated by `scoring.ceilings`) |
| 16-char comm truncation | `bpf/exec.bpf.c` | Low — no full argv captured |

---

## Build & Run

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Build BPF + Go binary
cd host/ebpf-agent
make all

# Run (requires root for eBPF attachment)
sudo ./ebpf-agent -config config.yaml

# Or use quick-start script
./scripts/quick-start.sh
```

**Makefile targets:**
- `make bpf` — compile C to exec.bpf.o (needs clang + kernel headers)
- `make build` — go build → ebpf-agent binary
- `make test` — go test ./...
- `make install` — install binary + systemd unit

---

## Roadmap / Pending Work

### Priority 1 — OpenTelemetry (done / follow-ups)
- **Done:** OTLP deps, `otel:` config, `internal/otelexport`, anomaly + security spans, collector example, `ebpf_otel_export_errors_total`
- **Follow-up:** Rich OTLP **LogRecord** emission (currently security events also emit as spans when tracing is enabled); baseline gauges via OTLP metrics SDK instruments

### Priority 2 — Scorer Improvements
- **Done:** MAD option (`mad_enabled`), per-metric **ceilings**
- Skewness-based auto selection of MAD vs z-score
- Cold-start fast-track: fully wire `new_dimension_learn_window`

### Priority 3 — Detection Coverage Expansion
- **Done:** IPv6, `unique_dest_ips`, openat `file_open` / differentiated sensitive metrics
- Full argv capture, LD_PRELOAD, DNS tunneling heuristics, `/tmp` rate, `write` tracepoint, OOM kill, fork bomb, short-lived lifetime, cgroup bytes

### Priority 4 — Reliability & Ops
- **Done:** poller removed; graceful shutdown with ringbuf drain + baseline persist
- Enricher TOCTOU mitigation: longer TTL / retry
- Structured log format flag; health endpoint hardening

### Priority 5 — Testing
- **Done:** `internal/scorer` tests, `internal/aggregator` test, `config_test`, integration build tag placeholder
- Benchmark / fuzz / anomaly replay harness

---

## Key Architectural Decisions (Do Not Change Without Discussion)

1. **Detection results: logs to stderr/journald and (when enabled) OpenTelemetry** — `/metrics` remains health-only; primary export for rich context is OTLP push.
2. **Seasonal baseline (168 buckets, not rolling window)** — Captures day-of-week and time-of-day patterns; don't collapse to a simple rolling average.
3. **Z-score floor on stddev** (`min_stddev=1.0`) — Prevents division-by-zero and +Inf scores; never remove this floor.
4. **EWMA α=0.01** — Intentionally slow adaptation; changing to a higher value makes evasion via drift easier.
5. **BPF ringbuf over per-CPU maps** — Preserves full event context for enrichment; per-CPU maps retained only for internal throughput counters.
6. **SQLite for baseline persistence** — Simple, zero-dependency embedded DB; baseline survives restarts without re-learning.

---

## Adding a New Monitor (Checklist)

When adding a new eBPF tracepoint/monitor, touch all of these:
1. `bpf/exec.bpf.c` — add SEC("tracepoint/...") program + emit_event call
2. `Makefile` — add `MONITOR_<NAME>` compile-time flag
3. `internal/config/config.go` — add tracepoint config entry
4. `config.yaml` — add tracepoint entry (`otel` / `scoring` as needed)
5. `internal/aggregator/aggregator.go` — add event_type → metric_name mapping
6. `internal/mitre/mitre.go` — add MITRE technique mappings
7. Tests — update `config_test.go`, add scorer/aggregator tests
8. Docs — update README.md technique table + ARCHITECTURE.md
9. **state.md** — document the addition

---

## Prometheus Health Metrics Reference

| Metric | Type | Description |
|---|---|---|
| `ebpf_agent_info` | Gauge | Agent metadata (host, version labels) |
| `ebpf_baseline_phase` | Gauge | 1=learning, 2=monitoring |
| `ebpf_baseline_progress` | Gauge | 0.0–1.0 during learning phase |
| `ebpf_events_processed_total` | Counter | Total enriched events through pipeline |
| `ebpf_ringbuf_drops_total` | Counter | Backpressure drops (channel full) |
| `ebpf_enrichment_failures_total` | Counter | PID/binary resolution failures |
| `ebpf_otel_export_errors_total` | Counter | OTel provider shutdown failures (`Shutdown` error) |
| `ebpf_tracepoints_attached` | Gauge | Number of active BPF attachments |

---

## Files to Know

| File | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Design document (~1015 lines); authoritative on intended architecture |
| [diagram.md](diagram.md) | Mermaid diagrams for all subsystems |
| [host/ebpf-agent/config.yaml](host/ebpf-agent/config.yaml) | Full configuration template with all options |
| [host/ebpf-agent/bpf/exec.bpf.c](host/ebpf-agent/bpf/exec.bpf.c) | All eBPF kernel programs |
| [host/ebpf-agent/cmd/agent/main.go](host/ebpf-agent/cmd/agent/main.go) | Entry point; component wiring |
| [state.md](state.md) | Living changelog — **all changes documented here** |
