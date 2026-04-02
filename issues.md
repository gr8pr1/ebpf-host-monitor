# issues.md — Codebase Issue Tracker

> **Status (2026-04-02):** All issues below were addressed in the implementation logged in [state.md](state.md). Descriptions are kept for historical context; line numbers may drift.

> Issues discovered during the 2026-04-02 code audit. Ordered by severity within each category.
> All fixes must be documented in [state.md](state.md) when resolved.

---

## BPF Layer (`bpf/exec.bpf.c`)

---

### ISSUE-001 — `openat` handler is alert-only, not behavioral
**Severity:** High
**File:** `bpf/exec.bpf.c:447-448`

```c
if (flags)
    emit_event(EVENT_OPENAT, flags, 0, 0);
```

The `openat` tracepoint only emits an event when a sensitive file flag is set (i.e., `/etc/shadow`, `/etc/sudoers`, `.ssh/authorized_keys`, etc. were accessed). Normal file opens produce zero kernel events and never reach the userspace pipeline.

**Why it matters:** The statistical baselining engine cannot learn "normal" file access behavior if it only ever sees anomalous accesses. Every sensitive file open is treated as a cold-start anomaly rather than a deviation from a learned baseline. The entire behavioral model for file access is broken — you cannot detect "this process opened `/etc/shadow` more than usual" if there is no baseline of usual. Detection degrades to a simple presence detector, not a behavioral anomaly detector.

**Fix direction:** Emit events for all `openat` calls (or at minimum all opens with a resolved path). Use the `flags` field to carry context (sensitive vs. normal). The aggregator already maps `EventOpenat` to `"sensitive_file"` metric — this would need splitting into `"file_open"` (all) and `"sensitive_file"` (flagged).

---

### ISSUE-002 — IPv6 connections are silently dropped
**Severity:** High
**File:** `bpf/exec.bpf.c:392-393`

```c
if (addr.sin_family != 2) /* AF_INET */
    goto done;
```

`done:` skips `emit_event` entirely. All IPv6 (`AF_INET6`) outbound connections produce no event and are invisible to the entire pipeline: no ringbuf entry, no enrichment, no MITRE mapping, no baseline data, no anomaly detection.

**Why it matters:** On modern Linux systems, a significant portion of network connections use IPv6 — browsers, DNS resolvers, SSH, cloud SDKs. An attacker using an IPv6 C2 endpoint bypasses all network-based detection. The connect baseline is silently skewed because a portion of real connection volume is never counted.

**Fix direction:** Add a parallel `sockaddr_in6` read path for `AF_INET6 (10)`. Extend the BPF event struct from `__u32 dest_ip` to a `__u8 dest_ip[16]` array (or a union) with an address family flag. Update the Go-side parser in `internal/ringbuf/ringbuf.go` accordingly.

---

### ISSUE-003 — Per-CPU BPF counters defined but never read
**Severity:** Medium
**File:** `bpf/exec.bpf.c:107-213`, `internal/poller/poller.go`

BPF per-CPU counter maps (`exec_counter`, `sudo_counter`, `connect_counter`, `suspicious_connect_counter`, `ptrace_counter`, `sensitive_file_counter`, `passwd_read_counter`) are defined and incremented in the kernel program. `internal/poller/poller.go` was written to read them but is never instantiated in `cmd/agent/main.go`. The config fields `metrics:` and `poll_interval:` that support the poller are also dead.

**Why it matters:** Lightweight per-CPU counters are a low-overhead way to export aggregate throughput without paying ringbuf per-event cost. Their absence means there is no independent cross-check on event throughput. Also creates confusion — the BPF code has dual instrumentation (counters + ringbuf) with only one side connected.

**Fix direction:** Either wire `poller.go` into `main.go` (instantiate, run on `PollInterval`, export via Prometheus or OTel) or remove all per-CPU counter maps from `exec.bpf.c` and delete `poller.go` and the dead config fields. Decision should be made based on whether the OTel integration (which will export detection metrics) makes the counters redundant.

---

## MITRE Mapper (`internal/mitre/mitre.go`)

---

### ISSUE-004 — T1036.003 HasPrefix creates interpreter masquerade blind spot
**Severity:** Medium
**File:** `internal/mitre/mitre.go:105`

```go
if base != "" && comm != "" && base != comm && !strings.HasPrefix(base, comm) {
```

The `HasPrefix` guard is intended to tolerate comm truncation (kernel caps comm at 15 chars). For example, binary `python3.11` with comm `python3` → `HasPrefix("python3.11", "python3")` is true → no false T1036.003. This is correct.

However it creates a false negative: if a malicious binary is named `python3_c2` and the attacker sets its comm to `python3`, then `base="python3_c2"` ≠ `comm="python3"` and `HasPrefix("python3_c2", "python3")` is **true** → no T1036.003 fires. The exact "masquerade as a trusted interpreter" pattern is undetectable by this logic.

**Why it matters:** Masquerading as a known interpreter (`python3`, `node`, `ruby`) is a common post-exploitation technique. The detection gap is in the most likely impersonation targets.

**Fix direction:** Replace `HasPrefix` with a tighter check: allow the base to start with comm only if the next character after the comm prefix is `.` (version separator) or end of string. Anything else (underscore, letter continuation) should be flagged.

---

### ISSUE-005 — T1059 fires on every unclassified exec, making it noise
**Severity:** Medium
**File:** `internal/mitre/mitre.go:111-115`

```go
if len(techniques) == 0 {
    techniques = append(techniques, Technique{
        ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution",
    })
}
```

Any exec that doesn't match a shell, interpreter, cron parent, or rename pattern falls through to T1059. This includes `ls`, `grep`, `curl`, `git`, `make`, `awk` — every normal system binary. T1059 is attached to the overwhelming majority of all exec events.

**Why it matters:** T1059 loses all signal value. Downstream consumers (future OTel, log analysis, alerting) cannot use T1059 as a meaningful indicator because it fires constantly. It also inflates MITRE tag counts in ways that mask actual technique frequency.

**Fix direction:** Remove the T1059 fallback entirely, or replace it with a more appropriate catch-all like T1106 (Native API — "use of OS APIs to execute") which is accurate for generic process execution. Reserve T1059 strictly for actual command interpreter invocations.

---

### ISSUE-006 — `EventExit` produces empty MITRE mapping
**Severity:** Low
**File:** `internal/mitre/mitre.go:70`

`EventExit` has no case in the `Map()` switch and falls through to `default: return Mapping{}`. Exit events flow through the full pipeline (ringbuf → enricher → aggregator → scorer) and are baselined as the `"exit"` metric, but carry no MITRE technique tags.

**Why it matters:** Inconsistency across event types. Rapid process exit patterns (e.g., fork-bomb precursors, short-lived reconnaissance tools) are baselined but produce no technique context in logs or future telemetry. Also means `enriched.MitreTags` is always empty for exit events, so any future tag-based filtering will miss them.

**Fix direction:** Add an explicit `case ringbuf.EventExit` that maps to T1106 (Native API) or a process lifecycle technique, consistent with how `EventFork` is handled.

---

## Aggregator (`internal/aggregator/aggregator.go`)

---

### ISSUE-007 — All sensitive file opens collapsed into one undifferentiated metric
**Severity:** Medium
**File:** `internal/aggregator/aggregator.go:110`

```go
case ringbuf.EventOpenat:
    return "sensitive_file"
```

Combined with ISSUE-001, all sensitive file access events map to a single `"sensitive_file"` metric regardless of which file was accessed. `/etc/shadow`, `/etc/sudoers`, and `.ssh/authorized_keys` are all counted together.

**Why it matters:** An attacker reading `/etc/shadow` looks identical in the baseline to one reading `.ssh/authorized_keys`. Anomaly scoring cannot distinguish credential dumping from SSH key enumeration. Detection granularity is lost at the aggregation layer, not just the BPF layer.

**Fix direction:** Add distinct metric names per sensitive file type using the existing `flags` field: `FlagSensitiveFile` → `"sensitive_file"`, `FlagPasswdRead` → `"passwd_read"` (the BPF already sets these separately). This requires ISSUE-001 to also be fixed — there's no point having per-type metrics if baseline data only contains anomalous accesses.

---

## Phase Manager (`internal/phase/phase.go`)

---

### ISSUE-008 — Learning timer resets to zero on every agent restart
**Severity:** High
**File:** `internal/phase/phase.go:50`

```go
learningStart: time.Now(),
```

`learningStart` is always initialized to `time.Now()` regardless of whether a saved baseline is restored from SQLite. If the saved `phase` metadata is `"learning"`, the manager restores the baseline data but resets the timer. Every agent restart during the 7-day learning window starts the clock over.

**Why it matters:** On a system that reboots for kernel updates, or where the service is restarted, the agent may never complete learning. Even a single restart per week means a 7-day learning phase never finishes. The baseline accumulates data across restarts (SQLite restore works), but the phase transition is permanently blocked because time elapsed is never persisted.

**Fix direction:** Persist `learning_started_at` as a Unix timestamp in the `metadata` table. On restore, if phase is `"learning"`, load the original start time instead of `time.Now()`. Add a fallback to `time.Now()` only when no saved start time exists (first run).

---

### ISSUE-009 — Double persist on learning-to-monitoring transition
**Severity:** Low
**File:** `internal/phase/phase.go:108,118`

When the learning phase completes and transitions to monitoring (lines 104-108), `m.persist("monitoring")` is called. Code then falls through to the recalibration check (line 115), which fires immediately (since `lastRecalib` was initialized to `time.Now()` at startup and the learning period just completed), calling `m.persist("monitoring")` a second time on the same window.

**Why it matters:** Two SQLite writes in the same `ProcessWindow` call on transition. Minor performance issue; also makes the persist logic harder to reason about.

**Fix direction:** Reset `lastRecalib` to `time.Now()` at the point of phase transition (line 107) so the recalibration check does not immediately fire after the transition persist.

---

## Configuration (`internal/config/config.go`)

---

### ISSUE-010 — `network`, `filesystem`, `scheduling` dimension flags silently ignored
**Severity:** Medium
**File:** `internal/config/config.go:74`, `cmd/agent/main.go:179-181`

```go
type DimensionsConfig struct {
    PerUser      bool `yaml:"per_user"`
    PerProcess   bool `yaml:"per_process"`
    PerContainer bool `yaml:"per_container"`
    Network      bool `yaml:"network"`      // never consumed
    FileSystem   bool `yaml:"filesystem"`   // never consumed
    Scheduling   bool `yaml:"scheduling"`  // never consumed
}
```

`main.go` passes only `PerUser`, `PerProcess`, `PerContainer` to the aggregator. The `Network`, `FileSystem`, and `Scheduling` flags are parsed and stored but no code path reads them.

**Why it matters:** `config.yaml` has all three set to `true` (default). Users reading the config would expect these to control something. Operators tuning the agent for high-throughput environments (disable network dimension to reduce cardinality) will find the knobs don't work.

**Fix direction:** Either implement the flags (filter aggregated metrics by event category — network events: connect/bind/dns/sendto; filesystem: openat; scheduling: fork/exit) or remove them from the config struct and YAML template to avoid misleading documentation.

---

### ISSUE-011 — `MetricConfig` slice and `PollInterval` are dead config fields
**Severity:** Low
**File:** `internal/config/config.go:40-43, 102`

The `metrics:` block in `config.yaml` (10 entries) and the `poll_interval:` setting are parsed into `Config.Metrics []MetricConfig` and `Config.PollInterval` respectively. Neither field is read by any code after loading.

**Why it matters:** Dead configuration increases cognitive overhead when reading the config file. Combined with ISSUE-003 (unused poller), these fields are the config surface of a never-connected subsystem.

**Fix direction:** Remove alongside resolving ISSUE-003. If the poller is wired in, these fields become active. If the poller is removed, delete these config fields and their YAML template entries.

---

## Main / Agent Wiring (`cmd/agent/main.go`)

---

### ISSUE-012 — Enrichment failures silently feed the baseline
**Severity:** Medium
**File:** `cmd/agent/main.go:209-214`

```go
if !enriched.Resolved {
    log.Printf("ENRICH-FAIL pid=%d comm=%s ...", ev.PID, ev.CommString())
}
agg.Add(enriched)  // always called regardless
```

When PID resolution fails (process exited before `/proc/<pid>/exe` could be read), the event still enters the aggregator. The `Binary` path is empty, so the MITRE rename check (ISSUE-004) never fires. The dimension key has an empty `Process` field if `perProcess=true`, or falls back to just the comm string.

**Why it matters:** During high fork-exec activity (build systems, test runners, shell scripts) enrichment failures are common and frequent. These events populate the baseline with lower-fidelity data. When monitoring phase begins, enriched events (with full binary path) may appear as anomalies against a baseline built partly from unenriched events. In the worst case, a baseline built during a CI/CD run will have significant unenriched event noise.

**Fix direction:** Options: (a) drop unenriched events from the baseline with a counter metric for visibility, or (b) keep them but mark the dimension key distinctly (e.g., `Process: "comm:"+comm` vs `Process: "bin:"+base`) so enriched and unenriched data don't mix in the same baseline bucket. Option (b) preserves data while avoiding contamination.

---

### ISSUE-013 — No baseline persist on shutdown — learning progress lost
**Severity:** Medium
**File:** `cmd/agent/main.go:263-268`

```go
case <-ctx.Done():
    log.Println("Shutting down...")
    shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    srv.Shutdown(shutdownCtx)
    return
```

The shutdown path closes the HTTP server and returns. There is no call to persist the baseline. The recalibration interval defaults to 24 hours — any learning accumulation since the last recalibration is lost on clean shutdown or crash.

**Why it matters:** A system in learning phase that is restarted daily (e.g., via automated patching) will lose up to 24 hours of baseline data per restart. Combined with ISSUE-008 (timer reset), restarts can cause both timer regression AND data loss. Even in monitoring phase, 24 hours of EWMA recalibration drift is lost.

**Fix direction:** Add a `phaseMgr.Persist()` (or equivalent) call in the shutdown path before returning, after draining in-flight window data.

---

### ISSUE-014 — Silent degraded mode when ringbuf initialization fails
**Severity:** Medium
**File:** `cmd/agent/main.go:274-278`

```go
case <-windowTicker.C:
    if hasRingbuf {
        w := agg.Rotate()
        phaseMgr.ProcessWindow(w)
    }
```

If the ringbuf consumer fails to initialize, `hasRingbuf` is false. The window ticker fires every minute but does nothing. The agent continues running: tracepoints may be attached, the HTTP health endpoint serves metrics, logs show the agent as active — but zero baseline work is being done.

**Why it matters:** An operator monitoring the health endpoint would see `ebpf_baseline_phase=1` (learning) and `ebpf_baseline_progress` slowly increasing, but no actual data is being collected. There is no metric or log distinguishing "ringbuf consumer not running" from normal operation after the initial `WARN` log line.

**Fix direction:** Add a dedicated Prometheus gauge `ebpf_ringbuf_consumer_active` (1=running, 0=not running). Alternatively, treat ringbuf failure as fatal — the agent's core function requires the consumer. Log the failure at `FATAL` level and exit rather than silently degrading.

---

## Status Summary

| ID | File | Severity | Status |
|---|---|---|---|
| ISSUE-001 | `bpf/exec.bpf.c:447` | High | Fixed |
| ISSUE-002 | `bpf/exec.bpf.c:392` | High | Fixed |
| ISSUE-003 | `bpf/exec.bpf.c:107-213` | Medium | Fixed (poller removed; maps retained in BPF) |
| ISSUE-004 | `internal/mitre/mitre.go:105` | Medium | Fixed |
| ISSUE-005 | `internal/mitre/mitre.go:111` | Medium | Fixed |
| ISSUE-006 | `internal/mitre/mitre.go:70` | Low | Fixed |
| ISSUE-007 | `internal/aggregator/aggregator.go:110` | Medium | Fixed |
| ISSUE-008 | `internal/phase/phase.go:50` | High | Fixed |
| ISSUE-009 | `internal/phase/phase.go:108,118` | Low | Fixed |
| ISSUE-010 | `internal/config/config.go:74` | Medium | Fixed |
| ISSUE-011 | `internal/config/config.go:40` | Low | Fixed |
| ISSUE-012 | `cmd/agent/main.go:209` | Medium | Fixed |
| ISSUE-013 | `cmd/agent/main.go:263` | Medium | Fixed |
| ISSUE-014 | `cmd/agent/main.go:274` | Medium | Fixed (fatal + no degraded path) |
