# state.md — Project Change Log

> **All changes to this project must be documented here.** Include: what changed, why, any caveats or follow-up tasks. Newest entries at the top.

---

## 2026-04-03 — Next implementation priorities (documented)

**What:** Recorded the **post-roadmap backlog** (what to build after the full implementation plan in `state.md` dated 2026-04-02) in **`ARCHITECTURE.md`** under *Next implementation priorities*, and refreshed the **Implementation Status** table there so OTel/MAD rows match shipped code. **`CLAUDE.md`** now points to that section and clarifies roles vs this changelog.

**Why:** The six-phase roadmap + `issues.md` items are done; future work is follow-ups (OTel LogRecords, cold-start fast-track wiring, ARCHITECTURE metric catalog, kill-chain, ops, testing). Planning lives in **ARCHITECTURE.md** + **CLAUDE.md** (roadmap); **state.md** remains the authoritative shipped changelog.

**See:** [ARCHITECTURE.md](ARCHITECTURE.md) § Implementation Status and § Next implementation priorities; [CLAUDE.md](CLAUDE.md) § Next implementation priorities (index) and § Roadmap / Pending Work.

**Note:** **`ARCHITECTURE.md`**, **`state.md`**, and **`CLAUDE.md`** are **not** listed in `.gitignore` — all are tracked in git so rules, changelog, and architecture stay in the repo.

---

## 2026-04-02 — Docs, gitignore, OTel protocol guard

**What:** Removed `CLAUDE.md` from `.gitignore` so the tracked workspace rules file is not ignored; added `.cursor/` to `.gitignore`. Updated **issues.md** (all Fixed) and **README** (OTel/TLS, health metrics, Phase 2 / MITRE / `ebpf_otel_export_errors_total` accuracy). **`otelexport.Init`** returns an error if `otel.protocol` is not `grpc`. **`EmitSecurityEvent`** adds `mitre.technique.ids` when present. Config **`headers`** / **`batch`** documented as reserved in YAML and struct tags. **CLAUDE.md** dependency name aligned with **go.mod**.

**Why:** Pre-commit + documentation subagent review; avoid misleading OTel docs.

---

## 2026-04-02 — Full roadmap implementation (issues.md + ARCHITECTURE plan)

**What:** Implemented the attached Full Implementation Roadmap: phase 1–6 work items across the Go agent, BPF programs, config, tests, OTel, scorer, aggregator, MITRE, docs, and changelog.

**Why:** Address all 14 issues in `issues.md`, align runtime behavior with `ARCHITECTURE.md`, and deliver OTel-first telemetry plus robustness fixes.

### Reliability & phase manager
- Persist `learning_started_at` in SQLite metadata; restore on startup so the 7-day learning timer survives restarts (`internal/phase/phase.go`, `internal/store/store.go` metadata API).
- Fix double SQLite persist on learning→monitoring transition (reset `lastRecalib` after transition persist).
- Expose `phase.Manager.Persist()`; call on shutdown after draining the ringbuf consumer and processing a final aggregation window (`cmd/agent/main.go`).
- Ringbuf consumer is **required**: missing map or consumer creation failure → `log.Fatal`. WaitGroup waits for reader + processing goroutines on shutdown.

### BPF / ringbuf (`bpf/exec.bpf.c`, `internal/ringbuf/ringbuf.go`)
- Event struct is **64 bytes**: `ip_version` + `dest_ip[16]`; IPv4 and IPv6 paths for `connect`, `bind`, `sendto`.
- **openat:** emit sensitive paths always; `/etc/passwd` → `FLAG_PASSWD_READ`; generic opens sampled (max 100/sec per CPU per 1s window) via `openat_rate_limit` + `file_open_counter`.
- `emit_event` signature updated; all tracepoints adjusted.

### Aggregation & scoring
- Metrics: `file_open`, `passwd_read`, `sensitive_file` for openat; **`unique_dest_ips`** via per-window IP deduplication for `connect` events.
- Dimension flags `network` / `filesystem` / `scheduling` filter which events are aggregated.
- Process dimension uses `bin:` / `comm:` prefixes to separate enriched vs unenriched baselines.
- **Scorer:** optional MAD (`mad_enabled`) using median/MAD from last 8 samples per seasonal bucket (`internal/baseline/baseline.go`); **ceilings** map per metric; `UsedMAD` on `scorer.Result`.
- `phase.Manager` passes `*aggregator.Window` into `onScore` for OTel anomaly spans.

### MITRE (`internal/mitre/mitre.go`)
- T1036.003: version-style prefix only (`python3` vs `python3.11`), not arbitrary prefix.
- Default unclassified exec fallback → **T1106** (was T1059 noise).
- **EventExit** → T1106.
- **mapOpenat:** passwd_read before sensitive_file; unflagged → T1005.
- IPv6 private/ULA handling for `mapConnect` via `isIPv6PrivateOrULA`.

### OpenTelemetry (`internal/otelexport`, `go.mod`, `config.yaml`)
- New package: OTLP gRPC trace + metric + log providers; `Init` / `EmitAnomaly` / `EmitSecurityEvent` (security events as spans when tracing enabled) / `Shutdown`.
- `otel:` configuration block; example `examples/otel-collector/otel-collector-config.yaml`.
- Prometheus: `ebpf_otel_export_errors_total`, `ebpf_enrichment_failures_total`.

### Config cleanup
- Removed dead **`metrics`**, **`poll_interval`**, **`bpf_object`**, **`quantile_threshold`** fields; removed **`internal/poller`**.
- Added `otel`, `scoring.mad_enabled`, `scoring.ceilings`, `baseline.new_dimension_learn_window` (reserved).

### Tests & placeholders
- `internal/scorer/scorer_test.go` (ceiling), `internal/aggregator/aggregator_test.go` (unique IPs), `internal/config/config_test.go` updated.
- `internal/integration/pipeline_test.go` (`//go:build integration`), `bpf/exec_bpf_test.go` (`//go:build bpf_test` stub).
- `internal/mitre/chain.go` placeholder for future kill-chain correlation.

### Docs
- `CLAUDE.md` updated to match this state (OTel, IPv6, issues resolved, roadmap trimmed).

**Caveats / follow-ups**
- OTel **log** pipeline registers a logger provider; high-value events are also emitted as **spans** for reliability — full LogRecord schema can be expanded later.
- `new_dimension_learn_window` is not yet fully applied in phase/scorer logic.
- ARCHITECTURE.md not fully rewritten line-by-line; `CLAUDE.md` + this entry are authoritative for what shipped.
- **issues.md** status table updated to Fixed; **README.md** updated for OTel and health metrics.

**Verification:** `make bpf`, `go test ./...`, `go build ./cmd/agent` (run locally).

---

## 2026-04-02 — Codebase audit, issues.md created

**What:** Full line-by-line code review of all source files. Findings documented in [issues.md](issues.md).

**14 issues identified** (now addressed in the implementation above).

**No code changed in this session.**

---

## 2026-04-02 — CLAUDE.md and state.md initialized

**What:** Created `CLAUDE.md` and this `state.md` file.

**Why:** Establishing a working context document for ongoing development.

**No code changed in this session.**

<!-- Add new entries above this line -->
