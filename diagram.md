# eBPF Adaptive Agent — Technical Diagrams

Mermaid sources for the host agent (`host/ebpf-agent`). Render in GitHub, GitLab, or any Mermaid-capable viewer.

---

## 1. System context

```mermaid
flowchart TB
    subgraph Host["Linux host"]
        subgraph Kernel["Kernel space"]
            TP["Tracepoint programs\nexecve, connect, ptrace, ..."]
            PC["Per-CPU counter maps"]
            RB["RingBuf map\nevents"]
            TP --> PC
            TP --> RB
        end

        subgraph Agent["ebpf-agent userspace"]
            RC["RingBuf consumer"]
            EN["Enricher\nPID LRU, UID, cgroup"]
            MT["MITRE mapper\nMitreTags"]
            AG["Aggregator\n1-min windows"]
            BL["Baseline engine\n168 seasonal buckets + EWMA"]
            ST[("SQLite\nbaseline.db")]
            PH["Phase manager\nlearning / monitoring"]
            SC["Scorer\nz-score, min stddev, cold-start"]
        end

        RB --> RC --> EN --> MT --> AG
        AG --> PH
        PH --> BL
        BL <--> ST
        PH --> SC
    end

    J["journald\nANOMALY, COLD-START, ENRICH-FAIL"]
    HM["HTTP :9110 /metrics\nhealth gauges only"]

    SC --> J
    PH --> HM
```

---

## 2. Event path (detection pipeline)

```mermaid
flowchart LR
    A["Syscall fires"] --> B["BPF: counters + ringbuf record\npid, uid, cgroup, comm, flags"]
    B --> C["Go: parse event"]
    C --> D["Enrich: /proc, passwd, cgroup label"]
    D --> E["MITRE: technique IDs on event"]
    E --> F["Aggregate: dimension keys\nper user / comm / container"]
    F --> G["Window tick: rotate 1m"]
    G --> H["Phase: ingest into baseline"]
    H --> I{"Monitoring phase?"}
    I -->|no| H
    I -->|yes| J["Score vs baseline"]
    J --> K["Log anomalies"]
```

---

## 3. Two-phase lifecycle

```mermaid
flowchart TB
    START([Agent start]) --> L["Phase 1: Learning"]
    L --> L1["Each window: ingest into baseline"]
    L1 --> L2{"learning_duration elapsed?"}
    L2 -->|no| L1
    L2 -->|yes| M["Phase 2: Monitoring"]
    M --> M1["Per window: ingest, score,\nlog anomalies, EWMA"]
    M1 --> M
    M --> R["Reset / reconfigure"]
    R --> L
```

---

## 4. Telemetry split (current implementation)

```mermaid
flowchart TB
    subgraph Detection["Detection output"]
        LOG["Structured text logs\njournald"]
    end

    subgraph Health["Operational health"]
        PROM["Prometheus scrape\nlocalhost:9110/metrics"]
    end

    subgraph Planned["Not implemented"]
        OTEL["OTLP to collector\ntraces / logs / metrics"]
    end

    Agent["ebpf-agent"] --> LOG
    Agent --> PROM
    Agent -.->|planned| OTEL
```

---

## 5. Config and BPF attachment

```mermaid
flowchart LR
    CFG["config.yaml\ntracepoints + baseline + scoring"] --> LOAD["config.Load"]
    LOAD --> SPEC["Load BPF object\nembed exec.bpf.o"]
    SPEC --> ATTACH["Attach each tracepoint\nto listed program"]
    ATTACH --> RUN["Main loop:\nringbuf + window ticker + health ticker"]
```
