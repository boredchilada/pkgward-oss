# Deployment topology

How pkgward runs as a **multi-host cluster**: one primary host that ingests +
scans + detonates, plus any number of scan-only worker hosts, all coordinated
through a single shared database. Complements the scan-*pipeline* diagrams in this
directory (`scan-pipeline.drawio` et al.) — those show what happens *inside* one
`process_one`; this shows where those processes *run* and how work is shared.

Grounded in: `docs/operations.md` ("Scaling horizontally"), `runtime.py`
(`_async_run` starts the worker + detonation pools), `queue.py` (`claim_next`,
claim-token CAS), `pkgward/detonation_worker.py`, and the env vars in
`CLAUDE.md` (`SCANNER_INGEST`, `DETONATION_ENABLED`, `DETONATION_SOCKET`).

> Roles, not hosts. A concrete site fills these roles with specific machines; this
> diagram is intentionally generic so it stays valid as hosts come and go.

## 1. Topology — who runs what

```mermaid
flowchart TB
    subgraph REG["Package registries"]
        PyPI["PyPI"]:::ext
        NPM["npm"]:::ext
        CR["crates.io"]:::ext
        GO["Go module index"]:::ext
    end

    subgraph PRIMARY["PRIMARY host — ingest + scan + detonate"]
        ING["Ingest / cursors<br/>SCANNER_INGEST=1"]:::svc
        PW["Scan worker pool"]:::svc
        DET["Detonation service<br/>rootless Docker + eBPF tracer<br/>DETONATION_SOCKET set"]:::svc
        DW["Detonation worker pool"]:::svc
    end

    subgraph WORKERS["SCAN-WORKER host(s) — scan only"]
        WW["Scan worker pool<br/>SCANNER_INGEST=0<br/>DETONATION_ENABLED=1"]:::svc
    end

    subgraph DATA["Data services (private VLAN)"]
        PG[("PostgreSQL<br/>ScanQueue + DetonationQueue<br/>Scan / Finding / Detonation")]:::db
        RD[("Redis")]:::db
    end

    DISC["Discord webhook<br/>alerts, node-tagged"]:::ext
    LLM["LLM triage API<br/>OpenRouter"]:::ext

    REG -->|"poll feeds / fetch tarballs"| ING
    REG -.->|"download under scan"| PW
    REG -.->|"download under scan"| WW

    ING -->|"enqueue packages"| PG
    PW <-->|"claim / persist (claim-token CAS)"| PG
    WW <-->|"claim / persist (claim-token CAS)"| PG
    PW -->|"enqueue detonation"| PG
    WW -->|"enqueue detonation"| PG
    DW <-->|"drain DetonationQueue"| PG
    DW -->|"detonate"| DET

    PW -->|"triage"| LLM
    WW -->|"triage"| LLM
    PW -->|"malicious alert"| DISC
    WW -->|"malicious alert"| DISC
    DW -->|"flip-to-malicious alert"| DISC

    classDef svc fill:#e3f2fd,stroke:#1565c0,color:#0d47a1;
    classDef db fill:#ede7f6,stroke:#5e35b1,color:#311b92;
    classDef ext fill:#f1f8e9,stroke:#558b3a,color:#2e5e1c;
```

**Key invariants**
- **One ingest source.** Only the primary runs `SCANNER_INGEST=1`; workers never
  enqueue, they only drain — so the feed cursor advances once, not per host.
- **DB is the only coordination.** No host talks to another directly. Both queues
  are claimed with a claim-token CAS (`queue.claim_next`), so N hosts scale almost
  linearly without a broker.
- **Detonation lives where the sandbox is.** Worker hosts have no detonation
  service; `DETONATION_ENABLED=1` makes their scans *enqueue* detonation jobs that
  the primary's detonation pool drains (`detonation_worker.py`).
- **Alerts are decentralised.** Any host can fire a Discord alert; the footer
  carries the node id + build SHA (`node_id.py`) so you can tell which fired it.

## 2. Code + intel deploy flow — how an update reaches each host

Two payloads ship on different rails: the **engine code** (image or git checkout)
and the **private intel overlay** (rules / prompts / thresholds, read once at
process start). Ordering matters — see the note.

```mermaid
flowchart LR
    DEV["Developer workstation<br/>edit + test"]:::node
    REPO["Code repo (git)"]:::node
    INTEL["Private intel overlay<br/>separate repo"]:::node

    subgraph PRIMARY["Primary host"]
        PB["docker compose build scanner<br/>+ up -d --no-deps scanner"]:::act
    end
    subgraph WORKER["Scan-worker host"]
        WC["deploy-worker.sh<br/>git pull + restart"]:::act
        WI["sync-worker.sh<br/>rsync overlay + restart"]:::act
    end

    DEV -->|"git push"| REPO
    DEV -->|"push (private)"| INTEL
    REPO -->|"build image / git pull"| PB
    REPO -->|"git pull (editable install)"| WC
    INTEL -->|"mounted overlay"| PB
    INTEL -->|"rsync"| WI

    classDef node fill:#fff3e0,stroke:#e65100,color:#bf360c;
    classDef act fill:#e3f2fd,stroke:#1565c0,color:#0d47a1;
```

> **Deploy order on a worker:** run `sync-worker.sh` (intel) **before**
> `deploy-worker.sh` (code). The overlay is read at startup; a new baseline rule
> that references overlay data must not restart against a stale overlay, or the
> YARA compile fails. Both verify recovery via the `intel_loaded
> source=baseline+overlay` log line. (See `docs/operations.md`.)

## 3. Work distribution — a package from ingest to alert

```mermaid
sequenceDiagram
    participant Reg as Registry
    participant Pri as Primary (ingest)
    participant DB as Postgres (queues)
    participant Any as Any scan worker
    participant Det as Detonation pool (primary)
    participant Dsc as Discord

    Reg->>Pri: new package on feed
    Pri->>DB: enqueue ScanQueue (gated)
    Any->>DB: claim_next (claim-token CAS)
    Any->>Reg: download + verify tarball
    Any->>Any: extract, analyze, score, LLM triage
    Any->>DB: persist Scan + Findings (static verdict)
    alt static verdict malicious
        Any->>Dsc: alert (node-tagged)
    end
    Any->>DB: enqueue DetonationQueue
    Det->>DB: drain DetonationQueue
    Det->>Reg: re-fetch tarball
    Det->>Det: detonate (sandbox + eBPF trace), re-score
    alt verdict flips to malicious
        Det->>Dsc: delayed dynamic alert
    end
```

## Maintenance

- **Tied to:** `runtime.py::_async_run` (pool startup + sizing), `queue.py`
  (`claim_next` scheduling + claim-token), `pkgward/detonation_worker.py`,
  `pkgward/node_id.py` (alert identity), `docs/operations.md` ("Scaling
  horizontally", "Code + intel deploys to worker hosts").
- **Update when:** the ingest/scan/detonation split changes, a new coordination
  channel is added (today it's DB-only), or the deploy tooling changes.
- **Deliberately generic** — no host names, IPs, or counts. A concrete site's map
  (specific hosts, network segmentation, tunnels) is maintained as private
  operational documentation, not here.

### Legend

```mermaid
flowchart LR
  S["service / process"]:::svc
  D[("datastore")]:::db
  E["external"]:::ext
  N["node / artifact"]:::node
  A["deploy action"]:::act
  S --- D --- E --- N --- A
  classDef svc fill:#e3f2fd,stroke:#1565c0,color:#0d47a1;
  classDef db fill:#ede7f6,stroke:#5e35b1,color:#311b92;
  classDef ext fill:#f1f8e9,stroke:#558b3a,color:#2e5e1c;
  classDef node fill:#fff3e0,stroke:#e65100,color:#bf360c;
  classDef act fill:#e3f2fd,stroke:#1565c0,color:#0d47a1;
```
