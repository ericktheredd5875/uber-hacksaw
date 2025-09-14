# Milestone Roadmap (12–14 weeks)

---

## M0 — Foundation & Safety (Week 1)

### Deliverables

- [x] Repo scaffold, pyproject.toml, Makefile, pre-commit (black/ruff/mypy), CI (pytest on 3 OSes).
- [x] Safe test corpus: EICAR, benign binaries, sample docs; VM images for Windows & Linux.
- [x] Threat model & data handling policy (no exfiltration of file contents by default; only hashes/metadata).

### Acceptance

- [x] scanner scan ./samples prints a table (path, type, size, hash).

---

## M1 — MVP Static Scanner (Weeks 2–3)

### Scope

- [ ] Collectors: directory walk, file filtering (size, type, extensions).
- [ ] Hashing (SHA-256), fuzzy hashing (ssdeep/TLSH).
- [ ] File-type ID + minimal PE/ELF parsing (imports, sections, entropy).
- [ ] YARA engine + rule loader (compile cache, timeouts).
- [ ] Basic heuristic rules (suspicious entropy, imported Win32 APIs, macro presence).
- [ ] Reporting: console + JSON; exit codes for CI.

### Acceptance
- [ ] Detects EICAR via YARA and flags a few hand-rolled “suspicious” samples with explainable reasons.
    - [ ] 95% line-level test coverage for core pipeline; scan throughput baseline captured.

---

## M2 — Unpack & Office Macro Path (Weeks 4–5)

### Scope

- [ ] Archive traversal (zip/tar/gz/7z); depth/size guards; temp extraction.
- [ ] UPX detection/unpack (where legal/safe); entropy before/after.
- [ ] Office/PDF: macro and suspicious link extraction (oletools/rtfobj/pdfid/pdf-parser).

### Acceptance
- [ ] Nested archives scanned up to a configured depth with cycle detection.
- [ ] Macro-containing docs flagged with readable findings.

---

## M3 — Reputation & Update Channel (Week 6)

###Scope

- [ ] Local reputation DB (SQLite): seen hashes, known-good publishers (code-signing), denylist/allowlist.
- [ ] Rule/update bundle fetcher (HTTPS) with signature verification and rollback.

### Acceptance

- [ ] scanner update pulls a signed rules bundle; cached lookups reduce repeat work.
- [ ] Reputation affects scoring with clear provenance notes.

---

## M4 — Quarantine & Daemon Mode (Weeks 7–8)

### Scope

- [ ] Quarantine: move/snapshot file + metadata; allow restore; integrity tag.
- [ ] Real-time watcher (watchdog) for folders; debounce + backoff.
- [ ] Minimal service/daemon (Windows Service & systemd) with health endpoint.

### Acceptance

- [ ] Policy: detect → quarantine → report → optional auto-restore on allowlist.
- [ ] Safe rollback demonstrated; audit log immutability (append-only JSONL).

---

## M5 — Behavioral Analysis (Remote-First) (Weeks 9–10)

### Scope

- [ ] Remote sandbox client interface (your own lightweight VM sandbox API, or stub for future): submit hash/sample → receive behavior events (filesystem, process, registry, network).
- [ ] Behavior schema + rules (e.g., drops to startup + suspicious network beacon).
- [ ] Keep sandbox out-of-process and out-of-host at first. If you later add on-host behavior collection on Windows, start with ETW/Sysmon event ingestion (read-only) before any injection/hooking.

### Acceptance

- [ ] Risk score combines static+behavioral with explainable contributors.

---

## M6 — Hardening, Performance & Packaging (Weeks 11–12)

### Scope

- [ ] Concurrency (asyncio) for I/O; batching; memory caps; watchdog timers.
- [ ] Tuning: rule timeouts, parallel YARA workers, dedup via content hash.
- [ ] Telemetry: OpenTelemetry metrics/traces to your preferred backend.
- [ ] Packaging: signed wheels, versioned rule bundles, Docker for CI runners.
- [ ] Docs: operator guide, rule authoring guide, upgrade compatibility notes.

### Acceptance

- [ ] Scans a 100k-file tree within target time/CPU bounds; metrics expose throughput and error rates.
- [ ] Clean release artifacts + changelog; reproducible builds.

---

## M7 — (Optional) Lightweight ML (Weeks 13–14)

### Scope

- [ ] Train a small model on static features (imports, section stats, strings) for anomaly/likelihood.
- [ ] Emphasis on explainability and guardrails (only as an additional signal).

### Acceptance

- [ ] Model AUC > baseline heuristics on your curated dataset; no spike in false positives on clean corpora.