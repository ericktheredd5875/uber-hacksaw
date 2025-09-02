# uber-hacksaw
Malware Scanner written in Python

---

## Goals & Guardrails

* Primary goal: Detect and report malicious files/processes with a modular, testable Python codebase.
* Platforms (initial → later): Windows (first), then Linux, macOS.
* Detection pillars: (1) Signatures (hash/YARA), (2) Heuristics/static analysis, (3) Behavioral/dynamic analysis (sandbox), (4) Reputation/intelligence feeds.
* Safety: Never run unknown binaries on the host while developing. Use VMs or containers. Start with benign test artifacts (e.g., EICAR) and known open-sample corpora.

---

## Architecture

➡️ [View Architecture](./docs/ARCHITECTURE.md)

### Key libs to consider (pick minimally for MVP):

* PE/ELF/Mach-O: pefile, lief, pyelftools, macholib
* Signatures: yara-python, regex
* Fuzzy hashes: ssdeep (pydeep), tlsh
* Archives/Docs: py7zr, rarfile, oletools, python-magic
* System: psutil, watchdog (real-time FS), pywin32 (Win), cryptography
* Telemetry: opentelemetry-sdk, structlog
* Async: asyncio, anyio; packaging: uv/pip, pyproject.toml

---

## Milestone Roadmap

➡️ [View Milestone Roadmap](./docs/MILESTONES.md)

---

## Detection & Scoring Strategy

* Signals
    * Signature: YARA hits (high weight), exact hash matches, known bad signer.
    * Static heuristics: very high entropy, suspicious imports, packed sections, unusual PE header anomalies, macro presence with auto-exec.
    * Reputation: unseen rare hash vs widely seen benign; trusted signer allowlist.
    * Behavior: persistence writes, registry run keys, suspicious child processes, outbound C2 patterns (domain heuristics).
*Risk Score 0–100
    * Weighted additive with caps + explanations (always show which rules fired and why).
    * Tiered actions: 0–29 log, 30–59 warn, 60–79 quarantine, 80–100 quarantine + mark for review.

---

## Testing & Data

* Safety first: Start with EICAR and benign corpora (open-source binaries, Office docs you generate).
* Unit tests for each parser/feature; property tests for parsers on fuzzed inputs.
* Golden tests for rules (feed sample → assert score/reasons).
* Performance tests on a synthetic 50–100k file tree.
* Corpus management: versioned sample manifests with hashes, not the samples themselves (store in a quarantined, isolated location).

---

## Observability & Ops

* Metrics: scanned_files, detections, avg_scan_ms/file, queue_depth, quarantine_actions, rule_timeouts.
* Traces: per-file pipeline (collect → type → static → yara → heuristics → report).
* Audit log: append-only JSONL (with HMAC chain optional) for forensic integrity.
* Config flags: depth limits, size caps, temp space thresholds, rule bundle version pin, offline mode.

--- 

## Security, Legal, and Compliance Notes

* Never ship real malware with the repo; keep sample refs as hashes/URLs.
* Respect licenses for rule sets and third-party data. Avoid uploading user files to third-party APIs without explicit consent.
* Quarantine encryption (optional) + tamper-evident logs.
* Map findings to MITRE ATT&CK techniques in reports to aid triage.

---

## Concrete 2-Week Starter Plan

### Day 1–2

* Scaffold repo, tooling (ruff, mypy, pytest, CI), scanner CLI.
* Implement file walker, hash calc, type identification (magic).

### Day 3–5

* Integrate yara-python with a tiny, internal rule set.
* Add PE basics via pefile; compute section entropy.
* JSON report with reasons; first tests & E2E on ./samples.

### Week 2

* Add ssdeep/TLSH; simple heuristic rules (entropy/imports).
* Archive traversal (zip/tar/gz) with size/depth caps.
* Quarantine stub (copy + metadata manifest) and safe restore.
* Baseline metrics & structured logs; publish 0.1.0 pre-release.

---

## Acceptance Criteria Checklists

### MVP (end of M1)

- [ ] scanner scan PATH → JSON + console output with rule reasons
- [ ] EICAR detected by YARA; benign corpus <1% false positive
- [ ] 85%+ coverage for core modules; CI green on Win/Linux/macOS

### By M4

- [ ] Real-time folder monitoring with backpressure
- [ ] Quarantine/restore proven safe; audit log entries chained
- [ ] Signed rules bundle fetch + rollback

### By M6

- [ ] Throughput target met on 100k files
- [ ] OpenTelemetry metrics available; dashboards for ops
- [ ] Reproducible build & signed packages

--- 

## Example CLI UX (early)

```bash
$ scanner scan ~/Downloads --max-depth 3 --format json --out report.json
Scanned 12,384 files in 92.4s | 7 detections | ruleset v2025.09.01

$ scanner quarantine --list
$ scanner restore <quarantine_id>
$ scanner update --channel stable
$ scanner daemon --watch ~/Downloads --policy strict
```

---

## Risks & Mitigations

* **False positives** → Emphasize explainability + allowlist workflow + reputation scoring.
* **Rule performance** → Timeouts, pre-filtering by type/size, compiled YARA caches, parallel workers.
* **Unpack bombs** → Depth/size guards, temp space quotas, signature-based unpack detection.
* **Platform divergence** → Start Windows-first; abstract OS APIs; integration tests per OS.