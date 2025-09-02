

```bash
uber-hacksaw/
├─ docs/ 
│  ├─ milestones
│  ├─ ARCHITECTURE.md
│  └─ PROJECT_STATE.md
│    
├─ cli/                     	# CLI entrypoints (scan file/dir, daemon mode)
├─ src/
│  └─uber-hacksaw/
│  	 ├─core/
│  	 │ ├─ scheduler.py          # Crawl queue, timeouts, concurrency (asyncio)
│  	 │ ├─ engine.py             # Orchestrates pipeline: collectors → analyzers → reporters
│    │ ├─ config.py             # Typed settings, feature flags
│    │ ├─ rules/
│    │ │  ├─ yara/              # YARA rules and compiled caches
│    │ │  └─ heuristics/        # JSON/YAML heuristic rules
│    │ └─ quarantine.py         # Isolated storage, rollback metadata
│    ├─io/
│    │ ├─ collectors.py         # File walkers, archive extractors, stream readers
│    │ ├─ fs_utils.py           # Safe open/read, extended attrs, ADS (Win)
│    │ └─ unpackers.py          # Zip/rar/7z/tar/gzip; later: UPX, custom packers
│	 ├─ static/
│	 │  ├─ type_id.py            # Magic/type inference (PE/ELF/Mach-O, scripts, docs)
│	 │  ├─ pe.py                 # PE parsing (imports, sections, resources, entropy)
│	 │  ├─ elf.py                # ELF parsing
│	 │  ├─ macho.py              # Mach-O parsing
│	 │  ├─ macros.py             # Office macro extraction (oletools)
│	 │  └─ classifiers.py        # Heuristics, fuzzy hash, TLSH/ssdeep
│	 ├─ dynamic/
│	 │  ├─ sandbox_client.py     # Remote sandbox API client (safe first)
│	 │  ├─ behavior_schema.py    # Event model (files, procs, registry, net)
│	 │  └─ etw_win.py            # (later) ETW/Sysmon ingestion on Windows
│	 ├─ detect/
│	 │  ├─ signatures.py         # YARA/regex/hard indicators
│	 │  ├─ reputation.py         # Hash and signer reputation, local cache
│	 │  ├─ scoring.py            # Risk score combiner with explainability
│	 │  └─ ml.py                 # (later) lightweight ML models
│	 ├─ telemetry/
│	 │  ├─ metrics.py            # Counters/latency, OpenTelemetry exporters
│	 │  └─ auditlog.py           # JSONL events for scans, detections, actions
│	 ├─ report/
│	 │  ├─ console.py            # Human readable
│	 │  ├─ sarif.py              # SARIF/JSON output for CI
│	 │  └─ api.py                # (later) REST/GRPC for Service/GUI
│	 └─ update/
│	    ├─ fetcher.py            # Periodic pull of rules, reputation sets
│	    └─ signer.py             # Verify rule bundle signatures
├─ tests/
│  └─ ...
│
├─ .gitignore
├─ LICENSE
├─ main.py
├─ Makefile
├─ pyproject.toml
├─ README.md
└─ tests/
```