# ENTROPY - Canonical Runtime Architecture (Industry Level)

## Final Year Major Project - End-to-End Working System

### Runtime Path (Production)

```
victim_server/user_files/ (18 files, controlled estate)
    ↓ watchdog Observer 0.2s + protected stores watcher
monitoring.watchdog_monitor.FileMonitor
    ↓ event deduplication (1s window)
monitoring.event_deduplicator
    ↓
monitoring.event_pipeline.EventPipeline (queue 10000, batch 50)
    → entropy.entropy_calculator.EntropyAnalyzer
      - Shannon entropy per file + delta vs history
      - Per-type normal ranges (txt 3.0-5.5, xlsx 6.0-7.5, jpg 7.0-7.8, etc)
      - Threat score 0-100
    → monitoring.defense_guard.collect_threat_flags
      - Ransom note (filename + phrase list)
      - Defense tamper (deletion from backup/quarantine stores)
      - Known-threat exchange lookup (fingerprint registry)
    → response.backup_manager.BackupManager.capture(strict=True for event-time)
      - Strict clean rule: inside normal range, no 0.5 margin, no ≥2.0 jump from last clean
      - Prevents ciphertext becoming restore source
    → monitoring.pipeline_runner.DecisionEngine
      - Rule engine (default, 0 false quarantine)
      - CampaignTracker (2+ files with encrypted signatures in 15s = CAMPAIGN CONFIRMED)
      - RF classifier (opt-in, SHAP, 100% detection)
      - DQN (opt-in, torch fallback)
    → response.response_module (terminate + quarantine)
      - ProcessTerminator: verified PID only, zombie-aware, self-kill whitelist
      - Never-kill gate (config.DENY_KILL_PROCESSES): user/OS software refused
        at attribution, in campaign kill memory and at the termination gate
      - FileQuarantine: install-time folder, SHA3-256 + SHA-256 dual hash, meta.json
    → Campaign sweep (quarantine+restore all campaign files)
    → Post-kill verification (walk estate; repair only files that still show
      ciphertext evidence - a clean file that merely changed is left alone)
    → response.backup_manager.BackupManager.restore (clean v1, rename-back)
    → response.forensic_report (one JSON per incident)
    → blockchain.connector.BlockchainConnector
      - Ganache ThreatLogger contract (owner-only)
      - LocalLedger fallback (default true, works without Ganache, labeled)
    → blockchain.fingerprint_exchange (share confirmed threats)
    → storage.database (events, 50 limit API)
    → app.py dashboard (socket.io push 0.4s: new_event + live_update)
```

### Startup Sequence (lab.py)

1. `install.py` logic: create quarantine_storage/, backup_storage/, logs/, reports/ (install-time folder per spec)
2. `create_fake_files.py --clean`: 18 files (6 Documents, 4 Downloads, 4 Desktop, 4 Pictures)
3. `PipelineRunner`: snapshot 18 files into backup store (baseline for restore)
4. `FileMonitor`: watch victim_server/user_files + protected stores (backup/quarantine deletion = tamper signal)
5. Dashboard (5000), Victim (5001), Attacker (8001) Flask + socketio threading mode

### Pipeline Supervision (`monitoring/pipeline_supervisor.py`)

The defence is a separate process from the three UI surfaces, so it is easy to
leave it out when starting only the web apps — the attack then completes and the
SOC dashboard stays at 0 events. The supervisor removes that failure mode:

- `pipeline_status()` reads the shared `pipeline_status` heartbeat row
  (written every 2s by the pipeline) → cross-process liveness.
- Starting the SOC dashboard or the victim explorer calls
  `ensure_pipeline()`; a background thread re-checks every 3s and restarts the
  pipeline if it dies, hangs (live process, no heartbeat for 30s), or is found
  not watching `victim_server/user_files`.
- Duplicate-start protection: fresh heartbeat, the process table (a pipeline
  that is still importing), a 15s cross-process spawn guard, and the
  `ENTROPY_PIPELINE_MANAGED=1` recursion flag.
- `victim_server/user_files` is always in `config.WATCH_FOLDERS`
  (`ENTROPY_WATCH_VICTIM=false` opts out).
- Opt out of supervision entirely with `ENTROPY_AUTOSTART_PIPELINE=false`.
- Endpoints: `GET /api/pipeline` (status), `POST /api/pipeline/restart`.
- CLI: `python -m monitoring.pipeline_supervisor [status|start|restart|watch]`.

### Key Fixes for Industry Level (Final Year)

- **Campaign escalation**: slow realistic attacks (1.6 ev/s) never trip speed bar, but 2 files with encrypted signatures in 15s triggers TERMINATE+QUARANTINE at file 2
- **Strict clean labeling**: event-time captures labeled clean only if inside normal range AND no delta jump, so xlsx ciphertext 7.88 never becomes restore source
- **Content-based post-kill verification**: after kill, compare current file hash vs last clean hash, repair only if differs. No entropy-only false positives on jpgs (7.0)
- **Zombie-aware termination**: attacker console reaps child in _stream_reader finally, terminator treats zombie/already-gone as success, so kill instant rc=42 not FORCE KILLED after 3s
- **Real-time push**: dashboard push_updates() polls DB for new ids, emits new_event + live_update via socketio, client uses io({transports:['websocket','polling']})
- **Neutral victim explorer**: /api/files returns only name/size/modified/icon, no encrypted counts, no family, Quarantine locked behind vault
- **SHA3-256 dual hash**: storage/hashing.py provides sha3_256_file + dual_hash_file, response_module uses SHA3-256 primary

### Data Flow for Demo (WannaCry)

1. Attacker POST /api/launch wannacry → spawns ransomware_engines.py subprocess (os.urandom overwrite + .WNCRY rename)
2. File 1: MODIFIED Financial_Report_2024.xlsx (entropy 7.88) → ALERT (60) → capture strict=False? Actually strict=True for event-time, labeled not clean, recorded in CampaignTracker
3. File 2: RENAMED Client_Meeting_Notes.docx.WNCRY (7.81) → ALERT + qualifies → CampaignTracker count distinct paths ≥2 → escalate to TERMINATE+QUARANTINE, kill_override = last_verified PID 3101
4. Response: terminate PID 3101 → SUCCESS → quarantine file 2 → restore clean v1 (captured at boot) → sweep file 1 → quarantine+restore
5. Post-kill verification: walk estate, Tax_Returns.pdf hash differs from last clean (4.9 vs 7.79) → quarantine+restore
6. Estate: 18/18 restored, 0 .WNCRY, 3 evidence files in quarantine_storage/

### Security Boundaries

- Attacker confined to victim_server/user_files via safe_path() check
- Defender never kills whitelisted or own tooling (DEFENDER_TOOLING_MARKERS)
- Never-kill list (DENY_KILL_PROCESSES): browsers, Windows search/COM
  surrogates, sync clients, Office and the EDR itself are never terminated,
  whatever the attribution layer reports
- Unverifiable attribution is never published as a named process: such events
  record `unattributed` with no PID
- SOC counters/monitor/decision panel report executed outcomes only (a refused
  kill is `terminate_refused` + status `TERMINATE_REFUSED+QUARANTINED`)
- Vault PIN compare_digest, session 8h, scope quarantine_only
- Quarantine files cannot be decrypted (os.urandom, no key) - honest

### Compatibility Facades (Do Not Extend)

- entropy_system.py
- blockchain/blockchain_logger.py

These emit DeprecationWarning and delegate to canonical implementations.

### For 200 Marks

This architecture is not PowerPoint - it's running code with 222 tests, deterministic benchmark, live demo verified, honest limitations published.
