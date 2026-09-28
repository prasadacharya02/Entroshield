# ============================================================
# ENTROPY federated exchange — multi-node simulation
# benchmark/exchange_simulation.py
#
# Simulates several "tenants" (nodes) sharing ONE threat-fingerprint
# exchange. Each tenant is a distinct identity with its own local
# state (its own EntropyAnalyzer history = its own victim estate),
# but every tenant's decision asks the exchange "have we seen this
# fingerprint before?" first.
#
# The simulation drives the REAL decision + response chain
# (EntropyAnalyzer -> collect_threat_flags -> make_decision ->
# execute_response, dry-run), so registration, lookup, scoring and
# explanation all run production code.
#
# Phases
# ──────
# 1. cold start   — a fresh node, empty exchange: a locally
#                   ambiguous file (high entropy, unknown ext, no
#                   baseline) is only an ALERT.
# 2. seeding A    — tenant A contains a known strain (ransom note +
#                   encrypted budget file). Both fingerprints are
#                   registered (1 source).
# 3. witness D    — tenant D meets the payload with only ONE source
#                   on record: corroboration (+25) but NO quarantine.
#                   The threshold is doing its job.
# 4. seeding B    — tenant B contains the same strain (2 sources).
# 5. warm start C — tenant C, fresh node, zero local history, meets
#                   the same payload with NO note and NO baseline.
#                   Locally it is only an ALERT — the exchange
#                   confirms it (>= 2 independent nodes) and the
#                   response escalates to QUARANTINE.
# 6. honesty      — tenant C handles legitimate work (a clean doc +
#                   high-entropy .zip archives): no quarantine, and
#                   the exchange stays threat-only.
#
# Run:  python -m benchmark.exchange_simulation
# ============================================================

import hashlib
import json
import os
import random
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from blockchain.fingerprint_exchange import FingerprintExchange
from entropy.entropy_calculator import EntropyAnalyzer
from monitoring.defense_guard import collect_threat_flags
from monitoring.pipeline_runner import (DecisionEngine, execute_response)

ACTION_NAMES = {0: "IGNORE", 1: "ALERT", 2: "TERMINATE", 3: "QUARANTINE"}

# Deterministic "encrypted" payload — the same bytes on every node,
# so its SHA-256 is the cross-node identity of the strain.
PAYLOAD_SEED = 42
PAYLOAD_SIZE = 65536

NOTE_BYTES = (
    b"Your files have been encrypted with AES-256.\n"
    b"To recover your files, pay 0.5 BTC to the wallet address below.\n"
    b"You have 72 hours to pay.\n"
)
CLEAN_TEXT = (
    b"Quarterly planning notes. The budget committee approved the "
    b"proposal and we will review the backup schedule next quarter.\n"
) * 12


def payload_bytes() -> bytes:
    return random.Random(PAYLOAD_SEED).randbytes(PAYLOAD_SIZE)


class _BcStub:
    """Blockchain is out of scope for the simulation (ledger anchor
    is exercised elsewhere); incidents are not lost — execute_response
    logs them and the exchange registration happens in the same call."""

    def log_event(self, _event):
        pass


def _make_events_db() -> sqlite3.Connection:
    """A throwaway events DB so execute_response's record-every-decision
    path runs exactly as in production (no 'NoneType' save errors)."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
            file_path TEXT, event_type TEXT, entropy REAL,
            entropy_delta REAL, pid INTEGER, process_name TEXT,
            action INTEGER, status TEXT, requested_action INTEGER,
            outcome TEXT, restore_result TEXT, dry_run INTEGER,
            engine TEXT, confidence REAL, explanation TEXT, q_values TEXT
        )
    """)
    conn.commit()
    return conn


def _engine() -> DecisionEngine:
    # The simulation measures the EXCHANGE layer (corroboration vs
    # confirmation, poison-node defence) with the baseline detector.
    # Pin it to the deterministic rule engine so the documented
    # invariants (cold start = alert-only, single sighting never
    # quarantines) hold regardless of which trained models exist.
    return DecisionEngine(engine="rules")


class Tenant:
    """One simulated node: its identity, its local state, and its
    view of the shared exchange."""

    def __init__(self, node_id: str, exchange: FingerprintExchange,
                 victim_root: Path, engine: DecisionEngine,
                 events_db=None):
        self.node_id = node_id
        self.exchange = exchange
        self.root = victim_root
        self.analyzer = EntropyAnalyzer()   # local history = local state
        self.engine = engine
        self.events_db = events_db
        self.ops = []

    def lay(self, files: list[tuple[str, bytes]]) -> None:
        """(Re)create this tenant's victim estate."""
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        for rel, content in files:
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def baseline(self, rel_paths: list[str]) -> None:
        """Model the startup snapshot the real pipeline takes."""
        for rel in rel_paths:
            self.analyzer.analyze(str(self.root / rel))

    def process(self, rel: str, event_type: str) -> dict:
        """Run one file event through the real decision + response
        chain (dry-run) and record the outcome."""
        path = self.root / rel
        result = self.analyzer.analyze(str(path))
        event = {
            "event_id": f"{self.node_id}-{rel}",
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "file_path": str(path),
            "file_extension": result.get("file_extension", ""),
            "file_size": result.get("file_size", 0),
            "file_hash": result.get("file_hash", ""),
            "entropy_overall": result.get("entropy_overall", 0.0),
            "entropy_delta": result.get("entropy_delta", 0.0),
            "threat_score": result.get("threat_score", 0.0),
            "chi2_uniformity": result.get("chi2_uniformity"),
            "chi2_tail": result.get("chi2_tail"),
            "magic_ok": result.get("magic_ok", True),
            "events_per_sec": 0.0,
            "is_suspicious_speed": False,
            "ext_changed": False,
            "process": {},
        }
        event.update(collect_threat_flags(event, exchange=self.exchange))
        decision = self.engine.decide(event)
        action = decision["action"]
        outcome = execute_response(
            action, event, _BcStub(), self.events_db, decision,
            backup=None, exchange=self.exchange,
        )
        rec = {
            "node": self.node_id,
            "file": rel,
            "event_type": event_type,
            "entropy": round(float(result.get("entropy_overall") or 0.0), 3),
            "local_score": round(float(result.get("threat_score") or 0.0), 2),
            "known_threat": bool(event.get("known_threat")),
            "known_threat_confirmed": bool(
                event.get("known_threat_confirmed")
            ),
            "action": action,
            "action_name": ACTION_NAMES[action],
            "outcome": outcome,
            "explanation": decision.get("explanation", ""),
        }
        self.ops.append(rec)
        return rec


def run_simulation(base_dir: str | None = None) -> dict:
    """Run all six phases against one shared exchange store."""
    base = Path(base_dir) if base_dir else \
        Path(tempfile.mkdtemp(prefix="exchange_sim_"))
    base.mkdir(parents=True, exist_ok=True)

    # Keep the simulation's forensic reports out of the repo.
    reports_dir = base / "reports"

    # One shared exchange — the "network" all tenants see.
    shared_db = base / "exchange.db"
    engine = _engine()
    tenants = {}
    for name in ("tenant-alpha", "tenant-bravo", "tenant-charlie",
                 "tenant-delta"):
        tenants[name] = Tenant(
            name,
            FingerprintExchange(str(shared_db), node_id=name),
            base / f"victim_{name}",
            engine,
            events_db=_make_events_db(),
        )
    alpha, bravo, charlie, delta = (
        tenants["tenant-alpha"], tenants["tenant-bravo"],
        tenants["tenant-charlie"], tenants["tenant-delta"],
    )

    payload = payload_bytes()
    budget_rel = "Documents/budget_2026.qrx"
    note_rel = "Documents/Restore-My-Files.txt"
    phases: list[dict] = []

    def strain_run(tenant: Tenant) -> None:
        """The known strain: ransom note + in-place encryption of the
        budget file (baseline available, so the delta confirms)."""
        tenant.lay([(budget_rel, CLEAN_TEXT)])
        tenant.baseline([budget_rel])
        (tenant.root / note_rel).parent.mkdir(parents=True, exist_ok=True)
        (tenant.root / note_rel).write_bytes(NOTE_BYTES)
        tenant.process(note_rel, "CREATED")
        (tenant.root / budget_rel).write_bytes(payload)
        tenant.process(budget_rel, "MODIFIED")

    def ambiguous_run(tenant: Tenant) -> dict:
        """Locally ambiguous: the payload alone, no note, no baseline,
        no history for this file on this node."""
        tenant.lay([])
        (tenant.root / "Documents").mkdir(parents=True, exist_ok=True)
        (tenant.root / "Documents/financials_q3.qrx").write_bytes(payload)
        return tenant.process("Documents/financials_q3.qrx", "CREATED")

    # Keep execute_response's side effects (forensic reports, quarantined
    # copies) inside the simulation, not the repo.
    import contextlib

    @contextlib.contextmanager
    def _side_effects_to_sim():
        original_reports = config.REPORTS_DIR
        original_quarantine = config.QUARANTINE_DIR
        config.REPORTS_DIR = str(reports_dir)
        config.QUARANTINE_DIR = str(base / "quarantine")
        try:
            yield
        finally:
            config.REPORTS_DIR = original_reports
            config.QUARANTINE_DIR = original_quarantine

    with _side_effects_to_sim():
        # ── Phase 1: cold start (empty exchange) ────────────
        cold = ambiguous_run(charlie)
        phases.append({
            "phase": "1_cold_start",
            "tenant": charlie.node_id,
            "exchange_state": "empty",
            "result": cold,
        })

        # ── Phase 2: tenant A seeds the strain ──────────────
        strain_run(alpha)
        phases.append({
            "phase": "2_seeding_alpha",
            "tenant": alpha.node_id,
            "ops": alpha.ops[-2:],
        })

        # ── Phase 3: tenant D — single sighting only ────────
        single = ambiguous_run(delta)
        phases.append({
            "phase": "3_single_sighting",
            "tenant": delta.node_id,
            "result": single,
        })

        # ── Phase 4: tenant B seeds the same strain ─────────
        strain_run(bravo)
        phases.append({
            "phase": "4_seeding_bravo",
            "tenant": bravo.node_id,
            "ops": bravo.ops[-2:],
        })

        # ── Phase 5: tenant C — warm start ──────────────────
        warm = ambiguous_run(charlie)
        phases.append({
            "phase": "5_warm_start",
            "tenant": charlie.node_id,
            "result": warm,
        })

        # ── Phase 6: honesty — legitimate work, threat-only
        #    exchange ─────────────────────────────────────────
        count_before = charlie.exchange.count()
        charlie.lay([])
        (charlie.root / "Archives").mkdir(parents=True, exist_ok=True)
        (charlie.root / "Documents").mkdir(parents=True, exist_ok=True)
        (charlie.root / "Documents/planning.txt").write_bytes(CLEAN_TEXT)
        workload_ops = [charlie.process("Documents/planning.txt", "CREATED")]
        import zipfile, io
        for i in range(3):
            name = f"Archives/backup_{i:02d}.zip"
            # Build a REAL zip file so its magic header (PK\x03\x04)
            # and byte distribution match a legitimate archive — not
            # uniform random bytes that would fail magic-byte / chi²
            # checks (which are the ciphertext fingerprints).
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                rng = random.Random(100 + i)
                # Use compressible textual content so the resulting
                # archive has the byte-frequency peaks (chi² > 300)
                # that distinguish real compressed files from
                # statistically-uniform ciphertext.
                zf.writestr(
                    f"manifest_{i}.txt",
                    ("backup index " + str(i) + "\n") * 800
                    + "".join(chr(rng.randint(32, 126)) for _ in range(8000)),
                )
                zf.writestr(
                    f"notes_{i}.txt",
                    ("quarterly results " + str(i) + "\n") * 600,
                )
            (charlie.root / name).write_bytes(buf.getvalue())
            workload_ops.append(charlie.process(name, "CREATED"))
        phases.append({
            "phase": "6_workload_honesty",
            "tenant": charlie.node_id,
            "ops": workload_ops,
            "exchange_count_before": count_before,
            "exchange_count_after": charlie.exchange.count(),
        })

    # ── Shared-store summary ─────────────────────────────────
    store = FingerprintExchange(str(shared_db), node_id="summary")
    records = []
    for row in store._conn.execute(   # noqa: SLF001 (summary view)
            "SELECT fingerprint, sightings, sources FROM threat_fingerprints"
    ):
        records.append({
            "fingerprint": row["fingerprint"],
            "sightings": row["sightings"],
            "sources": json.loads(row["sources"]),
        })
    store.close()

    payload_fp = hashlib.sha256(payload_bytes()).hexdigest()

    # Known-threat metrics at first sight. A "first-sight encounter" is a
    # fresh node meeting a fingerprint already in the exchange:
    #   - recall:    sources >= threshold -> must auto-quarantine
    #   - restraint: sources <  threshold -> corroborate, NOT quarantine
    recall_encounters = 0
    recall_confirmed = 0
    restraint_encounters = 0
    restraint_held = 0
    workload_runs = 0
    workload_false_positives = 0
    for phase in phases:
        if phase["phase"] in ("3_single_sighting", "5_warm_start"):
            rec = phase["result"]
            if phase["phase"] == "5_warm_start":
                recall_encounters += 1
                if rec["known_threat_confirmed"] and \
                        rec["action"] == config.ACTION_TERMINATE_QUARANTINE:
                    recall_confirmed += 1
            else:
                restraint_encounters += 1
                if rec["known_threat"] and \
                        rec["action"] != config.ACTION_TERMINATE_QUARANTINE:
                    restraint_held += 1
        elif phase["phase"] == "6_workload_honesty":
            workload_runs += len(phase["ops"])
            workload_false_positives += sum(
                1 for o in phase["ops"] if o["action"] >= config.ACTION_ALERT
            )
    recall_pct = (
        round(100.0 * recall_confirmed / recall_encounters, 1)
        if recall_encounters else 0.0
    )
    restraint_pct = (
        round(100.0 * restraint_held / restraint_encounters, 1)
        if restraint_encounters else 0.0
    )

    report = {
        "generated": datetime.now().isoformat(),
        "exchange_db": str(shared_db),
        "confirm_threshold": config.EXCHANGE_CONFIRM_THRESHOLD,
        "phases": phases,
        "exchange_records": records,
        "payload_fingerprint": payload_fp[:16] + "…",
        "recall_metrics": {
            "known_threat_recall_first_sight": (
                f"{recall_confirmed}/{recall_encounters}"
            ),
            "known_threat_recall_pct": recall_pct,
            "single_sighting_restraint": (
                f"{restraint_held}/{restraint_encounters}"
            ),
            "single_sighting_restraint_pct": restraint_pct,
            "workload_false_positives": workload_false_positives,
            "workload_runs": workload_runs,
        },
        "headline": {
            "cold_start_action": cold["action_name"],
            "single_sighting_action": single["action_name"],
            "single_sighting_corroborated": single["known_threat"],
            "warm_start_action": warm["action_name"],
            "warm_start_confirmed": warm["known_threat_confirmed"],
            "warm_start_explanation": warm["explanation"],
            "workload_max_action": max(
                o["action"] for o in workload_ops
            ),
            "workload_added_exchange_records": (
                charlie.exchange.count() - count_before
            ),
        },
    }
    for tenant in tenants.values():
        tenant.exchange.close()
    return report


def _print_report(report: dict) -> None:
    print()
    print("=" * 72)
    print("  FEDERATED EXCHANGE — MULTI-NODE SIMULATION")
    print(f"  Confirmation threshold: "
          f"{report['confirm_threshold']} independent nodes")
    print("=" * 72)

    def show(rec: dict, indent: str = "    "):
        flags = []
        if rec.get("known_threat_confirmed"):
            flags.append("KNOWN-CONFIRMED")
        elif rec.get("known_threat"):
            flags.append("known+1")
        print(f"{indent}{rec['file']}  H={rec['entropy']:.2f} "
              f"local={rec['local_score']:>5.1f} "
              f"→ {rec['action_name']:<9} "
              f"{' '.join(flags)}")

    for phase in report["phases"]:
        name = phase["phase"]
        print(f"\n  [{name}]  ({phase.get('tenant', '')})")
        if "result" in phase:
            show(phase["result"])
        for rec in phase.get("ops", []):
            show(rec)

    h = report["headline"]
    print("\n" + "-" * 72)
    print("  HEADLINE")
    print("-" * 72)
    print(f"  Cold start (empty exchange)      : {h['cold_start_action']}")
    print(f"  Single sighting (1 node)         : "
          f"{h['single_sighting_action']} "
          f"(corroborated={h['single_sighting_corroborated']})")
    print(f"  Warm start (>=2 nodes)           : {h['warm_start_action']} "
          f"(confirmed={h['warm_start_confirmed']})")
    print(f"  Workload max action              : "
          f"{ACTION_NAMES[h['workload_max_action']]} "
          f"(exchange records added: "
          f"{h['workload_added_exchange_records']})")
    print(f"\n  Exchange now holds {len(report['exchange_records'])} "
          f"threat fingerprint(s):")
    for rec in report["exchange_records"]:
        print(f"    {rec['fingerprint']}…  "
              f"sightings={rec['sightings']} "
              f"sources={rec['sources']}")
    print("=" * 72)


def main() -> int:
    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    report = run_simulation()
    artifact = results_dir / (
        f"exchange_simulation_{datetime.now():%Y%m%d_%H%M%S}.json"
    )
    artifact.write_text(json.dumps(report, indent=2))
    _print_report(report)
    print(f"\n  Artifact → {artifact.relative_to(Path(__file__).parents[1])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
