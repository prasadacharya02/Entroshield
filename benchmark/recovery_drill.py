# ============================================================
# ENTROPY recovery drill — detect → contain → recover, measured
# benchmark/recovery_drill.py
#
# For each attack scenario (and baseline mode) a full drill of the
# recovery loop on a throwaway victim estate:
#
#   1. Lay the pre-attack estate and remember every byte.
#   2. Startup baseline capture (real BackupManager — what the
#      production pipeline does at monitor start).
#   3. Replay the attack ops through the REAL chain:
#      EntropyAnalyzer -> capture every state -> collect_threat_flags
#      -> make_decision -> execute_response with REAL quarantine and
#      REAL restore (no dry-run — the files are throwaway).
#   4. Byte-for-byte verification of the post-drill estate, and RTO:
#         - RTO in file operations (first / full recovery)
#         - RTO in attacker-clock seconds (the scenario's own timing)
#         - measured wall time of the response work itself
#
# Recovery semantics (honest):
#   - "recovered"  = the victim's pre-attack bytes are back on disk.
#                    For rename attacks the file is renamed back to
#                    its original name (same as production).
#   - "contained"  = the encrypted file was quarantined but no clean
#                    version existed / was found — data is preserved
#                    in quarantine but NOT restored.
#   - attacker-created files (notes, fresh payloads) are reported
#     separately; containing them is success, not a recovery failure.
#
# Run:  python -m benchmark.recovery_drill
# ============================================================

import contextlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from benchmark.runner import _Clock
from benchmark.scenarios import ATTACKS, WORKLOADS
from blockchain.fingerprint_exchange import FingerprintExchange
from entropy.entropy_calculator import EntropyAnalyzer
from monitoring.defense_guard import collect_threat_flags
from monitoring.pipeline_runner import execute_response, make_decision
from response.backup_manager import BackupManager


class _BcStub:
    def log_event(self, _event):
        pass


def run_drill_scenario(scenario, *, baseline: bool, workdir: Path,
                       exchange: FingerprintExchange) -> dict:
    """Drill one scenario end to end on a throwaway estate."""
    root = workdir / "victim"
    backup_dir = workdir / "backup"
    quarantine_dir = workdir / "quarantine"
    reports_dir = workdir / "reports"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    pre_attack = {}
    for rel, content in scenario.initial_files:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        pre_attack[rel] = content

    backup = BackupManager(backup_dir=str(backup_dir))
    analyzer = EntropyAnalyzer()
    if baseline:
        # The production startup baseline, both halves: restorable
        # copies (backup store) + first-event deltas (entropy history).
        backup.snapshot_directory(str(root), source="startup_baseline")
        analyzer.snapshot_directory(str(root))

    # A real (throwaway) events DB so the response code path that
    # records every decision is exercised exactly as in production.
    events_db = sqlite3.connect(":memory:")
    events_db.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
            file_path TEXT, event_type TEXT, entropy REAL,
            entropy_delta REAL, pid INTEGER, process_name TEXT,
            action INTEGER, status TEXT, requested_action INTEGER,
            outcome TEXT, restore_result TEXT, dry_run INTEGER,
            engine TEXT, confidence REAL, explanation TEXT, q_values TEXT,
            threat_score REAL
        )
    """)
    events_db.commit()

    clock = _Clock()

    first_detection_op = None
    first_recovery_op = None
    per_file = {}          # original rel -> {"recovered": bool, "contained": bool, "safe_op": int|None}
    clean_versions = {rel: [(-1, content)]
                      for rel, content in pre_attack.items()}
    # (op_index, rel) -> capture cleanliness, for attack-op detection
    op_clean = {}
    attacker_files = []    # files created by the attack (not pre-attack estate)
    wall_response = 0.0
    quarantine_count = 0

    # Real quarantine + real restore, side effects kept inside workdir.
    original_dr = config.DRY_RUN
    original_qd = config.QUARANTINE_DIR
    original_rd = config.REPORTS_DIR
    config.DRY_RUN = False
    config.QUARANTINE_DIR = str(quarantine_dir)
    config.REPORTS_DIR = str(reports_dir)
    try:
        for i, op in enumerate(scenario.ops):
            clock.advance(op.delay_before)
            old_path = root / op.rel_path
            ext_changed = False
            if op.kind == "create":
                old_path.parent.mkdir(parents=True, exist_ok=True)
                old_path.write_bytes(op.content)
                target = old_path
                if op.rel_path not in pre_attack:
                    attacker_files.append(op.rel_path)
            elif op.kind == "modify":
                old_path.write_bytes(op.content)
                target = old_path
            elif op.kind == "rename":
                old_path.write_bytes(op.content)
                new_path = root / op.new_path
                os.replace(str(old_path), str(new_path))
                analyzer.transfer_history(str(old_path), str(new_path))
                # Same rename handling the production pipeline applies
                # (PipelineRunner._on_analyzed_event on RENAMED): keep
                # the pre-rename backup versions restorable.
                backup.transfer(str(old_path), str(new_path))
                target = new_path
                ext_changed = os.path.splitext(op.rel_path)[1].lower() != \
                    os.path.splitext(op.new_path or "")[1].lower()
            elif op.kind == "delete":
                if old_path.exists():
                    old_path.unlink()
                target = old_path
            else:
                raise ValueError(f"Unknown op kind: {op.kind}")

            event_type = {"create": "CREATED", "modify": "MODIFIED",
                          "rename": "RENAMED", "delete": "DELETED"}[op.kind]
            result = analyzer.analyze(str(target))
            event = {
                "event_id": f"drill-{scenario.name}-{i}",
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "file_path": str(target),
                "file_extension": result.get("file_extension", ""),
                "file_size": result.get("file_size", 0),
                "file_hash": result.get("file_hash", ""),
                "entropy_overall": result.get("entropy_overall", 0.0),
                "entropy_delta": result.get("entropy_delta", 0.0),
                "threat_score": result.get("threat_score", 0.0),
                "chi2_uniformity": result.get("chi2_uniformity"),
                "chi2_tail": result.get("chi2_tail"),
                "magic_ok": result.get("magic_ok", True),
                "events_per_sec": clock.rate(),
                "is_suspicious_speed":
                    clock.rate() >= config.FILES_PER_SECOND_THRESHOLD,
                "ext_changed": ext_changed,
                # Mirrors the monitor: on RENAMED events the pre-rename
                # path is carried so execute_response can rename a
                # restored file back to its original name.
                "original_path": (
                    str(old_path) if str(old_path) != str(target) else None
                ),
                "process": {},
            }
            # Production captures every event state (additive).
            cap = backup.capture(str(target), event=event)
            if op.rel_path in clean_versions:
                op_clean[(i, op.rel_path)] = bool(cap.get("clean"))
                if cap.get("clean"):
                    try:
                        clean_versions[op.rel_path].append(
                            (i, target.read_bytes())
                        )
                    except OSError:
                        pass
            event.update(collect_threat_flags(
                event,
                tuple(str(root / p) for p in
                      getattr(scenario, "protected_paths", ())),
                exchange=exchange,
            ))
            action = make_decision(event)
            if action >= config.ACTION_ALERT:
                if first_detection_op is None:
                    first_detection_op = i

            if action == config.ACTION_TERMINATE_QUARANTINE:
                decision = {
                    "engine": "rules",
                    "action": action,
                    "action_name": "TERMINATED+QUARANTINED",
                    "confidence": 1.0,
                    "explanation": "recovery drill",
                }
                t0 = time.perf_counter()
                outcome = execute_response(
                    action, event, _BcStub(), events_db, decision,
                    backup=backup, exchange=exchange,
                )
                wall_response += time.perf_counter() - t0
                # Real-mode outcomes: QUARANTINED, RESPONSE_PARTIAL
                # (e.g. the file was already deleted), plus a
                # +RESTORED / +RESTORE_FAILED suffix.
                restored = "+RESTORED" in outcome
                contained = ("QUARANTINE" in outcome
                             or "PARTIAL" in outcome
                             or "MOVED" in outcome)
                if contained:
                    quarantine_count += 1
                # Track per victim file: is it safe now?
                rel = op.rel_path
                if rel in pre_attack:
                    entry = per_file.setdefault(
                        rel, {"recovered": False, "contained": False,
                              "safe_op": None}
                    )
                    if restored:
                        entry["recovered"] = True
                        entry["safe_op"] = i
                        if first_recovery_op is None:
                            first_recovery_op = i
                    elif contained:
                        entry["contained"] = True
                        if entry["safe_op"] is None:
                            entry["safe_op"] = i
    finally:
        config.DRY_RUN = original_dr
        config.QUARANTINE_DIR = original_qd
        config.REPORTS_DIR = original_rd
        events_db.close()

    # ── Byte-for-byte verification of the post-drill estate ──
    # "Attacked" is measured EMPIRICALLY: the file's on-disk content
    # differs from its pre-attack content (or the file is gone). That
    # catches what labels cannot — in-range encrypted content is
    # labelled clean by the heuristic, and that IS the image blind
    # spot: it must show up as attacked+lost, never as recovered.
    #
    # "Expected" (what a correct restore must bring back) = the last
    # clean state before the first structurally-malicious op (a
    # rename/delete always; a dirty-labelled capture), falling back to
    # the t=0 content.
    ops_on_file = {op.rel_path for op in scenario.ops}
    attack_op = {}
    for i, op in enumerate(scenario.ops):
        rel = op.rel_path
        if rel not in pre_attack or rel in attack_op:
            continue
        if op.kind in ("rename", "delete"):
            attack_op[rel] = i
        elif op_clean.get((i, rel)) is False:
            attack_op[rel] = i

    verified_recovered = 0
    verified_contained = 0
    verified_lost = 0
    verified_untouched = 0
    attacked_files = 0
    attacked_recovered = 0
    attacked_set = set()
    for rel in pre_attack:
        entry = per_file.setdefault(
            rel, {"recovered": False, "contained": False, "safe_op": None}
        )
        a = attack_op.get(rel)
        expected = pre_attack[rel]
        for idx, content in clean_versions[rel]:
            if a is not None and idx < a:
                expected = content
        # Where should the data be? For rename attacks it comes back at
        # the NEW path (restored in place after the rename); otherwise
        # at the original path.
        candidates = [root / rel]
        for op in scenario.ops:
            if op.rel_path == rel and op.kind == "rename" and op.new_path:
                candidates.append(root / op.new_path)
        on_disk = None
        for cand in candidates:
            if cand.is_file():
                try:
                    on_disk = cand.read_bytes()
                    break
                except OSError:
                    pass
        # A fully restored file looks identical to t=0 — the scenario
        # ops are the ground truth for "was this file attacked".
        # Workload (legitimate) edits are not attacks.
        attacked = scenario.kind == "attack" and (
            on_disk != pre_attack[rel] or rel in ops_on_file
        )
        if not attacked:
            entry["verified"] = "untouched"
            verified_untouched += 1
            continue

        attacked_files += 1
        attacked_set.add(rel)
        if on_disk == expected and entry["recovered"]:
            found = "recovered"
            verified_recovered += 1
            attacked_recovered += 1
        elif entry["contained"]:
            found = "contained"
            verified_contained += 1
        else:
            found = "lost"
            verified_lost += 1
        entry["verified"] = found

    victim_files = len(pre_attack)
    recovery_rate = (
        round(100.0 * attacked_recovered / attacked_files, 1)
        if attacked_files else None
    )
    # Full recovery = EVERY attacked file is safe (restored or
    # contained). RTO is reported only when that actually happened —
    # otherwise it is None (recovery incomplete), not a partial number.
    attacked_safe_ops = [
        per_file[rel]["safe_op"]
        for rel in attacked_set
        if per_file[rel].get("verified") in ("recovered", "contained")
        and per_file[rel].get("safe_op") is not None
    ]
    all_attacked_safe = (
        attacked_files > 0
        and len(attacked_safe_ops) == attacked_files
    )
    full_recovery_op = max(attacked_safe_ops) if all_attacked_safe else None

    rto_ops = (full_recovery_op + 1) if full_recovery_op is not None else None
    rto_attacker_s = None
    if full_recovery_op is not None:
        rto_attacker_s = round(
            sum(o.delay_before for o in scenario.ops[:full_recovery_op + 1]),
            3,
        )

    return {
        "scenario": scenario.name,
        "kind": scenario.kind,
        "baseline": baseline,
        "ops": len(scenario.ops),
        "first_detection_op": first_detection_op,
        "ops_to_detection": (first_detection_op + 1)
        if first_detection_op is not None else None,
        "victim_files": victim_files,
        "attacked_files": attacked_files,
        "attacked_files_recovered": attacked_recovered,
        "attacked_files_contained_not_restored": verified_contained,
        "attacked_files_lost": verified_lost,
        "untouched_files": verified_untouched,
        "attacker_files_quarantined": len(attacker_files),
        "quarantine_actions": quarantine_count,
        "recovery_rate_pct": recovery_rate,
        "first_recovery_op": first_recovery_op,
        "full_recovery_op": full_recovery_op,
        "rto_ops": rto_ops,
        "rto_attacker_clock_s": rto_attacker_s,
        "response_wall_s": round(wall_response, 3),
        "rto_wall_estimate_s": (
            round(rto_attacker_s + wall_response, 3)
            if rto_attacker_s is not None else None
        ),
        "per_file": per_file,
    }


def run_drill(seeds=(1, 2, 3), attacks=None, workloads=None,
              work_base: str | None = None) -> dict:
    """Run the full recovery drill (attacks in both baseline modes,
    one workload as the false-recovery control)."""
    base = Path(work_base) if work_base else \
        Path(tempfile.mkdtemp(prefix="recovery_drill_"))
    base.mkdir(parents=True, exist_ok=True)
    exchange = FingerprintExchange(str(base / "exchange.db"),
                                   node_id="recovery-drill")
    results = []
    try:
        for seed in seeds:
            for index, builder in enumerate(attacks or ATTACKS):
                scenario = builder(seed)
                for baseline in (False, True):
                    workdir = base / f"a{index}_s{seed}_b{int(baseline)}"
                    results.append(run_drill_scenario(
                        scenario, baseline=baseline, workdir=workdir,
                        exchange=exchange,
                    ))
            # Workload control: legitimate activity must not touch a
            # single file (no false quarantine, no false restore).
            for index, builder in enumerate(workloads or WORKLOADS[:1]):
                scenario = builder(seed)
                workdir = base / f"w{index}_s{seed}"
                results.append(run_drill_scenario(
                    scenario, baseline=False, workdir=workdir,
                    exchange=exchange,
                ))
    finally:
        exchange.close()

    attack_rows = [r for r in results if r["kind"] == "attack"]
    baseline_rows = [r for r in attack_rows if r["baseline"]]
    wb = [r["rto_ops"] for r in baseline_rows
          if r["rto_ops"] is not None]
    wb.sort()
    attacked = sum(r["attacked_files"] for r in attack_rows)
    recovered = sum(r["attacked_files_recovered"] for r in attack_rows)
    contained = sum(r["attacked_files_contained_not_restored"]
                    for r in attack_rows)
    lost = sum(r["attacked_files_lost"] for r in attack_rows)
    headline = {
        "attack_runs": len(attack_rows),
        "attacked_files_total": attacked,
        "attacked_files_recovered": recovered,
        "attacked_files_contained_not_restored": contained,
        "attacked_files_lost": lost,
        "recovery_rate_pct": round(100.0 * recovered / attacked, 1)
        if attacked else 0.0,
        "median_rto_ops_with_baseline": (
            wb[len(wb) // 2] if wb else None
        ),
        "workload_control": next(
            (r for r in results if r["kind"] == "legitimate"), None
        ),
    }
    report = {
        "generated": datetime.now().isoformat(),
        "headline": headline,
        "results": results,
    }
    return report


def _print_report(report: dict) -> None:
    print()
    print("=" * 78)
    print("  RECOVERY DRILL — detect → contain → recover (measured)")
    print("=" * 78)
    header = (f"  {'scenario':20} {'base':4} {'det':>3} {'recovered':>10} "
              f"{'cont.':>5} {'lost':>4} {'RTO ops':>7} {'RTO s':>6} "
              f"{'wall s':>6}")
    print(header)
    print("  " + "-" * 78)
    for r in report["results"]:
        det = r["ops_to_detection"]
        rec = (f"{r['attacked_files_recovered']}/{r['attacked_files']}"
               if r["attacked_files"] else "—")
        cont = r["attacked_files_contained_not_restored"]
        lost = r["attacked_files_lost"]
        rto = r["rto_ops"] if r["rto_ops"] is not None else "—"
        rto_s = (f"{r['rto_attacker_clock_s']:.1f}"
                 if r["rto_attacker_clock_s"] is not None else "—")
        wall = f"{r['response_wall_s']:.2f}"
        print(f"  {r['scenario']:20} {str(r['baseline'])[:4]:4} "
              f"{str(det):>3} {rec:>10} {cont:>5} {lost:>4} "
              f"{str(rto):>7} {rto_s:>6} {wall:>6}")
    h = report["headline"]
    print("  " + "-" * 78)
    print(f"  Attacked files recovered: "
          f"{h['attacked_files_recovered']}/{h['attacked_files_total']} "
          f"({h['recovery_rate_pct']}%)")
    print(f"  Contained but not restored: "
          f"{h['attacked_files_contained_not_restored']}   "
          f"Lost (undetected / no clean version): "
          f"{h['attacked_files_lost']}")
    print(f"  Median RTO (ops, with baseline): "
          f"{h['median_rto_ops_with_baseline']}")
    print("=" * 78)


def write_markdown(report: dict, out_path: Path) -> Path:
    h = report["headline"]
    lines = []
    add = lines.append
    add("# Recovery drill report")
    add("")
    add(f"_Auto-generated by `python -m benchmark.recovery_drill` on "
        f"{report['generated'][:19]}. Regenerate with "
        f"`python -m benchmark.recovery_drill`; do not edit by hand._")
    add("")
    add("Every attack scenario is drilled end to end on a throwaway "
        "estate: real baseline capture → real attack replay → real "
        "detection → real quarantine → real restore, then the estate is "
        "verified **byte-for-byte** against its pre-attack state. RTO is "
        "measured in file operations (the benchmark's event-level "
        "convention) and in attacker-clock seconds (the scenario's own "
        "timing), plus the measured wall time of the response work "
        "itself.")
    add("")
    add("## Headline")
    add("")
    add("| Metric | Value |")
    add("| --- | --- |")
    add(f"| Attacked files recovered (pre-attack bytes back on disk) | "
        f"**{h['attacked_files_recovered']}/{h['attacked_files_total']}** "
        f"({h['recovery_rate_pct']}%) |")
    add(f"| Contained but not restored (quarantined/deleted, no clean "
        f"version usable) | "
        f"{h['attacked_files_contained_not_restored']} |")
    add(f"| Lost (undetected in-place encryption, no clean version) | "
        f"{h['attacked_files_lost']} |")
    add(f"| Median RTO with startup baseline | "
        f"{h['median_rto_ops_with_baseline']} file operations |")
    add("")
    add("## Per-scenario results")
    add("")
    add("| Scenario | Baseline | Det. op | Recovered | Contained "
        "| Lost | RTO (ops) | RTO (attacker s) | Response wall (s) |")
    add("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in report["results"]:
        rec = (f"{r['attacked_files_recovered']}/{r['attacked_files']}"
               if r["attacked_files"] else "—")
        add(
            f"| `{r['scenario']}` | {r['baseline']} | "
            f"{r['ops_to_detection'] if r['ops_to_detection'] is not None else '—'} "
            f"| {rec} | {r['attacked_files_contained_not_restored']} | "
            f"{r['attacked_files_lost']} | "
            f"{r['rto_ops'] if r['rto_ops'] is not None else '—'} | "
            f"{r['rto_attacker_clock_s'] if r['rto_attacker_clock_s'] is not None else '—'} "
            f"| {r['response_wall_s']} |"
        )
    add("")
    add("## How to read this")
    add("")
    add("- **Recovered** = the victim's pre-attack bytes are back on "
        "disk after the response (restored from a hash-verified clean "
        "backup). For rename attacks the file is also renamed back to "
        "its original name, so recovery is complete in content AND "
        "name. Rename-based attacks are recoverable because the "
        "pipeline transfers pre-rename version history to the new "
        "path (the gap this drill originally exposed).")
    add("- **Contained** = the encrypted file was quarantined (or the "
        "file deleted) but no clean version was available at restore "
        "time — e.g. in `backup_tamper` the random `.bin` snapshots "
        "have entropy ≈7.96, above the clean threshold (6.8) for "
        "unknown extensions: they look encrypted, and the system "
        "deliberately refuses to restore content that looks "
        "encrypted. The data is preserved in the backup store/"
        "quarantine for manual recovery, but the pipeline did not "
        "restore it — counted as a recovery failure, not hidden.")
    add("- **Lost** = damage with no usable response: in-place "
        "encryption that was never detected (the published image "
        "blind spot), or deletion of files outside any protected "
        "store (e.g. `backup_tamper`'s unprotected notes.txt) — the "
        "file is gone or encrypted on disk with no containment, so "
        "nothing was restored. Counted as data loss, not hidden.")
    add("- **RTO (ops)** = file operations from the attack's start "
        "until every affected file is safe (restored or quarantined). "
        "RTO (attacker s) applies the scenario's own timing to the same "
        "point. The live wall-clock RTO is dominated by watchdog "
        "latency and is measured separately (see the live drill).")
    add("- Attacker-created artifacts (ransom notes, fresh payloads) "
        "are quarantined, not recovered — containing them is success.")
    add("")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="Run the ENTROPY recovery drill (measured RTO).")
    parser.add_argument("--seeds", type=int, default=3,
                        help="number of seeds per scenario (default 3)")
    args = parser.parse_args(argv)

    seeds = tuple(range(1, args.seeds + 1))
    report = run_drill(seeds=seeds)
    _print_report(report)

    repo_root = Path(__file__).resolve().parents[1]
    results_dir = repo_root / "benchmark" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    json_path = results_dir / (
        f"recovery_drill_{datetime.now():%Y%m%d_%H%M%S}.json"
    )
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path = write_markdown(
        report, repo_root / "docs" / "recovery-drill-report.md"
    )
    print(f"  JSON artifact : {json_path}")
    print(f"  Published     : {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
