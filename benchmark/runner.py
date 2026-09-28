# ============================================================
# ENTROPY benchmark — simulation + reporting
# benchmark/runner.py
#
# Drives the REAL detection chain (EntropyAnalyzer +
# make_decision from the pipeline runner) over each scenario
# with a deterministic simulated clock, then publishes:
#   - benchmark/results/benchmark_<timestamp>.json  (artifact)
#   - docs/benchmark-report.md                      (published)
#
# Detection is measured at the file-event level: a scenario is
# "detected" when the first operation triggers action >= ALERT.
# A quarantine (action 3) on a legitimate file is the critical
# failure metric — it means data was destroyed by the defender.
# ============================================================

import json
import os
import shutil
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import config
from blockchain.fingerprint_exchange import FingerprintExchange
from entropy.entropy_calculator import EntropyAnalyzer
from monitoring.defense_guard import collect_threat_flags
from monitoring.pipeline_runner import DecisionEngine  # noqa: F401
from benchmark.scenarios import ATTACKS, WORKLOADS

ACTION_NAMES = {0: "IGNORE", 1: "ALERT", 2: "TERMINATE", 3: "QUARANTINE"}


class _Clock:
    """Deterministic event-rate tracker mirroring SpeedTracker's
    semantics (count of events in a trailing window / window)."""

    def __init__(self, window: float = 10.0):
        self.window = window
        self.t = 0.0
        self._events = []

    def advance(self, dt: float) -> None:
        self.t += dt

    def record(self) -> None:
        self._events.append(self.t)
        cutoff = self.t - self.window
        while self._events and self._events[0] < cutoff:
            self._events.pop(0)

    def rate(self) -> float:
        cutoff = self.t - self.window
        recent = [t for t in self._events if t >= cutoff]
        return len(recent) / self.window


def simulate_scenario(scenario, *, baseline: bool, root: Path,
                      exchange=None, engine=None) -> dict:
    """Run one scenario through the real detection chain.

    *engine* is an optional DecisionEngine: when given, decisions come
    from that engine (the exact path the live pipeline uses). When
    omitted, the rules path still goes through a DecisionEngine
    (rule engine + cross-file campaign escalation) — never the bare
    per-file function — so the battery measures the product's actual
    decision chain."""
    if engine is None:
        engine = DecisionEngine(engine="rules")
    else:
        # A shared engine (the RF comparison battery) must get a fresh
        # campaign window per scenario so scenarios cannot
        # cross-contaminate each other.
        engine.reset()
    # Reset the victim root and lay down the initial estate.
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in scenario.initial_files:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    analyzer = EntropyAnalyzer()

    # "startup baseline" mode models the production pipeline
    # snapshotting the protected estate when the monitor starts.
    if baseline:
        for rel, _content in scenario.initial_files:
            analyzer.analyze(str(root / rel))

    clock = _Clock()
    ops_record = []
    first_detection_op = None
    peak_score = 0.0
    protected_roots = tuple(
        str(root / p) for p in getattr(scenario, "protected_paths", ())
    )

    for i, op in enumerate(scenario.ops):
        clock.advance(op.delay_before)
        old_path = root / op.rel_path
        if op.kind == "create":
            old_path.parent.mkdir(parents=True, exist_ok=True)
            old_path.write_bytes(op.content)
            target = old_path
            ext_changed = False
        elif op.kind == "modify":
            old_path.write_bytes(op.content)
            target = old_path
            ext_changed = False
        elif op.kind == "rename":
            old_path.write_bytes(op.content)          # encrypt in place
            new_path = root / op.new_path
            os.replace(str(old_path), str(new_path))  # then disguise
            analyzer.transfer_history(str(old_path), str(new_path))
            target = new_path
            _, s_ext = os.path.splitext(op.rel_path)
            _, d_ext = os.path.splitext(op.new_path or "")
            ext_changed = s_ext.lower() != d_ext.lower()
        elif op.kind == "delete":
            if old_path.exists():
                old_path.unlink()
            target = old_path
            ext_changed = False
        else:
            raise ValueError(f"Unknown op kind: {op.kind}")

        # Mirror the real monitor's event vocabulary exactly.
        event_type = {
            "create": "CREATED",
            "modify": "MODIFIED",
            "rename": "RENAMED",
            "delete": "DELETED",
        }[op.kind]

        result = analyzer.analyze(str(target))
        clock.record()
        rate = round(clock.rate(), 2)

        event = {
            "event_id": f"bench-{scenario.name}-{i}",
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "file_path": str(target),
            "file_extension": result.get("file_extension", ""),
            "file_hash": result.get("file_hash", ""),
            "entropy_overall": result.get("entropy_overall", 0.0),
            "entropy_delta": result.get("entropy_delta", 0.0),
            "threat_score": result.get("threat_score", 0.0),
            "events_per_sec": rate,
            "is_suspicious_speed": rate >= config.FILES_PER_SECOND_THRESHOLD,
            "ext_changed": ext_changed,
            # Structural fingerprint — the same two signals the live
            # monitor forwards (EventPipeline._merge_event). Without
            # them the benchmark could not exercise the rule that
            # contains an encrypted file renamed to a never-seen
            # extension on first sight.
            "chi2_uniformity": result.get("chi2_uniformity"),
            "chi2_tail": result.get("chi2_tail"),
            "magic_ok": result.get("magic_ok", True),
            "file_size": result.get("file_size"),
        }
        # Identical hard-confirmation signal collection as the live
        # pipeline (EventPipeline._merge_event). The benchmark passes an
        # isolated exchange so it neither reads nor pollutes the real
        # federated registry.
        try:
            event.update(collect_threat_flags(
                event, protected_roots or None, exchange=exchange,
            ))
        except Exception:
            pass
        # The campaign layer may escalate this event to quarantine AND
        # return the earlier campaign files it sweeps. In the live
        # pipeline the sweep runs as real responses; at the run level
        # the escalated action below is what the report measures.
        action = int(engine.decide(event)["action"])

        peak_score = max(peak_score, float(result.get("threat_score") or 0.0))
        if action >= config.ACTION_ALERT and first_detection_op is None:
            first_detection_op = i

        ops_record.append({
            "op": i,
            "event_type": event_type,
            "file": os.path.relpath(str(target), str(root)),
            "entropy": round(float(result.get("entropy_overall") or 0.0), 3),
            "delta": round(float(result.get("entropy_delta") or 0.0), 3),
            "score": round(float(result.get("threat_score") or 0.0), 2),
            "rate": rate,
            "action": action,
        })

    max_action = max((r["action"] for r in ops_record), default=0)
    detected = first_detection_op is not None
    return {
        "scenario": scenario.name,
        "kind": scenario.kind,
        "description": scenario.description,
        "engine": engine.engine_name() if engine is not None else "rules",
        "baseline": baseline,
        "ops": len(ops_record),
        "detected": detected,
        "first_detection_op": first_detection_op,
        "ops_to_detection": (first_detection_op + 1) if detected else None,
        "max_action": max_action,
        "max_action_name": ACTION_NAMES[max_action],
        "peak_score": peak_score,
        "ops_record": ops_record,
    }


def run_battery(seeds=(1, 2, 3),
                attacks=None, workloads=None, engine=None) -> list:
    """Run the full battery. Attacks in both baseline modes;
    workloads without a baseline (the harder false-positive case).
    *engine* optionally routes every decision through a DecisionEngine
    (e.g. the Random Forest) instead of the bare rule function."""
    runs = []
    tmp_base = Path(tempfile.mkdtemp(prefix="entropy_bench_"))
    # Isolated, per-battery exchange: the benchmark must be a closed,
    # reproducible system. No battery reads or writes the real registry.
    exchange = FingerprintExchange(
        str(tmp_base / "exchange.db"), node_id="benchmark-battery"
    )
    try:
        for seed in seeds:
            for index, builder in enumerate(attacks or ATTACKS):
                scenario = builder(seed)
                for baseline in (False, True):
                    root = tmp_base / f"a{index}_s{seed}_b{int(baseline)}"
                    runs.append(simulate_scenario(
                        scenario, baseline=baseline, root=root,
                        exchange=exchange, engine=engine,
                    ))
            for index, builder in enumerate(workloads or WORKLOADS):
                scenario = builder(seed)
                root = tmp_base / f"w{index}_s{seed}"
                runs.append(simulate_scenario(
                    scenario, baseline=False, root=root,
                    exchange=exchange, engine=engine,
                ))
    finally:
        exchange.close()
        shutil.rmtree(tmp_base, ignore_errors=True)
    return runs


def summarize(runs: list) -> dict:
    attack_runs = [r for r in runs if r["kind"] == "attack"]
    legit_runs = [r for r in runs if r["kind"] == "legitimate"]

    by_attack = defaultdict(list)
    for r in attack_runs:
        by_attack[r["scenario"]].append(r)
    by_workload = defaultdict(list)
    for r in legit_runs:
        by_workload[r["scenario"]].append(r)

    attack_summary = {}
    for name, rows in by_attack.items():
        detected = [r for r in rows if r["detected"]]
        latencies = sorted(r["ops_to_detection"] for r in detected)
        attack_summary[name] = {
            "runs": len(rows),
            "detected": len(detected),
            "detection_rate": round(len(detected) / len(rows) * 100, 1),
            "quarantined_runs": sum(
                1 for r in rows if r["max_action"] == 3
            ),
            "median_ops_to_detection": (
                latencies[len(latencies) // 2] if latencies else None
            ),
        }

    workload_summary = {}
    for name, rows in by_workload.items():
        alerts = [r for r in rows if r["max_action"] >= 1]
        workload_summary[name] = {
            "runs": len(rows),
            "alerted_runs": len(alerts),
            "false_quarantine_runs": sum(
                1 for r in rows if r["max_action"] == 3
            ),
            "false_positive_rate": round(len(alerts) / len(rows) * 100, 1),
        }

    detected_total = sum(1 for r in attack_runs if r["detected"])
    alerted_total = sum(1 for r in legit_runs if r["max_action"] >= 1)
    false_quarantines = sum(1 for r in legit_runs if r["max_action"] == 3)

    blind_spots = sorted(
        name for name, s in attack_summary.items()
        if s["detection_rate"] == 0.0
    )

    return {
        "engine": runs[0].get("engine", "rules") if runs else "rules",
        "generated_at": datetime.now().isoformat(),
        "config": {
            "entropy_threshold": config.ENTROPY_THRESHOLD,
            "entropy_delta_threshold": config.ENTROPY_DELTA_THRESHOLD,
            "files_per_second_threshold": config.FILES_PER_SECOND_THRESHOLD,
        },
        "summary": {
            "attack_runs": len(attack_runs),
            "attacks_detected": detected_total,
            "detection_rate": (
                round(detected_total / len(attack_runs) * 100, 1)
                if attack_runs else 0.0
            ),
            "legitimate_runs": len(legit_runs),
            "legitimate_alerted": alerted_total,
            "false_positive_rate": (
                round(alerted_total / len(legit_runs) * 100, 1)
                if legit_runs else 0.0
            ),
            "false_quarantines": false_quarantines,
        },
        "attacks": attack_summary,
        "workloads": workload_summary,
        "known_blind_spots": blind_spots,
        "runs": runs,
    }


# ── Report writers ──────────────────────────────────────────

def _pct(x: float) -> str:
    return f"{x:.1f}%"


def write_json(summary: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out_dir / f"benchmark_{stamp}.json"
    with path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def write_markdown(summary: dict, out_path: Path) -> Path:
    s = summary["summary"]
    lines = []
    add = lines.append

    add("# Detection benchmark report")
    add("")
    add(f"_Auto-generated by `python -m benchmark` on "
        f"{summary['generated_at'][:19]}. Regenerate with "
        f"`python -m benchmark`; do not edit by hand._")
    add("")
    add(f"Engine: **{summary['engine']}** "
        f"(entropy threshold {summary['config']['entropy_threshold']}, "
        f"delta threshold {summary['config']['entropy_delta_threshold']}, "
        f"speed threshold {summary['config']['files_per_second_threshold']}/s). "
        f"Detection is measured at file-event level: a scenario is detected "
        f"when the first operation triggers an alert or higher.")
    add("")
    add("## Headline numbers")
    add("")
    add("| Metric | Value |")
    add("| --- | --- |")
    add(f"| Attack detection rate | **{_pct(s['detection_rate'])}** "
        f"({s['attacks_detected']}/{s['attack_runs']} runs) |")
    add(f"| False-positive rate (legitimate workloads alerted) | "
        f"{_pct(s['false_positive_rate'])} "
        f"({s['legitimate_alerted']}/{s['legitimate_runs']} runs) |")
    add(f"| **False quarantines** (legitimate files destroyed) | "
        f"**{s['false_quarantines']}** |")
    add("")
    add("> A *false quarantine* is the critical safety metric: the defender")
    add("> destroyed a legitimate file. Alerts on benign-but-busy activity")
    add("> (e.g. a git burst) are reported separately and are not data loss.")
    add("")
    add("## Attack scenarios (run with and without a startup baseline)")
    add("")
    add("| Scenario | Detected | Quarantined | Median ops to detect | Notes |")
    add("| --- | --- | --- | --- | --- |")
    notes = {
        "burst_encoder": "speed + extension + range",
        "slow_crawler": "extension + range only",
        "polymorphic": "randomized order, extensions, timing",
        "baseline_first": "clean edit then encryption (delta)",
        "silent_unknown_ext": "no prior history, unknown exts",
        "image_blindspot": "in-range entropy, no rename — see blind spots",
        "note_dropper": "ransom note is the only signal (blind-spot payload)",
        "backup_tamper": "backup store deleted — defense tamper signal",
    }
    for name, row in summary["attacks"].items():
        med = row["median_ops_to_detection"]
        add(f"| `{name}` | {row['detected']}/{row['runs']} "
            f"({_pct(row['detection_rate'])}) | "
            f"{row['quarantined_runs']}/{row['runs']} | "
            f"{med if med is not None else '—'} | "
            f"{notes.get(name, '')} |")
    add("")
    add("## Legitimate workloads (no baseline — the harder FP case)")
    add("")
    add("| Workload | Alerted runs | False quarantines | FP rate |")
    add("| --- | --- | --- | --- |")
    for name, row in summary["workloads"].items():
        add(f"| `{name}` | {row['alerted_runs']}/{row['runs']} | "
            f"{row['false_quarantine_runs']} | "
            f"{_pct(row['false_positive_rate'])} |")
    add("")
    if summary["known_blind_spots"]:
        add("## Known blind spots (honest limitations)")
        add("")
        for name in summary["known_blind_spots"]:
            add(f"- `{name}`: 0% detection in this battery. In-place "
                f"encryption of already-high-entropy media (images, video) "
                f"without a rename leaves entropy within the file type's "
                f"normal range — the encrypted payload is indistinguishable "
                f"from native compressed content by entropy alone. "
                f"Candidates for future signals: magic-byte validation, "
                f"partial-encryption (front) detection, and size anomalies.")
        add("")
    fx = summary.get("federated_exchange")
    if fx and "error" not in fx:
        add("## Federated exchange (multi-node simulation)")
        add("")
        add("Four simulated tenants share one threat-fingerprint registry "
            "and drive the real decision + response chain. A fingerprint "
            f"contained by >= {fx.get('confirm_threshold', 2)} independent "
            "nodes auto-confirms; a single node's sighting only "
            "corroborates and can never quarantine alone (the poison-node "
            "defence).")
        add("")
        add("| Metric | Value |")
        add("| --- | --- |")
        add(f"| Known-threat recall at first sight "
            f"(confirmed, auto-quarantine) | "
            f"**{fx['known_threat_recall_first_sight']}** "
            f"({fx['known_threat_recall_pct']}%) |")
        add(f"| Single-sighting restraint "
            f"(recognised, NOT over-quarantined) | "
            f"{fx['single_sighting_restraint']} "
            f"({fx['single_sighting_restraint_pct']}%) |")
        add(f"| Workload false positives "
            f"(legitimate files alerted) | "
            f"{fx['workload_false_positives']}/{fx['workload_runs']} |")
        add("")
        add("Headline: a fresh node with zero local history quarantined a "
            "locally-ambiguous file (score 40, alert-only) purely on "
            "cross-node memory. Run "
            "`python -m benchmark.exchange_simulation`; see "
            "`docs/federated-exchange.md`.")
        add("")
    add("## Recovery drill (detect → contain → recover)")
    add("")
    add("Detection above is only half the defence. A separate drill "
        "measures the full recovery loop end to end on a throwaway "
        "estate: real startup baseline → real attack replay → real "
        "detection → real quarantine → real restore, then verifies the "
        "estate **byte-for-byte** against its pre-attack state and "
        "reports RTO (in file operations and attacker-clock seconds) "
        "alongside an honest recovery rate (recovered vs "
        "contained-but-not-restored vs lost).")
    add("")
    add("Run `python -m benchmark.recovery_drill`; the published "
        "numbers and the honest limitations live in "
        "`docs/recovery-drill-report.md`.")
    add("")
    rf = summary.get("rf_classifier")
    if rf and "error" not in rf:
        rfs = rf["summary"]
        rs = summary["summary"]
        add("## Second classifier (Random Forest + SHAP)")
        add("")
        add("The identical battery, driven through the Random Forest "
            "engine (the calibrated, explainable 0–100 risk score). "
            "The RF is trained on synthetic, seeded data; this table is "
            "the measured comparison against the deterministic rule "
            "engine on the same scenarios.")
        add("")
        add("| Metric | Rules | Random Forest |")
        add("| --- | --- | --- |")
        add(f"| Attack detection | "
            f"**{rs['attacks_detected']}/{rs['attack_runs']}** "
            f"({rs['detection_rate']}%) | "
            f"**{rfs['attacks_detected']}/{rfs['attack_runs']}** "
            f"({rfs['detection_rate']}%) |")
        add(f"| Legit FP rate (workloads alerted) | "
            f"{rs['legitimate_alerted']}/{rs['legitimate_runs']} "
            f"({rs['false_positive_rate']}%) | "
            f"{rfs['legitimate_alerted']}/{rfs['legitimate_runs']} "
            f"({rfs['false_positive_rate']}%) |")
        add(f"| **False quarantines** | "
            f"**{rs['false_quarantines']}** | "
            f"**{rfs['false_quarantines']}** |")
        add("")
        add("Per-scenario (detected/runs):")
        add("")
        add("| Scenario | Rules | RF |")
        add("| --- | --- | --- |")
        for name in summary["attacks"]:
            add(f"| `{name}` | "
                f"{summary['attacks'][name]['detected']}/"
                f"{summary['attacks'][name]['runs']} | "
                f"{rf['attacks'].get(name, {}).get('detected', '—')}/"
                f"{rf['attacks'].get(name, {}).get('runs', '—')} |")
        add("")
        add("Per-workload (alerted/runs | false quarantines):")
        add("")
        add("| Workload | Rules | RF |")
        add("| --- | --- | --- |")
        for name in summary["workloads"]:
            add(f"| `{name}` | "
                f"{summary['workloads'][name]['alerted_runs']}/"
                f"{summary['workloads'][name]['runs']} "
                f"(fq {summary['workloads'][name]['false_quarantine_runs']})"
                f" | "
                f"{rf['workloads'].get(name, {}).get('alerted_runs', '—')}/"
                f"{rf['workloads'].get(name, {}).get('runs', '—')} "
                f"(fq {rf['workloads'].get(name, {}).get('false_quarantine_runs', 0)}) |")
        add("")
        fq_workloads = [
            f"`{name}` ({rf['workloads'][name]['false_quarantine_runs']}"
            f"/{rf['workloads'][name]['runs']})"
            for name in rf["workloads"]
            if rf["workloads"][name]["false_quarantine_runs"]
        ]
        verdict = (
            f"The Random Forest is a **high-recall, opt-in** engine: it "
            f"detects {rfs['detection_rate']}% of attacks (closing the "
            f"image blind spot the rules publish as a limitation) but "
            f"false-quarantines "
            f"{rfs['false_quarantines']} legitimate run(s)"
            f"{' — ' + ', '.join(fq_workloads) if fq_workloads else ''} — "
            f"so it does **not** meet the 0-false-quarantine safety bar "
            f"and is **not the default**. The rule engine stays the "
            f"default; select the RF explicitly with "
            f"`ENTROPY_AI_ENGINE=rf`."
        )
        add(verdict)
        add("")
        add("Per-incident explanations (SHAP) name the top features "
            "that drove each decision — e.g. `entropy_delta +risk, "
            "in_normal_range -risk`. Train: `python -m ai.train_rf`.")
        add("")
    elif rf and "error" in rf:
        add("## Second classifier (Random Forest + SHAP)")
        add("")
        add(f"Random Forest second classifier not active: {rf['error']}. "
            "The rule-engine numbers above are the published result.")
        add("")
    add("## Method")
    add("")
    add("- Deterministic: all content and timing are seeded "
        "(`random.Random`); rerunning produces identical results.")
    add("- The real detection chain is exercised: "
        "`entropy.entropy_calculator.EntropyAnalyzer` + "
        "`monitoring.pipeline_runner.DecisionEngine` (the exact decision "
        "layer the live pipeline uses) — per-file scoring plus the "
        "cross-file campaign escalator, which confirms a ransomware "
        "campaign when ≥2 distinct files show encrypted-data signatures "
        "within 15s — with the monitor's 10-second event-rate window "
        "simulated deterministically. Each scenario gets a fresh "
        "decision engine so scenarios cannot cross-contaminate.")
    add("- `baseline` = the production startup snapshot of the protected "
        "estate; `no baseline` = the estate existed before monitoring with "
        "no snapshot (the worst case).")
    add("- Detection latency is counted in file operations (event-level), "
        "not wall-clock seconds.")
    add("- The Random Forest comparison reuses the identical scenarios, "
        "seeds, and event stream; only the decision engine differs "
        "(`DecisionEngine(engine='rf')`). The RF is trained on seeded "
        "synthetic data (`python -m ai.train_rf`), so its numbers are a "
        "measured model-vs-rules comparison, not a claim that "
        "synthetic training predicts real-world prevalence.")
    add("")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def _rf_battery_summary(seeds) -> dict:
    """Run the identical battery through the Random Forest engine and
    return a compact, comparable summary. Returns {"error": ...} when
    the RF is not trained / scikit-learn is missing — the rules battery
    still publishes either way."""
    from monitoring.pipeline_runner import DecisionEngine
    try:
        engine = DecisionEngine(engine="rf")
        if engine.engine_name() != "rf":
            return {"error": ("Random Forest not active "
                              "(train with: python -m ai.train_rf)")}
        rf_runs = run_battery(seeds=seeds, engine=engine)
        s = summarize(rf_runs)
        return {
            "engine": "rf",
            "summary": s["summary"],
            "attacks": s["attacks"],
            "workloads": s["workloads"],
            "known_blind_spots": s["known_blind_spots"],
        }
    except Exception as exc:
        return {"error": str(exc)}


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="Run the ENTROPY detection benchmark battery."
    )
    parser.add_argument("--seeds", type=int, default=3,
                        help="number of seeds per scenario (default 3)")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print the table")
    args = parser.parse_args(argv)

    seeds = tuple(range(1, args.seeds + 1))
    runs = run_battery(seeds=seeds)
    summary = summarize(runs)

    # Federated-exchange metrics: run the multi-node simulation in an
    # isolated temp store so the published report carries the
    # known-threat recall numbers alongside the detection battery.
    from benchmark.exchange_simulation import run_simulation
    sim_dir = Path(tempfile.mkdtemp(prefix="exchange_bench_"))
    try:
        sim = run_simulation(base_dir=str(sim_dir))
        summary["federated_exchange"] = sim["recall_metrics"] | {
            "confirm_threshold": sim["confirm_threshold"],
        }
    except Exception as exc:  # the detection battery still publishes
        summary["federated_exchange"] = {"error": str(exc)}
    finally:
        shutil.rmtree(sim_dir, ignore_errors=True)

    # Second classifier (Random Forest + SHAP): the identical battery
    # through the RF engine, published side by side with the rules.
    summary["rf_classifier"] = _rf_battery_summary(seeds)

    repo_root = Path(__file__).resolve().parents[1]
    json_path = write_json(summary, repo_root / "benchmark" / "results")
    md_path = write_markdown(summary, repo_root / "docs" / "benchmark-report.md")

    s = summary["summary"]
    if not args.quiet:
        print("=" * 64)
        print("  ENTROPY detection benchmark")
        print("=" * 64)
        print(f"  Attack detection   : {s['attacks_detected']}/"
              f"{s['attack_runs']} ({s['detection_rate']}%)")
        print(f"  Legit FP rate      : {s['legitimate_alerted']}/"
              f"{s['legitimate_runs']} ({s['false_positive_rate']}%)")
        print(f"  False quarantines  : {s['false_quarantines']}")
        fx = summary.get("federated_exchange")
        if fx and "error" not in fx:
            print(f"  Known-threat recall: "
                  f"{fx['known_threat_recall_first_sight']} "
                  f"({fx['known_threat_recall_pct']}%)")
        print("-" * 64)
        print("  Attacks (detected/runs | quarantined | median ops):")
        for name, row in summary["attacks"].items():
            print(f"    {name:22} {row['detected']}/{row['runs']}"
                  f"  |  {row['quarantined_runs']}/{row['runs']}"
                  f"  |  {row['median_ops_to_detection'] or '-'}")
        print("  Workloads (alerted/runs | false quarantines):")
        for name, row in summary["workloads"].items():
            print(f"    {name:22} {row['alerted_runs']}/{row['runs']}"
                  f"  |  {row['false_quarantine_runs']}")
        rf = summary.get("rf_classifier")
        if rf and "error" not in rf:
            rfs = rf["summary"]
            print("-" * 64)
            print("  Random Forest second classifier (same battery):")
            print(f"    Attack detection   : {rfs['attacks_detected']}/"
                  f"{rfs['attack_runs']} ({rfs['detection_rate']}%)")
            print(f"    Legit FP rate      : "
                  f"{rfs['legitimate_alerted']}/{rfs['legitimate_runs']} "
                  f"({rfs['false_positive_rate']}%)")
            print(f"    False quarantines  : {rfs['false_quarantines']}")
        elif rf and "error" in rf:
            print("-" * 64)
            print(f"  Random Forest second classifier: {rf['error']}")
        if summary["known_blind_spots"]:
            print("-" * 64)
            print(f"  Known blind spots: {', '.join(summary['known_blind_spots'])}")
        print("=" * 64)
        print(f"  JSON artifact : {json_path}")
        print(f"  Published     : {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
