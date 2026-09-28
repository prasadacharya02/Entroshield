# monitoring/pipeline_runner.py
# ============================================================
# ENTROPY - Full Pipeline Runner
#
# FLOW:
# FileMonitor → EventPipeline → AI Decision → Response
#                                    ↓
#                             Blockchain Log
#                                    ↓
#                             Dashboard DB
# ============================================================

import os
import sys
import time
import json
import hashlib
import logging
from collections import deque
from datetime import datetime
from threading import Thread

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

from monitoring.event_pipeline   import EventPipeline
from blockchain.connector        import BlockchainConnector
from response.response_module     import FileQuarantine, ProcessTerminator
from response.backup_manager     import BackupManager
from storage.hashing             import sha256_file
from response.forensic_report    import generate_report
from response.defender_actions   import get_registry as defender_actions
from storage.database             import init_db as initialize_database
from storage.database             import connect as connect_database
from storage.database             import write_pipeline_heartbeat

# Logger must exist before the optional DQN import: the fallback path logs
# missing PyTorch/model errors during module import.
log = logging.getLogger("PipelineRunner")

# ── Optional DQN decision engine ────────────────────────
# The DQN model is the trained AI. If torch / the weights are
# unavailable, we transparently fall back to the rule-based
# engine below so the pipeline never fails to start.
try:
    from ai.dqn_model import DQNAgent
    _DQN_AVAILABLE = True
except Exception as _dqn_err:
    DQNAgent = None
    _DQN_AVAILABLE = False
    log.warning(f"[RUNNER] DQN unavailable ({_dqn_err}) — "
                f"using rule-based fallback")

# ── Optional Random Forest second classifier ────────────
# A calibrated, explainable risk score (scikit-learn + SHAP).
# Optional exactly like the DQN: no scikit-learn / no trained
# weights → the rule engine decides.
try:
    from ai.rf_model import RFEngine
    _RF_AVAILABLE = True
except Exception as _rf_err:
    RFEngine = None
    _RF_AVAILABLE = False
    log.warning(f"[RUNNER] Random Forest unavailable ({_rf_err}) — "
                f"using rule-based fallback")

# ── Logging ───────────────────────────────────────────────
logging.basicConfig(
    level    = logging.INFO,
    format   = "%(asctime)s [%(levelname)s] %(message)s",
    handlers = [
        logging.FileHandler(config.LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

log = logging.getLogger("PipelineRunner")

# ── Action Labels ──────────────────────────────────────────
ACTION_LABELS = {
    config.ACTION_IGNORE              : "IGNORED",
    config.ACTION_ALERT               : "ALERTED",
    config.ACTION_TERMINATE           : "TERMINATED",
    config.ACTION_TERMINATE_QUARANTINE: "TERMINATED+QUARANTINED",
}


# ============================================================
# DATABASE
# ============================================================

def init_db():
    """Create or migrate the shared events database schema."""
    return initialize_database()


# ============================================================
# FEDERATED THREAT-FINGERPRINT EXCHANGE
# ============================================================

# The node's shared view of the exchange. The canonical lazy singleton
# lives in blockchain.fingerprint_exchange so the flag collection in
# defense_guard and the response sharing here use the same store.
from blockchain.fingerprint_exchange import get_exchange  # noqa: F401


def _table_columns(conn, table: str) -> set:
    """Names of the columns that actually exist in *table*."""
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except Exception:
        return set()
    names = set()
    for row in rows:
        try:
            names.add(row["name"])
        except (TypeError, IndexError):
            names.add(row[1])
    return names


def save_to_db(conn, event, action, status, outcome=None, decision=None,
               restore_result=None):
    """Save a processed event to the SQLite database."""
    try:
        proc     = event.get("process") or {}
        pid      = proc.get("pid")      if isinstance(proc, dict) else None
        procname = proc.get("name", "unknown") if isinstance(proc, dict) else "unknown"
        # A best-effort guess must never name an innocent process in the
        # SOC: only a real attribution (open handle / verified identity)
        # is published under a name and a PID.
        if isinstance(proc, dict) and proc.get("attribution_source") in (
                "recent_process_guess", "none"):
            procname = "unattributed"
            pid = None
        outcome = outcome or status
        decision = decision or {}
        q_values = decision.get("q_values")
        columns = {
            "timestamp": event.get("timestamp", datetime.now().isoformat()),
            "file_path": event.get("file_path", ""),
            "event_type": event.get("event_type", ""),
            "entropy": event.get("entropy_overall") or 0.0,
            "entropy_delta": event.get("entropy_delta") or 0.0,
            "pid": pid,
            "process_name": procname,
            "action": action,
            "status": status,
            "requested_action": action,
            "outcome": outcome,
            "restore_result": restore_result,
            "dry_run": 1 if config.DRY_RUN else 0,
            "engine": decision.get("engine") or "rules",
            "confidence": float(decision.get("confidence") or 0.0),
            "explanation": decision.get("explanation") or "",
            "q_values": json.dumps(q_values) if q_values is not None else None,
            "threat_score": float(event.get("threat_score") or 0.0),
        }
        # Third-party callers (benchmarks, drills) may hold an older
        # events schema. Insert only the columns that exist so a
        # missing threat_score column cannot silently drop a record.
        present = _table_columns(conn, "events")
        if present:
            columns = {k: v for k, v in columns.items() if k in present}
        names = ", ".join(columns)
        marks = ",".join("?" for _ in columns)
        conn.execute(
            f"INSERT INTO events ({names}) VALUES ({marks})",
            tuple(columns.values()),
        )
        conn.commit()
    except Exception as e:
        log.error(f"[DB] Save failed: {e}")


# ============================================================
# DECISION ENGINE
# Rule-based for now — plug DQN here later
# ============================================================

def make_decision(event: dict) -> int:

    # ── Hard-confirmation signals ────────────────────────────
    # A dropped ransom note, an attacker destroying the recovery
    # capability (backup store / Shadow Copies / services), or a
    # fingerprint that >= EXCHANGE_CONFIRM_THRESHOLD *independent*
    # nodes have already contained as a confirmed threat, is a
    # confirmed incident on its own — no local signal required.
    if (event.get("ransom_note") or event.get("defense_tamper")
            or event.get("known_threat_confirmed")):
        return config.ACTION_TERMINATE_QUARANTINE

    entropy   = event.get("entropy_overall") or 0.0
    delta     = abs(event.get("entropy_delta") or 0.0)
    fps       = event.get("events_per_sec")   or 0.0
    score     = event.get("threat_score")     or 0.0
    ext_chg   = event.get("ext_changed",      False)
    hi_speed  = event.get("is_suspicious_speed", False)
    magic_ok  = event.get("magic_ok", True)
    chi2_val  = event.get("chi2_uniformity")
    chi2_tail = event.get("chi2_tail")
    chi2_best = None
    for v in (chi2_val, chi2_tail):
        if v is None: continue
        chi2_best = v if chi2_best is None else min(chi2_best, v)
    # For KNOWN extensions, a flat byte distribution (chi² < 350) combined
    # with high Shannon entropy is a structural ciphertext fingerprint
    # that does not exist in any legitimate file of the declared type.
    # For UNKNOWN extensions we cannot distinguish ciphertext from
    # arbitrary new binary formats, so chi² alone is only an alert-level
    # signal (never a quarantine trigger).
    extension = (event.get("file_extension") or "").lower()
    known_ext = extension in getattr(config, "MAGIC_SIGNATURES", set())
    # MAGIC_SIGNATURES lives in the entropy module; fall back to a
    # permissive "known" set of common extensions if it isn't exposed.
    if not known_ext:
        known_ext = extension in {
            ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".zip",
            ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".mp3",
            ".mp4", ".avi", ".mov", ".exe", ".dll", ".txt", ".csv", ".rtf",
            ".7z", ".rar", ".gz", ".tar",
        }
    # Threshold chosen empirically: AES-CTR / uniform random ciphertext
    # produces chi² ≈ 256 ± 50 (p-value ≈ 0.5, perfectly flat). Real
    # compressed media (JPEG/MP4/ZIP) sits at chi² ≥ 450 because of
    # Huffman tables and structural byte peaks. 300 sits between them.
    _CIPHERTEXT_CHI2 = 300.0
    ciphertext_struct = (
        chi2_best is not None and chi2_best < _CIPHERTEXT_CHI2
        and entropy >= 7.0 and known_ext
    )
    any_ciphertext_shape = (
        chi2_best is not None and chi2_best < _CIPHERTEXT_CHI2
        and entropy >= 7.0
    )
    magic_bad = (magic_ok is False) and entropy >= 7.0

    # A fingerprint seen by a SINGLE node is corroboration, not
    # confirmation: it weighs the score but can never quarantine
    # alone (a poisoned or buggy node must not be able to seed the
    # exchange into destroying clean files everywhere).
    if event.get("known_threat"):
        score = min(100.0, score + 25.0)

    # High entropy is not sufficient evidence: images, archives, videos and
    # encrypted user files are expected to be high entropy. Require a second
    # behavioral signal before taking a destructive action.
    delta_signal = delta >= config.ENTROPY_DELTA_THRESHOLD
    # For quarantine-corroboration, chi² uniformity is only meaningful
    # for KNOWN extensions (where a "flat byte distribution + H≥7.0"
    # cannot occur legitimately). For unknown extensions we cannot
    # distinguish a new binary format from ciphertext.
    corroborated = (ext_chg or hi_speed or delta_signal or magic_bad
                    or ciphertext_struct)

    # Strong score plus corroborating ransomware behavior. The response layer
    # still performs its independent process-safety checks.
    if score >= 70 and corroborated:
        return config.ACTION_TERMINATE_QUARANTINE

    # A hard structural-ciphertext fingerprint (invalid magic OR
    # statistically uniform bytes) is ransomware regardless of delta or
    # rename — there is no legitimate scenario where a file of the
    # declared extension has both H>=7.0 and chi²<=350 or a broken
    # magic header.  Quarantine immediately (campaign escalation
    # handles sweeping the rest).
    if (magic_bad or ciphertext_struct) and score >= 50:
        return config.ACTION_TERMINATE_QUARANTINE

    # ── Extension-independent structural fingerprint ──────────────
    # Uniformly distributed bytes at near-maximum entropy: no
    # legitimate file of ANY extension looks like that, because every
    # real format carries structure (magic headers, tables, text,
    # Huffman peaks) that shows up as chi² in the thousands. Ciphertext
    # is flat (chi² ≈ 256).
    #
    # Combined with evidence of the ransomware pattern — the file was
    # RENAMED to a new extension (disguise), or its declared extension
    # is a format whose structural header was destroyed — this contains
    # the file on FIRST sight instead of waiting for a second victim
    # file: that wait is exactly what lets a fast encoder run through
    # the rest of the estate.
    #
    # A brand-new file with an unfamiliar extension that merely looks
    # uniform stays an ALERT: it can be an arbitrary new binary format,
    # and there is no disguise evidence yet. The campaign layer and the
    # federated exchange still escalate real multi-file attacks.
    if (any_ciphertext_shape and score >= 40
            and (ext_chg or ciphertext_struct)):
        return config.ACTION_TERMINATE_QUARANTINE

    # A high score without corroboration is only an alert.
    if score >= 40:
        return config.ACTION_ALERT

    # Speed alone is useful for detection, but not enough for quarantine.
    if hi_speed:
        return config.ACTION_ALERT

    # Do not alert merely because a legitimate known file type is high
    # entropy. Unknown high-entropy files remain visible as alerts.
    extension = (event.get("file_extension") or "").lower()
    if entropy >= config.ENTROPY_THRESHOLD and (
        extension not in config.NORMAL_ENTROPY_RANGES
    ):
        return config.ACTION_ALERT

    return config.ACTION_IGNORE


# ============================================================
# RESPONSE EXECUTOR
# ============================================================

# ── What the last execute_response() call really achieved ─────
# The SOC counters and the process monitor must never claim a kill or
# a containment that the safety gates refused, so the outcome of every
# response is published here for the caller to read back.
_LAST_RESPONSE: dict = {}


def response_summary() -> dict:
    """Copy of the last :func:`execute_response` result summary."""
    return dict(_LAST_RESPONSE)


def execute_response(action: int,
                     event: dict,
                     bc: BlockchainConnector,
                     db_conn, decision: dict | None = None,
                     backup: "BackupManager | None" = None,
                     exchange=None) -> str:

    file_path = event.get("file_path", "")
    proc      = event.get("process") or {}
    pid       = proc.get("pid")       if isinstance(proc, dict) else None
    procname  = proc.get("name", "unknown") if isinstance(proc, dict) else "unknown"

    # ── If whitelisted process, rename to simulator ──
    if procname in config.WHITELISTED_PROCESSES:
        procname = "ransomware_simulator"
        pid      = None

    entropy   = event.get("entropy_overall") or 0.0
    file_hash = event.get("file_hash", "")
    status    = ACTION_LABELS.get(action, "UNKNOWN")
    fname     = os.path.basename(file_path)
    outcome   = status

    # ── Files inside the quarantine / backup stores are evidence the
    # defender already holds. Tamper there (a DELETED event) is still
    # reported and can kill the attacker, but the evidence itself must
    # never be re-quarantined ("<hash>_<hash>_file") or "restored"
    # under its quarantine name. ──
    in_store = _is_defender_store(file_path)

    terminate_result  = None
    quarantine_result = None
    restore_result    = None

    # ── IGNORE ───────────────────────────────────
    if action == config.ACTION_IGNORE:
        log.info(f"  [OK]     {fname} | H={entropy:.2f}")
        save_to_db(db_conn, event, action, status, outcome, decision)
        return _publish_response(action, status, outcome, None, None, None)

    # ── ALERT ─────────────────────────────────────
    if action == config.ACTION_ALERT:
        log.warning(f"  [ALERT]  {fname} | H={entropy:.2f}")
        outcome = status

    # ── TERMINATE ─────────────────────────────────
    if action == config.ACTION_TERMINATE:
        log.warning(f"  [KILL]   {fname} | H={entropy:.2f}")
        killed = _terminate_process(pid, procname, proc)
        terminate_result = "TERMINATED" if killed else "TERMINATE_REFUSED"
        outcome = "DRY_RUN_TERMINATE" if config.DRY_RUN else (
            "TERMINATED" if killed else "TERMINATE_REFUSED"
        )

    # ── TERMINATE + QUARANTINE ────────────────────
    if action == config.ACTION_TERMINATE_QUARANTINE:
        log.warning(f"  [THREAT] {fname} | H={entropy:.2f}")
        killed = _terminate_process(pid, procname, proc)
        terminate_result = "TERMINATED" if killed else "TERMINATE_REFUSED"
        # Carry the kill into the vault record (the campaign's kill
        # covers sweep files contained right after it).
        event = dict(event, response_kill=_kill_record(
            killed, pid, procname, proc))
        if in_store:
            quarantine_result = "ALREADY_IN_VAULT"
            log.warning("  [ACTION] Evidence already inside the protected "
                        "store — not re-quarantined")
        else:
            quarantine_result = _quarantine_file(file_path, event=event,
                                                 action=action)
        log.warning(f"  [ACTION] Quarantine result: {quarantine_result}")
        outcome = quarantine_result if isinstance(quarantine_result, str) else status
        if config.DRY_RUN:
            outcome = "DRY_RUN_QUARANTINE"
        elif in_store:
            outcome = "TERMINATED" if killed else "TAMPER_LOGGED"
        elif not killed and quarantine_result != "QUARANTINED":
            outcome = "RESPONSE_PARTIAL"

        # ── RECOVERY: restore the last known-good version ──
        # Dry-run: the lab attack engine is one-shot, so simulating the
        # restore is safe. Live mode: only restore once the file is
        # contained (quarantined or already gone) so the attacker cannot
        # re-encrypt the restored copy in place.
        if backup is not None and not in_store:
            contained = config.DRY_RUN or quarantine_result in (
                "QUARANTINED", "FILE_ALREADY_MOVED", "DRY_RUN_QUARANTINE"
            )
            if not contained:
                restore_result = "RESTORE_SKIPPED"
                log.warning("  [RESTORE] Skipped: file not contained "
                            "(quarantine failed)")
            else:
                try:
                    r = backup.restore(file_path, event=event)
                    if r.get("success") and r.get("restored"):
                        restore_result = "RESTORED"
                        # Our own write — its filesystem echo must not
                        # be judged as a new attack event.
                        defender_actions().record_restore(
                            file_path, r.get("sha256"))
                    elif r.get("success") and r.get("dry_run"):
                        restore_result = "DRY_RUN_RESTORE"
                    else:
                        restore_result = "RESTORE_FAILED"
                    log.warning(f"  [RESTORE] {restore_result}: "
                                f"{r.get('message')}")
                except Exception as e:
                    restore_result = "RESTORE_FAILED"
                    log.error(f"  [RESTORE] {e}")

        # ── RENAME BACK: complete the recovery ──
        # A rename attack (doc.txt → doc.txt.locked) leaves the restored
        # content under the disguised name. Move the file — and its
        # backup version history — back to the original path so
        # recovery is complete: content AND name.
        if (restore_result == "RESTORED" and isinstance(event, dict)):
            original = event.get("original_path")
            if (original
                    and os.path.abspath(original) != os.path.abspath(file_path)
                    and os.path.exists(file_path)
                    and not os.path.exists(original)):
                try:
                    os.replace(file_path, original)
                    defender_actions().record_moved_away(file_path)
                    defender_actions().record_restore(
                        original, sha256_file(original))
                    if backup is not None:
                        backup.transfer(file_path, original)
                    log.info(
                        f"  [RESTORE] Rename-back complete: "
                        f"{os.path.basename(original)}"
                    )
                except OSError as e:
                    log.warning(f"  [RESTORE] Rename-back failed: {e}")
        if restore_result:
            outcome = f"{outcome}+{restore_result}"

    # ── Honest action label ───────────────────────
    # The stored status must describe what the response layer actually
    # achieved: a kill the safety gates refused is not a kill, and the
    # SOC process monitor / event table render this column verbatim.
    if terminate_result is not None:
        contained = quarantine_result in (
            "QUARANTINED", "DRY_RUN_QUARANTINE", "FILE_ALREADY_MOVED")
        if terminate_result == "TERMINATED":
            status = "TERMINATED+QUARANTINED" if contained else "TERMINATED"
        else:
            status = ("TERMINATE_REFUSED+QUARANTINED" if contained
                      else "TERMINATE_REFUSED")

    # ── FORENSIC REPORT for every incident ────────
    if action >= config.ACTION_ALERT:
        try:
            report_path = generate_report(
                event, decision or {}, {
                    "requested_action":     action,
                    "outcome":              outcome,
                    "dry_run":              bool(config.DRY_RUN),
                    "terminate":            terminate_result,
                    "quarantine":           quarantine_result,
                    "restore":              restore_result,
                    "blockchain_reference": file_hash or None,
                }
            )
            if report_path:
                log.info(f"  [REPORT] Forensic report → "
                         f"{os.path.basename(report_path)}")
        except Exception as e:
            log.error(f"  [REPORT] Generation failed: {e}")

    save_to_db(db_conn, event, action, status, outcome, decision,
               restore_result)

    # ── Blockchain log ────────────────────────────
    if action >= config.ACTION_ALERT:
        try:
            fingerprint = file_hash or hashlib.sha256(
                file_path.encode()
            ).hexdigest()

            bc.log_event({
                "fingerprint" : fingerprint[:64],
                "threat_type" : "ransomware",
                "pid"         : pid or 0,
                "entropy"     : entropy,
                "process"     : procname,
                "file_path"   : file_path,
                "action"      : str(action),
                "status"      : status
            })
        except Exception as e:
            log.error(f"  [BLOCKCHAIN] Failed: {e}")

    # ── Federated exchange: share the confirmed threat ──────
    # Only CONFIRMED threats (quarantine) are shared — an alert is a
    # suspicion, not a shared fact. And only when we hold the file's
    # real content hash: a path hash or a missing file (e.g. the
    # already-deleted target of a defense-tamper event) must never be
    # published as a threat fingerprint.
    if (action == config.ACTION_TERMINATE_QUARANTINE and file_hash
            and not in_store
            and quarantine_result in ("QUARANTINED", "DRY_RUN_QUARANTINE")):
        # An injected exchange (benchmark / multi-node simulation) is an
        # explicit opt-in and always registers. The canonical store is
        # gated by config.EXCHANGE_ENABLED (tests / single-node offline).
        if exchange is None and not config.EXCHANGE_ENABLED:
            store = None
        else:
            store = exchange if exchange is not None else get_exchange()
        if store is not None:
            try:
                rec = store.register(
                    file_hash,
                    threat_type="ransomware",
                    file_extension=os.path.splitext(file_path)[1].lower(),
                    file_size=event.get("file_size") or 0,
                    evidence=(decision or {}).get("explanation", ""),
                )
                log.warning(
                    f"  [EXCHANGE] fingerprint {file_hash[:12]}… shared "
                    f"(sightings={rec['sightings']}, "
                    f"sources={len(rec['sources'])})"
                )
            except Exception as e:
                log.error(f"  [EXCHANGE] Registration failed: {e}")

    # Return the detailed outcome (e.g. "DRY_RUN_QUARANTINE+DRY_RUN_RESTORE"),
    # not just the action label — callers and the dashboard rely on it.
    return _publish_response(action, status, outcome, terminate_result,
                             quarantine_result, restore_result)


_LAST_KILL: dict = {}


def _publish_response(action, status, outcome, terminate_result,
                      quarantine_result, restore_result):
    """Record what this response achieved and return the outcome string."""
    _LAST_RESPONSE.clear()
    _LAST_RESPONSE.update({
        "action": action,
        "status": status,
        "outcome": outcome,
        "terminated": terminate_result == "TERMINATED",
        "kill_refused": terminate_result == "TERMINATE_REFUSED",
        "quarantined": quarantine_result in (
            "QUARANTINED", "DRY_RUN_QUARANTINE", "FILE_ALREADY_MOVED"),
        "restored": restore_result in ("RESTORED", "DRY_RUN_RESTORE"),
    })
    return outcome


def _kill_record(killed: bool, pid, procname: str,
                 process_info: dict | None) -> dict | None:
    """Describe the process kill that belongs to this containment."""
    now = time.time()
    if killed and pid and not config.DRY_RUN:
        _LAST_KILL.clear()
        _LAST_KILL.update({
            "pid": pid, "name": procname, "time": now,
            "cmdline": (process_info or {}).get("cmdline"),
        })
        return {"pid": pid, "name": procname, "terminated": True,
                "killed_at": datetime.fromtimestamp(now).isoformat(),
                "scope": "this file"}
    if _LAST_KILL and now - _LAST_KILL["time"] <= \
            config.CAMPAIGN_WINDOW_SECONDS:
        return {"pid": _LAST_KILL["pid"], "name": _LAST_KILL["name"],
                "terminated": True,
                "killed_at": datetime.fromtimestamp(
                    _LAST_KILL["time"]).isoformat(),
                "scope": "campaign"}
    return None


def _is_defender_store(path: str) -> bool:
    """True for paths inside the quarantine vault or the backup store."""
    if not path:
        return False
    target = os.path.abspath(path)
    for root in (config.QUARANTINE_DIR, config.BACKUP_DIR):
        root = os.path.abspath(root)
        if target == root or target.startswith(root + os.sep):
            return True
    return False


def _terminate_process(pid, procname: str, process_info: dict | None = None):
    """Terminate only a freshly revalidated process identity.

    Filesystem attribution is best-effort. If the monitor cannot provide a
    process name, this function deliberately refuses to terminate anything.
    """
    if not isinstance(process_info, dict):
        log.warning("  [SAFE] No verified process identity; termination refused")
        return False

    expected_pid = process_info.get("pid")
    expected_name = process_info.get("name")
    expected_create_time = process_info.get("create_time")
    if not process_info.get("identity_verified", False):
        log.warning(
            "  [SAFE] Process attribution is best-effort; "
            "automatic termination refused"
        )
        return False
    # Final gate: ordinary user/OS software is never terminated
    # automatically, whatever the attribution layer reported.
    if config.is_denied_process(expected_name):
        log.warning(
            "  [SAFE] %s is on the never-kill list (user/OS software); "
            "termination refused", expected_name,
        )
        return False
    if expected_pid != pid or not expected_name or expected_name != procname:
        log.warning("  [SAFE] Process identity changed; termination refused")
        return False

    try:
        result = ProcessTerminator().terminate(
            int(pid),
            process_name=expected_name,
            expected_create_time=expected_create_time,
        )
        if not result["success"]:
            log.warning("  [SAFE] Termination refused: %s", result["message"])
        return result["success"]
    except Exception as exc:
        log.error("  [TERMINATE] Safety layer failed: %s", exc)
        return False


def _quarantine_file(file_path: str, event: dict | None = None,
                     action: int | None = None) -> str:
    """Quarantine a suspicious file via the shared response layer.

    Uses FileQuarantine (response/response_module.py) so the pipeline and
    the response tests share one dry-run-aware implementation. In dry-run
    mode the file is NEVER moved; the DRY_RUN outcome is recorded by the
    caller. Returns a string status: QUARANTINED, DRY_RUN_QUARANTINE,
    FILE_ALREADY_MOVED, PERMISSION_DENIED, or FAILED.
    """
    try:
        result = FileQuarantine().quarantine(file_path, event=event)
    except Exception as e:
        log.error(f"  [QUARANTINE] ❌ {e}")
        return "FAILED"

    if config.DRY_RUN and result.get("success"):
        log.info("  [DRY-RUN] Quarantine simulated — file left in place")
        return "DRY_RUN_QUARANTINE"

    if not result.get("success"):
        message = (result.get("message") or "").lower()
        if "not found" in message:
            log.warning(f"  [QUARANTINE] Already moved: {os.path.basename(file_path)}")
            return "FILE_ALREADY_MOVED"
        if "permission" in message or "denied" in message:
            log.error("  [QUARANTINE] ❌ Permission denied")
            return "PERMISSION_DENIED"
        log.error(f"  [QUARANTINE] ❌ {result.get('message')}")
        return "FAILED"

    defender_actions().record_moved_away(file_path)
    log.warning(f"  [QUARANTINE] ✅ → {os.path.basename(result.get('quarantine_path') or file_path)}")
    return "QUARANTINED"


# ============================================================
# DECISION ENGINE
# Combines the trained DQN (primary) with the rule-based engine
# (fallback). Both produce an action in the same 0-3 space.
# ============================================================

class CampaignTracker:
    """Cross-file campaign detection for ransomware.

    The per-file score is deliberately conservative: one high-entropy
    file is not proof (video writes, archive creation and photo
    imports all produce high-entropy content). Ransomware is, by
    definition, multi-file: the same threat touches many files in
    rapid succession. This tracker remembers recent suspicious files
    and confirms a campaign when ``CAMPAIGN_MIN_FILES`` distinct files
    all carry an encrypted-data signature inside
    ``CAMPAIGN_WINDOW_SECONDS``:

      * entropy >= ENTROPY_THRESHOLD (looks like encrypted data), AND
      * behavioural corroboration: an entropy jump of at least
        ENTROPY_DELTA_THRESHOLD (the file used to be something else)
        OR a rename to a new extension (disguise).

    Files that merely produce high entropy without corroboration
    (a new video, an imported zip, …) never enter the tracker, so
    legitimate media workloads can never confirm a campaign.

    The tracker also remembers the most recent process verified as
    holding a suspicious file open (``last_verified``). On escalation
    that attribution is the kill target — by the time a campaign is
    confirmed the newest file's handle may already be closed, but the
    malware process is the same one that wrote the earlier files.
    """

    def __init__(self):
        # (timestamp, path, event, action)
        self.entries: deque = deque()
        self.last_verified = None  # (timestamp, process dict)
        # path -> time it was swept. In live mode a swept file is moved
        # to quarantine, so it drops out naturally; in DRY-RUN nothing
        # moves, and without this every later campaign event re-swept
        # every earlier file (hundreds of duplicate SOC rows per attack).
        self.swept: dict = {}

    def reset(self):
        self.entries.clear()
        self.last_verified = None
        self.swept.clear()

    @staticmethod
    def _qualifies(event: dict) -> bool:
        ent = event.get("entropy_overall") or 0.0
        if ent < config.ENTROPY_THRESHOLD:
            return False
        delta = abs(event.get("entropy_delta") or 0.0)
        corroborated = (delta >= config.ENTROPY_DELTA_THRESHOLD
                        or bool(event.get("ext_changed")))
        # Hard structural-ciphertext fingerprints (magic-byte mismatch
        # or chi² ≈ 255, i.e. uniformly distributed bytes) are treated
        # as an automatic corroborator: they cannot come from a
        # legitimate file of the declared extension, regardless of
        # delta or rename. This closes the in-place media blind spot
        # at the campaign layer too.
        magic_bad = event.get("magic_ok") is False
        chi2_val = event.get("chi2_uniformity")
        chi2_tail = event.get("chi2_tail")
        chi2_best = min(x for x in (chi2_val, chi2_tail) if x is not None) if (chi2_val is not None or chi2_tail is not None) else None
        ext_q = (event.get("file_extension") or "").lower()
        _known_set = {
            ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".zip",
            ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".mp3",
            ".mp4", ".avi", ".mov", ".exe", ".dll", ".txt", ".csv", ".rtf",
            ".7z", ".rar", ".gz", ".tar",
        }
        _CIPHERTEXT_CHI2_Q = 300.0
        ciphertext_struct = (
            chi2_best is not None and chi2_best < _CIPHERTEXT_CHI2_Q
            and ent >= 7.0 and ext_q in _known_set
        )
        score = event.get("threat_score") or 0.0
        return corroborated or magic_bad or ciphertext_struct or score >= 55.0

    @staticmethod
    def _verified_process(event: dict) -> dict | None:
        proc = event.get("process")
        if not isinstance(proc, dict):
            return None
        if not (proc.get("identity_verified") and proc.get("pid")):
            return None
        # Ordinary user/OS software (browser, search indexer, COM
        # surrogate, sync client, …) is never a kill target — not even
        # if a handle scan attributed the file to it.
        if config.is_denied_process(proc.get("name")):
            return None
        # Never let the defender's own software be a kill target.
        cmdline = str(proc.get("cmdline") or "").lower()
        if any(marker in cmdline for marker in config.DEFENDER_TOOLING_MARKERS):
            return None
        return dict(proc)

    def check_and_record(self, event: dict,
                         action: int) -> tuple[bool, list, dict | None]:
        """Record ``event`` and report whether a campaign is confirmed.

        Returns ``(escalate, sweep_events, kill_override)``:
          escalate      — act as TERMINATE_QUARANTINE for this event
          sweep_events  — other campaign files to quarantine + restore
          kill_override — recently verified malware process, used when
                          this event's own attribution is missing
        """
        now = time.time()
        window = config.CAMPAIGN_WINDOW_SECONDS
        while self.entries and now - self.entries[0][0] > window:
            self.entries.popleft()
        for p in [p for p, t in self.swept.items() if now - t > window]:
            del self.swept[p]
        if self.last_verified and now - self.last_verified[0] > window:
            self.last_verified = None

        verified = self._verified_process(event)
        if verified is not None:
            self.last_verified = (now, verified)

        if not self._qualifies(event):
            return False, [], None

        path = os.path.normpath(event.get("file_path") or "")
        others = [e for (_t, p, e, a) in self.entries
                  if p != path and a >= config.ACTION_ALERT]
        escalate = (action >= config.ACTION_ALERT
                    and len(others) >= config.CAMPAIGN_MIN_FILES - 1)

        # Keep this event for the window (and for later sweeps).
        self.entries.append((now, path, event, action))
        if not escalate:
            return False, [], None

        # Sweep: the other campaign files that are still on disk.
        sweep = []
        seen = set()
        for (_t, p, e, a) in self.entries:
            if p == path or p in seen or a < config.ACTION_ALERT:
                continue
            if p in self.swept:
                continue  # already contained during this campaign
            target = e.get("file_path") or p
            if os.path.exists(target):
                seen.add(p)
                self.swept[p] = now
                sweep.append(dict(e))

        kill_override = (None if verified is not None
                         else (self.last_verified[1]
                               if self.last_verified else None))
        return True, sweep, kill_override


class DecisionEngine:
    """
    Selects the decision engine and wraps it, falling back to the
    rule-based detector when a requested model cannot be loaded.

    Engine selection (config.AI_ENGINE / ENTROPY_AI_ENGINE):
      auto / rules (default) — the deterministic rule engine. This is
            the measured 0-false-quarantine safety bar, so it is the
            default even when trained models exist.
      rf — the Random Forest second classifier (calibrated, SHAP-
           explained risk). Opt-in: measured on the benchmark battery
           it detects 100% of attacks (including the image blind
           spot) but false-quarantines high-entropy media workloads.
      dqn — the trained DQN (opt-in).

    Hard-confirmation signals (ransom note, defense tamper,
    exchange-confirmed fingerprint) are applied BEFORE any learned
    engine, so no model can ever talk the pipeline out of a
    confirmed incident.
    """

    def __init__(self, engine: str | None = None,
                 campaign: bool | None = None):
        # Cross-file campaign escalation (multi-file confirmation)
        # applies on top of whichever base engine decides. Off by
        # explicit request (tests that must exercise the bare
        # per-file behaviour).
        self.campaign = (config.CAMPAIGN_ENABLED
                         if campaign is None else bool(campaign))
        self.campaign_tracker = CampaignTracker()
        self.requested = (engine or config.AI_ENGINE or "auto").lower()
        if self.requested not in ("auto", "rules", "dqn", "rf"):
            log.warning("[DECISION] Unknown ENTROPY_AI_ENGINE %r — "
                        "using rules", self.requested)
            self.requested = "auto"
        self.agent = None
        self.rf = None
        self.using_dqn = False
        self.using_rf = False

        # Learned engines are explicit opt-ins; the default is the
        # deterministic rule engine.
        if self.requested == "dqn" and _DQN_AVAILABLE \
                and DQNAgent is not None:
            try:
                self.agent = DQNAgent()
                model_path = os.path.join(
                    config.AI_DIR, "dqn_weights.pth"
                )
                if os.path.exists(model_path):
                    if self.agent.load(model_path):
                        self.using_dqn = True
                        log.info("[DECISION] DQN model loaded ✅")
                    else:
                        log.warning("[DECISION] DQN load failed — "
                                    "falling back to rules")
                else:
                    log.warning("[DECISION] No dqn_weights.pth — "
                                "falling back to rules")
            except Exception as e:
                log.warning(f"[DECISION] DQN init error ({e}) — rules")

        if self.requested == "rf" and _RF_AVAILABLE \
                and RFEngine is not None:
            rf_model_path = os.path.join(config.AI_DIR, "rf_weights.json")
            if os.path.exists(rf_model_path):
                try:
                    self.rf = RFEngine(rf_model_path)
                    self.using_rf = True
                    log.info("[DECISION] Random Forest model loaded ✅")
                except Exception as e:
                    log.warning(f"[DECISION] RF load failed ({e}) — "
                                "falling back to rules")
            else:
                log.warning("[DECISION] No rf_weights.json — falling "
                            "back to rules (train with "
                            "python -m ai.train_rf)")

    def _active_engine(self) -> str:
        if self.requested == "dqn":
            return "dqn" if self.using_dqn else "rules"
        if self.requested == "rf":
            return "rf" if self.using_rf else "rules"
        return "rules"

    def engine_name(self) -> str:
        return self._active_engine()

    def reset(self):
        """Clear campaign state (used between isolated test/benchmark
        scenarios; in live operation the rolling window simply ages
        out on its own)."""
        self.campaign_tracker.reset()

    def decide(self, event: dict) -> dict:
        """
        Return a decision dict compatible with the response layer:
        { 'action', 'action_name', 'confidence', 'explanation' }
        plus, when campaign tracking is active, optional keys:
        { 'sweep_events': [...], 'kill_override': {...}, 'campaign': bool }
        """
        decision = self._base_decide(event)
        if not self.campaign:
            return decision

        action = int(decision.get("action", 0))
        escalate, sweep, kill_override = (
            self.campaign_tracker.check_and_record(event, action)
        )
        if not escalate:
            return decision

        if action < config.ACTION_TERMINATE_QUARANTINE:
            decision["action"] = config.ACTION_TERMINATE_QUARANTINE
            decision["action_name"] = ACTION_LABELS[
                config.ACTION_TERMINATE_QUARANTINE]
        decision["campaign"] = True
        decision["sweep_events"] = sweep
        decision["kill_override"] = kill_override
        prior = decision.get("explanation") or ""
        decision["explanation"] = (
            f"CAMPAIGN CONFIRMED: {len(sweep) + 1} files with "
            f"encrypted-data signatures in "
            f"{int(config.CAMPAIGN_WINDOW_SECONDS)}s | {prior}"
        ).strip(" |")
        return decision

    def _base_decide(self, event: dict) -> dict:
        """
        Per-event decision from the selected engine (rules / rf / dqn)
        plus the hard-confirmation signals — before campaign logic.
        """
        # ── Hard-confirmation signals apply to EVERY engine ──
        # A dropped ransom note, a destroyed recovery capability, or
        # a fingerprint the exchange has confirmed is a confirmed
        # incident on its own — no model may override it.
        if (event.get("ransom_note") or event.get("defense_tamper")
                or event.get("known_threat_confirmed")):
            explanation = "Hard-confirmation signal"
            if event.get("ransom_note"):
                explanation += " | RANSOM NOTE: " + "; ".join(
                    event.get("ransom_note_evidence") or []
                )
            if event.get("defense_tamper"):
                explanation += " | DEFENSE TAMPER: " + "; ".join(
                    event.get("defense_tamper_evidence") or []
                )
            if event.get("known_threat_confirmed"):
                explanation += " | KNOWN THREAT (CONFIRMED BY EXCHANGE): " \
                    + str(event.get("known_threat_evidence") or "")
            return {
                "action"      : config.ACTION_TERMINATE_QUARANTINE,
                "action_name" : ACTION_LABELS[config.ACTION_TERMINATE_QUARANTINE],
                "confidence"  : 1.0,
                "explanation" : explanation,
                "q_values"    : None,
                "engine"      : self.engine_name(),
            }

        active = self._active_engine()

        if active == "dqn":
            try:
                decision = self.agent.decide(event)
                return {
                    "action"      : int(decision.get("action", 0)),
                    "action_name" : decision.get("action_name", "IGNORE"),
                    "confidence"  : float(decision.get("confidence", 0.0)),
                    "explanation" : decision.get("explanation", ""),
                    "q_values"    : decision.get("q_values"),
                    "engine"      : "dqn",
                }
            except Exception as e:
                log.warning(f"[DECISION] DQN inference error ({e}) — "
                            f"falling back to rules")

        if active == "rf":
            try:
                result = self.rf.score(event)
                action = int(result["action"])
                # Exchange corroboration floor: a SINGLE node's
                # sighting can raise an ignore to an alert but can
                # never quarantine alone (poison-node defence).
                if (event.get("known_threat")
                        and not event.get("known_threat_confirmed")
                        and action < config.ACTION_ALERT):
                    action = config.ACTION_ALERT
                explanation = result["explanation"]
                if event.get("known_threat"):
                    explanation += (
                        " | KNOWN THREAT (CORROBORATED BY EXCHANGE): "
                        + str(event.get("known_threat_evidence") or "")
                    )
                return {
                    "action"      : action,
                    "action_name" : ACTION_LABELS.get(action, "UNKNOWN"),
                    "confidence"  : float(result["probability"]),
                    "explanation" : explanation,
                    "q_values"    : None,
                    "engine"      : "rf",
                    "risk"        : float(result["risk"]),
                    "top_features": result.get("top_features"),
                }
            except Exception as e:
                log.warning(f"[DECISION] RF inference error ({e}) — "
                            f"falling back to rules")

        action = make_decision(event)
        explanation = "Rule-based detector"
        if event.get("ransom_note"):
            explanation += " | RANSOM NOTE: " + "; ".join(
                event.get("ransom_note_evidence") or []
            )
        if event.get("defense_tamper"):
            explanation += " | DEFENSE TAMPER: " + "; ".join(
                event.get("defense_tamper_evidence") or []
            )
        if event.get("known_threat"):
            marker = "KNOWN THREAT (CONFIRMED BY EXCHANGE): " \
                if event.get("known_threat_confirmed") else \
                "KNOWN THREAT (CORROBORATED BY EXCHANGE): "
            explanation += " | " + marker + (
                event.get("known_threat_evidence") or ""
            )
        elif event.get("reason"):
            explanation += f" | {event['reason']}"
        return {
            "action"      : action,
            "action_name" : ACTION_LABELS.get(action, "UNKNOWN"),
            "confidence"  : 1.0 if action >= config.ACTION_ALERT else 0.0,
            "explanation" : explanation,
            "q_values"    : None,
            "engine"      : "rules",
        }


# ============================================================
# PIPELINE RUNNER
# ============================================================

class PipelineRunner:
    """
    Connects all components and runs the full pipeline.
    """

    def __init__(self):
        log.info("[RUNNER] Initializing pipeline...")

        # Core pipeline
        self.pipeline = EventPipeline()

        # Decision engine (DQN + rule fallback)
        self.engine = DecisionEngine()

        # Database
        self.db = init_db()
        log.info("[RUNNER] Database ready ✅")

        # Blockchain
        self.bc = BlockchainConnector()

        # Backup & recovery store
        self.backup = BackupManager()

        # Stats
        self.stats = {
            "total"      : 0,
            "ignored"    : 0,
            "alerted"    : 0,
            "terminated" : 0,
            "quarantined": 0,
        }

    def start(self):
        """Start the full pipeline."""
        print()
        print("=" * 60)
        print("  ENTROPY - Full Pipeline Active")
        print("=" * 60)
        print(f"  Watching   : {len(config.WATCH_FOLDERS)} folders")
        print(f"  Dashboard  : http://localhost:{config.DASHBOARD_PORT}")
        print(f"  Blockchain : {config.GANACHE_URL}")
        print(f"  DB         : {config.DB_PATH}")
        _engine_labels = {
            "rules": "Rule-based (default)",
            "dqn": "DQN (trained)",
            "rf": "Random Forest (calibrated, SHAP-explained)",
        }
        print(f"  AI Engine  : "
              f"{_engine_labels.get(self.engine.engine_name(), 'Rule-based')}")
        print(f"  Dry-run    : {config.DRY_RUN}")
        print("=" * 60)
        print()

        # ── Seed the backup store with the pre-watch state of the
        # protected estate so files that existed before monitoring
        # started are restorable after an attack. ──
        try:
            baselined = 0
            for folder in config.WATCH_FOLDERS:
                baselined += self.backup.snapshot_directory(
                    folder, source="startup_baseline"
                )
            backup_stats = self.backup.stats()
            log.info(f"[RUNNER] Backup baseline: {baselined} file(s) captured "
                     f"({backup_stats['files_restorable']} restorable)")
        except Exception as e:
            log.warning(f"[RUNNER] Backup baseline failed: {e}")

        # ── Prime entropy history with the same pre-watch state, so
        # the FIRST event on a pre-existing file has a real delta
        # (otherwise a rename encrypting an old file scores only its
        # raw-entropy points — alert, not quarantine). This is what
        # the benchmark's "baseline mode" models. ──
        try:
            primed = 0
            for folder in config.WATCH_FOLDERS:
                primed += self.pipeline.entropy_analyzer.snapshot_directory(
                    folder
                )
            log.info(f"[RUNNER] Entropy history baseline: "
                     f"{primed} file(s) primed")
        except Exception as e:
            log.warning(f"[RUNNER] Entropy baseline failed: {e}")

        # Register our callback with the pipeline
        self.pipeline.register_ai_callback(self._on_analyzed_event)

        # Start the event pipeline
        self.pipeline.start()

        # ── Heartbeat for the SOC dashboard (separate process) ──
        self._started_at = time.time()
        self._heartbeat_running = True
        Thread(target=self._heartbeat_loop, daemon=True,
               name="PipelineHeartbeat").start()

        log.info("[RUNNER] Pipeline running — waiting for events...")

    def _heartbeat_loop(self, interval: float = 2.0):
        """Publish liveness + watch folders so the dashboard can show
        whether detection is really running and what it watches."""
        conn = None
        while getattr(self, "_heartbeat_running", False):
            try:
                if conn is None:
                    conn = connect_database()
                pstats = {}
                try:
                    pstats = self.pipeline.get_stats()
                except Exception:
                    pass
                write_pipeline_heartbeat(
                    conn,
                    started_at=self._started_at,
                    pid=os.getpid(),
                    watch_folders=config.WATCH_FOLDERS,
                    dry_run=bool(config.DRY_RUN),
                    engine=self.engine.engine_name(),
                    stats={**self.stats,
                           "received": pstats.get("total_received", 0),
                           "analyzed": pstats.get("total_analyzed", 0)},
                )
            except Exception as e:
                log.debug(f"[RUNNER] Heartbeat write failed: {e}")
                conn = None
            time.sleep(interval)

    def _on_analyzed_event(self, event: dict):
        """
        Called by the pipeline for every analyzed event.

        This is where detection + response happens.
        """
        self.stats["total"] += 1

        # ── Drop echoes of the defender's own actions ──
        # Restoring a clean copy, renaming a file back and moving a file
        # into quarantine all produce filesystem events. Judging those
        # as attacks quarantined CLEAN restored files and sometimes lost
        # a file. Only genuinely new activity reaches the decision.
        echo = self._defender_echo(event)
        if echo:
            log.info(f"  [SELF]   {os.path.basename(event.get('file_path',''))}"
                     f" — {echo} (defender's own action, not re-analysed)")
            try:
                if event.get("event_type") in ("CREATED", "MODIFIED",
                                               "RENAMED"):
                    # Keep the clean content as the newest baseline.
                    self.backup.capture(event["file_path"], event=event,
                                        strict=True)
            except Exception:
                pass
            return

        # ── Capture the current file state for recovery ──
        # Additive (reads the file, writes only to backup_storage/),
        # so it runs in every mode. Clean versions (entropy below
        # threshold) become restore candidates; dirty ones are kept
        # for forensics but are never restorable.
        file_path = event.get("file_path", "")
        original_path = event.get("original_path")
        if file_path:
            # ── Ransomware disguise: encrypted file gets renamed ──
            # Keep the pre-rename version history (clean captures)
            # usable for restore BEFORE capturing the new (encrypted)
            # state, so versions stay in time order: without this,
            # rename-based attacks are quarantined but never recovered.
            if (event.get("event_type") == "RENAMED"
                    and original_path
                    and original_path != file_path
                    and not os.path.exists(original_path)):
                try:
                    if self.backup.transfer(original_path, file_path):
                        log.info(
                            f"[BACKUP] Version history transferred "
                            f"{os.path.basename(original_path)} → "
                            f"{os.path.basename(file_path)}")
                except Exception as e:
                    log.warning(
                        f"[BACKUP] Transfer failed for {file_path}: {e}")
            try:
                # strict=True: this capture is event-time, so the
                # triggering event is suspicious and the current content
                # is the "after" state (likely ciphertext). The lenient
                # 0.5 margin would label office-format ciphertext
                # (7.8-8.0) as clean and let restore put it back.
                self.backup.capture(file_path, event=event, strict=True)
            except Exception as e:
                log.warning(f"[BACKUP] Capture failed for {file_path}: {e}")

        # ── Make decision ──────────────────────────
        decision = self.engine.decide(event)
        action   = decision["action"]

        # ── Campaign kill override ───────────────────
        # When a campaign is confirmed, this event's own process
        # attribution can be missing (a RENAMED event fires after the
        # handle is closed). Use the process the tracker verified as
        # writing the earlier campaign files — the malware is the same
        # process across the whole attack.
        if (action >= config.ACTION_TERMINATE
                and decision.get("kill_override")):
            proc = event.get("process")
            if not (isinstance(proc, dict)
                    and proc.get("identity_verified")
                    and proc.get("pid")):
                event = dict(event)
                event["process"] = decision["kill_override"]
                log.warning(
                    f"  [KILL] Using campaign-verified process "
                    f"PID:{decision['kill_override'].get('pid')} "
                    f"({decision['kill_override'].get('name')})")

        # ── Execute response ───────────────────────
        status = execute_response(
            action, event, self.bc, self.db, decision, backup=self.backup
        )

        # ── Campaign sweep ───────────────────────────
        # Quarantine + restore the remaining campaign files the
        # confirmed malware touched. The process is already dealt with
        # above, so the sweep events carry no kill intent.
        for sweep_event in (decision.get("sweep_events") or []):
            se = dict(sweep_event)
            se_proc = se.get("process")
            if isinstance(se_proc, dict) and se_proc.get("pid"):
                se_proc = dict(se_proc, identity_verified=False)
                se["process"] = se_proc
            se_decision = dict(decision)
            se_decision["explanation"] = "Campaign sweep: " + \
                str(decision.get("explanation") or "")
            try:
                sweep_status = execute_response(
                    config.ACTION_TERMINATE_QUARANTINE, se,
                    self.bc, self.db, se_decision, backup=self.backup
                )
                if response_summary().get("quarantined"):
                    self.stats["quarantined"] += 1
                log.warning(
                    f"  [SWEEP] {os.path.basename(se.get('file_path',''))} "
                    f"→ {sweep_status}")
            except Exception as e:
                log.error(f"  [SWEEP] Failed for "
                          f"{se.get('file_path')}: {e}")

        # ── Post-kill verification ─────────────────────
        # The process can be killed while writing a file that has not
        # yet produced its own detection event (or one that scored
        # below the alert bar): its ciphertext would remain on disk
        # after the campaign sweep. Walk the estate once and repair
        # whatever is still encrypted.
        if (decision.get("campaign")
                and action >= config.ACTION_TERMINATE):
            # Dry-run leaves every file in place, so rescanning after
            # each campaign event would re-report the same files.
            # Run the scan once per campaign window there.
            now = time.time()
            last = getattr(self, "_last_postkill", 0.0)
            if (not config.DRY_RUN
                    or now - last > config.CAMPAIGN_WINDOW_SECONDS):
                self._last_postkill = now
                self._post_kill_verification()

        # ── Mirror the rename-back in the entropy history ──
        # execute_response may have moved a renamed file back to its
        # original path; keep the analyzer's per-path history with it.
        if (isinstance(status, str) and status.endswith("+RESTORED")
                and original_path
                and os.path.abspath(original_path) != os.path.abspath(file_path)):
            try:
                self.pipeline.entropy_analyzer.transfer_history(
                    file_path, original_path
                )
            except Exception:
                pass

        # ── Update stats ───────────────────────────
        # Count what actually happened: a kill or a containment the
        # safety layer refused must never be reported as a success.
        summary = response_summary()
        if action == config.ACTION_IGNORE:
            self.stats["ignored"] += 1
        elif action == config.ACTION_ALERT:
            self.stats["alerted"] += 1
        else:
            # "terminated" counts real kills only; refusals are visible
            # in the event status column instead.
            if summary.get("terminated"):
                self.stats["terminated"] += 1
            elif action >= config.ACTION_TERMINATE and config.DRY_RUN:
                # Dry-run simulates the kill; keep the demo counter live.
                self.stats["terminated"] += 1
            if summary.get("quarantined"):
                self.stats["quarantined"] += 1
            elif action == config.ACTION_TERMINATE_QUARANTINE and config.DRY_RUN:
                self.stats["quarantined"] += 1

    @staticmethod
    def _defender_echo(event: dict) -> str | None:
        """Name the defender action that caused *event*, or None."""
        reg = defender_actions()
        etype = event.get("event_type")
        path = event.get("file_path") or ""
        src = event.get("original_path") or ""
        base = os.path.basename(src)
        if etype == "RENAMED" and base.startswith(".restore_tmp."):
            return "restore write"
        if etype in ("CREATED", "MODIFIED", "RENAMED") and \
                reg.is_restore_echo(path, event.get("file_hash")):
            return "restored clean copy"
        if etype == "DELETED" and reg.is_own_removal(path):
            return "moved to quarantine / renamed back"
        if etype == "DELETED" and _is_defender_store(path) and \
                reg.is_own_removal(path):
            return "vault housekeeping"
        # The entropy reading of a just-restored file is momentarily 0.0
        # while it is being replaced; never judge that transient state.
        if etype in ("CREATED", "MODIFIED") and reg.recently_restored(path) \
                and not (event.get("entropy_overall") or 0.0):
            return "restore in progress"
        return None

    def _post_kill_verification(self):
        """Walk the protected estate once after a confirmed campaign kill.

        A process can die mid-write on a file that has not produced its
        own detection event yet (or one that scored below the alert
        bar); the campaign sweep does not know about such a file. This
        pass repairs the remainder: quarantines the replaced content,
        restores the last clean version, and re-primes the entropy
        history.

        The repair signal is CONTENT, not entropy level: a file is
        repaired only when its current hash differs from the hash of
        its last clean version. High entropy alone is not evidence —
        photos, videos and archives are legitimately high-entropy and
        legitimately untouched, and must never be quarantined on that
        basis. Files with no clean backup version cannot be
        auto-repaired and are left in place for manual recovery.
        """
        log.warning("  [SWEEP] Post-kill verification scan ...")
        repaired = 0
        seen = set()
        for root_dir in config.WATCH_FOLDERS:
            if not os.path.isdir(root_dir):
                continue
            for dirpath, _dirnames, filenames in os.walk(root_dir):
                for name in filenames:
                    path = os.path.join(dirpath, name)
                    apath = os.path.abspath(path)
                    if apath in seen:
                        continue
                    seen.add(apath)
                    try:
                        candidate = self.backup.find_restore_candidate(path)
                    except Exception:
                        continue
                    if candidate is None or not candidate.get("sha256"):
                        continue
                    try:
                        current_sha = sha256_file(path)
                    except OSError:
                        continue
                    if current_sha == candidate["sha256"]:
                        continue  # identical to the last clean state
                    try:
                        result = self.pipeline.entropy_analyzer.analyze(path)
                    except Exception:
                        result = {}
                    entropy = float(result.get("entropy_overall") or 0.0)
                    log.warning(
                        f"  [SWEEP] {name}: content differs from last clean "
                        f"version (H={entropy:.2f}) — quarantining + "
                        f"restoring")
                    event = {
                        "event_id": (
                            f"postkill-{int(time.time() * 1000)}-"
                            f"{os.path.basename(path)}"),
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "SWEEP",
                        "file_path": path,
                        "file_extension": os.path.splitext(name)[1].lower(),
                        "file_hash": result.get("file_hash", ""),
                        "entropy_overall": entropy,
                        "entropy_delta": 0.0,
                        "threat_score": result.get("threat_score", 0.0),
                        "process": {},
                    }
                    decision = {
                        "action": config.ACTION_TERMINATE_QUARANTINE,
                        "action_name": ACTION_LABELS[
                            config.ACTION_TERMINATE_QUARANTINE],
                        "explanation": (
                            "Post-kill verification: encrypted content "
                            "present after campaign kill"),
                        "engine": self.engine.engine_name(),
                    }
                    try:
                        sweep_status = execute_response(
                            config.ACTION_TERMINATE_QUARANTINE, event,
                            self.bc, self.db, decision,
                            backup=self.backup)
                        if "RESTORED" in str(sweep_status):
                            repaired += 1
                            # Re-prime the entropy history with the
                            # restored (clean) content so future deltas
                            # are meaningful again.
                            try:
                                clean = (self.pipeline.entropy_analyzer
                                         .analyze(path))
                                self.backup.capture(
                                    path,
                                    event={"event_type": "RESTORED",
                                           "entropy_overall":
                                               clean.get("entropy_overall")},
                                    strict=True)
                            except Exception:
                                pass
                        if response_summary().get("quarantined"):
                            self.stats["quarantined"] += 1
                        log.warning(f"  [SWEEP] {name} → {sweep_status}")
                    except Exception as e:
                        log.error(f"  [SWEEP] Failed for {path}: {e}")
        log.warning(
            f"  [SWEEP] Post-kill verification complete: "
            f"{repaired} file(s) repaired")

    def stop(self):
        self._heartbeat_running = False
        self.pipeline.stop()
        # Give queued ledger writes a chance to complete before the runner
        # exits. This prevents daemon-thread writes from being silently lost.
        self.bc.flush(timeout=10.0)
        log.info("[RUNNER] Stopped.")

    def print_stats(self):
        print()
        print("=" * 40)
        print("  PIPELINE STATS")
        print("=" * 40)
        for k, v in self.stats.items():
            print(f"  {k:12} : {v}")
        print("=" * 40)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:
        import colorama
        colorama.init()
    except ImportError:
        pass

    runner = PipelineRunner()
    runner.start()

    try:
        while True:
            time.sleep(30)
            runner.print_stats()

    except KeyboardInterrupt:
        print()
        runner.stop()
        runner.print_stats()