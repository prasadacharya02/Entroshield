# app.py
# ============================================================
# ENTROPY - Flask Dashboard Backend
# ============================================================

import sys
import os
import json
import threading
import logging
import time
from datetime import datetime

# ── Fix paths FIRST before anything else ──────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ── Import config and modules ───────────
import config
from monitoring import pipeline_supervisor
from storage.database import connect, init_db as initialize_database
from storage.database import read_pipeline_heartbeat
from blockchain.connector import BlockchainConnector
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# ── App Setup ──────────────────────────────────────
app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, "dashboard", "templates"),
            static_folder=os.path.join(BASE_DIR, "dashboard", "static"))

app.config["SECRET_KEY"] = config.SECRET_KEY
log = logging.getLogger("Dashboard")


def _api_error(message="dashboard service unavailable", status=500):
    return jsonify({"error": message, "status": status}), status


socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
bc       = BlockchainConnector()


# ═══════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════

def get_db():
    return connect()


def init_db():
    conn = initialize_database()
    conn.close()
    print("[DASHBOARD] Database ready ✅")


# ── Action Labels ──────────────────────────────────
ACTION_MAP = {
    0: "IGNORE",
    1: "ALERT",
    2: "TERMINATE",
    3: "QUARANTINE"
}


# ═══════════════════════════════════════════════════
# CORE ROUTES
# ═══════════════════════════════════════════════════

@app.route("/")
def index():
    """Main route mapped back to the SOC Dashboard."""
    return render_template("dashboard.html")


def _is_bind_address(url: str | None) -> bool:
    """True for URLs that name a bind address (0.0.0.0 / ::) — not browsable."""
    if not url:
        return True
    return "//0.0.0.0" in url or "//[::]" in url or "//::" in url


def _public_base_url(port: int, explicit: str | None = None) -> str:
    """Browser-reachable URL for a sibling service on the same host.

    Mirrors the request (scheme + hostname), so links keep working
    locally (127.0.0.1) and behind a preview proxy alike. An explicit
    PUBLIC_* override wins when it names a real host.
    """
    if explicit and not _is_bind_address(explicit):
        return explicit
    host = request.host.split(":", 1)[0] or "127.0.0.1"
    return f"{request.scheme}://{host}:{port}"


@app.route("/platform")
def platform_dashboard():
    """Secondary route for Command Platform."""
    return render_template(
        "platform.html",
        victim_url=_public_base_url(config.VICTIM_PORT,
                                    config.PUBLIC_VICTIM_URL),
        attacker_url=_public_base_url(config.ATTACKER_PORT,
                                      config.PUBLIC_ATTACKER_URL),
    )


@app.route("/api/platform")
def platform():
    status = bc.get_status()
    return jsonify({
        "product": "ENTROPY",
        "tagline": "Entropy fingerprinting with an auditable response ledger",
        "edition": "Command Platform",
        "version": "2.0.0",
        "dry_run": bool(config.DRY_RUN),
        "watch_folders": config.WATCH_FOLDERS,
        "ledger_mode": status.get("mode"),
        "is_blockchain": status.get("is_blockchain", False),
        "positioning": "Purple-team range for SOC training — not an EDR replacement",
    })


# A heartbeat older than this means the detection pipeline is not running.
PIPELINE_STALE_SECONDS = 8.0


def pipeline_status() -> dict:
    """Liveness + watch folders of the detection pipeline process."""
    try:
        db = get_db()
        hb = read_pipeline_heartbeat(db)
        db.close()
    except Exception:
        log.exception("Pipeline status read failed")
        hb = None
    victim = os.path.abspath(config.VICTIM_USER_FILES)
    if not hb:
        return {
            "online": False, "age_seconds": None, "watch_folders": [],
            "watching_victim": False, "dry_run": None, "engine": None,
            "stats": {}, "victim_folder": victim,
        }
    age = max(0.0, time.time() - float(hb["heartbeat"]))
    folders = [os.path.abspath(f) for f in hb["watch_folders"]]
    watching_victim = any(
        victim == f or victim.startswith(f + os.sep) for f in folders
    )
    return {
        "online": age <= PIPELINE_STALE_SECONDS,
        "age_seconds": round(age, 1),
        "pid": hb.get("pid"),
        "watch_folders": folders,
        "watching_victim": watching_victim,
        "dry_run": hb["dry_run"],
        "engine": hb.get("engine"),
        "stats": hb.get("stats") or {},
        "victim_folder": victim,
    }


@app.route("/api/pipeline")
def pipeline():
    return jsonify(pipeline_status())


@app.route("/api/pipeline/restart", methods=["POST"])
def pipeline_restart():
    """Start (or restart) the detection pipeline from the SOC dashboard.

    The supervisor thread normally does this automatically; this route
    exists so an analyst can force it from the UI without touching the
    terminal.
    """
    status = pipeline_status()
    if status["online"] and status["watching_victim"]:
        return jsonify({"status": "already-running", "pipeline": status})
    if status["online"]:
        started = pipeline_supervisor.restart_pipeline(
            "manual restart from the SOC dashboard")
    else:
        started = pipeline_supervisor.start_pipeline(
            "manual start from the SOC dashboard")
    return jsonify({
        "status": "started" if started else "unavailable",
        "pipeline": pipeline_status(),
    }), (200 if started else 503)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "dashboard"})


@app.route("/api/stats")
def stats():
    try:
        db  = get_db()
        row = db.execute("""
            SELECT
                COUNT(*)                    AS total,
                SUM(CASE WHEN action >= 1
                    THEN 1 ELSE 0 END)      AS threats,
                SUM(CASE WHEN action >= 2
                    THEN 1 ELSE 0 END)      AS terminated,
                SUM(CASE WHEN action = 3
                    THEN 1 ELSE 0 END)      AS quarantined,
                SUM(CASE WHEN restore_result IS NOT NULL
                    THEN 1 ELSE 0 END)      AS recovery,
                ROUND(AVG(entropy), 2)      AS avg_entropy,
                ROUND(MAX(entropy), 2)      AS max_entropy
            FROM events
        """).fetchone()
        db.close()

        bc_count = bc.get_event_count()

        return jsonify({
            "total"        : row["total"]       or 0,
            "threats"      : row["threats"]     or 0,
            "terminated"   : row["terminated"]  or 0,
            "quarantined"  : row["quarantined"] or 0,
            "recovery"     : row["recovery"]    or 0,
            "avg_entropy"  : row["avg_entropy"] or 0,
            "max_entropy"  : row["max_entropy"] or 0,
            "blockchain_tx": bc_count
        })
    except Exception:
        log.exception("Stats API failed")
        return _api_error()


@app.route("/api/events")
def events():
    try:
        db   = get_db()
        rows = db.execute("""
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()
        db.close()
        return jsonify([dict(r) for r in rows])
    except Exception:
        log.exception("Events API failed")
        return _api_error()


@app.route("/api/entropy")
def entropy_data():
    try:
        db   = get_db()
        rows = db.execute("""
            SELECT timestamp, entropy, entropy_delta, file_path
            FROM events
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()
        db.close()
        return jsonify([dict(r) for r in rows])
    except Exception:
        log.exception("Entropy API failed")
        return _api_error()


@app.route("/api/alerts")
def alerts():
    try:
        db   = get_db()
        rows = db.execute("""
            SELECT * FROM events
            WHERE action >= 1
            ORDER BY id DESC
            LIMIT 20
        """).fetchall()
        db.close()
        return jsonify([dict(r) for r in rows])
    except Exception:
        log.exception("Alerts API failed")
        return _api_error()


@app.route("/api/blockchain")
def blockchain_events():
    try:
        events = bc.get_all_events()
        return jsonify(events)
    except Exception:
        log.exception("Blockchain API failed")
        return _api_error("blockchain service unavailable")


@app.route("/api/blockchain/status")
def blockchain_status():
    try:
        connected = bc.verify_chain()
        count     = bc.get_event_count()
        status = bc.get_status()
        labels = {
            "ganache": "Ganache smart contract",
            "fallback": "Local SQLite ledger (not a blockchain)",
            "none": "Offline — no ledger",
        }
        mode = status.get("mode", "none")
        return jsonify({
            "connected"      : connected,
            "is_blockchain"  : status.get("is_blockchain", connected),
            "mode"           : mode,
            "mode_label"     : labels.get(mode, mode),
            "tx_count"       : count,
            "address"        : config.CONTRACT_ADDRESS,
            "network"        : config.GANACHE_URL
        })
    except Exception:
        log.exception("Blockchain status API failed")
        return _api_error("blockchain status unavailable")


@app.route("/api/quarantine")
def quarantine_files():
    try:
        files = []
        q_dir = config.QUARANTINE_DIR

        if os.path.exists(q_dir):
            for fname in os.listdir(q_dir):
                if fname.endswith(".meta.json") or fname.endswith(".tmp"):
                    continue
                fpath = os.path.join(q_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                fstat = os.stat(fpath)
                item = {
                    "name"     : fname,
                    "size"     : fstat.st_size,
                    "modified" : datetime.fromtimestamp(
                        fstat.st_mtime
                    ).isoformat()
                }
                metadata_path = fpath + ".meta.json"
                if os.path.isfile(metadata_path):
                    try:
                        with open(metadata_path, encoding="utf-8") as metadata_file:
                            item["metadata"] = json.load(metadata_file)
                    except (OSError, ValueError):
                        item["metadata_error"] = True
                files.append(item)

        return jsonify(files)
    except Exception:
        log.exception("Quarantine API failed")
        return _api_error("quarantine service unavailable")


@app.route("/api/live")
def live_stats():
    """Super fast endpoint — only reads counts"""
    try:
        db  = get_db()
        row = db.execute("""
            SELECT
                COUNT(*)                         AS total,
                SUM(CASE WHEN action >= 1 THEN 1 ELSE 0 END) AS threats,
                SUM(CASE WHEN action >= 2 THEN 1 ELSE 0 END) AS terminated,
                SUM(CASE WHEN action  = 3 THEN 1 ELSE 0 END) AS quarantined
            FROM events
        """).fetchone()
        db.close()
        return jsonify({
            "total"      : row["total"]       or 0,
            "threats"    : row["threats"]     or 0,
            "terminated" : row["terminated"]  or 0,
            "quarantined": row["quarantined"] or 0,
        })
    except Exception:
        log.exception("Live stats API failed")
        return _api_error("live statistics unavailable")


@app.route("/api/backup")
def backup_status():
    """Status of the clean-copy backup store (recovery source)."""
    try:
        from response.backup_manager import BackupManager
        manager = BackupManager()
        return jsonify({
            "stats": manager.stats(),
            "files": manager.list_backups(),
            "dry_run": bool(config.DRY_RUN),
        })
    except Exception:
        log.exception("Backup API failed")
        return _api_error("backup service unavailable")


@app.route("/api/reports")
def reports():
    """List forensic incident reports, newest first."""
    try:
        from response.forensic_report import list_reports
        return jsonify(list_reports())
    except Exception:
        log.exception("Reports API failed")
        return _api_error("forensic report service unavailable")


@app.route("/api/reports/<path:name>")
def report_detail(name):
    """Fetch one forensic report by file name."""
    try:
        from response.forensic_report import load_report
        data = load_report(name)
        if data is None:
            return _api_error("report not found", status=404)
        return jsonify(data)
    except Exception:
        log.exception("Report detail API failed")
        return _api_error("forensic report service unavailable")


# ═══════════════════════════════════════════════════
# WEBSOCKET — Real Time Push
# ═══════════════════════════════════════════════════

@socketio.on("connect")
def handle_connect():
    print("[DASHBOARD] Client connected")
    emit("status", {"message": "Connected to Entropy Dashboard"})


def _last_event_id() -> int:
    """Highest row id already pushed to websocket clients (per process)."""
    try:
        db = get_db()
        row = db.execute("SELECT COALESCE(MAX(id), 0) AS last_id FROM events").fetchone()
        db.close()
        return int(row["last_id"] or 0)
    except Exception:
        return 0


def push_updates():
    """Real-time push loop.

    Two channels, both driven by the shared events database (the
    pipeline process writes, the dashboard process reads):

    * ``new_event``   — every filesystem/detection event as soon as it
                        is persisted (sub-second), full row payload so
                        the SOC timeline, entropy graph, and alert
                        panel update live without polling.
    * ``live_update`` — counter heartbeat (totals / threats).

    If the database is rotated/reset underneath us (e.g. the attacker
    reset endpoint or an operator wipe), the thread re-initialises the
    schema and resyncs its cursor rather than 500-looping.
    """
    last_id = _last_event_id()
    while True:
        try:
            with app.app_context():
                db = get_db()
                # Defensive: if the events table disappeared under us,
                # re-initialise the schema and resync before querying.
                try:
                    new_rows = db.execute(
                        "SELECT * FROM events WHERE id > ? ORDER BY id LIMIT 100",
                        (last_id,),
                    ).fetchall()
                except Exception:
                    try:
                        init_db()
                    except Exception:
                        pass
                    last_id = _last_event_id()
                    db = get_db()
                    new_rows = db.execute(
                        "SELECT * FROM events WHERE id > ? ORDER BY id LIMIT 100",
                        (last_id,),
                    ).fetchall()
                if new_rows:
                    for row in new_rows:
                        try:
                            socketio.emit("new_event", dict(row))
                        except Exception:
                            log.exception("new_event emit failed")
                        last_id = int(row["id"])
                else:
                    # DB was reset/rotated under us — resync the cursor
                    # so future events are still pushed.
                    cur_max = int(
                        db.execute(
                            "SELECT COALESCE(MAX(id), 0) AS m FROM events"
                        ).fetchone()["m"] or 0
                    )
                    if cur_max < last_id:
                        last_id = cur_max
                db.close()

                # ── 2) Counter heartbeat.
                db = get_db()
                stat = db.execute("""
                    SELECT COUNT(*) AS total,
                           SUM(CASE WHEN action >= 1
                               THEN 1 ELSE 0 END) AS threats
                    FROM events
                """).fetchone()
                db.close()

                socketio.emit("live_update", {
                    "total"   : stat["total"]   or 0,
                    "threats" : stat["threats"] or 0,
                    "time"    : datetime.now().strftime("%H:%M:%S"),
                    "pipeline": pipeline_status(),
                })
        except Exception:
            log.exception("Live update push failed")
        time.sleep(0.4)


# ═══════════════════════════════════════════════════
# DQN + PROCESSES + DEMO + THREAT LEVEL
# ═══════════════════════════════════════════════════

# ═══════════════════════════════════════════════════
# LAB CONTROL — the Command Platform page drives the
# attacker console through these routes
# ═══════════════════════════════════════════════════
# The console (attacker_server, port 8001) owns the campaign process.
# The SOC dashboard proxies to it server-side, so the operator does not
# have to paste the control token into a second UI — the same token the
# console would demand is attached here.

LAB_FOLDER_NAMES = ("Documents", "Downloads", "Desktop", "Pictures")


def _attacker_console(path: str, method: str = "GET",
                      payload: dict | None = None,
                      timeout: float = 6.0):
    """Call the attacker console. Returns (json|None, status_code)."""
    import urllib.error
    import urllib.request

    url = f"http://127.0.0.1:{config.ATTACKER_PORT}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if config.CONTROL_TOKEN:
        req.add_header("Authorization", f"Bearer {config.CONTROL_TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8")), response.status
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8")), exc.code
        except Exception:
            return {"ok": False, "error": f"console returned {exc.code}"}, exc.code
    except Exception:
        return None, 0


def _console_offline():
    return jsonify({
        "ok": False,
        "error": ("attacker console is not reachable on port "
                  f"{config.ATTACKER_PORT} — start it with: "
                  "python attacker_server/app.py"),
    }), 503


@app.route("/api/lab/status")
def lab_status():
    """Campaign + victim state, read from the attacker console."""
    stats, status = _attacker_console("/api/stats")
    if stats is None:
        return _console_offline()
    stats = dict(stats)
    stats["dry_run"] = bool(config.DRY_RUN)
    return jsonify(stats), status


@app.route("/api/lab/families")
def lab_families():
    families, status = _attacker_console("/api/families")
    if families is None:
        return _console_offline()
    return jsonify(families), status


@app.route("/api/lab/launch", methods=["POST"])
def lab_launch():
    payload = request.get_json(silent=True) or {}
    family = str(payload.get("family") or "").strip().lower()
    result, status = _attacker_console("/api/launch", "POST", {"family": family})
    if result is None:
        return _console_offline()
    return jsonify(result), status


@app.route("/api/lab/stop", methods=["POST"])
def lab_stop():
    result, status = _attacker_console("/api/stop", "POST", {})
    if result is None:
        return _console_offline()
    return jsonify(result), status


@app.route("/api/lab/reset", methods=["POST"])
def lab_reset():
    result, status = _attacker_console("/api/reset", "POST", {})
    if result is None:
        return _console_offline()
    return jsonify(result), status


@app.route("/api/folders")
def victim_folders():
    """Neutral folder inventory of the victim estate (no attack detail)."""
    folders = []
    root = config.VICTIM_USER_FILES
    for name in LAB_FOLDER_NAMES:
        path = os.path.join(root, name)
        count, size = 0, 0
        if os.path.isdir(path):
            for entry in os.scandir(path):
                if entry.is_file():
                    count += 1
                    try:
                        size += entry.stat().st_size
                    except OSError:
                        pass
        folders.append({
            "name": name,
            "file_count": count,
            "size": f"{size / 1024:.1f} KB" if size else "0 KB",
            "locked": False,
        })
    return jsonify(folders)


@app.route("/api/dqn/last")
def dqn_last_decision():
    try:
        db = get_db()
        row = db.execute("""
            SELECT * FROM events
            ORDER BY id DESC LIMIT 1
        """).fetchone()
        db.close()

        if not row:
            return jsonify({
                "decision": "STANDBY",
                "confidence": 0,
                "engine": "none",
                "explanation": "",
                "factors": []
            })

        keys = row.keys()
        entropy = row["entropy"] or 0
        delta   = row["entropy_delta"] or 0
        action  = row["action"] or 0
        engine  = row["engine"] if "engine" in keys and row["engine"] else "rules"
        explanation = row["explanation"] if "explanation" in keys else ""
        confidence = row["confidence"] if "confidence" in keys and row["confidence"] is not None else 0
        if isinstance(confidence, float) and confidence <= 1:
            confidence = round(confidence * 100, 1)

        decisions = {
            0: "IGNORE",
            1: "ALERT",
            2: "TERMINATE",
            3: "TERMINATE + QUARANTINE"
        }
        outcome = row["outcome"] if "outcome" in keys and row["outcome"] else row["status"]

        factors = [
            {"name": "Engine", "value": engine, "pass": engine == "dqn"},
            {"name": "Requested action", "value": decisions.get(action, "UNKNOWN"), "pass": action >= 1},
            {"name": "Outcome", "value": outcome or "--", "pass": True},
            {"name": "Entropy", "value": f"{entropy:.2f}", "pass": entropy >= config.ENTROPY_THRESHOLD},
            {"name": "Entropy delta", "value": f"{abs(delta):.2f}", "pass": abs(delta) >= config.ENTROPY_DELTA_THRESHOLD},
        ]
        if explanation:
            factors.append({"name": "Explanation", "value": explanation[:80], "pass": True})

        return jsonify({
            "decision": decisions.get(action, "UNKNOWN"),
            "confidence": confidence,
            "engine": engine,
            "explanation": explanation,
            "factors": factors
        })
    except Exception:
        log.exception("Decision API failed")
        return _api_error("decision service unavailable")


@app.route("/api/processes")
def flagged_processes():
    try:
        db = get_db()
        rows = db.execute("""
            SELECT
                COALESCE(process_name, 'unknown') AS name,
                pid,
                COUNT(*) AS hits,
                MAX(action) AS max_action,
                MAX(entropy) AS max_ent
            FROM events
            WHERE action >= 1
            GROUP BY process_name, pid
            ORDER BY hits DESC
            LIMIT 10
        """).fetchall()
        db.close()

        return jsonify([{
            "name": r["name"] or "unknown",
            "pid": r["pid"],
            "hits": r["hits"],
            "status": "killed" if r["max_action"] >= 2 else "watch",
            "entropy": r["max_ent"] or 0
        } for r in rows])
    except Exception:
        log.exception("Process summary API failed")
        return _api_error("process summary unavailable")


@app.route("/api/demo/trigger", methods=["POST"])
def demo_trigger():
    """Demo injection is disabled and rejected with 409 Conflict.

    Synthetic events must come from the controlled attack simulator
    (attacker console), which modifies only the victim fixture estate.
    Fabricated events injected from the dashboard would pollute the
    event log and the audit ledger, so the endpoint refuses loudly
    instead of silently complying.
    """
    return jsonify({
        "status": "rejected",
        "error": (
            "Demo injection is disabled. Run a controlled simulation "
            "from the attacker console (http://127.0.0.1:8001) against "
            "the victim fixture estate."
        ),
    }), 409


@app.route("/api/threat-level")
def threat_level():
    try:
        db = get_db()
        row = db.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN action >= 2 THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN action >= 1 THEN 1 ELSE 0 END) AS threats
            FROM events
            WHERE datetime(timestamp) >= datetime('now', '-5 minutes')
        """).fetchone()
        db.close()

        total    = row["total"] or 0
        critical = row["critical"] or 0
        threats  = row["threats"] or 0

        if total == 0:
            level, label = 0, "MINIMAL"
        else:
            score = min(100, int((critical / max(total, 1)) * 100 + threats * 3))
            if score < 20:
                level, label = score, "MINIMAL"
            elif score < 50:
                level, label = score, "ELEVATED"
            elif score < 80:
                level, label = score, "HIGH"
            else:
                level, label = score, "CRITICAL"

        return jsonify({
            "level": level,
            "label": label,
            "recent_threats": threats,
            "recent_critical": critical
        })
    except Exception:
        log.exception("Threat level API failed")
        return _api_error("threat level unavailable")


# ═══════════════════════════════════════════════════
# START
# ═══════════════════════════════════════════════════

if __name__ == "__main__":
    init_db()

    # Start background push thread
    t = threading.Thread(target=push_updates, daemon=True)
    t.start()

    print(f"\n[DASHBOARD] Starting...")
    print(f"            URL     → http://localhost:{config.FLASK_PORT}")
    print(f"            DB      → {config.DB_PATH}")
    print(f"            Chain   → {config.GANACHE_URL}\n")

    # The dashboard is useless without the detection pipeline: make sure
    # one is running (and keep it running) before serving the UI.
    pipeline_supervisor.ensure_pipeline("SOC dashboard startup")
    pipeline_supervisor.wait_for_pipeline(timeout=8.0)
    pipeline_supervisor.print_status()
    pipeline_supervisor.start_supervisor()

    socketio.run(
        app,
        host   = config.FLASK_HOST,
        port   = config.FLASK_PORT,
        debug  = False,
        use_reloader = False,
        allow_unsafe_werkzeug = True,
    )