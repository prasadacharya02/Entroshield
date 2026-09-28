# monitoring/pipeline_supervisor.py
# ============================================================
# ENTROPY - Detection Pipeline Supervisor
# ============================================================
"""Keeps the detection pipeline running, whoever starts the lab.

The lab is four processes:

    monitoring/pipeline_runner.py   the defence (monitor → entropy →
                                    decision → kill/quarantine/restore)
    app.py                          SOC dashboard          :5000
    victim_server/app.py            victim file explorer   :5001
    attacker_server/app.py          attacker console       :8001

While working on the three web surfaces it is very easy to launch
only those three — the pipeline is invisible, and without it an
attack simply succeeds: the files stay encrypted, nothing is moved
to ``quarantine_storage/``, and the SOC dashboard shows
``0 events / 0 threats`` forever.

This module removes that failure mode:

  * :func:`pipeline_status`  — is a detection pipeline alive anywhere?
    (read from the shared ``pipeline_status`` heartbeat row, so it
    works across processes)
  * :func:`ensure_pipeline`  — start one if none is running
  * :func:`start_supervisor` — background thread that re-checks and
    restarts the pipeline if it dies or if it stopped watching the
    victim estate, so monitoring is continuous by construction.

The supervisor never starts a second pipeline while a fresh heartbeat
exists, and it honours ``ENTROPY_AUTOSTART_PIPELINE=false`` for
operators (and tests) who want to stay in full control.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIPELINE_SCRIPT = Path(__file__).resolve().parent / "pipeline_runner.py"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config  # noqa: E402
from storage.database import connect, init_db, read_pipeline_heartbeat  # noqa: E402

log = logging.getLogger("PipelineSupervisor")

# Marker placed in the environment of every pipeline we start, so a
# supervised pipeline can never start another supervisor (recursion
# guard when the pipeline itself imports this module).
MANAGED_ENV_FLAG = "ENTROPY_PIPELINE_MANAGED"

# Cross-process guard: while this file is fresh, another supervisor
# (victim explorer + SOC dashboard + ...) is already starting a
# pipeline, so we must not start a second one.
_GUARD_NAME = "pipeline_supervisor.lock"
_GUARD_TTL = 15.0

_lock = threading.Lock()
_stop_event = threading.Event()
_thread: threading.Thread | None = None
_last_attempt = 0.0
_consecutive_failures = 0
_last_forced_restart = 0.0

# A process that has been alive this long without a single heartbeat is
# treated as hung (restarted) rather than as "still starting up".
_HUNG_AFTER = 30.0


# ═══════════════════════════════════════════════════
# STATUS
# ═══════════════════════════════════════════════════

def _guard_path() -> Path:
    return Path(config.LOG_DIR) / _GUARD_NAME


def pipeline_status(db_path: str | None = None) -> dict:
    """Return the live/dead state of the detection pipeline.

    ``online``           a heartbeat arrived within the staleness window
    ``age_seconds``      age of that heartbeat, or None if it never ran
    ``pid``              process id reported by the pipeline
    ``watch_folders``    folders the running pipeline monitors
    ``watching_victim``  True when the victim estate is among them
    ``stats``            pipeline counters (received / analyzed / engine)
    """
    victim = os.path.abspath(config.VICTIM_USER_FILES)
    status = {
        "online": False,
        "age_seconds": None,
        "pid": None,
        "watch_folders": [],
        "watching_victim": False,
        "dry_run": None,
        "engine": None,
        "stats": {},
        "victim_folder": victim,
    }
    try:
        conn = connect(db_path)
        try:
            heartbeat = read_pipeline_heartbeat(conn)
        finally:
            conn.close()
    except Exception as exc:  # unreadable/locked DB must not crash a server
        log.debug("Pipeline heartbeat unreadable: %s", exc)
        return status

    if not heartbeat:
        return status

    age = max(0.0, time.time() - float(heartbeat.get("heartbeat") or 0.0))
    folders = [os.path.abspath(f) for f in (heartbeat.get("watch_folders") or [])]
    status.update({
        "age_seconds": round(age, 1),
        "pid": heartbeat.get("pid"),
        "watch_folders": folders,
        "watching_victim": any(
            victim == f or victim.startswith(f + os.sep) for f in folders
        ),
        "dry_run": bool(heartbeat.get("dry_run")),
        "engine": heartbeat.get("engine"),
        "stats": heartbeat.get("stats") or {},
        "online": age <= config.PIPELINE_STALE_SECONDS,
    })
    return status


def pipeline_alive(db_path: str | None = None) -> bool:
    """True when a fresh pipeline heartbeat exists."""
    return bool(pipeline_status(db_path)["online"])


def pipeline_processes() -> list[int]:
    """PIDs of running detection-pipeline processes (excluding ourselves).

    A pipeline takes a couple of seconds to import, open the database
    and snapshot the estate before its first heartbeat lands. During
    that window the heartbeat alone would say "offline" and a second
    pipeline could be started — so the process table is consulted too.
    """
    pids: list[int] = []
    me = os.getpid()

    def _matches(cmdline) -> bool:
        return any(str(part).endswith("pipeline_runner.py")
                   for part in (cmdline or []))

    try:
        import psutil

        for proc in psutil.process_iter(["pid", "cmdline"]):
            try:
                pid = int(proc.info.get("pid") or 0)
                if pid <= 0 or pid == me:
                    continue
                if _matches(proc.info.get("cmdline")):
                    pids.append(pid)
            except Exception:
                continue
        return pids
    except ImportError:
        pass

    # No psutil: fall back to /proc where it exists.
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return pids
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == me:
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if _matches([part.decode("utf-8", "replace")
                     for part in raw.split(b"\0") if part]):
            pids.append(pid)
    return pids


# ═══════════════════════════════════════════════════
# SPAWN
# ═══════════════════════════════════════════════════

def pipeline_env() -> dict:
    """Environment for the pipeline we spawn.

    Inherits the operator's configuration (``.env`` / process env), and
    makes sure the values the live demo depends on are explicit:

    * the victim estate is always watched (``config`` also enforces this
      unless ``ENTROPY_WATCH_VICTIM=false``),
    * dry-run stays off unless it was explicitly requested — a pipeline
      that only logs would look exactly like "the backend does nothing",
    * unbuffered output, so the log file is usable while debugging.
    """
    env = os.environ.copy()
    env[MANAGED_ENV_FLAG] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    if not (env.get("ENTROPY_DRY_RUN") or "").strip():
        env["ENTROPY_DRY_RUN"] = "true" if config.DRY_RUN else "false"

    folders = [os.path.abspath(f) for f in config.WATCH_FOLDERS]
    victim = os.path.abspath(config.VICTIM_USER_FILES)
    if config.WATCH_VICTIM and victim not in folders:
        folders.insert(0, victim)
    if folders:
        env["ENTROPY_WATCH_FOLDERS"] = ",".join(folders)
    return env


def _guard_is_fresh() -> bool:
    guard = _guard_path()
    try:
        age = time.time() - guard.stat().st_mtime
    except OSError:
        return False
    if age <= _GUARD_TTL:
        return True
    try:
        guard.unlink()
    except OSError:
        pass
    return False


def _touch_guard() -> None:
    guard = _guard_path()
    try:
        guard.parent.mkdir(parents=True, exist_ok=True)
        guard.write_text(f"{os.getpid()} {time.time()}\n", encoding="utf-8")
    except OSError:
        pass


def spawn_pipeline(reason: str = "") -> bool:
    """Start one detection pipeline process (no liveness checks)."""
    try:
        log_dir = Path(config.LOG_DIR)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = open(log_dir / "pipeline_managed.log", "a", encoding="utf-8")
    except OSError:
        log_file = None

    try:
        proc = subprocess.Popen(
            [sys.executable, str(PIPELINE_SCRIPT)],
            cwd=str(ROOT),
            env=pipeline_env(),
            stdin=subprocess.DEVNULL,
            stdout=log_file or subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
    except Exception as exc:
        if log_file:
            log_file.close()
        log.error("Could not start the detection pipeline: %s", exc)
        print(f"[SUPERVISOR] ❌ Could not start the detection pipeline: {exc}",
              flush=True)
        return False
    finally:
        _touch_guard()

    print(
        f"[SUPERVISOR] ▶ Detection pipeline started (pid={proc.pid}"
        + (f", {reason}" if reason else "") + ") — watching "
        + ", ".join(pipeline_env().get("ENTROPY_WATCH_FOLDERS", "").split(",")),
        flush=True,
    )
    log.warning("Detection pipeline started pid=%s (%s)", proc.pid, reason)
    return True


def ensure_pipeline(reason: str = "", force: bool = False) -> bool:
    """Start a pipeline when none is running. Returns True if we started one.

    ``force`` restarts even a live pipeline (used when the running one is
    not watching the victim estate).
    """
    if not config.AUTOSTART_PIPELINE and not force:
        return False
    if os.environ.get(MANAGED_ENV_FLAG) == "1":
        # We ARE the pipeline (or a child of it) — never recurse.
        return False

    with _lock:
        global _last_attempt, _consecutive_failures

        status = pipeline_status()
        if status["online"] and not force:
            # A live pipeline is already defending the estate.
            return False

        if not force and pipeline_processes():
            # A pipeline process exists but has not reported a heartbeat
            # yet: it is still starting up (lab.py spawns it itself).
            # Starting another one would mean two processes racing to
            # kill/quarantine the same files.
            return False

        now = time.time()
        cooldown = config.PIPELINE_RESTART_COOLDOWN * min(
            2 ** _consecutive_failures, 6
        )
        if _last_attempt and (now - _last_attempt) < cooldown:
            return False

        if _guard_is_fresh():
            # Another supervised server is starting the pipeline right now.
            _last_attempt = now
            return False

        _last_attempt = now
        started = spawn_pipeline(reason)
        if started:
            _consecutive_failures = 0
        else:
            _consecutive_failures = min(_consecutive_failures + 1, 10)
        return started


def wait_for_pipeline(timeout: float = 10.0,
                      db_path: str | None = None) -> bool:
    """Block until a pipeline heartbeat appears (or *timeout* expires)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pipeline_alive(db_path):
            return True
        time.sleep(0.25)
    return pipeline_alive(db_path)


def start_pipeline(reason: str = "on demand",
                   timeout: float = 10.0) -> bool:
    """Ensure a pipeline is running and wait briefly for its heartbeat."""
    if pipeline_alive():
        return True
    ensure_pipeline(reason)
    return wait_for_pipeline(timeout)


# ═══════════════════════════════════════════════════
# STALE / WRONG PIPELINE
# ═══════════════════════════════════════════════════

def _process_cmdline(pid: int) -> list[str]:
    try:
        import psutil

        return list(psutil.Process(pid).cmdline())
    except Exception:
        pass
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
    except Exception:
        return []


def stop_pipeline(pid: int | None = None) -> bool:
    """Stop the pipeline process, but only if it really is the pipeline.

    The command line is re-checked before signalling: a PID from the
    heartbeat table is never trusted blindly.
    """
    pid = int(pid or 0)
    if pid <= 0 or pid == os.getpid():
        return False
    cmdline = _process_cmdline(pid)
    if not cmdline or not any("pipeline_runner" in part for part in cmdline):
        log.warning("Refusing to stop PID %s — not the detection pipeline", pid)
        return False
    try:
        os.kill(pid, 15)  # SIGTERM / TerminateProcess
    except OSError as exc:
        log.warning("Could not stop pipeline PID %s: %s", pid, exc)
        return False
    log.warning("Stopped stale detection pipeline PID %s", pid)
    print(f"[SUPERVISOR] ⏹ Stopped stale detection pipeline (pid={pid})",
          flush=True)
    return True


def restart_pipeline(reason: str) -> bool:
    """Replace the running pipeline with a correctly configured one."""
    global _last_forced_restart

    with _lock:
        now = time.time()
        if now - _last_forced_restart < config.PIPELINE_RESTART_COOLDOWN:
            return False
        _last_forced_restart = now

    status = pipeline_status()
    targets: list[int] = []
    if status["online"] and status.get("pid"):
        targets.append(int(status["pid"]))
    else:
        # No usable PID in the heartbeat (never wrote one, or a hung
        # process): find the process itself.
        targets.extend(pipeline_processes())

    stopped = False
    for pid in dict.fromkeys(targets):
        stopped = stop_pipeline(pid) or stopped
    if stopped:
        # Give the old process a moment to release the SQLite handle.
        time.sleep(1.0)
    return ensure_pipeline(reason, force=True)


# ═══════════════════════════════════════════════════
# SUPERVISOR THREAD
# ═══════════════════════════════════════════════════

def _supervise_once() -> None:
    """One health check: start / restart the pipeline when needed."""
    status = pipeline_status()

    if not status["online"]:
        age = status["age_seconds"]
        live = pipeline_processes()
        if live and (age is None or age <= _HUNG_AFTER):
            # Alive but not reporting yet — a pipeline needs a moment
            # to import, open the DB and snapshot the estate. Wait
            # instead of racing it with a second instance.
            log.debug("Pipeline pid(s) %s starting up (heartbeat age %s)",
                      live, age)
            return
        if live:
            # Alive for a long time with no heartbeat: it is hung.
            restart_pipeline(
                f"no heartbeat for {age:.0f}s with a live process"
            )
            return
        ensure_pipeline(
            "no heartbeat" if age is None else f"heartbeat stale ({age}s)"
        )
        return

    if config.WATCH_VICTIM and not status["watching_victim"]:
        # A pipeline is alive but blind to the victim estate: the attack
        # would run to completion while the SOC dashboard stayed at zero.
        folders = ", ".join(status["watch_folders"]) or "(nothing)"
        print(
            f"[SUPERVISOR] ⚠ Pipeline is watching {folders} — not the victim "
            f"folder {config.VICTIM_USER_FILES}. Restarting it.",
            flush=True,
        )
        restart_pipeline("not watching the victim estate")


def _supervise_loop(interval: float) -> None:
    _supervise_once()  # act immediately on startup
    while not _stop_event.wait(interval):
        try:
            _supervise_once()
        except Exception:
            log.exception("Pipeline supervisor iteration failed")


def start_supervisor(interval: float | None = None) -> threading.Thread | None:
    """Start the keep-alive thread for the detection pipeline.

    Safe to call from every web surface: only one thread per process is
    started, and the cross-process guard plus the heartbeat prevent a
    second pipeline from being launched while one is alive.
    """
    global _thread

    if not config.AUTOSTART_PIPELINE:
        print("[SUPERVISOR] Pipeline auto-start disabled "
              "(ENTROPY_AUTOSTART_PIPELINE=false)", flush=True)
        return None

    with _lock:
        if _thread is not None and _thread.is_alive():
            return _thread
        _stop_event.clear()
        _thread = threading.Thread(
            target=_supervise_loop,
            args=(interval or config.PIPELINE_SUPERVISOR_INTERVAL,),
            daemon=True,
            name="entropy-pipeline-supervisor",
        )
        _thread.start()
        return _thread


def stop_supervisor() -> None:
    """Stop the keep-alive thread (does not stop the pipeline itself)."""
    _stop_event.set()


def print_status() -> None:
    """Human-readable one-liner for service banners."""
    status = pipeline_status()
    if status["online"]:
        print(f"  Detection  : ONLINE (pid {status['pid']}, "
              f"engine {status['engine']}, "
              f"folders {len(status['watch_folders'])})", flush=True)
    else:
        print("  Detection  : OFFLINE — starting it now", flush=True)


# ═══════════════════════════════════════════════════
# CLI — `python -m monitoring.pipeline_supervisor`
# ═══════════════════════════════════════════════════

def _main(argv: list[str]) -> int:
    action = (argv[0] if argv else "status").strip().lower()
    if action in ("start", "ensure"):
        started = start_pipeline("manual supervisor run")
        print("[SUPERVISOR] pipeline running" if started
              else "[SUPERVISOR] pipeline could not be started")
        return 0 if started else 1
    if action == "restart":
        ok = restart_pipeline("manual restart")
        print("[SUPERVISOR] restarted" if ok else "[SUPERVISOR] restart skipped")
        return 0 if ok else 1
    if action == "stop":
        status = pipeline_status()
        ok = bool(status["online"]) and stop_pipeline(status["pid"])
        print("[SUPERVISOR] stopped" if ok else "[SUPERVISOR] nothing to stop")
        return 0 if ok else 1
    if action == "watch":
        ensure_pipeline("watcher start")
        thread = start_supervisor()
        print("[SUPERVISOR] watching (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            stop_supervisor()
            print("\n[SUPERVISOR] stopped")
        return 0

    status = pipeline_status()
    if status["online"]:
        print(f"pipeline ONLINE  pid={status['pid']}  "
              f"age={status['age_seconds']}s  engine={status['engine']}")
        print(f"watch folders    : {', '.join(status['watch_folders'])}")
        print(f"watching victim  : {status['watching_victim']}")
        print(f"stats            : {status['stats']}")
        return 0
    print("pipeline OFFLINE (no fresh heartbeat)")
    print(f"victim folder    : {status['victim_folder']}")
    return 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(_main(sys.argv[1:]))
