"""Single-process launcher for the ENTROPY ransomware lab.

Starts the detection pipeline, SOC dashboard, victim explorer, and attacker
console together, then shuts them down on Ctrl+C.

This is the industry-level entry point for final year demo.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# ── Auto-bootstrap ────────────────────────────────────────────
# If the user site-packages got wiped (sandbox snapshots do this),
# silently reinstall requirements before spawning children.
def _ensure_deps() -> None:
    try:
        import flask, psutil, numpy, watchdog, sklearn, eventlet, flask_socketio  # noqa: F401
        return
    except ImportError:
        pass
    req = ROOT / "requirements-ci.txt"
    if req.exists():
        import subprocess as _sp
        print("[lab] Installing dependencies (one-time)...", flush=True)
        _sp.check_call(
            [sys.executable, "-m", "pip", "install", "--user",
             "--no-cache-dir", "-q", "-r", str(req)],
            env={**os.environ, "PIP_BREAK_SYSTEM_PACKAGES": "1"},
        )
_ensure_deps()

# Make user site-packages visible to this process (and children via env).
import site as _site
_site.main()
_sp_user = _site.getusersitepackages()
if _sp_user not in sys.path:
    sys.path.insert(0, _sp_user)
os.environ["PYTHONPATH"] = _sp_user + os.pathsep + os.environ.get("PYTHONPATH", "")

# Prefer a repo-local virtualenv when one exists; otherwise fall back to
# the system python (deps installed via pip3 --user).
_VENV_CANDIDATES = [ROOT / n / "bin" / "python" for n in (".runenv", "py-env", ".venv")]
PYTHON = next((str(p) for p in _VENV_CANDIDATES if p.exists()), sys.executable)

SERVICES = (
    ("pipeline", [PYTHON, str(ROOT / "monitoring" / "pipeline_runner.py")]),
    ("dashboard", [PYTHON, str(ROOT / "app.py")]),
    ("victim", [PYTHON, str(ROOT / "victim_server" / "app.py")]),
    ("attacker", [PYTHON, str(ROOT / "attacker_server" / "app.py")]),
)


VICTIM_FOLDER = "victim_server/user_files"


def _set_default(env: dict[str, str], key: str, value: str) -> None:
    """Like setdefault, but an EMPTY value also counts as unset.

    A .env copied from .env.example contains lines such as
    ``ENTROPY_WATCH_FOLDERS=`` — python-dotenv exports those as empty
    strings, and plain ``setdefault`` would then keep the empty value.
    """
    if not (env.get(key) or "").strip():
        env[key] = value


def _env(dry_run: bool | None = None) -> dict[str, str]:
    env = os.environ.copy()
    _set_default(env, "ENTROPY_DASHBOARD_HOST", "0.0.0.0")
    _set_default(env, "ENTROPY_VICTIM_HOST", "0.0.0.0")
    # The lab is the LIVE demo: kill the attacker, move the file to the
    # quarantine vault, restore the clean copy. A .env copied from an
    # older .env.example set ENTROPY_DRY_RUN=true, which silently
    # turned all of that into log lines. Dry-run is now an explicit
    # opt-in: `python lab.py --dry-run`.
    if dry_run is not None:
        env["ENTROPY_DRY_RUN"] = "true" if dry_run else "false"
    _set_default(env, "ENTROPY_DRY_RUN", "false")
    _set_default(env, "ENTROPY_CONTROL_TOKEN", "entropy-lab")
    _set_default(env, "ENTROPY_BLOCKCHAIN_FALLBACK", "true")
    _set_default(env, "PYTHONUNBUFFERED", "1")

    # The lab exists to defend the victim estate: it must ALWAYS be
    # watched, whatever else the operator adds. Without this, an empty
    # or unrelated ENTROPY_WATCH_FOLDERS (e.g. from .env) made the
    # pipeline watch data/testing only, so the SOC dashboard never saw
    # a single victim-folder change or attack.
    folders = [
        part.strip()
        for part in (env.get("ENTROPY_WATCH_FOLDERS") or "").split(",")
        if part.strip()
    ]
    victim_abs = (ROOT / VICTIM_FOLDER).resolve()
    if not any((ROOT / f).resolve() == victim_abs for f in folders):
        folders.insert(0, VICTIM_FOLDER)
    env["ENTROPY_WATCH_FOLDERS"] = ",".join(folders)
    return env


def _ensure_quarantine():
    """Install-time quarantine folder creation - required by spec."""
    import config
    q_dir = config.QUARANTINE_DIR
    b_dir = config.BACKUP_DIR
    os.makedirs(q_dir, exist_ok=True)
    os.makedirs(b_dir, exist_ok=True)
    os.makedirs(config.LOG_DIR, exist_ok=True)
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    print(f"[install] Quarantine folder created by user at install: {q_dir}")
    print(f"[install] Backup vault: {b_dir}")
    print(f"[install] Reports: {config.REPORTS_DIR}")
    print(f"[install] Vault credentials: {config.VAULT_USER} / PIN {config.VAULT_PIN}")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    _ensure_quarantine()

    fixtures = ROOT / "victim_server" / "create_fake_files.py"
    victim_files = ROOT / "victim_server" / "user_files"
    if not victim_files.exists() or not any(victim_files.iterdir()):
        print("[lab] Creating victim fixtures...")
        subprocess.check_call([PYTHON, str(fixtures), "--clean"], cwd=ROOT)

    print("=" * 70)
    print("  ENTROPY - Ransomware Shield | Final Year Major Project")
    print("  Industry Level - Proactive Defence with Blockchain Audit")
    print("=" * 70)
    print("  SOC Dashboard   : http://127.0.0.1:5000  (real-time feed)")
    print("  Victim PC       : http://127.0.0.1:5001  (neutral explorer)")
    print("  Attacker Console: http://127.0.0.1:8001  (launch attacks)")
    env = _env(dry_run="--dry-run" in argv)
    dry_run = env["ENTROPY_DRY_RUN"].strip().lower() in {"1", "true", "yes", "on"}
    print(f"  Watching        : {env['ENTROPY_WATCH_FOLDERS']}")
    print("  Quarantine      : quarantine_storage/ (install-time, PIN locked)")
    print("  Backup Vault    : backup_storage/ (versioned clean copies)")
    print("  Dry-run         : " + (
        "ON - detections are logged, files are NOT moved (ENTROPY_DRY_RUN)"
        if dry_run else "OFF - real kill+quarantine+restore active"))
    print("  Blockchain      : Local ledger fallback (Ganache optional)")
    print("=" * 70)

    processes: list[subprocess.Popen] = []
    try:
        for name, command in SERVICES:
            proc = subprocess.Popen(command, cwd=ROOT, env=env)
            processes.append(proc)
            print(f"[lab] started {name:12s} pid={proc.pid}")

        print("\n[lab] All services running. Press Ctrl+C to stop.")
        print("[lab] Open attacker console to launch WannaCry demo.\n")

        while True:
            for (svc_name, _), proc in zip(SERVICES, processes):
                code = proc.poll()
                if code is not None:
                    print(f"[lab] {svc_name} exited with {code} - restarting not supported, shutting down")
                    return code or 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[lab] shutting down...")
        return 0
    finally:
        for proc in processes:
            if proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGINT)
                except Exception:
                    pass
        deadline = time.time() + 8
        for proc in processes:
            remaining = max(0.1, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except Exception:
                    pass
        print("[lab] stopped - estate preserved for forensics")


if __name__ == "__main__":
    raise SystemExit(main())
