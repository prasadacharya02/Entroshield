# config.py
# ============================================================
# ENTROPY - Central Configuration
# ============================================================
"""Central configuration for the ENTROPY ransomware shield.

Values can be overridden through environment variables or a local ``.env``
file.  Paths supplied as relative values are resolved from the repository root.
The checked-in ``.env.example`` documents the supported runtime settings.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_PATH = Path(__file__).resolve().parent
BASE_DIR = str(BASE_PATH)

try:
    from dotenv import load_dotenv
except ImportError:  # Optional: health check reports missing loader.
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv(BASE_PATH / ".env")

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        f"Invalid boolean value for {name}: {value!r} "
        f"(expected true/false, yes/no, 1/0, or on/off)"
    )


def _env_int(name: str, default: int, *, minimum: int | None = None) -> int:
    raw = os.getenv(name)
    try:
        value = default if raw is None else int(raw.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid integer value for {name}: {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ValueError(f"{name}={value} is below the minimum of {minimum}")
    return value


def _env_float(name: str, default: float, *, minimum: float | None = None) -> float:
    raw = os.getenv(name)
    try:
        value = default if raw is None else float(raw.strip())
    except ValueError as exc:
        raise ValueError(f"Invalid float value for {name}: {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ValueError(f"{name}={value} is below the minimum of {minimum}")
    return value


def _resolve_path(value: str | os.PathLike) -> str:
    """Resolve *value* against the repository root when it is relative."""
    path = Path(str(value)).expanduser()
    if path.is_absolute():
        return str(path)
    return str((BASE_PATH / path).resolve())


def _env_path(name: str, default: Path) -> str:
    raw = os.getenv(name)
    if raw and raw.strip():
        return _resolve_path(raw.strip())
    return str((BASE_PATH / default).resolve()) if not default.is_absolute() else str(default)


# ── Project Folders ──────────────────────────────────────────
MONITORING_DIR = str(BASE_PATH / "monitoring")
ENTROPY_DIR = str(BASE_PATH / "entropy")
AI_DIR = str(BASE_PATH / "ai")
RESPONSE_DIR = str(BASE_PATH / "response")
BLOCKCHAIN_DIR = str(BASE_PATH / "blockchain")
DASHBOARD_DIR = str(BASE_PATH / "dashboard")
DATA_DIR = str(BASE_PATH / "data")
TRAINING_DATA_DIR = str(BASE_PATH / "data" / "training")
TESTING_DATA_DIR = str(BASE_PATH / "data" / "testing")
VICTIM_USER_FILES = str(BASE_PATH / "victim_server" / "user_files")

# ── Install-time quarantine folder ───────────────────────────
# The quarantine store is created by the operator when the shield
# is installed: point ENTROPY_QUARANTINE_DIR at the folder you want
# protected files moved to (absolute or relative to the repo root).
# It is created automatically if it does not exist.
QUARANTINE_DIR = _env_path("ENTROPY_QUARANTINE_DIR", Path("quarantine_storage"))
BACKUP_DIR = str(BASE_PATH / "backup_storage")
REPORTS_DIR = str(BASE_PATH / "reports")

# ── Runtime Files & Directories ──────────────────────────────
LOG_FILE = _env_path("ENTROPY_LOG_FILE", Path("logs") / "entropy_system.log")
LOG_DIR = str(Path(LOG_FILE).parent)
DB_PATH = _env_path("ENTROPY_DB_PATH", Path("entropy.db"))


def ensure_runtime_directories() -> None:
    """Create required runtime directories (idempotent)."""
    for d in (
        LOG_DIR,
        QUARANTINE_DIR,
        BACKUP_DIR,
        REPORTS_DIR,
        TRAINING_DATA_DIR,
        TESTING_DATA_DIR,
        VICTIM_USER_FILES,
    ):
        os.makedirs(d, exist_ok=True)


ensure_runtime_directories()

# ── Watch Folders ────────────────────────────────────────────
# Accepts comma-separated (lab.py convention) OR os.pathsep-separated lists.
#
# The victim estate (``victim_server/user_files``) is the asset the whole
# lab defends, so it is ALWAYS watched — even when ENTROPY_WATCH_FOLDERS
# is empty (a .env copied from .env.example ships it empty) or lists
# unrelated folders. Without this guarantee the monitor silently watched
# ``data/testing`` while the SOC dashboard reported 0 events and an
# attack on the victim PC ran to completion unopposed.
#
# Set ENTROPY_WATCH_VICTIM=false only if you deliberately want the
# pipeline to ignore the victim estate (e.g. a custom deployment).
WATCH_VICTIM = _env_bool("ENTROPY_WATCH_VICTIM", True)


def _watch_folders() -> list[str]:
    raw = os.getenv("ENTROPY_WATCH_FOLDERS")

    # split on both comma and os.pathsep for cross-platform convenience
    parts: list[str] = []
    if raw and raw.strip():
        for chunk in raw.replace(";", ",").split(","):
            chunk = chunk.strip()
            if chunk:
                parts.append(_resolve_path(chunk))
    if not parts:
        parts = [TESTING_DATA_DIR]

    # Read the switch here (not just at import) so the module-level
    # constant and the parsed list can never disagree.
    if _env_bool("ENTROPY_WATCH_VICTIM", True):
        victim = str(Path(VICTIM_USER_FILES).resolve())
        resolved = {str(Path(p).resolve()) for p in parts}
        if victim not in resolved:
            parts.insert(0, victim)
    return parts


WATCH_FOLDERS = _watch_folders()

# Processes that must never be terminated by the response layer.
WHITELISTED_PROCESSES = [
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "systemd", "init", "kthreadd",
    "code.exe", "explorer.exe",
]

# ── Never-kill list: ordinary user & OS software ─────────────
# These processes routinely hold *legitimate* handles on files in a
# user folder — the Windows Search indexer (SearchFilterHost /
# SearchProtocolHost / SearchIndexer), the COM surrogate (dllhost),
# browsers that just downloaded a file, OneDrive/Dropbox sync, Office,
# the AV engine. Open-handle attribution alone therefore CANNOT prove
# they are the writer.
#
# Killing any of them is a worse outcome than a late kill: it destroys
# the operator's session and has nothing to do with the ransomware.
# They are refused at attribution time (never offered as a candidate),
# inside the campaign kill memory, and again at the termination gate —
# three independent layers, so a single bad attribution cannot reach
# os.kill().
DENY_KILL_PROCESSES = [
    # Windows shell / search / COM infrastructure
    "dllhost.exe", "searchfilterhost.exe", "searchprotocolhost.exe",
    "searchindexer.exe", "sihost.exe", "runtimebroker.exe", "wmiprvse.exe",
    "taskhostw.exe", "ctfmon.exe", "textinputhost.exe", "dwm.exe",
    "fontdrvhost.exe", "audiodg.exe", "spoolsv.exe", "winlogon.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "smartscreen.exe", "backgroundtaskhost.exe", "conhost.exe",
    # Browsers
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    "vivaldi.exe", "iexplore.exe", "msedgewebview2.exe",
    # Cloud sync / collaboration
    "onedrive.exe", "dropbox.exe", "googledrivesync.exe", "teams.exe",
    "ms-teams.exe", "zoom.exe", "slack.exe", "discord.exe",
    # Office / PDF readers
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "acrord32.exe", "acrobat.exe", "notepad.exe", "notepad++.exe",
    # Endpoint protection
    "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe", "avp.exe", "avastui.exe",
    # macOS / Linux desktop equivalents
    "finder", "google chrome", "safari", "firefox", "chromium",
    "chromium-browser", "google-chrome", "gnome-shell", "nautilus",
    "tracker-miner-fs", "gvfsd", "baloo_file",
]

_DENY_KILL_SET = {name.lower() for name in DENY_KILL_PROCESSES}


def is_denied_process(process_name: str | None) -> bool:
    """True when this process must never be auto-terminated.

    Matches the full name and the basename, so both ``dllhost.exe`` and
    ``C:\\Windows\\System32\\dllhost.exe`` are refused.
    """
    if not process_name:
        return False
    name = str(process_name).strip().lower()
    if name in _DENY_KILL_SET:
        return True
    basename = os.path.basename(name.replace("\\", "/"))
    if basename in _DENY_KILL_SET:
        return True
    # Windows search infrastructure can appear with suffixes
    # (e.g. "SearchFilterHost.exe", "SearchProtocolHost.exe").
    return basename.startswith("search") and basename.endswith("host.exe")

# ── Self-kill safety gate ────────────────────────────────────
# Command-line fragments that identify THIS software (defender
# pipeline, dashboards, lab services). The response layer refuses to
# terminate any process whose command line matches one of these.
DEFENDER_TOOLING_MARKERS = (
    "pipeline_runner",
    "entropy_system",
    "lab.py",
    "victim_server",
    "attacker_server/app",
    "attacker_server\\app",
    "dashboard",
    "app.py",
    "main.py",
)

# ── Event Pipeline & Monitoring Config ───────────────────────
EVENT_DEDUP_WINDOW_SECONDS = _env_float("EVENT_DEDUP_WINDOW_SECONDS", 1.0, minimum=0.0)
EVENT_QUEUE_SIZE = _env_int("EVENT_QUEUE_SIZE", 10000, minimum=1)
EVENT_BATCH_SIZE = _env_int("EVENT_BATCH_SIZE", 50, minimum=1)

# ── Detection & Entropy Engine Thresholds ────────────────────
ENTROPY_THRESHOLD = _env_float("ENTROPY_THRESHOLD", 6.8, minimum=0.0)
ENTROPY_DELTA_THRESHOLD = _env_float("ENTROPY_DELTA_THRESHOLD", 2.0, minimum=0.0)
FILES_PER_SECOND_THRESHOLD = _env_float("ENTROPY_FILES_PER_SECOND_THRESHOLD", 3.0, minimum=0.0)

# ── Campaign (multi-file) escalation ───────────────────────
CAMPAIGN_ENABLED = _env_bool("ENTROPY_CAMPAIGN_ENABLED", True)
CAMPAIGN_WINDOW_SECONDS = _env_float("ENTROPY_CAMPAIGN_WINDOW_SECONDS", 15.0, minimum=1.0)
CAMPAIGN_MIN_FILES = _env_int("ENTROPY_CAMPAIGN_MIN_FILES", 2, minimum=2)
SAMPLE_SIZE_BYTES = _env_int("ENTROPY_SAMPLE_SIZE_BYTES", 65536, minimum=1)

# ── Decision Engine Selection ────────────────────────────────
AI_ENGINE = os.getenv("ENTROPY_AI_ENGINE", "auto").strip().lower()

# ── Backup & Recovery ────────────────────────────────────────
BACKUP_MAX_VERSIONS_PER_FILE = _env_int("ENTROPY_BACKUP_MAX_VERSIONS", 10, minimum=1)

# ── Blockchain Settings ──────────────────────────────────────
GANACHE_URL = os.getenv("ENTROPY_GANACHE_URL", "http://127.0.0.1:7545")
CONTRACT_ADDRESS = os.getenv("ENTROPY_CONTRACT_ADDRESS", "0x7d5fd3ad0ffbeaAf9df76d1CF74058b5E14ddC1D").strip()
WALLET_ADDRESS = os.getenv("ENTROPY_WALLET_ADDRESS", "0x4769fFb50b3bE30331056C2f174A0eaa64436E5d").strip()
ACCOUNT_INDEX = _env_int("ENTROPY_ACCOUNT_INDEX", 0, minimum=0)
BLOCKCHAIN_FALLBACK = _env_bool("ENTROPY_BLOCKCHAIN_FALLBACK", True)

# ── Federated Threat-Fingerprint Exchange ─────────────────────
THREAT_EXCHANGE_DB = str(BASE_PATH / "blockchain" / "exchange.db")
EXCHANGE_NODE_ID = os.getenv("ENTROPY_NODE_ID", "").strip()
EXCHANGE_CONFIRM_THRESHOLD = _env_int("ENTROPY_EXCHANGE_CONFIRM_THRESHOLD", 2, minimum=2)
EXCHANGE_ENABLED = _env_bool("ENTROPY_EXCHANGE", True)

# ── Web Servers & Hosts ──────────────────────────────────────
DASHBOARD_HOST = os.getenv("ENTROPY_DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = _env_int("ENTROPY_DASHBOARD_PORT", 5000, minimum=1)
FLASK_HOST = DASHBOARD_HOST
FLASK_PORT = DASHBOARD_PORT
PUBLIC_DASHBOARD_URL = (
    os.getenv("ENTROPY_PUBLIC_DASHBOARD_URL", "").strip()
    or f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}"
)

VICTIM_HOST = os.getenv("ENTROPY_VICTIM_HOST", "0.0.0.0")
VICTIM_PORT = _env_int("ENTROPY_VICTIM_PORT", 5001, minimum=1)
PUBLIC_VICTIM_URL = (
    os.getenv("ENTROPY_PUBLIC_VICTIM_URL", "").strip()
    or f"http://{VICTIM_HOST}:{VICTIM_PORT}"
)

ATTACKER_HOST = "0.0.0.0"
ATTACKER_PORT = _env_int("ENTROPY_ATTACKER_PORT", 8001, minimum=1)
PUBLIC_ATTACKER_URL = (
    os.getenv("ENTROPY_PUBLIC_ATTACKER_URL", "").strip()
    or f"http://127.0.0.1:{ATTACKER_PORT}"
)

DEBUG_MODE = _env_bool("ENTROPY_DEBUG", False)
SECRET_KEY = os.getenv("ENTROPY_SECRET_KEY", "entropy-local-development-only")
# Live-demo default: real kill+quarantine+restore active. Dry-run is opt-in.
DRY_RUN = _env_bool("ENTROPY_DRY_RUN", False)
CONTROL_TOKEN = (
    os.getenv("ENTROPY_CONTROL_TOKEN")
    or os.getenv("CONTROL_TOKEN")
    or "entropy-lab"
).strip()

# ── Detection Pipeline Supervision ───────────────────────────
# The pipeline is the process that actually kills the attacker and
# moves files to quarantine. Starting a web surface (SOC dashboard or
# victim explorer) also starts it and keeps it alive, so the backend
# can never be "quietly missing" during a demo.
AUTOSTART_PIPELINE = _env_bool("ENTROPY_AUTOSTART_PIPELINE", True)
# A heartbeat older than this counts as "pipeline is not running".
PIPELINE_STALE_SECONDS = _env_float(
    "ENTROPY_PIPELINE_STALE_SECONDS", 8.0, minimum=2.0
)
# How often the supervisor re-checks the pipeline.
PIPELINE_SUPERVISOR_INTERVAL = _env_float(
    "ENTROPY_PIPELINE_SUPERVISOR_INTERVAL", 3.0, minimum=0.5
)
# Minimum delay between pipeline start attempts (backs off when the
# pipeline keeps crashing).
PIPELINE_RESTART_COOLDOWN = _env_float(
    "ENTROPY_PIPELINE_RESTART_COOLDOWN", 10.0, minimum=1.0
)

# ── Privileged Vault Access (Victim UI) ──────────────────────
VAULT_USER = os.getenv("ENTROPY_VAULT_USER", "victim_user")
VAULT_PIN = os.getenv("ENTROPY_VAULT_PIN", "1234")
VAULT_SESSION_HOURS = _env_int("ENTROPY_VAULT_SESSION_HOURS", 8, minimum=0)

# ── Reinforcement Learning (DQN) ─────────────────────────────
STATE_SIZE = 10
ACTION_SIZE = 4
LEARNING_RATE = 0.001
GAMMA = 0.95
EPSILON_START = 1.0
EPSILON_END = 0.01
EPSILON_DECAY = 0.995
MEMORY_SIZE = 10000
BATCH_SIZE = 64
TARGET_UPDATE = 10

ACTION_IGNORE = 0
ACTION_ALERT = 1
ACTION_TERMINATE = 2
ACTION_TERMINATE_QUARANTINE = 3

NORMAL_ENTROPY_RANGES = {
    ".txt": (3.0, 5.5),   ".doc": (6.0, 7.5),   ".docx": (6.0, 7.5),
    ".pdf": (6.5, 7.8),   ".jpg": (7.0, 7.8),   ".jpeg": (7.0, 7.8),
    ".png": (6.5, 7.5),   ".mp4": (7.0, 7.9),   ".zip": (7.5, 8.0),
    ".exe": (5.0, 7.2),   ".py": (4.0, 6.0),    ".csv": (4.0, 6.0),
    ".xlsx": (6.0, 7.5),  ".dat": (4.0, 6.5),
}
