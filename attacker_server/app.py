from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
VICTIM_DIR = os.path.join(ROOT_DIR, "victim_server")
USER_FILES = os.path.join(VICTIM_DIR, "user_files")

HTML_PATH = os.path.join(
    BASE_DIR,
    "templates",
    "attacker.html",
)

sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, VICTIM_DIR)

import config
import ransomware_engines as engines

try:
    from create_fake_files import restore_all_files
except Exception:
    restore_all_files = None


# ============================================================
# Malware process manager
# ============================================================
# The attack runs as a SEPARATE OS process (python -m
# attacker_server.ransomware_engines <family>). This mirrors real
# malware — a rogue process on the machine — so the defender's
# response (kill the PID that has the file open + quarantine the
# file) acts on a genuine, verifiable process instead of a thread
# inside the attacker console.
#
#   operator stop  -> SIGINT -> clean exit (code 0)
#   defender kill  -> SIGTERM -> exit code 42 (KILLED_BY_DEFENDER)
#
# The streamed process output becomes the console log.
# ============================================================

_proc_lock = threading.Lock()
_proc = None            # subprocess.Popen | None
_proc_family = None     # selected family id
_stream = deque(maxlen=300)
_control_path = os.path.join(ROOT_DIR, "attacker_control.json")

_KILLED_EXIT = 42

_SCAN_RE = re.compile(
    r"scan complete:\s*(\d+)\s*targets,\s*(\d+)\s*skipped"
)
_HIT_RE = re.compile(r"encrypted\s+(\d+)/(\d+)")
_NOTE_RE = re.compile(r"Note dropped:")
_BYTES_RE = re.compile(r"\((\d+)\s*bytes\)")


def _write_control(payload):
    """Merge *payload* into the operator control file."""
    current = {}
    try:
        with open(_control_path, encoding="utf-8") as fh:
            current = json.load(fh)
    except (OSError, ValueError):
        pass
    current.update(payload)
    try:
        with open(_control_path, "w", encoding="utf-8") as fh:
            json.dump(current, fh)
    except OSError:
        pass


def _stream_reader(proc):
    """Copy the child's stdout into the in-memory console log.

    When the stream closes (the child exited — killed by the defender
    or finished), reap the child here. Without this the child sits as
    a zombie until something polls the console, and any *other*
    process waiting on that PID (the defender's ProcessTerminator is
    not the child's parent) times out on a process that is already
    dead.
    """
    try:
        for line in proc.stdout:
            text = line.rstrip("\n")
            if text:
                with _proc_lock:
                    _stream.append(text)
    except (OSError, ValueError):
        pass
    finally:
        try:
            proc.wait(timeout=10)
        except Exception:
            pass


def _spawn(family_id):
    """Start the attack as a child process. Returns (ok, message)."""
    global _proc, _proc_family
    with _proc_lock:
        if _proc is not None and _proc.poll() is None:
            return False, f"{_proc_family} already running"
        _stream.clear()
        _write_control({"factor": 1.0, "paused": False})
        command = [
            sys.executable,
            "-m",
            "attacker_server.ransomware_engines",
            family_id,
            "--control",
            _control_path,
        ]
        _proc = subprocess.Popen(
            command,
            cwd=ROOT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        _proc_family = family_id
    threading.Thread(
        target=_stream_reader, args=(_proc,), daemon=True
    ).start()
    return True, "ok"


def _child_state():
    """Summarize the running (or last) attack process."""
    with _proc_lock:
        proc = _proc
        family = _proc_family
        lines = list(_stream)

    if proc is None:
        return {
            "active": False, "family": None, "phase": "IDLE",
            "progress": 0, "log": lines, "pid": None,
            "defender_killed": False,
        }

    alive = proc.poll() is None
    last = lines[-1] if lines else ""

    targets = skipped = hit = total = notes = 0
    bytes_encrypted = 0
    for line in lines:
        m = _SCAN_RE.search(line)
        if m:
            targets, skipped = int(m.group(1)), int(m.group(2))
        m = _HIT_RE.search(line)
        if m:
            hit, total = int(m.group(1)), int(m.group(2))
        if _NOTE_RE.search(line):
            notes += 1
        m = _BYTES_RE.search(line)
        if m and "encrypting" in line:
            bytes_encrypted += int(m.group(1))

    defender_killed = ("TERMINATED BY DEFENSE" in last) or (
        (not alive) and proc.returncode == _KILLED_EXIT
    )

    if defender_killed:
        phase = "KILLED_BY_DEFENDER"
    elif alive:
        phase = (
            "PAUSED"
            if _read_control_or_default().get("paused")
            else "ENCRYPTING"
        )
    elif proc.returncode == 0:
        phase = "COMPLETED" if total else "STOPPED"
    else:
        phase = "STOPPED"

    return {
        "active": alive,
        "family": family,
        "phase": phase,
        "progress": round(min(100, hit / max(total, 1) * 100), 1) if total else 0,
        "targets": targets,
        "files_hit": hit,
        "files_skipped": skipped,
        "notes_dropped": notes,
        "bytes_encrypted": bytes_encrypted,
        "pid": proc.pid if alive else None,
        "returncode": proc.returncode,
        "defender_killed": defender_killed,
        "log": lines,
    }


def _read_control_or_default():
    try:
        with open(_control_path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _stop_child(operator: bool):
    """Stop the child: SIGINT for the operator, wait for exit."""
    with _proc_lock:
        proc = _proc
    if proc is None or proc.poll() is not None:
        return False
    try:
        proc.send_signal(signal.SIGINT if operator else signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return False
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    return True


def victim_snapshot():
    total = 0
    locked = 0
    notes = 0

    lock_extensions = (
        ".wncry",
        ".wncryt",
        ".ryk",
        ".maze",
        ".revil",
        ".lockbit",
        ".akira",
        ".clop",
        ".qilin",
        ".abcd",
    )

    note_markers = (
        "@please_read_me@",
        "ryukreadme",
        "restore-my-files",
        "recover-",
        "maze-readme",
        "revil-readme",
        "akira-readme",
        "clop-readme",
        "qilin-readme",
    )

    if not os.path.isdir(USER_FILES):
        return {
            "exists": False,
            "total": 0,
            "locked": 0,
            "notes": 0,
        }

    for directory, _, filenames in os.walk(USER_FILES):
        for filename in filenames:
            total += 1

            extension = os.path.splitext(filename)[1].lower()
            lowercase_name = filename.lower()

            if extension in lock_extensions:
                locked += 1

            if (
                extension.startswith(".")
                and len(extension) == 8
            ):
                locked += 1

            if any(marker in lowercase_name for marker in note_markers):
                notes += 1

    return {
        "exists": True,
        "total": total,
        "locked": locked,
        "notes": notes,
    }


def read_json(handler):
    content_length = int(
        handler.headers.get("Content-Length") or 0
    )

    if content_length <= 0:
        return {}

    raw = handler.rfile.read(content_length)

    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def send_json(handler, payload, status=200):
    body = json.dumps(payload).encode("utf-8")

    handler.send_response(status)
    handler.send_header(
        "Content-Type",
        "application/json; charset=utf-8",
    )
    handler.send_header(
        "Content-Length",
        str(len(body)),
    )
    handler.send_header(
        "Cache-Control",
        "no-store",
    )
    handler.end_headers()
    handler.wfile.write(body)


def send_text(
    handler,
    text,
    content_type="text/plain; charset=utf-8",
):
    body = text.encode("utf-8")

    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header(
        "Content-Disposition",
        "attachment; filename=campaign.log",
    )
    handler.end_headers()
    handler.wfile.write(body)


def send_html(handler):
    with open(HTML_PATH, "r", encoding="utf-8") as file:
        html = file.read()

    host_header = handler.headers.get(
        "Host",
        "127.0.0.1:8001",
    )

    host = host_header.split(":", 1)[0]

    forwarded_protocol = handler.headers.get(
        "X-Forwarded-Proto"
    )

    scheme = (
        "https"
        if forwarded_protocol == "https"
        else "http"
    )

    victim_url = (
        config.PUBLIC_VICTIM_URL
        or f"{scheme}://{host}:8002"
    )

    dashboard_url = (
        config.PUBLIC_DASHBOARD_URL
        or f"{scheme}://{host}:5000"
    )

    attacker_url = (
        config.PUBLIC_ATTACKER_URL
        or f"{scheme}://{host}:8001"
    )

    html = html.replace(
        "__VICTIM_URL__",
        victim_url,
    )

    html = html.replace(
        "__DASHBOARD_URL__",
        dashboard_url,
    )

    html = html.replace(
        "__ATTACKER_URL__",
        attacker_url,
    )
    html = html.replace(
        "__CONTROL_TOKEN__",
        getattr(config, "CONTROL_TOKEN", "") or "",
    )

    body = html.encode("utf-8")

    handler.send_response(200)
    handler.send_header(
        "Content-Type",
        "text/html; charset=utf-8",
    )
    handler.send_header(
        "Content-Length",
        str(len(body)),
    )
    handler.send_header(
        "Cache-Control",
        "no-store",
    )
    handler.end_headers()
    handler.wfile.write(body)


def control_authorized(handler):
    """
    Localhost is allowed by default.

    If ENTROPY_CONTROL_TOKEN is configured,
    remote control requires:
    Authorization: Bearer <token>
    """
    configured_token = config.CONTROL_TOKEN

    if configured_token:
        supplied = handler.headers.get(
            "Authorization",
            "",
        )

        expected = f"Bearer {configured_token}"

        return hmac.compare_digest(
            supplied,
            expected,
        )

    try:
        address = ipaddress.ip_address(
            handler.client_address[0]
        )
        return address.is_loopback
    except ValueError:
        return False


# Compatibility alias expected by tests/test_control_security.py
_control_authorized = control_authorized


def send_forbidden(handler):
    send_json(
        handler,
        {
            "ok": False,
            "error": (
                "control route requires local access "
                "or a valid bearer token"
            ),
        },
        status=403,
    )


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, format_string, *args):
        sys.stderr.write(
            "[attacker] "
            + (format_string % args)
            + "\n"
        )

    def do_GET(self):
        path = urlparse(self.path).path

        if path in {
            "/",
            "/index.html",
            "/attacker.html",
        }:
            send_html(self)
            return

        if path == "/api/families":
            send_json(self, engines.list_families())
            return

        if path == "/api/stats":
            stats = _child_state()
            stats["victim"] = victim_snapshot()
            send_json(self, stats)
            return

        if path == "/api/log":
            stats = engines.current_stats()
            lines = [
                entry.get("msg", "")
                for entry in stats.get("log", [])
            ]
            send_text(self, "\n".join(lines) + "\n")
            return

        self.send_error(404, "not found")

    def do_POST(self):
        path = urlparse(self.path).path

        protected_routes = {
            "/api/launch",
            "/api/stop",
            "/api/pause",
            "/api/resume",
            "/api/speed",
            "/api/reset",
        }

        if (
            path in protected_routes
            and not control_authorized(self)
        ):
            send_forbidden(self)
            return

        data = read_json(self)

        if path == "/api/launch":
            family = (
                data.get("family") or ""
            ).strip().lower()

            if family not in engines.FAMILIES:
                send_json(
                    self,
                    {
                        "ok": False,
                        "error": "unknown family",
                    },
                    status=400,
                )
                return

            snapshot = victim_snapshot()

            if (
                not snapshot["exists"]
                or snapshot["total"] == 0
            ):
                send_json(
                    self,
                    {
                        "ok": False,
                        "error": (
                            "victim folder is empty — "
                            "hit RESET first"
                        ),
                    },
                    status=400,
                )
                return

            current = _child_state()

            if current.get("active"):
                send_json(
                    self,
                    {
                        "ok": False,
                        "error": (
                            f"{current.get('family')} "
                            "already running"
                        ),
                    },
                    status=409,
                )
                return

            ok, message = _spawn(family)

            if not ok:
                send_json(
                    self,
                    {
                        "ok": False,
                        "error": message,
                    },
                    status=500,
                )
                return

            send_json(
                self,
                {
                    "ok": True,
                    "family": family,
                    "pid": _child_state()["pid"],
                    "stats": _child_state(),
                },
            )
            return

        if path == "/api/stop":
            # Operator stop = SIGINT (clean exit), distinct from the
            # defender's SIGTERM kill so the console can tell them apart.
            stopped = _stop_child(operator=True)
            send_json(
                self,
                {
                    "ok": True,
                    "stopped": bool(stopped),
                },
            )
            return

        if path == "/api/pause":
            state = _child_state()
            ok = bool(state.get("active"))
            if ok:
                _write_control({"paused": True})

            send_json(
                self,
                {
                    "ok": ok,
                    "paused": ok,
                },
            )
            return

        if path == "/api/resume":
            state = _child_state()
            ok = bool(state.get("active"))
            if ok:
                _write_control({"paused": False})

            send_json(
                self,
                {
                    "ok": ok,
                    "paused": False,
                },
            )
            return

        if path == "/api/speed":
            try:
                factor = float(
                    data.get("factor", 1.0)
                )

                speed = min(5.0, max(0.1, factor))
                _write_control({"factor": speed})

                send_json(
                    self,
                    {
                        "ok": True,
                        "speed_factor": speed,
                    },
                )
            except (TypeError, ValueError):
                send_json(
                    self,
                    {
                        "ok": False,
                        "error": "invalid speed",
                    },
                    status=400,
                )
            return

        if path == "/api/reset":
            if _child_state().get("active"):
                _stop_child(operator=True)

            if restore_all_files is None:
                send_json(
                    self,
                    {
                        "ok": False,
                        "error": (
                            "create_fake_files.py "
                            "is unavailable"
                        ),
                    },
                    status=500,
                )
                return

            try:
                restore_all_files()

                send_json(
                    self,
                    {
                        "ok": True,
                        "victim": victim_snapshot(),
                    },
                )
            except Exception as exc:
                send_json(
                    self,
                    {
                        "ok": False,
                        "error": str(exc),
                    },
                    status=500,
                )
            return

        self.send_error(404, "not found")


if __name__ == "__main__":
    if not os.path.isfile(HTML_PATH):
        print(f"MISSING: {HTML_PATH}")
        raise SystemExit(1)

    print("=" * 60)
    print("  ATTACKER SITE")
    print("  http://0.0.0.0:8001")
    print("=" * 60)

    server = ThreadingHTTPServer(
        ("0.0.0.0", 8001),
        Handler,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAttacker server stopped")
        server.shutdown()
        server.server_close()