# ============================================================
# ENTROPY - File System Monitor (Polling Observer for Windows)
# monitoring\watchdog_monitor.py
# ============================================================

import os
import sys
import time
import json
import hashlib
import psutil
import logging
from datetime import datetime
from collections import deque, defaultdict
from threading import Lock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# Use PollingObserver to prevent Windows Win32 handle freezes
try:
    from watchdog.observers.polling import PollingObserver as Observer
except ImportError:
    from watchdog.observers import Observer

from watchdog.events import FileSystemEventHandler

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

log = logging.getLogger("FileMonitor")


class EventStore:
    def __init__(self, max_events=2000):
        self.events    = deque(maxlen=max_events)
        self.lock      = Lock()
        self.callbacks = []
    
    def add_event(self, event):
        with self.lock:
            self.events.append(event)
        for callback in self.callbacks:
            try:
                callback(event)
            except Exception as e:
                log.error(f"Callback error: {e}")
    
    def get_recent_events(self, n=50):
        with self.lock:
            return list(self.events)[-n:]
    
    def get_all_events(self):
        with self.lock:
            return list(self.events)
    
    def register_callback(self, func):
        self.callbacks.append(func)


class ProcessFinder:
    """Fast, non-blocking process attribution with explicit verification.

    Attribution is two-tier:
      1. open-file evidence  — a process holds the file open right now,
         so its identity is verified;
      2. recent-process guess — the youngest non-whitelisted process,
         which is NEVER treated as verified identity (the response layer
         refuses to act on unverified attribution).
    """

    GUESS_MAX_AGE_SECONDS = 120

    def __init__(self):
        pass

    def _find_by_open_file(self, file_path):
        """Return the process that currently holds *file_path* open."""
        try:
            target = os.path.realpath(file_path)
        except OSError:
            return None

        for proc in psutil.process_iter(
            ['pid', 'name', 'create_time']
        ):
            try:
                for opened in proc.open_files():
                    try:
                        if os.path.realpath(opened.path) == target:
                            info = {
                                'pid': proc.info['pid'],
                                'name': proc.info.get('name') or proc.name(),
                                'create_time': proc.info.get('create_time'),
                                'identity_verified': True,
                            }
                            # The command line is carried for the
                            # response layer's safety gate: the
                            # defender must be able to tell the
                            # attacker's process apart from its own
                            # software (never kill itself).
                            try:
                                cmdline = proc.cmdline()
                                if cmdline:
                                    info['cmdline'] = " ".join(
                                        cmdline
                                    )[:300]
                            except (
                                psutil.NoSuchProcess,
                                psutil.AccessDenied,
                                OSError,
                            ):
                                pass
                            return info
                    except (OSError, ValueError):
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    def _find_recent_suspicious(self, max_age_seconds=None):
        """Guess: the youngest non-whitelisted process (unverified)."""
        if max_age_seconds is None:
            max_age_seconds = self.GUESS_MAX_AGE_SECONDS

        suspicious = []
        current_time = time.time()
        whitelist = {name.lower() for name in getattr(config, "WHITELISTED_PROCESSES", [])}

        try:
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                try:
                    proc_info = proc.info
                    process_name = proc_info.get('name') or ''
                    if process_name.lower() in whitelist:
                        continue
                    create_time = proc_info.get('create_time')
                    if create_time and (current_time - create_time) < max_age_seconds:
                        suspicious.append({
                            'pid': proc_info['pid'],
                            'name': process_name,
                            'create_time': create_time,
                            'identity_verified': False,
                            'age_seconds': round(current_time - create_time, 2)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        if not suspicious:
            return None
        suspicious.sort(key=lambda x: x['age_seconds'])
        return suspicious[0]

    def get_process_info(self, file_path):
        verified = self._find_by_open_file(file_path)
        if verified:
            info = dict(verified)
            info['identity_verified'] = True
            info['attribution_source'] = 'open_file'
            return info

        guess = self._find_recent_suspicious()
        if guess:
            info = dict(guess)
            # A recent-process guess must never be treated as verified
            # identity, regardless of what the heuristic reports.
            info['identity_verified'] = False
            info['attribution_source'] = 'recent_process_guess'
            return info

        return {
            'pid': 0,
            'name': 'unknown',
            'identity_verified': False,
            'attribution_source': 'none',
        }


class SpeedTracker:
    def __init__(self, window_seconds=10):
        self.window = window_seconds
        self.events = deque()
        self.lock   = Lock()
    
    def record_event(self):
        now = time.time()
        with self.lock:
            self.events.append(now)
            self._cleanup(now)
    
    def get_rate(self):
        now = time.time()
        with self.lock:
            self._cleanup(now)
            return len(self.events) / max(self.window, 1)
    
    def get_count_in_window(self):
        now = time.time()
        with self.lock:
            self._cleanup(now)
            return len(self.events)
    
    def _cleanup(self, now):
        cutoff = now - self.window
        while self.events and self.events[0] < cutoff:
            self.events.popleft()


class EntropyEventHandler(FileSystemEventHandler):
    def __init__(self, event_store, speed_tracker, process_finder,
                 protected_stores=None, watch_folders=None):
        super().__init__()
        self.event_store    = event_store
        self.speed_tracker  = speed_tracker
        self.process_finder = process_finder
        self.protected_stores = protected_stores or (
            config.QUARANTINE_DIR, config.BACKUP_DIR
        )
        self.watch_folders = tuple(
            os.path.abspath(w).lower() for w in (watch_folders or config.WATCH_FOLDERS)
        )
    
    def on_created(self, event):
        if not event.is_directory:
            self._handle("CREATED", event.src_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            self._handle("MODIFIED", event.src_path)
    
    def on_deleted(self, event):
        if not event.is_directory:
            self._handle("DELETED", event.src_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            self._handle("RENAMED", event.src_path, dest_path=event.dest_path)
    
    def _handle(self, event_type, file_path, dest_path=None):
        target_path = dest_path if dest_path else file_path
        if self._should_ignore(event_type, target_path):
            return
        
        self.speed_tracker.record_event()
        rate = self.speed_tracker.get_rate()
        win_count = self.speed_tracker.get_count_in_window()
        proc = self.process_finder.get_process_info(target_path)
        
        _, ext = os.path.splitext(target_path)
        
        file_size = None
        if os.path.exists(target_path):
            try: file_size = os.path.getsize(target_path)
            except Exception: pass
        
        event_dict = {
            'event_id'       : hashlib.md5(str(time.time()).encode()).hexdigest()[:12],
            'timestamp'      : datetime.now().isoformat(),
            'unix_timestamp' : time.time(),
            'event_type'     : event_type,
            'file_path'      : target_path,
            'original_path'  : file_path,
            'dest_path'      : dest_path,
            'file_extension' : ext.lower(),
            'file_size'      : file_size,
            'events_per_sec' : round(rate, 2),
            'events_in_window': win_count,
            'process'        : proc,
            'is_suspicious_speed': rate > getattr(config, "FILES_PER_SECOND_THRESHOLD", 1.0),
            'ext_changed'    : self._check_ext_changed(file_path, dest_path),
            'entropy_score'  : None,
            'ai_decision'    : None,
            'action_taken'   : None,
        }
        
        self.event_store.add_event(event_dict)
        
        symbols = {'CREATED': '[+]', 'MODIFIED': '[~]', 'DELETED': '[-]', 'RENAMED': '[>]'}
        sym = symbols.get(event_type, '[?]')
        fname = os.path.basename(target_path)
        log.info(f"{sym} {event_type:8} | {fname:35} | {rate:.1f} ev/sec")
    
    # Defender-only temporary suffixes. These are OUR files. An
    # attacker who writes to these exact suffixes is deliberately
    # hiding in defence noise and must NOT be ignored — the filter
    # only applies inside protected stores below.
    _DEFENDER_TMP_SUFFIXES = ('.tmp', '.temp', '.log', '.part', '.crdownload',
                              '.swp', '.swx', '.bak', '~')

    def _should_ignore(self, event_type, file_path):
        p = file_path.lower()
        fn = os.path.basename(file_path)

        # Always ignore log files regardless of folder.
        if p.endswith('.log'):
            return True

        # Hidden / temp names are only ignored OUTSIDE the victim
        # folder. Inside the watched victim tree, ransomware CAN hide
        # files by prefixing with '.' or '~' (Conti/LockBit both do
        # this for staging files) so we must analyze them.
        in_protected = FileMonitor._is_protected_store_path(
            file_path, self.protected_stores
        )
        in_victim = any(
            os.path.commonpath([p, wp.lower()]) == wp.lower()
            for wp in (self.watch_folders or [])
        )
        if not in_victim:
            if fn.startswith('~') or fn.startswith('.'):
                return True
            if any(p.endswith(s) for s in self._DEFENDER_TMP_SUFFIXES):
                return True

        if config.LOG_DIR.lower() in p:
            return True
        # Our own defense stores: only deletions are meaningful
        # (defense tamper). Writes there are the defender's own
        # quarantine/backup operations and must stay silent.
        if FileMonitor._is_protected_store_path(
            file_path, self.protected_stores
        ):
            if event_type != "DELETED":
                return True
            # The backup store's own housekeeping (manifest rewrites
            # via os.replace, temp files) deletes these names itself;
            # they are not tampering.
            name = os.path.basename(file_path)
            if name == "manifest.json" or ".tmp" in name:
                return True
            # The backup store evicts old version blobs itself
            # (bounded history); those deletions are housekeeping.
            try:
                from response.defender_actions import get_registry
                if get_registry().is_own_removal(file_path):
                    return True
            except Exception:
                pass
        return False
    
    def _check_ext_changed(self, src_path, dest_path):
        if not dest_path: return False
        _, s_ext = os.path.splitext(src_path)
        _, d_ext = os.path.splitext(dest_path)
        return s_ext.lower() != d_ext.lower()


class FileMonitor:
    def __init__(self):
        self.event_store    = EventStore()
        self.speed_tracker  = SpeedTracker()
        self.process_finder = ProcessFinder()
        # The defender's own stores are always watched, but only for
        # DELETIONS: writes there are our own quarantine/backup
        # operations (feedback loop), while deletions there mean the
        # attacker is destroying recovery capability.
        self.protected_stores = (config.BACKUP_DIR, config.QUARANTINE_DIR)
        self.handler = EntropyEventHandler(
            self.event_store, self.speed_tracker, self.process_finder,
            protected_stores=self.protected_stores,
        )
        self.observer       = Observer(timeout=0.2)
        self.running        = False

    @staticmethod
    def _is_protected_store_path(file_path: str, stores) -> bool:
        target = os.path.abspath(file_path).lower()
        return any(
            target == os.path.abspath(store).lower() or
            target.startswith(os.path.abspath(store).lower() + os.sep)
            for store in stores
        )

    def start(self):
        log.info("=" * 60)
        log.info("  ENTROPY Polling File Monitor Active")
        log.info("=" * 60)

        watched = 0
        for folder in config.WATCH_FOLDERS:
            if os.path.exists(folder):
                self.observer.schedule(self.handler, folder, recursive=True)
                log.info(f"[WATCHING RECURSIVE] {folder}")
                watched += 1

        for store in self.protected_stores:
            if os.path.exists(store) and not any(
                os.path.abspath(store) == os.path.abspath(folder)
                for folder in config.WATCH_FOLDERS
            ):
                self.observer.schedule(self.handler, store, recursive=True)
                log.info(f"[WATCHING PROTECTED STORE] {store}")

        self.observer.start()
        self.running = True
    
    def stop(self):
        self.observer.stop()
        self.observer.join()
        self.running = False
    
    def register_callback(self, func):
        self.event_store.register_callback(func)