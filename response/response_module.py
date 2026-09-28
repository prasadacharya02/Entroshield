# ============================================================
# ENTROPY - Response Module
# response\response_module.py
#
# WHAT THIS DOES:
# Takes action when DQN detects ransomware.
#
# ACTIONS:
# 1. Kill the malicious process (using psutil)
# 2. Quarantine the suspicious file (move to safe folder)
# 3. Generate fingerprint (SHA-256 hash)
# 4. Log everything for blockchain recording
#
# SAFETY:
# - Never kills whitelisted processes
# - Never touches files outside quarantine
# - Always logs every action taken
# ============================================================

import os
import sys
import time
import shutil
import hashlib
import logging
import psutil
from datetime import datetime
from threading import Lock
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

log = logging.getLogger("ResponseModule")


# ============================================================
# FINGERPRINT GENERATOR
# Creates a unique hash identity for each threat event.
# Uses SHA-256 + SHA3-256 dual fingerprint for forensic integrity
# This hash goes into the blockchain.
# ============================================================

class FingerprintGenerator:
    """
    Generates cryptographic fingerprints for threat events.

    WHY:
    ────
    The blockchain stores fingerprints, not entire files.
    A fingerprint uniquely identifies a specific threat event.
    Uses SHA3-256 (NIST standard) + SHA-256 for industry-grade integrity.
    """

    def generate_file_fingerprint(self, file_path: str) -> str:
        """
        Generate SHA3-256 fingerprint of a file (with SHA-256 fallback).

        Returns:
            SHA3-256 hash string (64 hex chars) or SHA-256 if file unreadable
        """
        try:
            # Primary: SHA3-256 (industry standard, claimed in pitch)
            sha3 = hashlib.sha3_256()
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(65536):
                    sha3.update(chunk)
                    sha256.update(chunk)
            # Store dual hash, return SHA3 as primary
            return sha3.hexdigest()
        except Exception as e:
            log.error(f"Fingerprint error for {file_path}: {e}")
            return hashlib.sha3_256(
                file_path.encode()
            ).hexdigest()

    def generate_file_fingerprint_dual(self, file_path: str) -> dict:
        """Return both SHA-256 and SHA3-256 for maximum integrity."""
        try:
            sha256 = hashlib.sha256()
            sha3 = hashlib.sha3_256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
                    sha3.update(chunk)
            return {
                "sha256": sha256.hexdigest(),
                "sha3_256": sha3.hexdigest(),
                "primary": sha3.hexdigest(),
            }
        except Exception as e:
            log.error(f"Dual fingerprint error for {file_path}: {e}")
            fallback = hashlib.sha3_256(file_path.encode()).hexdigest()
            return {"sha256": fallback, "sha3_256": fallback, "primary": fallback}

    def generate_event_fingerprint(self, event: dict) -> str:
        """
        Generate fingerprint from event data.
        Used when file is already deleted/encrypted.
        """
        data = (
            f"{event.get('file_path', '')}"
            f"{event.get('timestamp', '')}"
            f"{event.get('entropy_overall', '')}"
            f"{event.get('process', {}).get('pid', '')}"
        ).encode()
        # SHA3-256 for event fingerprint
        return hashlib.sha3_256(data).hexdigest()


# ============================================================
# PROCESS TERMINATOR
# Safely kills malicious processes.
# ============================================================

class ProcessTerminator:
    """
    Terminates malicious processes using psutil.

    SAFETY MEASURES:
    ────────────────
    1. Never kills whitelisted processes
    2. Never kills system processes (PID < 10)
    3. Never kills our own process
    4. Verifies process exists before killing
    5. Verifies process is dead after killing
    """

    def __init__(self):
        self.our_pid         = os.getpid()
        self.terminated_pids = set()

    def terminate(self, pid: int,
                  process_name: str = None,
                  expected_create_time: Optional[float] = None) -> dict:
        """
        Terminate a process by PID.

        Args:
            pid:          Process ID to kill
            process_name: Process name (for safety check)

        Returns:
            Result dictionary with success status
        """
        result = {
            'success'     : False,
            'pid'         : pid,
            'process_name': process_name,
            'action'      : 'terminate',
            'message'     : '',
            'timestamp'   : datetime.now().isoformat(),
            'dry_run'     : bool(config.DRY_RUN),
        }

        # Refuse incomplete identities. A best-effort process guess must
        # never be enough to kill a process automatically.
        if not isinstance(pid, int) or pid <= 0 or not process_name:
            result['message'] = 'Refused: PID and process name are required'
            log.warning('[SAFETY] Refused termination with incomplete identity')
            return result

        # Safety check 1: Don't kill our own process
        if pid == self.our_pid:
            result['message'] = 'Refused: cannot kill own process'
            log.warning(f"[SAFETY] Refused to kill own PID {pid}")
            return result

        # Safety check 2: Don't kill system processes
        if pid < 10:
            result['message'] = f'Refused: system PID {pid}'
            log.warning(f"[SAFETY] Refused to kill system PID {pid}")
            return result

        # Safety check 3: Don't kill whitelisted processes. Compare both the
        # reported and actual names case-insensitively.
        whitelist = {p.lower() for p in config.WHITELISTED_PROCESSES}
        if process_name.lower() in whitelist:
            result['message'] = (f'Refused: {process_name} '
                                f'is whitelisted')
            log.warning(f"[SAFETY] Refused to kill "
                       f"whitelisted process: {process_name}")
            return result

        # Safety check 3b: ordinary user/OS software (browsers, the
        # Windows search indexer, COM surrogate, sync clients, Office,
        # the AV engine) routinely holds legitimate handles on files in
        # a user folder. It is never terminated automatically.
        if config.is_denied_process(process_name):
            result['message'] = (f'Refused: {process_name} is user/OS '
                                 f'software (never-kill list)')
            log.warning("[SAFETY] Refused to kill user/OS process: %s",
                        process_name)
            return result

        if config.DRY_RUN:
            result['success'] = True
            result['message'] = 'Dry-run: termination simulated, process left running'
            log.info('[DRY-RUN] Would terminate PID %s (%s)', pid, process_name)
            return result

        # Safety check 4: Don't kill already terminated
        if pid in self.terminated_pids:
            result['message'] = f'PID {pid} already terminated'
            result['success'] = True
            return result

        # Try to get process
        try:
            proc = psutil.Process(pid)

            # Re-read the identity immediately before termination. This
            # prevents killing a different process after PID reuse and rejects
            # stale or incorrectly attributed filesystem events.
            actual_name = proc.name()
            if actual_name.lower() != process_name.lower():
                result['message'] = (
                    f'Refused: process name mismatch '
                    f'(expected {process_name}, found {actual_name})'
                )
                log.warning(f"[SAFETY] Process identity mismatch for PID {pid}")
                return result

            if actual_name.lower() in whitelist:
                result['message'] = (f'Refused: actual process '
                                    f'{actual_name} is whitelisted')
                log.warning(f"[SAFETY] Refused to kill "
                           f"whitelisted: {actual_name}")
                return result

            if config.is_denied_process(actual_name):
                result['message'] = (f'Refused: actual process '
                                    f'{actual_name} is user/OS software')
                log.warning("[SAFETY] Refused to kill user/OS process: %s",
                            actual_name)
                return result

            if expected_create_time is not None:
                actual_create_time = proc.create_time()
                if abs(actual_create_time - expected_create_time) > 1.0:
                    result['message'] = 'Refused: process identity is stale'
                    log.warning(f"[SAFETY] Creation-time mismatch for PID {pid}")
                    return result

            # Safety check 5: never kill our own software. A file-event
            # attribution must never be able to point the defender at
            # its pipeline, dashboard, or any lab service process.
            try:
                cmdline = " ".join(proc.cmdline() or []).lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                cmdline = ""
            for marker in getattr(config, "DEFENDER_TOOLING_MARKERS", ()):
                if marker and marker.lower() in cmdline:
                    result['message'] = (
                        f'Refused: PID {pid} runs defender tooling '
                        f'(cmdline matches {marker!r})'
                    )
                    log.warning(
                        f"[SAFETY] Refusing to kill our own software "
                        f"(PID {pid}, marker {marker!r})"
                    )
                    return result

            result['process_name'] = actual_name

            # Terminate the process
            log.info(f"[TERMINATE] Killing PID {pid} ({actual_name})")
            proc.terminate()

            # Wait up to 3 seconds for it to die
            try:
                proc.wait(timeout=3)
                result['success'] = True
                result['message'] = (f'Process {actual_name} '
                                    f'(PID {pid}) terminated')
                self.terminated_pids.add(pid)
                log.info(f"[TERMINATE] SUCCESS: PID {pid} terminated")

            except psutil.TimeoutExpired:
                # This waiter may not be the process's parent (the
                # malware's parent is the attacker console). A process
                # that has exited but not yet been reaped by its real
                # parent shows up as a zombie: it is already dead.
                try:
                    if proc.status() == psutil.STATUS_ZOMBIE:
                        result['success'] = True
                        result['message'] = (
                            f'Process {actual_name} (PID {pid}) '
                            f'terminated (awaiting reap)')
                        self.terminated_pids.add(pid)
                        log.info(
                            f"[TERMINATE] SUCCESS: PID {pid} terminated "
                            f"(zombie)")
                        return result
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    result['success'] = True
                    result['message'] = f'PID {pid} already gone'
                    self.terminated_pids.add(pid)
                    log.info(f"[TERMINATE] PID {pid} already gone")
                    return result
                # Force kill if terminate didn't work
                proc.kill()
                result['success'] = True
                result['message'] = (f'Process {actual_name} '
                                    f'(PID {pid}) force killed')
                self.terminated_pids.add(pid)
                log.info(f"[TERMINATE] FORCE KILLED: PID {pid}")

        except psutil.NoSuchProcess:
            result['success'] = True
            result['message'] = f'PID {pid} already gone'
            log.info(f"[TERMINATE] PID {pid} already gone")

        except psutil.AccessDenied:
            result['message'] = (f'Access denied for PID {pid}. '
                                f'Run as Administrator.')
            log.error(f"[TERMINATE] Access denied for PID {pid}")

        except Exception as e:
            result['message'] = f'Error: {str(e)}'
            log.error(f"[TERMINATE] Error killing PID {pid}: {e}")

        return result


# ============================================================
# FILE QUARANTINE
# Moves suspicious files to a protected location.
# ============================================================

class FileQuarantine:
    """
    Moves suspicious files to quarantine directory.

    QUARANTINE PROCESS:
    ───────────────────
    1. Generate fingerprint of the file
    2. Create unique quarantine filename
    3. Move file to quarantine directory
    4. Create metadata file alongside it
    5. Set restricted permissions

    QUARANTINE DIRECTORY:
    ---------------------
    quarantine_storage/
    - {hash}_{original_name}        (the quarantined file)
    - {hash}_{original_name}.meta.json (metadata about it)
    """

    def __init__(self):
        self.quarantine_dir = config.QUARANTINE_DIR
        self.lock           = Lock()
        self.fingerprinter  = FingerprintGenerator()

        # Create quarantine directory
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def quarantine(self, file_path: str,
                   event: dict = None) -> dict:
        """
        Move a file to quarantine.

        Args:
            file_path: Path to the suspicious file
            event:     The analysis event (for metadata)

        Returns:
            Result dictionary
        """
        result = {
            'success'         : False,
            'original_path'   : file_path,
            'quarantine_path' : None,
            'fingerprint'     : None,
            'message'         : '',
            'timestamp'       : datetime.now().isoformat(),
            'dry_run'         : bool(config.DRY_RUN),
        }

        if not os.path.exists(file_path):
            result['message'] = 'File not found (may be deleted)'
            log.warning(f"[QUARANTINE] File not found: {file_path}")
            return result

        if config.DRY_RUN:
            result['success'] = True
            result['message'] = 'Dry-run: quarantine simulated, file left in place'
            log.info('[DRY-RUN] Would quarantine %s', file_path)
            return result

        with self.lock:
            try:
                # Generate fingerprint
                fingerprint = self.fingerprinter.generate_file_fingerprint(
                    file_path
                )
                result['fingerprint'] = fingerprint

                # Create quarantine filename
                original_name  = os.path.basename(file_path)
                short_hash     = fingerprint[:12]
                quarantine_name = f"{short_hash}_{original_name}"
                quarantine_path = os.path.join(
                    self.quarantine_dir, quarantine_name
                )

                # Handle name conflicts. Evidence must NEVER be
                # overwritten: a second quarantine of the same file in
                # the same second used to reuse the timestamped name,
                # silently replacing the first copy (and the replace
                # looked like vault tampering to the monitor).
                n = 0
                while os.path.exists(quarantine_path):
                    n += 1
                    ts = str(int(time.time()))
                    quarantine_name = (f"{short_hash}_{ts}_{n}_{original_name}"
                                       if n > 1 else
                                       f"{short_hash}_{ts}_{original_name}")
                    quarantine_path = os.path.join(
                        self.quarantine_dir, quarantine_name
                    )

                # Move the file (never replaces an existing entry)
                shutil.move(file_path, quarantine_path)
                try:
                    # Read-only evidence: the vault is for forensics.
                    os.chmod(quarantine_path, 0o400)
                except OSError:
                    pass
                result['quarantine_path'] = quarantine_path

                log.info(f"[QUARANTINE] Moved: {file_path}")
                log.info(f"[QUARANTINE] To:    {quarantine_path}")

                # Save metadata
                self._save_metadata(
                    quarantine_path, file_path,
                    fingerprint, event
                )

                result['success'] = True
                result['message'] = (f'File quarantined: '
                                    f'{quarantine_name}')

            except PermissionError:
                result['message'] = ('Permission denied. '
                                    'Run as Administrator.')
                log.error(f"[QUARANTINE] Permission denied: {file_path}")

            except Exception as e:
                result['message'] = f'Error: {str(e)}'
                log.error(f"[QUARANTINE] Error: {e}")

        return result

    def _save_metadata(self, quarantine_path: str,
                       original_path: str,
                       fingerprint: str,
                       event: dict = None):
        """Save metadata file alongside quarantined file."""
        import json

        metadata = {
            'original_path'  : original_path,
            'quarantine_path': quarantine_path,
            'fingerprint'    : fingerprint,
            'quarantine_time': datetime.now().isoformat(),
            'entropy'        : (event.get('entropy_overall')
                               if event else None),
            'threat_score'   : (event.get('threat_score')
                               if event else None),
            'process'        : (event.get('process')
                               if event else None),
            'original_name'  : os.path.basename(original_path),
            'event_type'     : (event.get('event_type')
                               if event else None),
            'terminated_process': (event.get('response_kill')
                                   if event else None),
        }

        # The dashboard's /api/quarantine endpoint reads ".meta.json"
        # sidecars — keep this name as the single source of truth.
        meta_path = quarantine_path + '.meta.json'
        try:
            with open(meta_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            log.error(f"[QUARANTINE] Metadata error: {e}")

    def list_quarantined(self) -> list:
        """List all quarantined files."""
        quarantined = []
        try:
            for fname in os.listdir(self.quarantine_dir):
                if fname.endswith('.meta') or fname.endswith('.meta.json'):
                    continue
                fpath = os.path.join(self.quarantine_dir, fname)
                quarantined.append({
                    'filename': fname,
                    'path'    : fpath,
                    'size'    : os.path.getsize(fpath),
                    'time'    : datetime.fromtimestamp(
                        os.path.getctime(fpath)
                    ).isoformat(),
                })
        except Exception as e:
            log.error(f"[QUARANTINE] List error: {e}")
        return quarantined


# ============================================================
# RESPONSE MODULE
# Main class that coordinates all response actions.
# ============================================================

class ResponseModule:
    """
    Coordinates response to detected threats.

    FLOW:
    ─────
    AI Decision received
          ↓
    ResponseModule.respond(event, decision)
          ↓
    ┌─────────────────────────┐
    │ ACTION_IGNORE           │ → Log only
    │ ACTION_ALERT            │ → Log + Alert
    │ ACTION_TERMINATE        │ → Kill process
    │ ACTION_TERMINATE_QUAR   │ → Kill + Quarantine
    └─────────────────────────┘
          ↓
    Build response record
          ↓
    Send to blockchain logger
    """

    def __init__(self):
        self.terminator   = ProcessTerminator()
        self.quarantine   = FileQuarantine()
        self.fingerprinter= FingerprintGenerator()

        # Response history
        self.response_log = []
        self.lock         = Lock()

        # Callbacks
        self.callbacks    = []

        log.info("[ResponseModule] Initialized")
        log.info(f"[ResponseModule] Quarantine: {config.QUARANTINE_DIR}")

    def respond(self, event: dict, decision: dict) -> dict:
        """
        Execute response based on AI decision.

        Args:
            event:    Analyzed file event from pipeline
            decision: DQN decision dictionary

        Returns:
            Response record with all actions taken
        """
        action      = decision.get('action', config.ACTION_IGNORE)
        action_name = decision.get('action_name', 'IGNORE')
        file_path   = event.get('file_path', '')
        process     = event.get('process') or {}
        pid         = process.get('pid')
        proc_name   = process.get('name', 'unknown')

        log.info(f"")
        log.info(f"{'='*50}")
        log.info(f"[RESPONSE] Action: {action_name}")
        log.info(f"[RESPONSE] File  : {os.path.basename(file_path)}")
        log.info(f"[RESPONSE] PID   : {pid}")
        log.info(f"[RESPONSE] Score : {event.get('threat_score',0)}/100")
        log.info(f"{'='*50}")

        # Build response record
        response = {
            'timestamp'       : datetime.now().isoformat(),
            'event_id'        : event.get('event_id', ''),
            'file_path'       : file_path,
            'process_name'    : proc_name,
            'pid'             : pid,
            'entropy'         : event.get('entropy_overall'),
            'threat_score'    : event.get('threat_score', 0),
            'ai_action'       : action,
            'ai_action_name'  : action_name,
            'ai_confidence'   : decision.get('confidence', 0),
            'ai_explanation'  : decision.get('explanation', ''),

            # Actions taken
            'process_killed'  : False,
            'file_quarantined': False,
            'fingerprint'     : None,
            'terminate_result': None,
            'quarantine_result': None,

            # Final status
            'status'          : 'pending',
        }

        # Generate fingerprint
        response['fingerprint'] = (
            self.fingerprinter.generate_file_fingerprint(file_path)
            if os.path.exists(file_path)
            else self.fingerprinter.generate_event_fingerprint(event)
        )

        # Execute based on action
        if action == config.ACTION_IGNORE:
            response['status'] = 'ignored'
            log.info(f"[RESPONSE] Action: IGNORE - No action taken")

        elif action == config.ACTION_ALERT:
            response['status'] = 'alerted'
            log.info(f"[RESPONSE] Action: ALERT - Admin notified")
            self._send_alert(event, decision)

        elif action == config.ACTION_TERMINATE:
            # Kill process only
            if pid:
                t_result = self.terminator.terminate(pid, proc_name)
                response['terminate_result'] = t_result
                response['process_killed']   = t_result['success']

            response['status'] = 'terminated'
            log.info(f"[RESPONSE] Process terminated: "
                    f"{response['process_killed']}")

        elif action == config.ACTION_TERMINATE_QUARANTINE:
            # Kill process AND quarantine file

            # Step 1: Kill process first
            if pid:
                t_result = self.terminator.terminate(pid, proc_name)
                response['terminate_result'] = t_result
                response['process_killed']   = t_result['success']
                log.info(f"[RESPONSE] Process killed: "
                        f"{response['process_killed']}")

            # Step 2: Quarantine file
            if file_path and os.path.exists(file_path):
                q_result = self.quarantine.quarantine(file_path, event)
                response['quarantine_result'] = q_result
                response['file_quarantined']  = q_result['success']
                log.info(f"[RESPONSE] File quarantined: "
                        f"{response['file_quarantined']}")

            response['status'] = 'terminated_and_quarantined'

        # Log the response
        with self.lock:
            self.response_log.append(response)

        # Print summary
        self._print_summary(response)

        # Notify callbacks (blockchain logger, dashboard)
        for cb in self.callbacks:
            try:
                cb(response)
            except Exception as e:
                log.error(f"[RESPONSE] Callback error: {e}")

        return response

    def _send_alert(self, event: dict, decision: dict):
        """Send alert notification."""
        log.info(f"")
        log.info(f"  *** SECURITY ALERT ***")
        log.info(f"  File    : {event.get('file_path','')}")
        log.info(f"  Entropy : {event.get('entropy_overall',0):.2f}")
        log.info(f"  Score   : {event.get('threat_score',0):.0f}/100")
        log.info(f"  Reason  : {decision.get('explanation','')}")
        log.info(f"")

    def _print_summary(self, response: dict):
        """Print response summary."""
        log.info(f"")
        log.info(f"  RESPONSE SUMMARY")
        log.info(f"  {'─'*40}")
        log.info(f"  Action    : {response['ai_action_name']}")
        log.info(f"  Status    : {response['status']}")
        log.info(f"  Entropy   : {response['entropy']}")
        log.info(f"  Score     : {response['threat_score']}/100")
        log.info(f"  Killed    : {response['process_killed']}")
        log.info(f"  Quarantined: {response['file_quarantined']}")
        log.info(f"  Fingerprint: {str(response['fingerprint'])[:20]}...")
        log.info(f"  {'─'*40}")
        log.info(f"")

    def register_callback(self, func):
        """Register callback for response events."""
        self.callbacks.append(func)

    def get_response_log(self) -> list:
        """Get all response records."""
        with self.lock:
            return list(self.response_log)

    def get_stats(self) -> dict:
        """Get response statistics."""
        log = self.get_response_log()
        return {
            'total_responses' : len(log),
            'processes_killed': sum(1 for r in log
                                   if r['process_killed']),
            'files_quarantined': sum(1 for r in log
                                    if r['file_quarantined']),
            'alerts_sent'     : sum(1 for r in log
                                   if r['status'] == 'alerted'),
            'ignored'         : sum(1 for r in log
                                   if r['status'] == 'ignored'),
        }


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    import sys
    logging.basicConfig(
        level   = logging.INFO,
        format  = "%(asctime)s [%(levelname)s] %(message)s",
        handlers= [logging.StreamHandler()]
    )

    if sys.stdout.encoding != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    print()
    print("=" * 60)
    print("  ENTROPY - Response Module Test")
    print("=" * 60)
    print()

    module = ResponseModule()

    # ── Test 1: Quarantine a test file ────────────────────
    print("TEST 1: File Quarantine")
    print("-" * 40)

    # Create a test file to quarantine
    test_file = os.path.join(config.TESTING_DATA_DIR, "test_to_quarantine.dat")
    os.makedirs(config.TESTING_DATA_DIR, exist_ok=True)

    with open(test_file, 'wb') as f:
        f.write(os.urandom(5000))

    print(f"Created test file: {test_file}")
    print(f"File exists: {os.path.exists(test_file)}")
    print()

    # Simulate an event
    test_event = {
        'event_id'       : 'test001',
        'file_path'      : test_file,
        'entropy_overall': 7.98,
        'threat_score'   : 90.0,
        'events_per_sec' : 15.0,
        'process'        : {'pid': 9999, 'name': 'test_process.exe'},
        'timestamp'      : datetime.now().isoformat(),
    }

    # Simulate a QUARANTINE decision
    test_decision = {
        'action'     : config.ACTION_TERMINATE_QUARANTINE,
        'action_name': 'TERMINATE_AND_QUARANTINE',
        'confidence' : 0.95,
        'explanation': 'High entropy + suspicious speed',
    }

    # Execute response
    response = module.respond(test_event, test_decision)

    print(f"Quarantine success: {response['file_quarantined']}")
    print(f"Quarantine path   : {response.get('quarantine_result',{}).get('quarantine_path','N/A')}")
    print(f"Fingerprint       : {str(response['fingerprint'])[:32]}...")

    # ── Test 2: Check quarantine folder ──────────────────
    print()
    print("TEST 2: Quarantine Folder Contents")
    print("-" * 40)
    quarantined = module.quarantine.list_quarantined()
    print(f"Files in quarantine: {len(quarantined)}")
    for f in quarantined:
        print(f"  {f['filename']} ({f['size']} bytes)")

    # ── Test 3: Safety check ──────────────────────────────
    print()
    print("TEST 3: Safety Checks")
    print("-" * 40)

    # Try to kill a whitelisted process
    safe_event    = dict(test_event)
    safe_event['process'] = {'pid': 4, 'name': 'svchost.exe'}
    safe_decision = dict(test_decision)
    safe_decision['action'] = config.ACTION_TERMINATE

    response2 = module.respond(safe_event, safe_decision)
    print(f"Whitelisted process killed: {response2['process_killed']}")
    print(f"(Should be False - safety check working)")

    # ── Stats ─────────────────────────────────────────────
    print()
    print("STATS")
    print("-" * 40)
    stats = module.get_stats()
    for k, v in stats.items():
        print(f"  {k:25}: {v}")

    print()
    print("=" * 60)
    print("Response Module Test Complete")
    print("=" * 60)