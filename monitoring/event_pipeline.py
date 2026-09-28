# ============================================================
# ENTROPY - Event Pipeline
# monitoring\event_pipeline.py
#
# WHAT THIS DOES:
# Connects the File Monitor and Entropy Calculator.
#
# FLOW:
# File Monitor detects event
#       ↓
# Event Pipeline receives it
#       ↓
# Entropy Calculator analyzes the file
#       ↓
# Combined result stored and displayed
#
# This is the BRIDGE between monitoring and analysis.
# ============================================================

import os
import sys
import time
import json
import logging
from datetime import datetime
from threading import Thread, Lock
from queue import Queue, Empty, Full
from collections import deque

# Add parent folder to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

from monitoring.watchdog_monitor import FileMonitor
from monitoring.event_deduplicator import EventDeduplicator
from monitoring.defense_guard import collect_threat_flags
from entropy.entropy_calculator  import EntropyAnalyzer, visualize_entropy

# ── Setup Logging ─────────────────────────────────────────
logging.basicConfig(
    level    = logging.INFO,
    format   = "%(asctime)s [%(levelname)s] %(message)s",
    handlers = [
        logging.FileHandler(config.LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Fix Windows terminal encoding
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

log = logging.getLogger("Pipeline")


# ============================================================
# ANALYZED EVENT STORE
# Stores events AFTER entropy analysis is complete.
# The AI engine will read from here.
# ============================================================

class AnalyzedEventStore:
    """
    Stores file events that have been through entropy analysis.

    Each event here contains:
    - Original file event (path, type, speed, process)
    - Entropy analysis (score, delta, suspicion level)
    - Combined threat indicators

    The AI engine reads from this store.
    """

    def __init__(self, max_events=500):
        self.events = deque(maxlen=max_events)
        self.lock   = Lock()
        self.callbacks = []
        self.dropped_count = 0

    def add(self, event):
        with self.lock:
            if len(self.events) == self.events.maxlen:
                self.dropped_count += 1
                log.warning("Analyzed event store full; evicting oldest event")
            self.events.append(event)

        for cb in self.callbacks:
            try:
                cb(event)
            except Exception as e:
                log.error(f"Callback error: {e}")

    def get_recent(self, n=20):
        with self.lock:
            return list(self.events)[-n:]

    def get_all(self):
        with self.lock:
            return list(self.events)

    def get_suspicious(self):
        """Return only events flagged as suspicious."""
        with self.lock:
            return [e for e in self.events
                    if e.get('is_suspicious', False)]

    def register_callback(self, func):
        self.callbacks.append(func)

    def count(self):
        with self.lock:
            return len(self.events)

    def dropped(self):
        with self.lock:
            return self.dropped_count


# ============================================================
# EVENT PIPELINE
# The main connector between monitor and entropy calculator.
# ============================================================

def _is_genuine_rename(event: dict) -> bool:
    """True unless the 'rename' source still exists (inode reuse)."""
    src = event.get('original_path') or ''
    dest = event.get('dest_path') or event.get('file_path') or ''
    if not src or not dest or src == dest:
        return False
    return not os.path.exists(src)


class EventPipeline:
    """
    Connects file monitoring to entropy analysis.

    When the file monitor detects an event:
    1. This pipeline receives it via callback
    2. Runs entropy analysis on the affected file
    3. Combines monitor data + entropy data
    4. Stores the enriched event
    5. Notifies the next stage (AI engine)

    IMPORTANT:
    Entropy analysis runs in a BACKGROUND THREAD.
    This prevents blocking the file monitor.
    """

    def __init__(self):
        # Components
        self.file_monitor    = FileMonitor()
        self.entropy_analyzer = EntropyAnalyzer()
        self.analyzed_store  = AnalyzedEventStore(max_events=500)
        self.deduplicator    = EventDeduplicator(config.EVENT_DEDUP_WINDOW_SECONDS)

        # Queue for events waiting to be analyzed
        # Monitor puts events here, analyzer reads from here
        # Do not use deque(maxlen=...): silently evicting pending events can
        # cause the detector to miss files during a burst. This queue is
        # drained by the worker and overload is exposed through statistics.
        self.pending_queue = Queue()
        self.queue_lock    = Lock()

        # Statistics
        self.stats = {
            'total_received'   : 0,
            'total_analyzed'   : 0,
            'total_suspicious' : 0,
            'total_skipped'    : 0,
            'total_dropped'    : 0,
            'total_deduplicated': 0,
        }

        # Control flag
        self.running = False

    def start(self):
        """Start the pipeline."""
        log.info("=" * 60)
        log.info("  ENTROPY Pipeline Starting")
        log.info("=" * 60)

        # Register our callback with the file monitor
        # When monitor detects event → _on_file_event() is called
        self.file_monitor.register_callback(self._on_file_event)

        # Start the entropy analysis worker thread
        self.running = True
        self.worker_thread = Thread(
            target = self._entropy_worker,
            daemon = True,
            name   = "EntropyWorker"
        )
        self.worker_thread.start()
        log.info("[OK] Entropy analysis worker started")

        # Start the file monitor
        self.file_monitor.start()

        log.info("[OK] Pipeline is active")
        log.info("")

    def stop(self):
        """Stop the pipeline."""
        log.info("Stopping pipeline...")
        self.running = False
        self.file_monitor.stop()
        log.info("Pipeline stopped.")

    def _on_file_event(self, event):
        """
        Called by file monitor when a file event occurs.

        This runs in the watchdog thread.
        We just add to queue and return quickly.
        Heavy analysis happens in the worker thread.
        """
        if self.deduplicator.is_duplicate(event):
            self.stats['total_deduplicated'] += 1
            log.debug(
                "Duplicate filesystem event suppressed: %s %s",
                event.get('event_type'), event.get('file_path'),
            )
            return

        self.stats['total_received'] += 1

        evt_type = event['event_type']

        # ── Reject fake renames ──
        # The polling observer infers a rename from a matching inode.
        # When files are deleted and recreated (lab reset, the
        # defender's own restore), freed inodes are reused, so it
        # reports renames between UNRELATED files ("Tax_Returns.pdf ->
        # Notes.txt"). Trusting those moved entropy + backup history to
        # the wrong file, so later restores wrote the wrong content. A
        # genuine rename leaves the source path gone.
        if evt_type == 'RENAMED' and not _is_genuine_rename(event):
            event = dict(event)
            event['event_type'] = 'CREATED'
            event['original_path'] = event.get('dest_path') or \
                event.get('file_path')
            event['file_path'] = event['original_path']
            event['dest_path'] = None
            event['ext_changed'] = False
            evt_type = 'CREATED'

        # Folders are not documents (a lab reset recreates them).
        if os.path.isdir(event.get('file_path') or ''):
            return

        # ── CREATED and MODIFIED go straight to entropy ──
        if evt_type in ('CREATED', 'MODIFIED'):
            self._enqueue_event(event)

        # ── RENAMED = analyze the NEW filename (dest_path) ──
        # This catches ransomware renaming .txt → .locked.
        # Note: the monitor already sets file_path=dest on RENAMED
        # events, so the pre-rename path is in 'original_path' —
        # transfer_history from the real source or the pre-rename
        # entropy history (and therefore the delta signal) is lost.
        elif evt_type == 'RENAMED':
            dest = event.get('dest_path')
            src = event.get('original_path') or event.get('file_path')
            if dest and os.path.exists(dest):
                # Create a copy of the event with dest_path as the file_path
                # This makes the entropy analyzer read the .locked file
                self.entropy_analyzer.transfer_history(src, dest)
                renamed_event = dict(event)
                renamed_event['file_path'] = dest
                renamed_event['original_path'] = src
                self._enqueue_event(renamed_event)
            else:
                self._store_without_entropy(event)

        # ── DELETED can't be read ──
        else:
            self._store_without_entropy(event)

    def _enqueue_event(self, event):
        """Queue an event without silently discarding it when overloaded."""
        try:
            self.pending_queue.put_nowait(event)
        except Full:
            self.stats['total_dropped'] += 1
            log.error(
                "Analysis queue full; dropped event %s for %s",
                event.get('event_id'), event.get('file_path'),
            )

    def _entropy_worker(self):
        """Background thread — processes the pending queue."""
        while self.running or not self.pending_queue.empty():
            event = None
            try:
                event = self.pending_queue.get(timeout=0.1)
            except Empty:
                continue

            try:
                self._analyze_event(event)
            finally:
                self.pending_queue.task_done()

    def _analyze_event(self, event):
        """Run entropy analysis on a single file event."""
        file_path = event['file_path']

        # ── If original file is gone, try dest_path ──
        if not os.path.exists(file_path):
            dest = event.get('dest_path')
            if dest and os.path.exists(dest):
                file_path = dest
                event['file_path'] = dest
            else:
                self.stats['total_skipped'] += 1
                return

        # ── Tiny files: too small for a meaningful entropy score, but
        #    the change itself must still reach the SOC timeline (a new
        #    empty/short note used to vanish without a trace). ──
        try:
            size = os.path.getsize(file_path)
            if size < 10:
                self.stats['total_skipped'] += 1
                self._store_without_entropy(
                    event, reason='File too small for entropy analysis')
                return
        except Exception:
            self.stats['total_skipped'] += 1
            return

        # ── Run entropy analysis ──
        try:
            entropy_result = self.entropy_analyzer.analyze(file_path)
        except Exception as e:
            log.error(f"Entropy analysis error for {file_path}: {e}")
            self.stats['total_skipped'] += 1
            return

        enriched_event = self._with_threat_flags(
            self._merge_event(event, entropy_result)
        )
        self.analyzed_store.add(enriched_event)
        self.stats['total_analyzed'] += 1

        if enriched_event['is_suspicious']:
            self.stats['total_suspicious'] += 1

        self._log_analyzed_event(enriched_event)

    def _store_without_entropy(self, event, reason='File deleted or renamed'):
        """
        Store a file event that doesn't need entropy analysis.
        (DELETED events, or RENAMED where dest is gone)
        """
        enriched = {
            # File event data
            'event_id'        : event['event_id'],
            'timestamp'       : event['timestamp'],
            'event_type'      : event['event_type'],
            'file_path'       : event['file_path'],
            'dest_path'       : event.get('dest_path'),
            'original_path'   : event.get('original_path'),
            'file_extension'  : event['file_extension'],
            'events_per_sec'  : event['events_per_sec'],
            'events_in_window': event['events_in_window'],
            'process'         : event.get('process'),

            # No entropy data
            'entropy_overall' : None,
            'entropy_delta'   : None,
            'entropy_score'   : None,
            'file_hash'       : None,
            'threat_score'    : 0.0,
            'is_suspicious'   : event.get('ext_changed', False),
            'reason'          : reason,
            'indicators'      : [],

            # Speed flag
            'is_suspicious_speed': event.get('is_suspicious_speed', False),

            # Extension change is suspicious for ransomware
            'ext_changed'     : event.get('ext_changed', False),

            # Pipeline metadata
            'entropy_analyzed': False,
            'pipeline_stage'  : 'monitor_only',
        }

        # Defense-tamper signals matter on this path too: a DELETED
        # event under the backup store is the whole point.
        enriched = self._with_threat_flags(enriched)

        self.analyzed_store.add(enriched)
        self.stats['total_analyzed'] += 1

    def _with_threat_flags(self, event: dict) -> dict:
        """Attach hard-confirmation signals (ransom note, defense
        tamper) before the decision engine sees the event. The
        benchmark harness calls the same collect_threat_flags
        function, so both paths stay identical."""
        try:
            event.update(collect_threat_flags(event))
        except Exception as flag_err:
            log.error(f"Threat flag collection failed: {flag_err}")
        return event

    def _merge_event(self, file_event, entropy_result):
        """
        Merge file monitor event with entropy analysis result.

        Creates one unified event dictionary that contains
        all information needed by the AI engine.
        """

        # Combined suspicion check
        is_suspicious = (
            entropy_result['is_suspicious'] or
            file_event.get('is_suspicious_speed', False) or
            file_event.get('ext_changed', False)
        )

        # Combined threat score
        threat_score = entropy_result['threat_score']

        # Add speed bonus to threat score
        if file_event.get('is_suspicious_speed', False):
            threat_score = min(100.0, threat_score + 25.0)

        # Add extension change bonus
        if file_event.get('ext_changed', False):
            threat_score = min(100.0, threat_score + 20.0)

        combined = {
            # ── File Event Data ────────────────────────────
            'event_id'         : file_event['event_id'],
            'timestamp'        : file_event['timestamp'],
            'event_type'       : file_event['event_type'],
            'file_path'        : file_event['file_path'],
            # RENAMED events carry the pre-rename path (needed for
            # backup-history transfer so restore works after disguise).
            'original_path'    : file_event.get('original_path'),
            'file_extension'   : file_event['file_extension'],
            'file_size'        : entropy_result['file_size'],
            'events_per_sec'   : file_event['events_per_sec'],
            'events_in_window' : file_event['events_in_window'],
            'process'          : file_event.get('process'),

            # ── Entropy Data ───────────────────────────────
            'entropy_overall'  : entropy_result['entropy_overall'],
            'entropy_start'    : entropy_result['entropy_start'],
            'entropy_middle'   : entropy_result['entropy_middle'],
            'entropy_end'      : entropy_result['entropy_end'],
            'entropy_delta'    : entropy_result['entropy_delta'],
            'prev_entropy'     : entropy_result['prev_entropy'],
            'file_hash'        : entropy_result['file_hash'],

            # ── Structural ciphertext fingerprints ─────────
            'chi2_uniformity'  : entropy_result.get('chi2_uniformity'),
            'chi2_tail'        : entropy_result.get('chi2_tail'),
            'magic_ok'         : entropy_result.get('magic_ok', True),
            'magic_sig'        : entropy_result.get('magic_sig', ''),

            # ── Normal Range ───────────────────────────────
            'normal_range_min' : entropy_result['normal_range_min'],
            'normal_range_max' : entropy_result['normal_range_max'],

            # ── Combined Analysis ──────────────────────────
            'threat_score'     : round(threat_score, 2),
            'is_suspicious'    : is_suspicious,
            'reason'           : entropy_result['reason'],
            'indicators'       : entropy_result['indicators'],

            # ── Flags ──────────────────────────────────────
            'is_suspicious_speed': file_event.get('is_suspicious_speed', False),
            'ext_changed'      : file_event.get('ext_changed', False),

            # ── Pipeline Metadata ──────────────────────────
            'entropy_analyzed' : True,
            'pipeline_stage'   : 'entropy_complete',

            # ── AI fields (filled later) ───────────────────
            'ai_decision'      : None,
            'ai_action'        : None,
            'action_taken'     : None,
        }
        return combined

    def _log_analyzed_event(self, event):
        """Log a nicely formatted analysis result."""

        filename = os.path.basename(event['file_path'])
        entropy  = event['entropy_overall']
        score    = event['threat_score']
        evt_type = event['event_type']

        if event['is_suspicious']:
            status = "*** SUSPICIOUS ***"
        else:
            status = "OK"

        bar = visualize_entropy(entropy) if entropy is not None else "N/A"

        log.info(f"")
        log.info(f"  [{evt_type}] {filename}")
        log.info(f"  Entropy : {bar}")
        log.info(f"  Speed   : {event['events_per_sec']:.1f} events/sec")
        log.info(f"  Score   : {score:.1f}/100  {status}")

        if event['is_suspicious'] and event['reason']:
            log.info(f"  Reason  : {event['reason']}")

        log.info(f"")

    def get_stats(self):
        """Get pipeline statistics."""
        return {
            **self.stats,
            'pending_queue_size': self.pending_queue.qsize(),
            'analyzed_stored'   : self.analyzed_store.count(),
            'suspicious_count'  : len(self.analyzed_store.get_suspicious()),
            'analyzed_dropped'  : self.analyzed_store.dropped(),
        }

    def register_ai_callback(self, func):
        """
        Register the AI engine callback.
        Called whenever a new analyzed event is ready.
        """
        self.analyzed_store.register_callback(func)


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("  ENTROPY - Pipeline Test")
    print("=" * 60)
    print()
    print("Monitor + Entropy Calculator connected.")
    print("Creating test files to trigger analysis...")
    print()
    print("Watch the entropy analysis appear automatically.")
    print("Press Ctrl+C to stop.")
    print()

    # Create and start the pipeline
    pipeline = EventPipeline()

    # Register a callback to show AI would receive
    def on_analyzed_event(event):
        if event.get('entropy_analyzed') and event['is_suspicious']:
            log.info(f"  [AI WOULD RECEIVE] Suspicious event!")
            log.info(f"  File: {os.path.basename(event['file_path'])}")
            log.info(f"  Entropy: {event['entropy_overall']}")
            log.info(f"  Score: {event['threat_score']}/100")

    pipeline.register_ai_callback(on_analyzed_event)
    pipeline.start()

    # After 5 seconds, create some test files automatically
    def create_test_files():
        time.sleep(5)
        test_dir = config.TESTING_DATA_DIR
        os.makedirs(test_dir, exist_ok=True)

        # ── Step 1: Normal file ──────────────────────────
        log.info("[TEST] Step 1: Creating NORMAL file...")
        log.info("[TEST] Expected: LOW entropy, NOT suspicious")
        normal = os.path.join(test_dir, "pipeline_test_normal.txt")
        with open(normal, 'w') as f:
            f.write("This is normal text content. " * 100)

        # Wait longer so monitor catches it BEFORE we change it
        time.sleep(8)

        # ── Step 2: High entropy file ────────────────────
        log.info("[TEST] Step 2: Creating HIGH ENTROPY file...")
        log.info("[TEST] Expected: HIGH entropy, SUSPICIOUS")
        suspicious = os.path.join(test_dir, "pipeline_test_encrypted.dat")
        with open(suspicious, 'wb') as f:
            f.write(os.urandom(50000))

        time.sleep(8)

        # ── Step 3: Simulate ransomware encrypting normal ─
        log.info("[TEST] Step 3: Simulating ransomware...")
        log.info("[TEST] Overwriting normal.txt with random bytes...")
        log.info("[TEST] Expected: HIGH entropy + DELTA detected")
        with open(normal, 'wb') as f:
            f.write(os.urandom(10000))

        time.sleep(8)

        log.info("[TEST] All test steps complete.")
        log.info("[TEST] Check results above.")

    # Run test file creation in background
    test_thread = Thread(target=create_test_files, daemon=True)
    test_thread.start()

    try:
        while True:
            time.sleep(10)
            stats = pipeline.get_stats()
            log.info(f"[STATS] Received:{stats['total_received']} | "
                    f"Analyzed:{stats['total_analyzed']} | "
                    f"Suspicious:{stats['total_suspicious']} | "
                    f"Queue:{stats['pending_queue_size']}")

    except KeyboardInterrupt:
        print()
        pipeline.stop()

        print()
        print("=" * 60)
        print("Pipeline Test Complete")
        print("=" * 60)

        stats = pipeline.get_stats()
        print(f"  Total events received : {stats['total_received']}")
        print(f"  Total analyzed        : {stats['total_analyzed']}")
        print(f"  Suspicious detected   : {stats['total_suspicious']}")

        print()
        print("Suspicious events:")
        for e in pipeline.analyzed_store.get_suspicious():
            print(f"  {e['event_type']:8} | "
                  f"{os.path.basename(e['file_path']):30} | "
                  f"Entropy: {e['entropy_overall']:.2f} | "
                  f"Score: {e['threat_score']:.0f}/100")