"""Kill-safety and SOC-coherence regression tests.

Three failures seen in the live demo are locked down here:

1. **Legitimate software killed.** The Windows Search indexer, the COM
   surrogate (dllhost.exe) and browsers keep legitimate open handles on
   user files. Plain "which process holds this file open?" attribution
   therefore accused them during an attack and the pipeline terminated
   them (screenshots showed chrome.exe / dllhost.exe / SearchFilterHost.exe
   "KILLED"). They are now filtered at attribution, in the campaign kill
   memory, and at the termination gate.
2. **Contradictory decision panel.** The SOC showed
   "TERMINATE + QUARANTINE · CONFIDENCE 97%" next to an engine line
   reading "Decision: ALERT | Threat score: 0/100". The panel now shows
   the action taken, the persisted threat score and the escalation
   reason.
3. **Unreadable events plotted as entropy 0**, which turned the entropy
   graph into a 0↔8 sawtooth and hid the real spikes.
"""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import config
from monitoring.pipeline_runner import CampaignTracker, _terminate_process
from monitoring.watchdog_monitor import ProcessFinder
from storage.database import connect, init_db


class FixtureStructureTests(unittest.TestCase):
    """The victim estate must not look like corrupted ciphertext.

    The fixtures used to hide PNG bytes inside ``.jpg``/``.zip`` files (and
    plain text inside a ``.docx``), so every benign rewrite tripped the
    magic-byte detector: the defender quarantined ~20 its own clean files,
    which inflated the SOC counters with threats that never existed.
    """

    def test_every_fixture_matches_its_extension_magic(self):
        from entropy.entropy_calculator import _magic_matches
        from victim_server.create_fake_files import create_all_files

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "victim"
        create_all_files(root, clean=True, quiet=True)

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            with self.subTest(file=str(path.relative_to(root))):
                ok, signature = _magic_matches(path.read_bytes(), path.suffix)
                self.assertTrue(
                    ok, f"{path.name} header {signature!r} does not match "
                        f"{path.suffix}")

    def test_fixtures_are_never_flagged_by_the_detector(self):
        from entropy.entropy_calculator import EntropyAnalyzer
        from victim_server.create_fake_files import create_all_files

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "victim"
        create_all_files(root, clean=True, quiet=True)
        analyzer = EntropyAnalyzer()

        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            with self.subTest(file=str(path.relative_to(root))):
                result = analyzer.analyze(str(path))
                self.assertEqual(result.get("threat_score") or 0, 0.0,
                                 result.get("reasons"))


class PostKillRepairGateTests(unittest.TestCase):
    """Post-kill verification repairs ciphertext, not legitimate edits."""

    def test_ciphertext_evidence_triggers_repair(self):
        from monitoring.pipeline_runner import _needs_ciphertext_repair

        self.assertTrue(_needs_ciphertext_repair(
            {"magic_ok": False, "threat_score": 0.0}))
        self.assertTrue(_needs_ciphertext_repair(
            {"magic_ok": True, "threat_score": 45.0}))

    def test_clean_edit_is_left_alone(self):
        from monitoring.pipeline_runner import _needs_ciphertext_repair

        self.assertFalse(_needs_ciphertext_repair(
            {"magic_ok": True, "threat_score": 0.0,
             "entropy_overall": 7.58}))
        self.assertFalse(_needs_ciphertext_repair({}))
        self.assertFalse(_needs_ciphertext_repair(None))


class NeverKillListTests(unittest.TestCase):
    """config.is_denied_process must recognise user/OS software."""

    def test_windows_search_and_shell_processes_are_denied(self):
        for name in ("dllhost.exe", "SearchFilterHost.exe",
                     "SearchProtocolHost.exe", "SearchIndexer.exe",
                     "RuntimeBroker.exe", "sihost.exe"):
            with self.subTest(name=name):
                self.assertTrue(config.is_denied_process(name))

    def test_browsers_and_sync_clients_are_denied(self):
        for name in ("chrome.exe", "msedge.exe", "firefox.exe",
                     "OneDrive.exe", "Dropbox.exe", "Teams.exe"):
            with self.subTest(name=name):
                self.assertTrue(config.is_denied_process(name))

    def test_full_paths_are_denied(self):
        self.assertTrue(config.is_denied_process(
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"))
        self.assertTrue(config.is_denied_process(
            "/usr/lib/firefox/firefox"))

    def test_ransomware_and_defender_processes_are_not_denied(self):
        for name in ("ransomware_engines", "python3", "python.exe",
                     "wannacry.exe", "evil.bin"):
            with self.subTest(name=name):
                self.assertFalse(config.is_denied_process(name))

    def test_empty_and_none_are_safe(self):
        self.assertFalse(config.is_denied_process(None))
        self.assertFalse(config.is_denied_process(""))

    def test_deny_list_never_contains_the_lab_attacker(self):
        # The lab attack runs as a Python child process; if Python ever
        # landed on the never-kill list the demo's kill would stop working.
        self.assertNotIn("python.exe", config.DENY_KILL_PROCESSES)
        self.assertNotIn("python3", config.DENY_KILL_PROCESSES)


class AttributionTests(unittest.TestCase):
    """ProcessFinder must not offer a denied process as a kill target."""

    def setUp(self):
        self.finder = ProcessFinder()
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        self.tmp.write(b"data")
        self.tmp.close()
        self.addCleanup(os.unlink, self.tmp.name)

    def _fake_proc(self, pid, name, create_time=None, path=None):
        proc = mock.MagicMock()
        proc.info = {"pid": pid, "name": name,
                     "create_time": create_time or time.time()}
        opened = mock.MagicMock()
        opened.path = path or self.tmp.name
        proc.open_files.return_value = [opened]
        proc.name.return_value = name
        return proc

    def test_holder_on_the_never_kill_list_is_rejected(self):
        proc = self._fake_proc(4242, "SearchFilterHost.exe")
        with mock.patch("psutil.process_iter", return_value=[proc]), \
                mock.patch("psutil.Process"):
            self.assertIsNone(self.finder._find_by_open_file(self.tmp.name))

    def test_youngest_non_denied_holder_wins(self):
        indexer = self._fake_proc(111, "SearchIndexer.exe",
                                  create_time=time.time() - 3600)
        old_app = self._fake_proc(222, "longlived.exe",
                                  create_time=time.time() - 7200)
        attacker = self._fake_proc(333, "ransomware_sim",
                                   create_time=time.time() - 2)
        with mock.patch("psutil.process_iter",
                        return_value=[indexer, old_app, attacker]), \
                mock.patch("psutil.Process"):
            info = self.finder._find_by_open_file(self.tmp.name)
        self.assertIsNotNone(info)
        self.assertEqual(info["pid"], 333)
        self.assertEqual(info["name"], "ransomware_sim")
        self.assertTrue(info["identity_verified"])

    def test_only_long_lived_holder_still_usable(self):
        app = self._fake_proc(222, "some_app.exe",
                              create_time=time.time() - 7200)
        with mock.patch("psutil.process_iter", return_value=[app]), \
                mock.patch("psutil.Process"):
            info = self.finder._find_by_open_file(self.tmp.name)
        self.assertIsNotNone(info)
        self.assertEqual(info["pid"], 222)


class CampaignKillMemoryTests(unittest.TestCase):
    """The remembered campaign kill target must pass the same gates."""

    def test_denied_process_is_not_remembered(self):
        tracker = CampaignTracker()
        event = {
            "file_path": "/tmp/x.txt",
            "entropy_overall": 7.9,
            "entropy_delta": 3.0,
            "process": {"pid": 999, "name": "dllhost.exe",
                        "identity_verified": True},
        }
        tracker.check_and_record(event, config.ACTION_ALERT)
        self.assertIsNone(tracker.last_verified)

    def test_real_malware_process_is_remembered(self):
        tracker = CampaignTracker()
        event = {
            "file_path": "/tmp/x.txt",
            "entropy_overall": 7.9,
            "entropy_delta": 3.0,
            "process": {"pid": 999, "name": "ransomware_sim",
                        "identity_verified": True},
        }
        tracker.check_and_record(event, config.ACTION_ALERT)
        self.assertIsNotNone(tracker.last_verified)
        self.assertEqual(tracker.last_verified[1]["pid"], 999)


class TerminationGateTests(unittest.TestCase):
    """Even a 'verified' identity must not kill user/OS software."""

    def test_denied_process_is_refused(self):
        event = {"file_path": "/tmp/x.txt"}
        proc = {"pid": 4242, "name": "chrome.exe", "identity_verified": True,
                "create_time": time.time()}
        with mock.patch("monitoring.pipeline_runner.ProcessTerminator") as term:
            self.assertFalse(_terminate_process(4242, "chrome.exe", proc))
        term.assert_not_called()

    def test_non_denied_verified_process_proceeds(self):
        event = {"file_path": "/tmp/x.txt"}
        proc = {"pid": 4242, "name": "ransomware_sim",
                "identity_verified": True, "create_time": time.time()}
        fake_result = {"success": True, "message": "terminated"}
        with mock.patch("monitoring.pipeline_runner.ProcessTerminator") as term:
            term.return_value.terminate.return_value = fake_result
            self.assertTrue(_terminate_process(4242, "ransomware_sim", proc))

    def test_response_layer_refuses_user_software_directly(self):
        from response.response_module import ProcessTerminator

        for name in ("chrome.exe", "dllhost.exe", "SearchFilterHost.exe"):
            with self.subTest(name=name):
                result = ProcessTerminator().terminate(
                    2 ** 20, process_name=name)  # unreachable PID
                self.assertFalse(result["success"])
                self.assertIn("Refused", result["message"])


class HonestReportingTests(unittest.TestCase):
    """A refused kill must never be reported as a kill."""

    def _make_runner(self):
        from monitoring.pipeline_runner import PipelineRunner

        return PipelineRunner.__new__(PipelineRunner)

    def test_refused_kill_records_a_refusal_status(self):
        """execute_response publishes the honest status + summary."""
        from monitoring import pipeline_runner as pr

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        target = Path(tmp.name, "victim.txt")
        target.write_bytes(b"a" * 2048)
        db = os.path.join(tmp.name, "events.db")
        init_db(db).close()
        conn = connect(db)
        self.addCleanup(conn.close)

        denied = {
            "pid": 4242, "name": "dllhost.exe", "identity_verified": True,
            "attribution_source": "open_file", "create_time": time.time(),
        }
        event = {
            "file_path": str(target), "event_type": "MODIFIED",
            "entropy_overall": 7.95, "entropy_delta": 3.0,
            "file_hash": "a" * 64, "threat_score": 95.0,
            "process": dict(denied),
        }
        decision = {"engine": "rules", "confidence": 1.0,
                    "explanation": "test incident"}

        with mock.patch.object(pr.config, "DRY_RUN", False), \
             mock.patch.object(pr, "generate_report", lambda *a, **k: None):
            outcome = pr.execute_response(
                config.ACTION_TERMINATE_QUARANTINE, event, None, conn,
                decision)

        row = conn.execute(
            "SELECT status, outcome FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row["status"], "TERMINATE_REFUSED+QUARANTINED")
        self.assertIn("QUARANTINED", outcome)
        summary = pr.response_summary()
        self.assertFalse(summary["terminated"])
        self.assertTrue(summary["kill_refused"])
        self.assertFalse(summary["quarantined"] in (None,))

    def _run_event(self, proc, *, kill_succeeds):
        """Drive one analyzed event through the runner's counter path."""
        from monitoring import pipeline_runner as pr

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        estate = Path(tmp.name, "estate")
        estate.mkdir()
        vault = Path(tmp.name, "quarantine")
        vault.mkdir()
        target = estate / "victim.txt"
        target.write_bytes(b"a" * 2048)
        db = os.path.join(tmp.name, "events.db")
        init_db(db).close()
        conn = connect(db)
        self.addCleanup(conn.close)

        class _Engine:
            engine_name = staticmethod(lambda: "rules")

            def decide(self, _event):
                return {"action": config.ACTION_TERMINATE_QUARANTINE,
                        "engine": "rules", "confidence": 1.0,
                        "explanation": "test incident"}

        class _Bc:
            def log_event(self, _event):
                pass

        runner = self._make_runner()
        runner.engine = _Engine()
        runner.bc = _Bc()
        runner.db = conn
        runner.backup = None
        runner.stats = {"total": 0, "ignored": 0, "alerted": 0,
                        "terminated": 0, "quarantined": 0}

        event = {
            "file_path": str(target), "event_type": "MODIFIED",
            "entropy_overall": 7.95, "entropy_delta": 3.0,
            "file_hash": "b" * 64, "threat_score": 95.0,
            "process": dict(proc),
        }
        term_result = {"success": kill_succeeds, "message": "stub"}
        with mock.patch.object(pr.config, "DRY_RUN", False), \
             mock.patch.object(pr.config, "QUARANTINE_DIR", str(vault)), \
             mock.patch.object(pr, "generate_report", lambda *a, **k: None), \
             mock.patch.object(pr, "ProcessTerminator") as term:
            term.return_value.terminate.return_value = term_result
            runner._on_analyzed_event(event)
        return runner.stats, conn

    def test_counters_ignore_refused_kills(self):
        """A refused kill decrements nothing — only containment counts."""
        proc = {"pid": 4242, "name": "dllhost.exe", "identity_verified": True,
                "attribution_source": "open_file", "create_time": time.time()}
        stats, conn = self._run_event(proc, kill_succeeds=True)
        self.assertEqual(stats["terminated"], 0)
        self.assertEqual(stats["quarantined"], 1)
        row = conn.execute(
            "SELECT status FROM events ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["status"], "TERMINATE_REFUSED+QUARANTINED")

    def test_counters_follow_a_real_kill(self):
        proc = {"pid": 4242, "name": "ransomware_sim",
                "identity_verified": True,
                "attribution_source": "open_file", "create_time": time.time()}
        stats, conn = self._run_event(proc, kill_succeeds=True)
        self.assertEqual(stats["terminated"], 1)
        self.assertEqual(stats["quarantined"], 1)
        row = conn.execute(
            "SELECT status FROM events ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["status"], "TERMINATED+QUARANTINED")

    def test_guessed_attribution_is_not_published_as_a_process(self):
        """An unverified guess must not name an innocent process in the SOC."""
        from monitoring.pipeline_runner import save_to_db

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = os.path.join(tmp.name, "events.db")
        init_db(db).close()
        conn = connect(db)
        self.addCleanup(conn.close)

        guess = {"pid": 2317, "name": "sleep", "identity_verified": False,
                 "attribution_source": "recent_process_guess"}
        save_to_db(conn, {"file_path": "/tmp/a.txt", "process": guess}, 0,
                   "IGNORED")
        row = conn.execute(
            "SELECT process_name, pid FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row["process_name"], "unattributed")
        self.assertIsNone(row["pid"])

    def test_verified_attribution_keeps_its_name(self):
        from monitoring.pipeline_runner import save_to_db

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = os.path.join(tmp.name, "events.db")
        init_db(db).close()
        conn = connect(db)
        self.addCleanup(conn.close)

        verified = {"pid": 1790, "name": "python3", "identity_verified": True,
                    "attribution_source": "open_file"}
        save_to_db(conn, {"file_path": "/tmp/a.txt", "process": verified}, 3,
                   "TERMINATED+QUARANTINED")
        row = conn.execute(
            "SELECT process_name, pid FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(row["process_name"], "python3")
        self.assertEqual(row["pid"], 1790)

    def test_saving_works_on_a_legacy_events_schema(self):
        """A caller holding an old events table must not lose records."""
        from monitoring.pipeline_runner import save_to_db
        import sqlite3

        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " timestamp TEXT, file_path TEXT, event_type TEXT, entropy REAL,"
            " entropy_delta REAL, pid INTEGER, process_name TEXT,"
            " action INTEGER, status TEXT, requested_action INTEGER,"
            " outcome TEXT, restore_result TEXT, dry_run INTEGER,"
            " engine TEXT, confidence REAL, explanation TEXT,"
            " q_values TEXT)")
        save_to_db(conn, {"file_path": "/tmp/a.txt",
                          "process": {"pid": 1, "name": "x"}}, 1, "ALERTED")
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(count, 1)
        conn.close()


class ProcessMonitorHonestyTests(unittest.TestCase):
    """/api/processes must say "killed" only for a real kill."""

    def setUp(self):
        import app as dashboard

        self.client = dashboard.app.test_client()
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "proc.db")
        init_db(self.db).close()
        self.patch = mock.patch("app.get_db",
                                side_effect=lambda: connect(self.db))
        self.patch.start()
        self.addCleanup(self._teardown)

    def _teardown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def _insert(self, status, action=3, name="python3", pid=1790):
        conn = connect(self.db)
        conn.execute(
            "INSERT INTO events (timestamp, file_path, event_type, entropy,"
            " pid, process_name, action, status, requested_action, outcome)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("2026-01-01T00:00:00", "/tmp/a.txt", "MODIFIED", 7.9, pid, name,
             action, status, action, "QUARANTINED+RESTORED"),
        )
        conn.commit()
        conn.close()

    def test_refused_kill_is_not_shown_as_killed(self):
        self._insert("TERMINATE_REFUSED+QUARANTINED", name="dllhost.exe",
                     pid=4242)
        data = self.client.get("/api/processes").get_json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["status"], "contained")
        self.assertTrue(data[0]["kill_refused"])

    def test_real_kill_is_shown_as_killed(self):
        self._insert("TERMINATED+QUARANTINED")
        data = self.client.get("/api/processes").get_json()
        self.assertEqual(data[0]["status"], "killed")
        self.assertFalse(data[0]["kill_refused"])

    def test_kill_still_wins_when_sweeps_are_refused(self):
        """A killed process keeps the kill even if later sweeps refuse."""
        self._insert("TERMINATED+QUARANTINED")
        self._insert("TERMINATE_REFUSED+QUARANTINED")
        data = self.client.get("/api/processes").get_json()
        self.assertEqual(data[0]["status"], "killed")


class StatsHonestyTests(unittest.TestCase):
    """/api/stats counts outcomes, never requests."""

    def setUp(self):
        import app as dashboard

        self.client = dashboard.app.test_client()
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "stats.db")
        init_db(self.db).close()
        self.patch = mock.patch("app.get_db",
                                side_effect=lambda: connect(self.db))
        self.patch.start()
        self.addCleanup(self._teardown)

    def _teardown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def _insert(self, status, outcome="QUARANTINED+RESTORED",
                restore="RESTORED", action=3, name="python3"):
        conn = connect(self.db)
        conn.execute(
            "INSERT INTO events (timestamp, file_path, event_type, entropy,"
            " pid, process_name, action, status, requested_action, outcome,"
            " restore_result) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ("2026-01-01T00:00:00", "/tmp/a.txt", "MODIFIED", 7.9, 1790, name,
             action, status, action, outcome, restore))
        conn.commit()
        conn.close()

    def test_refused_kill_is_not_counted_as_terminated(self):
        self._insert("TERMINATE_REFUSED+QUARANTINED", name="unattributed")
        data = self.client.get("/api/stats").get_json()
        self.assertEqual(data["terminated"], 0)
        self.assertEqual(data["terminate_refused"], 1)
        self.assertEqual(data["quarantined"], 1)
        self.assertEqual(data["recovery"], 1)

    def test_real_kill_is_counted(self):
        self._insert("TERMINATED+QUARANTINED")
        data = self.client.get("/api/stats").get_json()
        self.assertEqual(data["terminated"], 1)
        self.assertEqual(data["terminate_refused"], 0)

    def test_failed_restore_is_not_counted_as_recovery(self):
        self._insert("TERMINATED+QUARANTINED", restore="RESTORE_FAILED")
        data = self.client.get("/api/stats").get_json()
        self.assertEqual(data["recovery"], 0)
        self.assertEqual(data["quarantined"], 1)


class DecisionPanelTests(unittest.TestCase):
    """/api/dqn/last must explain the action that was actually taken."""

    def setUp(self):
        import app as dashboard

        self.dashboard = dashboard
        self.client = dashboard.app.test_client()
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "decision.db")
        init_db(self.db).close()
        self.patch = mock.patch("app.get_db",
                                side_effect=lambda: connect(self.db))
        self.patch.start()
        self.addCleanup(self._teardown)

    def _teardown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def _insert(self, **values):
        columns = {
            "timestamp": "2026-01-01T00:00:00", "file_path": "/tmp/a.txt",
            "event_type": "MODIFIED", "entropy": 7.9, "entropy_delta": 0.6,
            "pid": 1, "process_name": "ransomware_sim", "action": 3,
            "status": "TERMINATED+QUARANTINED", "requested_action": 3,
            "outcome": "QUARANTINED+RESTORED", "restore_result": "RESTORED",
            "dry_run": 0, "engine": "dqn", "confidence": 0.97,
            "explanation": "", "q_values": None, "threat_score": 0.0,
        }
        columns.update(values)
        conn = connect(self.db)
        conn.execute(
            f"INSERT INTO events ({','.join(columns)}) "
            f"VALUES ({','.join('?' * len(columns))})",
            tuple(columns.values()),
        )
        conn.commit()
        conn.close()

    def test_threat_score_column_is_persisted_by_the_pipeline(self):
        # save_to_db must write the score the panel displays.
        import inspect

        from monitoring.pipeline_runner import save_to_db

        source = inspect.getsource(save_to_db)
        self.assertIn("threat_score", source)

    def test_escalation_is_explained(self):
        self._insert(explanation=(
            "CAMPAIGN CONFIRMED: 2 files with encrypted-data signatures in "
            "15s | DQN | Decision: ALERT | Threat score: 0/100 | "
            "Reasons: Normal activity pattern"
        ))
        data = self.client.get("/api/dqn/last").get_json()
        self.assertEqual(data["decision"], "TERMINATE + QUARANTINE")
        self.assertTrue(data["escalated"])
        self.assertIn("Campaign", data["escalation"])
        self.assertEqual(data["threat_score"], 0.0)
        self.assertIn("Normal activity pattern", data["reasons"])
        names = [f["name"] for f in data["factors"]]
        self.assertIn("Action taken", names)
        self.assertIn("Threat score", names)
        self.assertIn("Escalated by", names)

    def test_engine_verdict_without_escalation(self):
        self._insert(action=1, requested_action=1, threat_score=45.0,
                     engine="rules", confidence=1.0,
                     explanation="Rule-based detector | High entropy: 7.90")
        data = self.client.get("/api/dqn/last").get_json()
        self.assertEqual(data["decision"], "ALERT")
        self.assertFalse(data["escalated"])
        self.assertEqual(data["threat_score"], 45.0)

    def test_old_rows_without_a_score_still_render(self):
        self._insert(threat_score=None, action=0, requested_action=0,
                     explanation="normal")
        data = self.client.get("/api/dqn/last").get_json()
        self.assertEqual(data["decision"], "IGNORE")
        self.assertIsNone(data["threat_score"])

    def test_standby_before_any_event(self):
        data = self.client.get("/api/dqn/last").get_json()
        self.assertEqual(data["decision"], "STANDBY")


class EntropySeriesTests(unittest.TestCase):
    """Unreadable events must not be plotted as entropy 0."""

    def setUp(self):
        import app as dashboard

        self.client = dashboard.app.test_client()
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "entropy.db")
        init_db(self.db).close()
        self.patch = mock.patch("app.get_db",
                                side_effect=lambda: connect(self.db))
        self.patch.start()
        self.addCleanup(self._teardown)

    def _teardown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def _insert(self, entropy, event_type, path):
        conn = connect(self.db)
        conn.execute(
            "INSERT INTO events (timestamp, file_path, event_type, entropy,"
            " action, status) VALUES (?,?,?,?,?,?)",
            ("2026-01-01T00:00:00", path, event_type, entropy, 0, "IGNORED"),
        )
        conn.commit()
        conn.close()

    def test_zero_entropy_rows_are_excluded_by_default(self):
        self._insert(7.9, "MODIFIED", "/tmp/encrypted.xlsx")
        self._insert(0.0, "DELETED", "/tmp/gone.txt")
        data = self.client.get("/api/entropy").get_json()
        values = [row["entropy"] for row in data]
        self.assertEqual(values, [7.9])

    def test_raw_series_still_available_on_request(self):
        self._insert(7.9, "MODIFIED", "/tmp/encrypted.xlsx")
        self._insert(0.0, "DELETED", "/tmp/gone.txt")
        data = self.client.get("/api/entropy?include_unread=1").get_json()
        self.assertEqual(len(data), 2)


if __name__ == "__main__":
    unittest.main()
