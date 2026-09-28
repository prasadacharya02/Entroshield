"""Regression tests for the detection-pipeline supervisor.

Bug being locked down: starting only the three web surfaces (SOC
dashboard, victim explorer, attacker console) left the detection
pipeline unstarted. The attack then ran to completion — files stayed
encrypted, nothing reached ``quarantine_storage/``, and the SOC
dashboard showed ``0 events / 0 threats`` forever.

The supervisor makes the pipeline self-starting and self-healing:
starting any web surface starts the defence, and it is restarted if it
dies or if it stops watching the victim estate.
"""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import config
from monitoring import pipeline_supervisor as supervisor
from storage.database import connect, init_db, write_pipeline_heartbeat

ROOT = Path(__file__).resolve().parents[1]
VICTIM = str((ROOT / "victim_server" / "user_files").resolve())


class SupervisorTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "supervisor.db")
        init_db(self.db).close()

        self.patches = [
            mock.patch.object(config, "DB_PATH", self.db),
            mock.patch.object(config, "LOG_DIR", self.tmp.name),
            mock.patch.object(config, "AUTOSTART_PIPELINE", True),
            # The developer running the tests may have a live lab next
            # door; the process scan is exercised explicitly below.
            mock.patch.object(supervisor, "pipeline_processes",
                              return_value=[]),
            mock.patch.dict(os.environ, {}, clear=False),
        ]
        for patch in self.patches:
            patch.start()
        os.environ.pop(supervisor.MANAGED_ENV_FLAG, None)

        supervisor._last_attempt = 0.0
        supervisor._consecutive_failures = 0
        supervisor._last_forced_restart = 0.0
        self.addCleanup(self._teardown)

    def _teardown(self):
        supervisor._last_attempt = 0.0
        supervisor._consecutive_failures = 0
        supervisor._last_forced_restart = 0.0
        for patch in reversed(self.patches):
            patch.stop()
        self.tmp.cleanup()

    def beat(self, age=0.0, folders=(VICTIM,), pid=4242):
        conn = connect(self.db)
        write_pipeline_heartbeat(conn, started_at=time.time(), pid=pid,
                                 watch_folders=list(folders), dry_run=False,
                                 engine="rules", stats={"received": 3})
        conn.execute("UPDATE pipeline_status SET heartbeat=?",
                     (time.time() - age,))
        conn.commit()
        conn.close()


class StatusTests(SupervisorTestCase):
    def test_offline_before_the_pipeline_ever_ran(self):
        status = supervisor.pipeline_status(self.db)
        self.assertFalse(status["online"])
        self.assertIsNone(status["age_seconds"])
        self.assertFalse(supervisor.pipeline_alive(self.db))

    def test_fresh_heartbeat_is_online_and_watching_the_victim(self):
        self.beat()
        status = supervisor.pipeline_status(self.db)
        self.assertTrue(status["online"])
        self.assertTrue(status["watching_victim"])
        self.assertEqual(status["pid"], 4242)

    def test_stale_heartbeat_is_offline(self):
        self.beat(age=config.PIPELINE_STALE_SECONDS + 30)
        self.assertFalse(supervisor.pipeline_status(self.db)["online"])

    def test_wrong_folder_is_reported_as_blind(self):
        self.beat(folders=[config.TESTING_DATA_DIR])
        status = supervisor.pipeline_status(self.db)
        self.assertTrue(status["online"])
        self.assertFalse(status["watching_victim"])


class StartTests(SupervisorTestCase):
    def test_no_start_while_a_fresh_pipeline_is_alive(self):
        self.beat()
        with mock.patch.object(supervisor, "spawn_pipeline") as spawn:
            self.assertFalse(supervisor.ensure_pipeline("test"))
        spawn.assert_not_called()

    def test_starts_when_no_heartbeat_exists(self):
        with mock.patch.object(supervisor, "spawn_pipeline",
                               return_value=True) as spawn:
            self.assertTrue(supervisor.ensure_pipeline("no heartbeat"))
        spawn.assert_called_once()

    def test_restarts_when_the_heartbeat_went_stale(self):
        self.beat(age=120)
        with mock.patch.object(supervisor, "spawn_pipeline",
                               return_value=True) as spawn:
            self.assertTrue(supervisor.ensure_pipeline("stale"))
        spawn.assert_called_once()

    def test_cooldown_prevents_a_restart_storm(self):
        with mock.patch.object(supervisor, "spawn_pipeline",
                               return_value=False) as spawn:
            supervisor.ensure_pipeline("first")
            supervisor.ensure_pipeline("second")
        self.assertEqual(spawn.call_count, 1)

    def test_fresh_guard_blocks_a_second_supervisor(self):
        """Two servers starting at once must not launch two pipelines."""
        guard = Path(self.tmp.name) / supervisor._GUARD_NAME
        guard.write_text("other-process", encoding="utf-8")
        with mock.patch.object(supervisor, "spawn_pipeline") as spawn:
            self.assertFalse(supervisor.ensure_pipeline("race"))
        spawn.assert_not_called()

    def test_stale_guard_is_reclaimed(self):
        guard = Path(self.tmp.name) / supervisor._GUARD_NAME
        guard.write_text("dead-process", encoding="utf-8")
        old = time.time() - supervisor._GUARD_TTL - 60
        os.utime(guard, (old, old))
        with mock.patch.object(supervisor, "spawn_pipeline",
                               return_value=True) as spawn:
            self.assertTrue(supervisor.ensure_pipeline("reclaim"))
        spawn.assert_called_once()

    def test_managed_child_never_starts_another_pipeline(self):
        os.environ[supervisor.MANAGED_ENV_FLAG] = "1"
        with mock.patch.object(supervisor, "spawn_pipeline") as spawn:
            self.assertFalse(supervisor.ensure_pipeline("recursion guard"))
        spawn.assert_not_called()

    def test_autostart_can_be_disabled(self):
        with mock.patch.object(config, "AUTOSTART_PIPELINE", False), \
                mock.patch.object(supervisor, "spawn_pipeline") as spawn:
            self.assertFalse(supervisor.ensure_pipeline("disabled"))
        spawn.assert_not_called()

    def test_starting_pipeline_process_blocks_a_second_instance(self):
        """lab.py starts the pipeline itself — the web surfaces that come
        up a second later must not start a second one while the first is
        still importing and hasn't written a heartbeat yet."""
        with mock.patch.object(supervisor, "pipeline_processes",
                               return_value=[31337]), \
                mock.patch.object(supervisor, "spawn_pipeline") as spawn:
            self.assertFalse(supervisor.ensure_pipeline("race with lab.py"))
        spawn.assert_not_called()


class HungPipelineTests(SupervisorTestCase):
    def test_starting_process_is_left_alone(self):
        with mock.patch.object(supervisor, "pipeline_processes",
                               return_value=[31337]), \
                mock.patch.object(supervisor, "restart_pipeline") as restart, \
                mock.patch.object(supervisor, "spawn_pipeline") as spawn:
            supervisor._supervise_once()
        restart.assert_not_called()
        spawn.assert_not_called()

    def test_hung_process_is_restarted(self):
        self.beat(age=600)
        with mock.patch.object(supervisor, "pipeline_processes",
                               return_value=[31337]), \
                mock.patch.object(supervisor, "restart_pipeline",
                                  return_value=True) as restart:
            supervisor._supervise_once()
        restart.assert_called_once()

    def test_restart_falls_back_to_the_process_table(self):
        """A hung pipeline that never wrote a PID is still restartable."""
        with mock.patch.object(supervisor, "pipeline_processes",
                               return_value=[31337]), \
                mock.patch.object(supervisor, "stop_pipeline",
                                  return_value=True) as stop, \
                mock.patch.object(supervisor, "ensure_pipeline",
                                  return_value=True):
            self.assertTrue(supervisor.restart_pipeline("hung"))
        stop.assert_called_once_with(31337)


class EnvironmentTests(SupervisorTestCase):
    def test_spawned_pipeline_always_watches_the_victim(self):
        env = supervisor.pipeline_env()
        folders = [os.path.abspath(p)
                   for p in env["ENTROPY_WATCH_FOLDERS"].split(",") if p]
        self.assertIn(VICTIM, folders)
        self.assertEqual(env[supervisor.MANAGED_ENV_FLAG], "1")
        self.assertEqual(env["ENTROPY_DRY_RUN"], "false")

    def test_explicit_dry_run_is_respected(self):
        with mock.patch.dict(os.environ, {"ENTROPY_DRY_RUN": "true"}):
            self.assertEqual(supervisor.pipeline_env()["ENTROPY_DRY_RUN"],
                             "true")


class StopSafetyTests(SupervisorTestCase):
    def test_refuses_to_stop_a_pid_that_is_not_the_pipeline(self):
        with mock.patch.object(supervisor, "_process_cmdline",
                               return_value=["python", "some_other_service.py"]), \
                mock.patch("os.kill") as kill:
            self.assertFalse(supervisor.stop_pipeline(1234))
        kill.assert_not_called()

    def test_stops_a_real_pipeline_pid(self):
        with mock.patch.object(supervisor, "_process_cmdline",
                               return_value=["python",
                                             "/repo/monitoring/pipeline_runner.py"]), \
                mock.patch("os.kill") as kill:
            self.assertTrue(supervisor.stop_pipeline(1234))
        kill.assert_called_once()

    def test_never_stops_its_own_process(self):
        with mock.patch("os.kill") as kill:
            self.assertFalse(supervisor.stop_pipeline(os.getpid()))
        kill.assert_not_called()


class SupervisorThreadTests(SupervisorTestCase):
    def test_health_check_starts_the_pipeline(self):
        with mock.patch.object(supervisor, "spawn_pipeline",
                               return_value=True) as spawn:
            supervisor._supervise_once()
        spawn.assert_called_once()

    def test_health_check_restarts_a_blind_pipeline(self):
        self.beat(folders=[config.TESTING_DATA_DIR])
        with mock.patch.object(supervisor, "restart_pipeline",
                               return_value=True) as restart:
            supervisor._supervise_once()
        restart.assert_called_once()

    def test_health_check_is_quiet_when_all_is_well(self):
        self.beat()
        with mock.patch.object(supervisor, "spawn_pipeline") as spawn, \
                mock.patch.object(supervisor, "restart_pipeline") as restart:
            supervisor._supervise_once()
        spawn.assert_not_called()
        restart.assert_not_called()


if __name__ == "__main__":
    unittest.main()
