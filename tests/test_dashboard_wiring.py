"""Frontend/backend contract tests for the three demo surfaces.

Locks down the wiring bugs that made the UI look "broken backend":

  * the attacker console and the Command Platform page linked the victim
    explorer to port 8002 — nothing listens there (it is 5001);
  * the Command Platform page called /api/lab/* and /api/folders, which
    did not exist on the SOC dashboard at all (silent 404s → the launch
    buttons, the campaign panel and the fixture inventory stayed empty);
  * the SOC dashboard had no way to (re)start the detection pipeline.
"""

import json
import unittest
from unittest import mock

import config


class PlatformPageTests(unittest.TestCase):
    def setUp(self):
        from app import app
        self.client = app.test_client()

    def test_sibling_links_use_the_real_ports(self):
        html = self.client.get("/platform").get_data(as_text=True)
        self.assertNotIn(":8002", html)
        self.assertIn(f":{config.VICTIM_PORT}", html)
        self.assertIn(f":{config.ATTACKER_PORT}", html)

    def test_platform_page_renders(self):
        response = self.client.get("/platform")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Command Platform", response.get_data(as_text=True))


class LabControlRouteTests(unittest.TestCase):
    """/api/lab/* is the dashboard-side proxy to the attacker console."""

    def setUp(self):
        from app import app
        self.client = app.test_client()

    def test_status_route_forwards_console_state(self):
        payload = {"active": True, "family": "wannacry", "phase": "ENCRYPTING",
                   "progress": 32, "victim": {"exists": True, "total": 18}}
        with mock.patch("app._attacker_console",
                        return_value=(payload, 200)) as call:
            data = self.client.get("/api/lab/status").get_json()
        call.assert_called_once()
        self.assertEqual(data["family"], "wannacry")
        self.assertTrue(data["dry_run"] is False)

    def test_families_route_is_exposed(self):
        families = [{"id": "wannacry", "name": "WannaCry (2017)"}]
        with mock.patch("app._attacker_console",
                        return_value=(families, 200)):
            data = self.client.get("/api/lab/families").get_json()
        self.assertEqual(data, families)

    def test_launch_and_stop_are_proxied(self):
        result = {"ok": True, "family": "wannacry", "pid": 4242}
        with mock.patch("app._attacker_console",
                        return_value=(result, 200)) as call:
            data = self.client.post("/api/lab/launch",
                                    json={"family": "wannacry"}).get_json()
            self.assertEqual(data, result)
            call.assert_called_with("/api/launch", "POST",
                                    {"family": "wannacry"})
        with mock.patch("app._attacker_console",
                        return_value=({"ok": True}, 200)) as call:
            self.client.post("/api/lab/stop")
            call.assert_called_with("/api/stop", "POST", {})
        with mock.patch("app._attacker_console",
                        return_value=({"ok": True}, 200)) as call:
            self.client.post("/api/lab/reset")
            call.assert_called_with("/api/reset", "POST", {})

    def test_offline_console_reports_a_clear_error(self):
        # Port 9 (discard) is never the attacker console.
        with mock.patch.object(config, "ATTACKER_PORT", 9):
            response = self.client.get("/api/lab/status")
        self.assertEqual(response.status_code, 503)
        body = response.get_json()
        self.assertFalse(body["ok"])
        self.assertIn("attacker console", body["error"])


class VictimFolderRouteTests(unittest.TestCase):
    def setUp(self):
        from app import app
        self.client = app.test_client()

    def test_folder_inventory_matches_the_explorer_shape(self):
        folders = self.client.get("/api/folders").get_json()
        names = [f["name"] for f in folders]
        self.assertEqual(names, ["Documents", "Downloads", "Desktop", "Pictures"])
        for folder in folders:
            self.assertIn("file_count", folder)
            self.assertIn("size", folder)
            self.assertFalse(folder["locked"])


class PipelineRestartRouteTests(unittest.TestCase):
    def setUp(self):
        from app import app
        self.client = app.test_client()

    def test_restart_starts_an_offline_pipeline(self):
        statuses = [{"online": False}, {"online": True, "watching_victim": True}]
        with mock.patch("app.pipeline_status", side_effect=statuses), \
                mock.patch("app.pipeline_supervisor.start_pipeline",
                           return_value=True) as start:
            response = self.client.post("/api/pipeline/restart")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "started")
        start.assert_called_once()

    def test_restart_is_a_no_op_for_a_healthy_pipeline(self):
        healthy = {"online": True, "watching_victim": True}
        with mock.patch("app.pipeline_status", return_value=healthy), \
                mock.patch("app.pipeline_supervisor.start_pipeline") as start, \
                mock.patch("app.pipeline_supervisor.restart_pipeline") as restart:
            response = self.client.post("/api/pipeline/restart")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "already-running")
        start.assert_not_called()
        restart.assert_not_called()

    def test_restart_replaces_a_blind_pipeline(self):
        blind = {"online": True, "watching_victim": False}
        with mock.patch("app.pipeline_status", return_value=blind), \
                mock.patch("app.pipeline_supervisor.restart_pipeline",
                           return_value=True) as restart:
            response = self.client.post("/api/pipeline/restart")
        self.assertEqual(response.status_code, 200)
        restart.assert_called_once()


class AttackerConsoleLinkTests(unittest.TestCase):
    """The console HTML is served with the sibling URLs substituted."""

    @classmethod
    def setUpClass(cls):
        from http.server import ThreadingHTTPServer
        from threading import Thread

        from attacker_server.app import Handler

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _html(self):
        from urllib.request import urlopen

        with urlopen(self.base + "/") as response:
            return response.read().decode("utf-8")

    def test_victim_link_points_at_the_victim_explorer(self):
        html = self._html()
        self.assertNotIn("__VICTIM_URL__", html)
        self.assertNotIn(":8002", html)
        self.assertIn(f":{config.VICTIM_PORT}", html)

    def test_soc_link_points_at_the_dashboard(self):
        html = self._html()
        self.assertNotIn("__DASHBOARD_URL__", html)
        self.assertIn(f":{config.DASHBOARD_PORT}", html)


if __name__ == "__main__":
    unittest.main()
