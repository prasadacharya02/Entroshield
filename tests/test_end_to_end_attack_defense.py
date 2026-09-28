import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config
from storage.database import connect, init_db
from victim_server.create_fake_files import restore_all_files
from monitoring.pipeline_supervisor import start_pipeline, stop_pipeline, pipeline_status


class EndToEndAttackDefenseTests(unittest.TestCase):
    def setUp(self):
        # Reset runtime state
        self.db = init_db()
        self.db.execute("DELETE FROM events")
        self.db.commit()
        restore_all_files(quiet=True)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass

    def test_attack_and_immediate_containment(self):
        # Start detection pipeline
        started = start_pipeline("e2e test")
        self.assertTrue(started, "Detection pipeline must be running")

        # Confirm 18 initial clean files
        victim_dir = Path(config.VICTIM_USER_FILES)
        initial_files = list(victim_dir.rglob("*.*"))
        self.assertEqual(len(initial_files), 18)

        # Launch WannaCry attack via foreground engine process
        control_file = ROOT / "attacker_control.json"
        control_file.write_text(json.dumps({"factor": 1.0, "paused": False}))

        res = subprocess.run(
            [sys.executable, "-m", "attacker_server.ransomware_engines", "wannacry", "--control", str(control_file)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )

        # Must be terminated by defender with code 42
        self.assertEqual(res.returncode, 42, f"Attacker process must be killed with exit 42. Output: {res.stdout}")
        self.assertIn("TERMINATED BY DEFENSE SYSTEM", res.stdout)

        # Wait briefly for post-kill verification
        time.sleep(1.0)

        # Verify files in quarantine_storage/
        q_dir = Path(config.QUARANTINE_DIR)
        q_files = [f for f in q_dir.iterdir() if not f.name.endswith(".meta.json")]
        self.assertGreater(len(q_files), 0, "Quarantined files must be transferred to quarantine folder")

        # Verify 18/18 files in victim estate restored and none with .WNCRY extension
        current_files = list(victim_dir.rglob("*.*"))
        wncry_files = [f for f in current_files if f.name.endswith(".WNCRY")]
        self.assertEqual(len(wncry_files), 0, "No .WNCRY files should remain in victim folder")
        self.assertEqual(len(current_files), 18, "All 18 original files must be restored")

        # Verify events table in database
        events = self.db.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
        self.assertGreater(len(events), 0, "SOC database must have recorded events")

        threat_events = [e for e in events if e["action"] >= 1]
        self.assertGreater(len(threat_events), 0, "SOC database must have recorded threat events")

        # Verify entropy spike
        max_entropy = max(e["entropy"] or 0.0 for e in events)
        self.assertGreaterEqual(max_entropy, 7.5, "Entropy variation spike must reach >= 7.5")

        # Verify termination recorded
        terminated = [e for e in events if "TERMINATED" in str(e["status"])]
        self.assertGreater(len(terminated), 0, "Process termination must be recorded in events")


if __name__ == "__main__":
    unittest.main()
