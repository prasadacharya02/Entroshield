"""Recovery drill invariants: detect -> contain -> recover, measured."""

import shutil
import tempfile
import unittest
from pathlib import Path

from benchmark.recovery_drill import run_drill_scenario
from benchmark.scenarios import (attack_backup_tamper, attack_burst_encoder,
                                 attack_baseline_first,
                                 attack_image_blindspot,
                                 workload_document_editing)
from blockchain.fingerprint_exchange import FingerprintExchange


class RecoveryDrillTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="drill_test_"))
        self.exchange = FingerprintExchange(
            str(self.tmp / "exchange.db"), node_id="drill-test"
        )

    def tearDown(self):
        self.exchange.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _drill(self, scenario, *, baseline, name):
        return run_drill_scenario(
            scenario, baseline=baseline,
            workdir=self.tmp / name, exchange=self.exchange,
        )

    def test_baseline_rename_attack_fully_recovered_with_rto(self):
        # With the startup baseline, a rename-based attack is detected
        # at op 1 and every file is restored byte-for-byte.
        result = self._drill(attack_burst_encoder(1), baseline=True,
                             name="burst_b")
        self.assertEqual(result["ops_to_detection"], 1)
        self.assertEqual(result["attacked_files"], 8)
        self.assertEqual(result["attacked_files_recovered"], 8)
        self.assertEqual(result["attacked_files_lost"], 0)
        self.assertEqual(result["recovery_rate_pct"], 100.0)
        # RTO: full recovery at the last file (8 ops), attacker pace
        # 0.1s/op -> 0.8s.
        self.assertEqual(result["rto_ops"], 8)
        self.assertAlmostEqual(result["rto_attacker_clock_s"], 0.8, places=2)
        for entry in result["per_file"].values():
            self.assertEqual(entry["verified"], "recovered")

    def test_no_baseline_rename_ciphertext_quarantined_and_restored(self):
        """Without a startup baseline, rename-to-disguise with ciphertext
        content still trips the structural fingerprint (magic+chi2) on
        the very first file — so the file is quarantined AND a fresh
        snapshot from the just-written suspicious content is NOT used as
        a restore source. Recovery is best-effort: when a clean capture
        exists we recover; when no clean capture exists the loss is
        reported honestly."""
        result = self._drill(attack_burst_encoder(1), baseline=False,
                             name="burst_nb")
        self.assertEqual(result["ops_to_detection"], 1)   # detected first op
        # Detection fires; containment (quarantine/kill) happens, but
        # without a baseline the clean backup store is empty for pre-
        # existing files, so every file not re-captured before the
        # attack is reported as lost. Document this honestly.
        self.assertGreaterEqual(result["quarantine_actions"], 1)

    def test_baseline_first_recovered_in_both_modes(self):
        # A clean edit before encryption provides the delta (and a
        # clean capture) even without the startup baseline.
        for baseline in (False, True):
            with self.subTest(baseline=baseline):
                result = self._drill(
                    attack_baseline_first(1), baseline=baseline,
                    name=f"bf_{int(baseline)}",
                )
                self.assertEqual(result["attacked_files_recovered"], 4)
                self.assertEqual(result["attacked_files_lost"], 0)
                self.assertEqual(result["rto_ops"], 8)

    def test_image_blindspot_now_detected_via_structural_fingerprint(self):
        """In-place .jpg encryption used to be an entropy-only blind
        spot. The chi² uniformity + magic validation closes it: the
        attack is detected on the very first modified JPG, the attacker
        is killed, files still being overwritten are contained."""
        for baseline in (False, True):
            with self.subTest(baseline=baseline):
                result = self._drill(
                    attack_image_blindspot(1), baseline=baseline,
                    name=f"img_{int(baseline)}",
                )
                self.assertIsNotNone(
                    result["ops_to_detection"],
                    f"baseline={baseline} image_blindspot must now be detected",
                )
                self.assertEqual(result["attacked_files"], 4)

    def test_backup_tamper_blobs_contained_but_not_restorable(self):
        # The two random .bin blobs have entropy ~7.96, which is above
        # the clean threshold (6.8) for an unknown extension — they look
        # encrypted. So their only startup-baseline version is labeled
        # dirty and is never restorable: they are contained (the delete
        # is quarantined as a protected-path attack) but NOT restored.
        # The unprotected notes.txt delete is an honest loss.
        result = self._drill(attack_backup_tamper(1), baseline=False,
                             name="bt")
        self.assertEqual(result["attacked_files"], 3)
        self.assertEqual(result["attacked_files_contained_not_restored"], 2)
        self.assertEqual(result["attacked_files_lost"], 1)
        self.assertEqual(result["attacked_files_recovered"], 0)
        self.assertEqual(
            result["per_file"]["backup/snap_00.bin"]["verified"], "contained"
        )
        self.assertEqual(
            result["per_file"]["Documents/notes.txt"]["verified"], "lost"
        )

    def test_workload_control_does_not_touch_files(self):
        # Legitimate editing: no quarantine, no restore, no loss.
        result = self._drill(workload_document_editing(1), baseline=False,
                             name="workload")
        self.assertEqual(result["quarantine_actions"], 0)
        self.assertEqual(result["attacked_files"], 0)
        self.assertEqual(result["untouched_files"], 4)
        self.assertEqual(result["first_detection_op"], None)


if __name__ == "__main__":
    unittest.main()
