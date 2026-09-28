import math
import os
import tempfile
import unittest

from entropy.entropy_calculator import calculate_entropy, calculate_file_entropy


class EntropyCalculationTests(unittest.TestCase):
    def test_empty_and_constant_data_have_zero_entropy(self):
        self.assertEqual(calculate_entropy(b""), 0.0)
        self.assertEqual(calculate_entropy(b"A" * 4096), 0.0)

    def test_uniform_byte_values_have_eight_bits_of_entropy(self):
        data = bytes(range(256)) * 32
        self.assertTrue(math.isclose(calculate_entropy(data), 8.0, abs_tol=0.0001))

    def test_file_analysis_returns_expected_metadata(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as handle:
            handle.write(b"normal readable text " * 200)
            path = handle.name

        try:
            result = calculate_file_entropy(path)
        finally:
            os.unlink(path)

        self.assertTrue(result["is_readable"])
        self.assertEqual(result["file_extension"], ".txt")
        self.assertGreater(result["entropy_overall"], 0)
        self.assertEqual(len(result["file_hash"]), 64)
        self.assertIsNone(result["error"])

    def test_realistic_compressed_binary_format_is_not_suspicious_alone(self):
        """A file with a valid JPEG magic header and non-uniform high-entropy
        body (realistic compressed media) must NOT be flagged."""
        import numpy as np
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as handle:
            magic = b"\xff\xd8\xff\xe0\x00\x10JFIF"
            # High-entropy but multimodal body (Huffman-style peaks)
            rng = np.random.default_rng(42)
            alpha = np.ones(256); peaks = rng.choice(256, 30, replace=False)
            alpha[peaks] += rng.uniform(2, 6, 30); alpha /= alpha.sum()
            body = rng.choice(256, size=8192 - len(magic), p=alpha).astype(np.uint8).tobytes()
            handle.write(magic + body)
            path = handle.name

        try:
            from entropy.entropy_calculator import EntropyAnalyzer
            result = EntropyAnalyzer().analyze(path)
        finally:
            os.unlink(path)

        self.assertTrue(result["magic_ok"])
        self.assertGreater(result["entropy_overall"], 7.0)
        self.assertFalse(result["is_suspicious"])
        self.assertEqual(result["threat_score"], 0.0)

    def test_uniform_bytes_faking_jpg_extension_is_caught(self):
        """Statistically uniform bytes (ciphertext) with a .jpg extension
        but missing valid JPEG magic + chi² ≈ 255 MUST be flagged even
        though Shannon entropy alone sits in the 'normal image' range —
        this is the structural ciphertext fingerprint."""
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as handle:
            handle.write(bytes(range(256)) * 32)  # uniform, no jpg magic
            path = handle.name

        try:
            from entropy.entropy_calculator import EntropyAnalyzer
            result = EntropyAnalyzer().analyze(path)
        finally:
            os.unlink(path)

        self.assertAlmostEqual(result["entropy_overall"], 8.0, places=3)
        self.assertTrue(result["is_suspicious"])
        self.assertFalse(result["magic_ok"])

    def test_high_entropy_text_file_is_suspicious(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as handle:
            handle.write(bytes(range(256)) * 32)
            path = handle.name

        try:
            from entropy.entropy_calculator import EntropyAnalyzer
            result = EntropyAnalyzer().analyze(path)
        finally:
            os.unlink(path)

        self.assertTrue(result["is_suspicious"])
        self.assertGreaterEqual(result["threat_score"], 40.0)

    def test_missing_file_is_reported_without_raising(self):
        result = calculate_file_entropy("/definitely/not/an/entropy-file")
        self.assertFalse(result["is_readable"])
        self.assertEqual(result["error"], "File not found")


if __name__ == "__main__":
    unittest.main()
