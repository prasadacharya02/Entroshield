# ============================================================
# ENTROPY - Entropy Calculator
# entropy\entropy_calculator.py
#
# WHAT THIS DOES:
# Calculates Shannon entropy of files.
# Entropy measures randomness in data.
# Normal files = low entropy
# Encrypted files = high entropy (close to 8.0)
#
# SHANNON ENTROPY FORMULA:
# H = -sum( p(x) * log2(p(x)) )
# Where p(x) = probability of each byte value (0-255)
# ============================================================

import os
import sys
import math
import time
import json
import hashlib
import logging
from datetime import datetime
from collections import defaultdict

import numpy as np

# Add parent folder to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

log = logging.getLogger("EntropyCalc")


# ============================================================
# CORE ENTROPY CALCULATION (vectorized for <1 ms latency)
# ============================================================

def calculate_entropy(data) -> float:
    """Calculate Shannon entropy of a byte sequence (vectorized).

    Uses numpy's bincount for a single C-call histogram over the 256 byte
    values, then computes -sum(p*log2(p)) only over non-zero bins. For a
    64 KiB sample this runs well under 1 ms on commodity hardware.

    Returns a float in [0.0, 8.0] rounded to 4 decimals.
    """
    # Accept bytes / bytearray / memoryview / ndarray without a copy
    if isinstance(data, np.ndarray):
        arr = data.ravel()
        if arr.dtype != np.uint8:
            arr = arr.astype(np.uint8, copy=False)
    else:
        if not data:
            return 0.0
        arr = np.frombuffer(data, dtype=np.uint8)

    total = arr.size
    if total == 0:
        return 0.0

    counts = np.bincount(arr, minlength=256)
    nz = counts[counts > 0].astype(np.float64)
    p = nz / total
    entropy = float(-np.sum(p * np.log2(p)))
    return round(entropy, 4)


# ============================================================
# MAGIC-BYTE SIGNATURES (format recognition)
# ============================================================

# Map extension -> (bytes-offset, tuple-of-valid-prefix-bytes) for quick
# structural validation. Ciphertext will almost never match the declared
# format's magic header, even if the attacker tries to spoof the first
# few bytes.
MAGIC_SIGNATURES = {
    ".jpg":  (0, (b"\xff\xd8\xff",)),                                  # JPEG SOI
    ".jpeg": (0, (b"\xff\xd8\xff",)),
    ".png":  (0, (b"\x89PNG\r\n\x1a\n",)),
    ".gif":  (0, (b"GIF87a", b"GIF89a")),
    ".bmp":  (0, (b"BM",)),
    ".pdf":  (0, (b"%PDF-",)),
    ".zip":  (0, (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),       # ZIP/DOCX/XLSX/PPTX/APK/JAR
    ".docx": (0, (b"PK\x03\x04",)),
    ".xlsx": (0, (b"PK\x03\x04",)),
    ".pptx": (0, (b"PK\x03\x04",)),
    ".jar":  (0, (b"PK\x03\x04",)),
    ".gz":   (0, (b"\x1f\x8b",)),
    ".bz2":  (0, (b"BZh",)),
    ".xz":   (0, (b"\xfd7zXZ\x00",)),
    ".7z":   (0, (b"7z\xbc\xaf\x27\x1c",)),
    ".rar":  (0, (b"Rar!",)),
    ".elf":  (0, (b"\x7fELF",)),
    ".exe":  (0, (b"MZ",)),
    ".mp4":  (4, (b"ftyp",)),                                           # offset 4: "ftyp" brand
    ".mov":  (4, (b"ftyp", b"moov", b"mdat", b"wide", b"pnot", b"skip")),
    ".mp3":  (0, (b"ID3", b"\xff\xfb",)),                              # ID3v2 or MPEG frame sync
    ".wav":  (8, (b"WAVE",)),
    ".avi":  (8, (b"AVI ",)),
}


def chi2_uniformity(data) -> float | None:
    """Return the reduced chi-squared statistic against a uniform byte
    distribution. Ciphertext (any block cipher in any mode, including
    AES-CTR/stream-ciphered ransomware) produces bytes that are
    essentially uniformly distributed over 0..255, giving chi² ≈ 255
    (df=255). Real compressed content (JPG/PNG/MP4/ZIP) has strong
    structural peaks — Huffman tables, magic markers, length fields —
    so chi² is in the thousands to millions even when Shannon entropy
    is 7.5+.

    Returns ``None`` when the sample is too small to be meaningful.
    """
    if isinstance(data, np.ndarray):
        arr = data.ravel()
        if arr.dtype != np.uint8:
            arr = arr.astype(np.uint8, copy=False)
    else:
        if not data:
            return None
        arr = np.frombuffer(data, dtype=np.uint8)
    n = arr.size
    if n < 1024:
        return None
    counts = np.bincount(arr, minlength=256).astype(np.float64)
    expected = n / 256.0
    return float(np.sum((counts - expected) ** 2) / expected)


def _magic_matches(data: bytes, ext: str) -> tuple[bool, str]:
    """Check the magic header of *data* against the declared extension.

    Returns (ok, observed_sig_hex).
    """
    sig = MAGIC_SIGNATURES.get(ext.lower())
    if sig is None or not data:
        return (True, "")  # unknown ext — don't score this signal
    offset, prefixes = sig
    if len(data) <= offset:
        return (False, "")
    window = data[offset:offset + 8]
    for p in prefixes:
        if window.startswith(p):
            return (True, p.hex())
    return (False, window[:4].hex())


def calculate_file_entropy(file_path: str,
                           sample_size: int = None) -> dict:
    """Calculate entropy of a file (single-pass I/O, vectorized math).

    Reads the first ``sample_size`` bytes once, computes the Shannon
    entropy for the whole sample and three equal sections (for partial-
    encryption detection), and a SHA-256 fingerprint, without making
    extra copies of the buffer. The hot path is well under 1 ms for a
    64 KiB sample.
    """

    if sample_size is None:
        sample_size = config.SAMPLE_SIZE_BYTES

    result = {
        'file_path'       : file_path,
        'timestamp'       : datetime.now().isoformat(),
        'entropy_overall' : 0.0,
        'entropy_start'   : 0.0,
        'entropy_middle'  : 0.0,
        'entropy_end'     : 0.0,
        'file_size'       : 0,
        'bytes_read'      : 0,
        'file_extension'  : '',
        'file_hash'       : '',
        'chi2_uniformity' : None,
        'chi2_tail'       : None,
        'magic_ok'        : True,
        'magic_sig'       : '',
        'is_readable'     : False,
        'error'           : None,
    }

    _, ext = os.path.splitext(file_path)
    result['file_extension'] = ext.lower()

    try:
        result['file_size'] = os.path.getsize(file_path)

        with open(file_path, 'rb') as f:
            data = f.read(sample_size)

        n = len(data)
        result['bytes_read'] = n
        result['is_readable'] = True

        if n == 0:
            result['error'] = 'File is empty'
            return result

        # Single zero-copy numpy view over the read buffer
        arr = np.frombuffer(data, dtype=np.uint8)

        # Overall entropy
        result['entropy_overall'] = calculate_entropy(arr)

        # Section entropies — use slices (views, no copy)
        third = n // 3
        if third > 0:
            result['entropy_start']  = calculate_entropy(arr[:third])
            result['entropy_middle'] = calculate_entropy(arr[third:2*third])
            result['entropy_end']    = calculate_entropy(arr[2*third:])

        # SHA-256 fingerprint (hashlib releases the GIL, fast)
        result['file_hash'] = hashlib.sha256(data).hexdigest()

        # Structural fingerprinting: chi² against uniform distribution
        # (ciphertext ~ 255, real compressed media > 1000) and magic-byte
        # validation against the declared extension.
        result['chi2_uniformity'] = chi2_uniformity(data)
        # Tail chi² catches IN-PROGRESS in-place encryption even when the
        # attacker preserves the first N KB of the original header.
        tail = data[-min(len(data), 20000):]
        result['chi2_tail'] = chi2_uniformity(tail)
        magic_ok, magic_sig = _magic_matches(data, ext)
        result['magic_ok'] = magic_ok
        result['magic_sig'] = magic_sig

    except PermissionError:
        result['error'] = 'Permission denied'
    except FileNotFoundError:
        result['error'] = 'File not found'
    except Exception as e:
        result['error'] = str(e)

    return result


# ============================================================
# ENTROPY ANALYZER
# Goes beyond raw entropy calculation.
# Compares entropy to baseline, detects anomalies.
# ============================================================

class EntropyAnalyzer:
    """
    Analyzes file entropy and determines if it is suspicious.

    This class:
    1. Calculates current entropy of a file
    2. Compares to historical entropy (if file was seen before)
    3. Compares to normal range for that file type
    4. Returns an analysis with threat indicators
    """

    def __init__(self):
        # Store previous entropy readings for each file
        # Key: file_path, Value: list of entropy scores over time
        self.entropy_history = defaultdict(list)

        # Maximum history entries per file
        self.max_history = 10

    def analyze(self, file_path: str) -> dict:
        """
        Full entropy analysis of a file.

        Returns a comprehensive analysis dictionary including:
        - Current entropy
        - Historical comparison
        - Threat indicators
        - Recommendation
        """

        # Step 1: Calculate current entropy
        entropy_data = calculate_file_entropy(file_path)

        if not entropy_data['is_readable']:
            return self._build_result(
                entropy_data,
                score        = 0.0,
                is_suspicious= False,
                reason       = f"Cannot read file: {entropy_data['error']}"
            )

        current_entropy = entropy_data['entropy_overall']
        ext             = entropy_data['file_extension']

        # Step 2: Get historical entropy for this file
        history      = self.entropy_history[file_path]
        prev_entropy = history[-1] if history else None
        entropy_delta = 0.0

        if prev_entropy is not None:
            entropy_delta = current_entropy - prev_entropy

        # Step 3: Update history
        history.append(current_entropy)
        if len(history) > self.max_history:
            history.pop(0)

        # Step 4: Check against known normal ranges
        normal_range    = config.NORMAL_ENTROPY_RANGES.get(ext, (3.0, 7.5))
        normal_min      = normal_range[0]
        normal_max      = normal_range[1]
        # A tiny amount above the empirical range is measurement noise for
        # compressed formats. Require a meaningful margin before scoring it.
        above_normal    = current_entropy > (normal_max + 0.5)

        # Step 5: Calculate threat indicators
        indicators = []
        threat_score = 0.0

        # Indicator 1: Absolute entropy threshold. High entropy is normal
        # for many legitimate formats (images, video, archives), so it is
        # only an indicator by itself for unknown formats. Known formats are
        # evaluated against their type-specific range below.
        if current_entropy >= config.ENTROPY_THRESHOLD and (
            ext not in config.NORMAL_ENTROPY_RANGES
        ):
            indicators.append(
                f"High entropy: {current_entropy:.2f} "
                f"(threshold: {config.ENTROPY_THRESHOLD})"
            )
            threat_score += 40.0

        # Indicator 2: Entropy above normal for file type
        if above_normal and ext in config.NORMAL_ENTROPY_RANGES:
            indicators.append(
                f"Above normal for {ext}: "
                f"{current_entropy:.2f} "
                f"(normal: {normal_min:.1f}-{normal_max:.1f})"
            )
            threat_score += 40.0

        # Indicator 3: Large entropy jump from previous reading
        if abs(entropy_delta) >= config.ENTROPY_DELTA_THRESHOLD:
            indicators.append(
                f"Large entropy change: "
                f"{entropy_delta:+.2f} "
                f"(from {prev_entropy:.2f} to {current_entropy:.2f})"
            )
            threat_score += 30.0

        # Indicator 4: Section entropy anomaly
        # If end of file has much higher entropy than start,
        # could indicate partial encryption in progress
        if entropy_data['entropy_start'] > 0:
            section_delta = (entropy_data['entropy_end'] -
                           entropy_data['entropy_start'])
            if section_delta > 2.0:
                indicators.append(
                    f"Section entropy anomaly: "
                    f"start={entropy_data['entropy_start']:.2f} "
                    f"end={entropy_data['entropy_end']:.2f}"
                )
                threat_score += 15.0

        # Indicator 5: Magic-byte mismatch with declared extension.
        # Real files always have valid headers; ciphertext overwriting
        # a file does not. Very strong signal — confirms the content is
        # not a valid instance of its declared format.
        if (entropy_data.get('magic_ok') is False
                and current_entropy >= 7.0):
            indicators.append(
                f"Magic-byte mismatch for {ext}: "
                f"observed 0x{entropy_data.get('magic_sig','')}"
            )
            threat_score += 45.0

        # Indicator 6: Chi-squared uniformity = "perfectly random" bytes.
        # This is the structural-ciphertext fingerprint that closes the
        # image/video blind spot. Shannon entropy cannot distinguish
        # properly encrypted output from legitimate JPG/H.264/ZIP
        # (all three live around 7.5-8.0), but the chi-squared test
        # against uniform 0..255 does: a real JPG has structural peaks
        # (Huffman tables, markers, length fields) → chi² in the
        # thousands; AES/stream-cipher output is statistically uniform
        # → chi² ≈ 255. We require BOTH a chi² value in the uniform
        # range AND high Shannon entropy to avoid flagging sparse
        # files (all-zeros, all-spaces) that also look "flat" but have
        # very low entropy.
        chi2_tail = entropy_data.get('chi2_tail')
        chi2_full = entropy_data.get('chi2_uniformity')
        chi2_best = (min(chi2_tail, chi2_full)
                     if (chi2_tail is not None and chi2_full is not None)
                     else (chi2_tail if chi2_tail is not None else chi2_full))
        # Chi-squared uniformity is only a hard indicator for KNOWN
        # extensions where we have ground truth (JPG/ZIP/MP4/office
        # etc. all have structural byte peaks). For unknown extensions
        # an arbitrary binary blob may legitimately look uniform, so
        # chi² is treated as a soft signal at most (handled by the
        # pipeline decision layer).
        _known_exts = {
            ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".zip",
            ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".mp3",
            ".mp4", ".avi", ".mov", ".exe", ".dll", ".7z", ".rar",
            ".gz", ".tar", ".txt", ".csv", ".rtf",
        }
        if (chi2_best is not None
                and chi2_best < 300.0
                and current_entropy >= 7.0
                and entropy_data['bytes_read'] >= 4096
                and ext in _known_exts):
            indicators.append(
                f"Ciphertext fingerprint: chi2={chi2_best:.0f} "
                f"(uniform byte distribution, H={current_entropy:.2f})"
            )
            threat_score += 55.0

        # Step 6: Determine if suspicious
        is_suspicious = threat_score >= 40.0

        # Build reason string
        if indicators:
            reason = " | ".join(indicators)
        else:
            reason = (f"Normal entropy {current_entropy:.2f} "
                     f"for {ext} files")

        return self._build_result(
            entropy_data,
            score         = min(threat_score, 100.0),
            is_suspicious = is_suspicious,
            reason        = reason,
            entropy_delta = entropy_delta,
            prev_entropy  = prev_entropy,
            normal_range  = normal_range,
            indicators    = indicators
        )

    def _build_result(self, entropy_data, score,
                      is_suspicious, reason,
                      entropy_delta=0.0, prev_entropy=None,
                      normal_range=(0.0, 8.0), indicators=None):
        """Build a standardized result dictionary."""

        return {
            # ── File Info ──────────────────────────────────
            'file_path'       : entropy_data['file_path'],
            'file_extension'  : entropy_data['file_extension'],
            'file_size'       : entropy_data['file_size'],
            'file_hash'       : entropy_data.get('file_hash', ''),

            # ── Entropy Values ─────────────────────────────
            'entropy_overall' : entropy_data.get('entropy_overall', 0.0),
            'entropy_start'   : entropy_data.get('entropy_start', 0.0),
            'entropy_middle'  : entropy_data.get('entropy_middle', 0.0),
            'entropy_end'     : entropy_data.get('entropy_end', 0.0),
            'entropy_delta'   : round(entropy_delta, 4),
            'prev_entropy'    : prev_entropy,

            # ── Structural ciphertext fingerprints ────────
            'chi2_uniformity' : entropy_data.get('chi2_uniformity'),
            'chi2_tail'       : entropy_data.get('chi2_tail'),
            'magic_ok'        : entropy_data.get('magic_ok', True),
            'magic_sig'       : entropy_data.get('magic_sig', ''),

            # ── Normal Range for this file type ───────────
            'normal_range_min': normal_range[0],
            'normal_range_max': normal_range[1],

            # ── Analysis Result ────────────────────────────
            'threat_score'    : round(score, 2),
            'is_suspicious'   : is_suspicious,
            'reason'          : reason,
            'indicators'      : indicators or [],

            # ── Metadata ──────────────────────────────────
            'timestamp'       : entropy_data.get('timestamp', ''),
            'is_readable'     : entropy_data.get('is_readable', False),
            'error'           : entropy_data.get('error', None),
        }

    def transfer_history(self, source_path: str, dest_path: str) -> None:
        """Keep entropy history across ransomware-style renames."""
        if not source_path or not dest_path or source_path == dest_path:
            return
        history = self.entropy_history.get(source_path)
        if history:
            self.entropy_history[dest_path] = list(history)

    def snapshot_directory(self, root: str) -> int:
        """Prime entropy history for every file under *root*.

        The startup baseline. Without this, the FIRST event on a
        pre-existing file has no delta (empty history), so a rename
        that encrypts an old file scores only its raw-entropy points
        (alert, not quarantine). Priming makes the first-event delta
        real — this is exactly what the benchmark's "baseline mode"
        models, so production and the benchmark agree.

        Read-only: mirrors BackupManager.snapshot_directory.
        """
        count = 0
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                path = os.path.join(dirpath, name)
                if os.path.isfile(path):
                    self.analyze(path)
                    count += 1
        return count

    def get_history(self, file_path: str) -> list:
        """Get entropy history for a specific file."""
        return list(self.entropy_history.get(file_path, []))

    def clear_history(self, file_path: str = None):
        """Clear entropy history."""
        if file_path:
            self.entropy_history.pop(file_path, None)
        else:
            self.entropy_history.clear()


# ============================================================
# ENTROPY VISUALIZER
# Displays entropy as a visual bar in the terminal.
# Makes it easy to understand the entropy value at a glance.
# ============================================================

def visualize_entropy(entropy: float,
                      label: str = "",
                      width: int = 40) -> str:
    """
    Create a text-based entropy bar visualization.

    Example output:
    [========================================] 8.00 ENCRYPTED
    [==========================              ] 5.20 NORMAL
    [================                        ] 3.10 LOW

    Args:
        entropy: Entropy value (0.0 to 8.0)
        label:   Optional label to show
        width:   Width of the bar in characters

    Returns:
        Formatted string for display
    """

    # Calculate fill amount
    fill = int((entropy / 8.0) * width)
    fill = max(0, min(fill, width))

    bar = '=' * fill + ' ' * (width - fill)

    # Choose status label based on entropy
    if entropy >= 7.5:
        status = "ENCRYPTED/COMPRESSED"
    elif entropy >= 6.0:
        status = "COMPRESSED"
    elif entropy >= 4.0:
        status = "NORMAL"
    elif entropy >= 2.0:
        status = "LOW"
    else:
        status = "VERY LOW"

    if label:
        return f"[{bar}] {entropy:.2f}  {status}  {label}"
    else:
        return f"[{bar}] {entropy:.2f}  {status}"


# ============================================================
# STANDALONE TEST
# Run this file directly to test entropy calculation.
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("  ENTROPY - Entropy Calculator Test")
    print("=" * 60)
    print()

    # ── Test 1: Calculate entropy of different data types ──
    print("TEST 1: Basic Entropy Calculation")
    print("-" * 40)

    test_cases = [
        # (description, data)
        ("All zeros (min entropy)",
         bytes([0] * 1000)),

        ("All same byte",
         bytes([65] * 1000)),

        ("Simple English text",
         b"Hello world this is a normal text file " * 25),

        ("Structured data (repeating)",
         bytes([i % 16 for i in range(1000)])),

        ("Random-looking data (simulated encrypted)",
         bytes([i % 256 for i in range(1000)])),

        ("High entropy (all 256 values equally)",
         bytes(list(range(256)) * 4)),
    ]

    for description, data in test_cases:
        entropy = calculate_entropy(data)
        bar = visualize_entropy(entropy, description)
        print(f"  {bar}")

    print()

    # ── Test 2: Create real test files and measure them ────
    print("TEST 2: Real File Entropy Measurement")
    print("-" * 40)

    test_dir = config.TESTING_DATA_DIR
    os.makedirs(test_dir, exist_ok=True)

    # Create test files
    test_files = []

    # File 1: Plain text (low entropy)
    f1 = os.path.join(test_dir, "test_normal.txt")
    with open(f1, 'w') as f:
        f.write("Hello world. " * 500)
    test_files.append(("Normal text file", f1))

    # File 2: Structured data (medium entropy)
    f2 = os.path.join(test_dir, "test_structured.dat")
    with open(f2, 'wb') as f:
        f.write(bytes([i % 64 for i in range(10000)]))
    test_files.append(("Structured data", f2))

    # File 3: Simulated encrypted (high entropy)
    # We use os.urandom() which produces random bytes
    # This simulates what encrypted file content looks like
    f3 = os.path.join(test_dir, "test_encrypted_sim.dat")
    with open(f3, 'wb') as f:
        f.write(os.urandom(10000))
    test_files.append(("Simulated encrypted (random bytes)", f3))

    # File 4: Mixed content (partly encrypted simulation)
    f4 = os.path.join(test_dir, "test_mixed.dat")
    with open(f4, 'wb') as f:
        f.write(b"Normal header content. " * 50)   # normal start
        f.write(os.urandom(8000))                   # encrypted end
    test_files.append(("Mixed (normal start, encrypted end)", f4))

    # Measure entropy of each file
    analyzer = EntropyAnalyzer()

    for description, filepath in test_files:
        result = analyzer.analyze(filepath)
        print(f"\n  File: {description}")
        print(f"  Path: {os.path.basename(filepath)}")
        print(f"  Size: {result['file_size']} bytes")

        bar = visualize_entropy(result['entropy_overall'])
        print(f"  Overall:  {bar}")

        bar_s = visualize_entropy(result['entropy_start'])
        bar_m = visualize_entropy(result['entropy_middle'])
        bar_e = visualize_entropy(result['entropy_end'])
        print(f"  Start:    {bar_s}")
        print(f"  Middle:   {bar_m}")
        print(f"  End:      {bar_e}")

        print(f"  Suspicious: {result['is_suspicious']}")
        print(f"  Threat Score: {result['threat_score']}/100")
        if result['reason']:
            print(f"  Reason: {result['reason']}")

    print()

    # ── Test 3: Simulate entropy CHANGE (ransomware effect) ─
    print()
    print("TEST 3: Entropy Change Detection")
    print("-" * 40)
    print("Simulating ransomware encrypting a file...")
    print()

    # Create a normal file
    target = os.path.join(test_dir, "target_file.txt")
    with open(target, 'w') as f:
        f.write("This is a normal document. " * 200)

    # First reading (normal)
    result1 = analyzer.analyze(target)
    print(f"  BEFORE encryption:")
    print(f"  {visualize_entropy(result1['entropy_overall'], 'target_file.txt')}")
    print(f"  Suspicious: {result1['is_suspicious']}")

    print()
    print("  [Simulating ransomware encrypting the file...]")
    time.sleep(1)

    # Simulate encryption: overwrite with random bytes
    with open(target, 'wb') as f:
        f.write(os.urandom(10000))

    # Second reading (after "encryption")
    result2 = analyzer.analyze(target)
    print()
    print(f"  AFTER encryption:")
    print(f"  {visualize_entropy(result2['entropy_overall'], 'target_file.txt')}")
    print(f"  Entropy delta: {result2['entropy_delta']:+.2f}")
    print(f"  Suspicious: {result2['is_suspicious']}")
    print(f"  Threat Score: {result2['threat_score']}/100")
    print(f"  Reason: {result2['reason']}")

    print()
    print("=" * 60)
    print("  Entropy Calculator Test Complete")
    print("=" * 60)
    print()
    print("Test files created in:")
    print(f"  {test_dir}")
    print()
    print("Next step: Connect entropy calculator to file monitor")