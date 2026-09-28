# ============================================================
# ENTROPY benchmark — scenario definitions
# benchmark/scenarios.py
#
# Every scenario models what the FILE MONITOR would observe:
#   initial_files : the victim estate that exists at t=0
#   ops           : ordered file operations with simulated timing
#
# All content generation is seeded (random.Random) so the battery
# is fully deterministic and reproducible.
# ============================================================

import random
import numpy as np
from dataclasses import dataclass, field


# ── Operation / scenario model ──────────────────────────────

@dataclass
class Op:
    """One filesystem operation as the monitor would see it."""
    kind: str                    # "create" | "modify" | "rename" | "delete"
    rel_path: str                # path relative to the victim root
    content: bytes = b""
    new_path: str | None = None  # rename destination (relative)
    delay_before: float = 1.0    # simulated seconds since previous op


@dataclass
class Scenario:
    name: str
    kind: str                    # "attack" | "legitimate"
    description: str
    initial_files: list = field(default_factory=list)  # [(rel_path, content)]
    ops: list = field(default_factory=list)            # [Op]
    # Subtree that the defender protects (backup store analogue);
    # deletions inside it are defense-tamper signals.
    protected_paths: list = field(default_factory=list)


_NOTE_TEXT = (
    "Your files have been encrypted with AES-256.\n"
    "To recover your files, pay 0.5 BTC to the wallet address below.\n"
    "You have 72 hours to pay. Private key verification required.\n"
)


# ── Seeded content helpers ──────────────────────────────────

_DOC_LINES = [
    "Quarterly performance review and planning notes.",
    "The budget committee approved the proposed allocation.",
    "Please review the attached draft before Friday.",
    "Customer onboarding checklist for the new account.",
    "Engineering standup summary and action items.",
    "Draft: product requirements for the upcoming release.",
    "Invoice and payment terms for the consulting engagement.",
    "Meeting minutes: strategy session with leadership.",
]


def text_bytes(rng: random.Random, size: int) -> bytes:
    """Low-entropy, document-like content (~3.5-4.5 bits/byte)."""
    out = bytearray()
    i = 0
    while len(out) < size:
        line = _DOC_LINES[i % len(_DOC_LINES)]
        out.extend(f"{i:05d} {line}\n".encode())
        i += 1
    return bytes(out[:size])


def random_bytes(rng: random.Random, size: int) -> bytes:
    """Encrypted-like content: ~8.0 bits/byte, statistically uniform."""
    return rng.randbytes(size)


def compressed_bytes(rng: random.Random, magic: bytes, size: int) -> bytes:
    """Legitimate compressed-media content: high entropy (~7.5 bits/byte)
    but STRUCTURED (non-uniform byte histogram), valid magic header.

    Real JPG/MP4/ZIP all have Huffman-coded streams whose per-byte
    distribution is sharply multimodal, giving chi² in the thousands
    even though Shannon entropy sits at 7-8 bits. Ciphertext is flat
    uniform at chi² ≈ 255. Using ``random_bytes`` (uniform) to
    simulate a "legitimate" photo import/archive creation makes the
    benchmark label real alerts as false positives — so we use this
    helper for legitimate compressed-format workloads.
    """
    if size <= len(magic):
        return magic[:size]
    rng_np = np.random.default_rng(rng.randint(0, 2**31))
    alpha = np.ones(256, dtype=np.float64)
    # Sprinkle ~30 "Huffman-style" peaks to get chi² in the thousands
    peaks = rng_np.choice(256, size=30, replace=False)
    alpha[peaks] += rng_np.uniform(2.0, 6.0, size=len(peaks))
    alpha /= alpha.sum()
    body = rng_np.choice(
        256, size=size - len(magic), p=alpha
    ).astype(np.uint8).tobytes()
    return (magic + body)[:size]


# ── Attack variants ─────────────────────────────────────────

DISGUISE_EXTS = [".locked", ".encrypted", ".crypt", ".wnaCry", ".paid",
                 ".winlock", ".data.lock"]
_OFFICE_EXTS = [".txt", ".docx", ".xlsx", ".pdf"]
PAYLOAD = 65536


def _estate(rng: random.Random, n_files: int,
            exts=_OFFICE_EXTS) -> list:
    """A clean victim estate of n small office files."""
    files = []
    for i in range(n_files):
        ext = exts[i % len(exts)]
        rel = f"Documents/file_{i:02d}{ext}"
        files.append((rel, text_bytes(rng, 2048 + rng.randrange(0, 4096))))
    return files


def attack_burst_encoder(seed: int) -> Scenario:
    """Fast bulk encryption (0.1s between files) with rename disguise.
    The classic lab attack: speed + extension + range signals."""
    rng = random.Random(seed)
    estate = _estate(rng, 8)
    ops = []
    for i, (rel, _content) in enumerate(estate):
        new = rel + DISGUISE_EXTS[i % len(DISGUISE_EXTS)]
        ops.append(Op("rename", rel, random_bytes(rng, PAYLOAD),
                      new_path=new, delay_before=0.1))
    return Scenario(
        "burst_encoder", "attack",
        "Fast bulk encryption (0.1s/file) with extension disguise",
        estate, ops,
    )


def attack_slow_crawler(seed: int) -> Scenario:
    """Slow encryption (2s between files) with rename disguise.
    No speed signal — extension + range signals only."""
    rng = random.Random(seed)
    estate = _estate(rng, 8)
    ops = []
    for i, (rel, _content) in enumerate(estate):
        new = rel + DISGUISE_EXTS[i % len(DISGUISE_EXTS)]
        ops.append(Op("rename", rel, random_bytes(rng, PAYLOAD),
                      new_path=new, delay_before=2.0))
    return Scenario(
        "slow_crawler", "attack",
        "Slow encryption (2s/file) with extension disguise",
        estate, ops,
    )


def attack_polymorphic(seed: int) -> Scenario:
    """Shape-shifter: random file order, random per-file disguise
    extension, random timing (0.2-1.5s). The flagship demo attack."""
    rng = random.Random(seed)
    estate = _estate(rng, 8)
    order = list(range(len(estate)))
    rng.shuffle(order)
    ops = []
    for i, idx in enumerate(order):
        rel, _content = estate[idx]
        new = rel + DISGUISE_EXTS[rng.randrange(len(DISGUISE_EXTS))]
        ops.append(Op("rename", rel, random_bytes(rng, PAYLOAD),
                      new_path=new, delay_before=rng.uniform(0.2, 1.5)))
    return Scenario(
        "polymorphic", "attack",
        "Polymorphic: randomized order, extensions, and timing",
        estate, ops,
    )


def attack_baseline_first(seed: int) -> Scenario:
    """Clean edit, then encryption of the same file: the entropy-
    delta signal. This is the scenario the startup baseline exists for."""
    rng = random.Random(seed)
    estate = _estate(rng, 4, exts=[".txt", ".docx"])
    ops = []
    for i, (rel, _content) in enumerate(estate):
        ops.append(Op("modify", rel, text_bytes(rng, 4096),
                      delay_before=0.5))
        new = rel + DISGUISE_EXTS[i % len(DISGUISE_EXTS)]
        ops.append(Op("rename", rel, random_bytes(rng, PAYLOAD),
                      new_path=new, delay_before=0.3))
    return Scenario(
        "baseline_first", "attack",
        "Clean edit followed by in-place encryption (delta signal)",
        estate, ops,
    )


def attack_silent_unknown_ext(seed: int) -> Scenario:
    """Encryption of files with never-before-seen extensions, fast,
    no prior history: absolute-entropy + speed signals only."""
    rng = random.Random(seed)
    estate = _estate(rng, 5)
    ops = []
    for i, (rel, _content) in enumerate(estate):
        new = rel + DISGUISE_EXTS[i % len(DISGUISE_EXTS)]
        ops.append(Op("rename", rel, random_bytes(rng, PAYLOAD),
                      new_path=new, delay_before=0.2))
    return Scenario(
        "silent_unknown_ext", "attack",
        "Fast encryption of unknown extensions without prior history",
        estate, ops,
    )


def attack_image_blindspot(seed: int) -> Scenario:
    """Slow, in-place encryption of .jpg files: entropy stays within
    the normal image range (7.0-7.8 + 0.5 margin), no rename, no
    speed. The original images are ALSO ~8.0, so there is no delta.
    This is a documented blind spot of entropy-only detection in BOTH
    baseline modes: the encrypted payload is indistinguishable from
    native compressed content."""
    rng = random.Random(seed)
    estate = [(f"Photos/pic_{i:02d}.jpg", random_bytes(rng, PAYLOAD))
              for i in range(4)]
    ops = []
    for rel, _content in estate:
        ops.append(Op("modify", rel, random_bytes(rng, PAYLOAD),
                      delay_before=3.0))
    return Scenario(
        "image_blindspot", "attack",
        "Slow in-place encryption of images (no rename, in-range entropy) — "
        "documented blind spot",
        estate, ops,
    )


def attack_note_dropper(seed: int) -> Scenario:
    """Drops a ransom note, then encrypts an image in place (the
    entropy blind spot). The ONLY signal is the note itself — if the
    note detector works, this is detected instantly."""
    rng = random.Random(seed)
    estate = [
        ("Documents/report.docx", text_bytes(rng, 2048)),
        ("Photos/pic_00.jpg", random_bytes(rng, PAYLOAD)),
    ]
    ops = [
        Op("create", "Documents/Restore-My-Files.txt",
           _NOTE_TEXT.encode(), delay_before=0.5),
        Op("modify", "Photos/pic_00.jpg",
           random_bytes(rng, PAYLOAD), delay_before=3.0),
    ]
    return Scenario(
        "note_dropper", "attack",
        "Ransom note dropped + image encrypted in place (note is the only signal)",
        estate, ops,
    )


def attack_backup_tamper(seed: int) -> Scenario:
    """The attacker destroys the backup store first (defense tamper),
    then deletes a victim file. Detection must come from the
    protected-path deletions, not entropy."""
    rng = random.Random(seed)
    estate = [
        ("Documents/notes.txt", text_bytes(rng, 2048)),
        ("backup/snap_00.bin", random_bytes(rng, 4096)),
        ("backup/snap_01.bin", random_bytes(rng, 4096)),
    ]
    ops = [
        Op("delete", "backup/snap_00.bin", delay_before=0.2),
        Op("delete", "backup/snap_01.bin", delay_before=0.2),
        Op("delete", "Documents/notes.txt", delay_before=0.2),
    ]
    return Scenario(
        "backup_tamper", "attack",
        "Backup store deleted before encryption (defense tamper)",
        estate, ops,
        protected_paths=["backup"],
    )


ATTACKS = [
    attack_burst_encoder,
    attack_slow_crawler,
    attack_polymorphic,
    attack_baseline_first,
    attack_silent_unknown_ext,
    attack_image_blindspot,
    attack_note_dropper,
    attack_backup_tamper,
]


# ── Legitimate workloads ────────────────────────────────────

def workload_document_editing(seed: int) -> Scenario:
    rng = random.Random(seed)
    estate = [(f"Documents/doc_{i}.txt", text_bytes(rng, 2048))
              for i in range(4)]
    ops = []
    for i, (rel, content) in enumerate(estate):
        # Append a new paragraph (a normal edit).
        ops.append(Op("modify", rel,
                      content + text_bytes(rng, 512), delay_before=1.0))
    return Scenario(
        "document_editing", "legitimate",
        "User editing text documents (low entropy, slow)",
        estate, ops,
    )


def workload_archive_creation(seed: int) -> Scenario:
    """High-entropy but legitimate: user creating .zip archives."""
    rng = random.Random(seed)
    ops = []
    for i in range(5):
        rel = f"Archives/backup_{i:02d}.zip"
        ops.append(Op("create", rel, compressed_bytes(rng, b"PK\x03\x04", PAYLOAD),
                      delay_before=1.0))
    return Scenario(
        "archive_creation", "legitimate",
        "User creating .zip archives (high entropy, known range)",
        [], ops,
    )


def workload_photo_import(seed: int) -> Scenario:
    """High-entropy but legitimate: importing photos (real JPEG)."""
    rng = random.Random(seed)
    ops = []
    for i in range(5):
        rel = f"Photos/photo_{i:02d}.jpg"
        ops.append(Op("create", rel,
                      compressed_bytes(rng, b"\xff\xd8\xff\xe0\x00\x10JFIF", PAYLOAD),
                      delay_before=0.5))
    return Scenario(
        "photo_import", "legitimate",
        "User importing photos (high entropy, known range)",
        [], ops,
    )


def workload_video_write(seed: int) -> Scenario:
    """User writing MP4 video files (real MPEG container + coded frames)."""
    rng = random.Random(seed)
    ops = []
    for i in range(2):
        rel = f"Videos/clip_{i}.mp4"
        ops.append(Op("create", rel,
                      compressed_bytes(rng, b"\x00\x00\x00\x20ftypisom", PAYLOAD * 2),
                      delay_before=0.2))
    return Scenario(
        "video_write", "legitimate",
        "User writing video files (high entropy, known range)",
        [], ops,
    )


def workload_git_burst(seed: int) -> Scenario:
    """Fast burst of many small clean files (e.g. a git checkout).
    Speed signal fires; entropy stays low. Expected outcome: a
    BENIGN ALERT (action 1) — never a quarantine."""
    rng = random.Random(seed)
    ops = []
    for i in range(40):
        rel = f"Project/src/module_{i:02d}.py"
        ops.append(Op("create", rel, text_bytes(rng, 256),
                      delay_before=0.08))
    return Scenario(
        "git_burst", "legitimate",
        "Rapid creation of 40 small text files (speed signal only)",
        [], ops,
    )


def workload_csv_export(seed: int) -> Scenario:
    rng = random.Random(seed)
    ops = []
    for i in range(3):
        rel = f"Exports/report_{i}.csv"
        ops.append(Op("create", rel, text_bytes(rng, 4096),
                      delay_before=1.0))
    return Scenario(
        "csv_export", "legitimate",
        "Exporting CSV reports (low entropy)",
        [], ops,
    )


def workload_db_dump(seed: int) -> Scenario:
    rng = random.Random(seed)
    ops = []
    for i in range(2):
        rel = f"Backups/dump_{i}.sql"
        ops.append(Op("create", rel, text_bytes(rng, 8192),
                      delay_before=1.0))
    return Scenario(
        "db_dump", "legitimate",
        "Writing SQL database dumps (low entropy)",
        [], ops,
    )


WORKLOADS = [
    workload_document_editing,
    workload_archive_creation,
    workload_photo_import,
    workload_video_write,
    workload_git_burst,
    workload_csv_export,
    workload_db_dump,
]
