"""Verify every vendored file's on-disk hash matches the one in HASHES.md.

Fails CI if someone edits a vendored file without updating the recorded
hash, or updates the hash without editing the file. Per CLAUDE.md's
vendoring policy (I-6), hash drift is a red flag.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

VENDOR_DIR = Path(__file__).resolve().parent.parent / "intel2sigma" / "web" / "static" / "vendor"
HASHES_MD = VENDOR_DIR / "HASHES.md"


def _parse_hashes(text: str) -> dict[str, str]:
    """Pull `(filename, sha256)` pairs out of the markdown table rows.

    The file uses one table per vendored asset with ``| File |`` and
    ``| SHA-256 |`` rows. We scan line-wise for those rows rather than
    parsing the markdown properly — the format is small and stable.
    """
    hashes: dict[str, str] = {}
    current_file: str | None = None
    for line in text.splitlines():
        file_match = re.match(r"^\|\s*File\s*\|\s*`([^`]+)`\s*\|", line)
        if file_match:
            current_file = file_match.group(1)
            continue
        hash_match = re.match(r"^\|\s*SHA-256\s*\|\s*`([0-9a-fA-F]{64})`\s*\|", line)
        if hash_match and current_file:
            hashes[current_file] = hash_match.group(1).lower()
            current_file = None
    return hashes


def test_hashes_md_exists() -> None:
    assert HASHES_MD.is_file(), f"{HASHES_MD} is missing"


def test_every_vendored_file_is_listed_and_matches() -> None:
    recorded = _parse_hashes(HASHES_MD.read_text(encoding="utf-8"))
    assert recorded, f"No hashes parsed from {HASHES_MD.name}"

    on_disk = sorted(p.name for p in VENDOR_DIR.iterdir() if p.is_file() and p.name != "HASHES.md")
    missing_from_hashes = set(on_disk) - set(recorded)
    extra_in_hashes = set(recorded) - set(on_disk)
    assert not missing_from_hashes, (
        f"Files in {VENDOR_DIR.name}/ not listed in HASHES.md: {sorted(missing_from_hashes)}"
    )
    assert not extra_in_hashes, (
        f"HASHES.md lists files not present on disk: {sorted(extra_in_hashes)}"
    )

    for filename, expected in recorded.items():
        path = VENDOR_DIR / filename
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == expected, (
            f"Hash mismatch for {filename}:\n"
            f"  expected (HASHES.md): {expected}\n"
            f"  actual (on disk):     {actual}\n"
            f"If the upgrade is intentional, update HASHES.md with the new hash."
        )


def test_parse_hashes_extracts_known_entry() -> None:
    sample = """
| File | `htmx.min.js` |
| Version | 2.0.4 |
| SHA-256 | `abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789` |
"""
    result = _parse_hashes(sample)
    expected = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    assert result == {"htmx.min.js": expected}
