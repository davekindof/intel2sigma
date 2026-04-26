"""Walk the synced SigmaHQ corpus and emit a bundled load-able index.

Produces ``intel2sigma/data/sigmahq_corpus.json`` — the data the
"Browse SigmaHQ" tab on Stage 0's load modal searches against.
Each entry carries:

* ``id``           — rule UUID (corpus-stable; primary key for load-by-click)
* ``title``        — for display + search
* ``description`` — first ~200 chars (truncated for index size)
* ``level``        — ``low``/``medium``/``high``/``critical``/etc.
* ``status``       — ``stable``/``test``/``experimental``/etc.
* ``logsource``    — ``{product, category, service}`` (any may be null)
* ``tags``         — list of ATT&CK + other tags
* ``file_path``    — relative path under ``sigmahq-rules/`` (provenance)
* ``raw_yaml``     — full file content, used when the user clicks-to-load
* ``search_blob``  — pre-computed lower-cased blob of title + tags + first
                     ~500 chars of detection block names + first sentence of
                     description; used by the runtime search to avoid
                     re-stringifying every entry.

Walks only the directories that actually contain shippable rules:
``rules/``, ``rules-emerging-threats/``, ``rules-threat-hunting/``.
Skips ``deprecated/``, ``tests/``, ``scripts/``, ``.github/``,
``images/``, ``unsupported/``, ``regression_data/``, ``other/``,
``documentation/`` — none of those are user-loadable rules.

Run as part of the quarterly recalibration cycle (after
``scripts/fetch_sigmahq.py`` bumps the pinned commit).

Usage::

    uv run python scripts/build_sigmahq_corpus.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = PROJECT_ROOT / "sigmahq-rules"
OUTPUT_PATH = PROJECT_ROOT / "intel2sigma" / "data" / "sigmahq_corpus.json"

# Top-level corpus directories that contain real, shippable Sigma rules.
# Anything outside this list is excluded — the SigmaHQ repo also carries
# tests, scripts, regression fixtures, deprecated rules, and other
# non-loadable content that would only confuse the user.
_INCLUDE_DIRS = ("rules", "rules-emerging-threats", "rules-threat-hunting")

_DESC_MAX_CHARS = 200
_SEARCH_BLOB_MAX_CHARS = 800


def _walk_yaml(root: Path) -> list[Path]:
    """Yield every ``*.yml`` under ``root`` recursively."""
    return sorted(root.rglob("*.yml"))


def _truncate(text: str, max_chars: int) -> str:
    """Trim free-text fields to ``max_chars``, keeping word boundaries."""
    text = text.strip().replace("\n", " ").replace("\r", " ")
    if len(text) <= max_chars:
        return text
    cut = text[:max_chars].rsplit(" ", 1)[0]
    return cut + "…"


def _entry_for(
    path: Path,
    repo_root: Path,
    parsed: dict[str, Any],
    raw: str,
) -> dict[str, Any] | None:
    """Build one corpus-index entry from a parsed rule dict."""
    rule_id = parsed.get("id")
    title = parsed.get("title")
    if not isinstance(rule_id, str) or not isinstance(title, str):
        return None
    logsource = parsed.get("logsource") or {}
    if not isinstance(logsource, dict):
        return None
    tags = parsed.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    description = parsed.get("description") or ""
    if not isinstance(description, str):
        description = ""

    # Search blob: lower-cased concatenation of the parts most useful for
    # keyword search. Avoids recomputing on every search call.
    blob_parts = [
        title,
        description,
        " ".join(str(t) for t in tags),
        str(logsource.get("category") or ""),
        str(logsource.get("product") or ""),
        str(logsource.get("service") or ""),
    ]
    search_blob = _truncate(" ".join(blob_parts).lower(), _SEARCH_BLOB_MAX_CHARS)

    return {
        "id": rule_id,
        "title": title,
        "description": _truncate(description, _DESC_MAX_CHARS),
        "level": parsed.get("level") or "",
        "status": parsed.get("status") or "",
        "logsource": {
            "category": logsource.get("category"),
            "product": logsource.get("product"),
            "service": logsource.get("service"),
        },
        "tags": [str(t) for t in tags],
        "file_path": str(path.relative_to(repo_root)).replace("\\", "/"),
        "raw_yaml": raw,
        "search_blob": search_blob,
    }


def main() -> int:
    if not CORPUS_DIR.is_dir():
        print(f"Corpus not synced at {CORPUS_DIR}.", file=sys.stderr)
        print("Run scripts/fetch_sigmahq.py first.", file=sys.stderr)
        return 1

    yaml = YAML(typ="safe")
    entries: list[dict[str, Any]] = []
    skipped_parse = 0
    skipped_shape = 0

    for sub in _INCLUDE_DIRS:
        root = CORPUS_DIR / sub
        if not root.is_dir():
            print(f"  WARN: {root} not found, skipping", file=sys.stderr)
            continue
        for path in _walk_yaml(root):
            try:
                raw = path.read_text(encoding="utf-8")
            except OSError as exc:
                skipped_parse += 1
                print(f"  read-fail: {path}: {exc}", file=sys.stderr)
                continue
            try:
                parsed = yaml.load(raw)
            except YAMLError:
                skipped_parse += 1
                continue
            if not isinstance(parsed, dict):
                skipped_shape += 1
                continue
            entry = _entry_for(path, CORPUS_DIR, parsed, raw)
            if entry is None:
                skipped_shape += 1
                continue
            entries.append(entry)

    # Sort by id for deterministic output (so re-running the script with
    # the same pinned commit produces identical bytes).
    entries.sort(key=lambda e: e["id"])

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(entries, indent=0, ensure_ascii=False), encoding="utf-8")

    size_mb = OUTPUT_PATH.stat().st_size / (1024 * 1024)
    print(f"Wrote {OUTPUT_PATH.relative_to(PROJECT_ROOT)}")
    print(f"  {len(entries)} rules indexed")
    print(f"  {size_mb:.1f} MB on disk")
    if skipped_parse:
        print(f"  {skipped_parse} files skipped due to parse errors")
    if skipped_shape:
        print(f"  {skipped_shape} files skipped due to shape (missing id/title/etc.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
