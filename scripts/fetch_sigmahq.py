"""Fetch the SigmaHQ rule corpus at a pinned commit.

Used by:
  * ``scripts/analyze_taxonomy.py`` — frequency analysis that calibrates
    the ``data/taxonomy/`` catalog before we hand-write it.
  * The v0 exit-gate integration test — every rule in the corpus must pass
    tier-1 + tier-2 validation.

We do **not** vendor the corpus. It lives under ``./sigmahq-rules/`` which is
git-ignored. Re-running this script is cheap: if the pinned commit is already
checked out, we no-op. If the directory exists at a different commit, we
``git fetch`` and ``reset --hard`` to the pinned SHA. Only the initial clone
takes time.

To bump the pinned commit, edit ``PINNED_COMMIT`` below and note the date.
The commit is fixed so that frequency analyses are reproducible: "these
fields were calibrated against SigmaHQ at commit X" is a defensible
provenance line on each taxonomy YAML.

Run from the project root::

    uv run python scripts/fetch_sigmahq.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

# Source of truth for the pinned commit lives in intel2sigma._version so the
# /version HTTP endpoint can surface the same value the corpus fetch uses.
# Bumped quarterly per the recalibration cadence documented in docs/taxonomy.md.
from intel2sigma._version import SIGMAHQ_PINNED_COMMIT as PINNED_COMMIT

REPO_URL = "https://github.com/SigmaHQ/sigma.git"
CLONE_DIR = Path(__file__).resolve().parent.parent / "sigmahq-rules"


class FetchError(RuntimeError):
    """Raised when the fetch cannot complete."""


def main() -> int:
    if not _git_available():
        print("ERROR: git is required but not found on PATH.", file=sys.stderr)
        return 1

    print(f"Target directory: {CLONE_DIR}")
    print(f"Pinned commit:    {PINNED_COMMIT}")

    try:
        if CLONE_DIR.is_dir():
            _update_existing(CLONE_DIR)
        else:
            _fresh_clone(CLONE_DIR)
    except FetchError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    head = _rev_parse(CLONE_DIR, "HEAD")
    if head != PINNED_COMMIT:
        print(
            f"ERROR: HEAD is {head} after fetch, expected {PINNED_COMMIT}.",
            file=sys.stderr,
        )
        return 3

    rule_count = _count_yml(CLONE_DIR)
    print(f"OK. Corpus at {head[:12]} with {rule_count} .yml rule files.")
    return 0


def _git_available() -> bool:
    return shutil.which("git") is not None


def _fresh_clone(target: Path) -> None:
    print(f"Cloning {REPO_URL} (shallow, pinned) ...")
    # A shallow clone with --revision needs git 2.49+. Fall back to full
    # fetch-and-reset if --revision is unsupported on the host.
    target.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "init", "-q", str(target)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(target), "remote", "add", "origin", REPO_URL],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(target), "fetch", "--depth=1", "origin", PINNED_COMMIT],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(target), "reset", "--hard", "FETCH_HEAD"],
        check=True,
    )


def _update_existing(target: Path) -> None:
    if not (target / ".git").is_dir():
        raise FetchError(f"{target} exists but is not a git checkout. Remove it and re-run.")
    current = _rev_parse(target, "HEAD")
    if current == PINNED_COMMIT:
        print("Already at pinned commit. Nothing to do.")
        return
    print(f"At {current[:12]}, advancing to {PINNED_COMMIT[:12]} ...")
    subprocess.run(
        ["git", "-C", str(target), "fetch", "--depth=1", "origin", PINNED_COMMIT],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(target), "reset", "--hard", "FETCH_HEAD"],
        check=True,
    )


def _rev_parse(target: Path, ref: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(target), "rev-parse", ref],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _count_yml(target: Path) -> int:
    return sum(1 for _ in target.rglob("*.yml"))


if __name__ == "__main__":
    sys.exit(main())
