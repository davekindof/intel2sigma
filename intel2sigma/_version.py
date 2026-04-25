"""Version + build provenance, surfaced via the ``/version`` endpoint.

The /version endpoint is for ops visibility (which build is live, what
data versions ship with it) and tester bug reports (which MITRE matrix /
SigmaHQ commit / build SHA is in play). It does NOT leak any rule
contents or per-request data.

All the values here are static for a given image, computed once at
import time. No I/O on each /version request.
"""

from __future__ import annotations

import json
import os
from typing import Any

from intel2sigma import __version__
from intel2sigma._data import data_path

# Pinned SigmaHQ corpus commit. Source of truth lives here (not in
# scripts/fetch_sigmahq.py) so the /version endpoint can surface it
# without the scripts/ tree having to ship in the wheel. Bumped
# quarterly per the recalibration cadence in docs/taxonomy.md.
SIGMAHQ_PINNED_COMMIT = "03412947a2d653ca1398db62a51d2de9da96b361"

# Bound to a name so ruff 0.15.x doesn't strip the parens off the
# ``except (X, Y):`` form below — see web/mitre.py for the same workaround.
_LOAD_FAILURES = (OSError, json.JSONDecodeError)


def _build_sha() -> str:
    """Git commit SHA the running container was built from.

    Set by the Dockerfile via ``ARG BUILD_SHA`` → ``ENV INTEL2SIGMA_BUILD_SHA``.
    Defaults to ``"dev"`` so local ``uv run uvicorn`` doesn't error.
    """
    return os.environ.get("INTEL2SIGMA_BUILD_SHA", "dev")


def _read_mitre_provenance() -> tuple[str, str]:
    """Pull (version, generated_at) out of the bundled MITRE tree.

    ``("?", "?")`` if the file is missing or malformed — the picker UI
    already degrades the same way, so /version stays consistent.
    """
    path = data_path("mitre_attack.json")
    if not path.is_file():
        return ("?", "?")
    try:
        tree: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except _LOAD_FAILURES:
        return ("?", "?")
    return (str(tree.get("version", "?")), str(tree.get("generated_at", "?")))


def build_version_payload() -> dict[str, str]:
    """Static manifest used by the /version endpoint.

    Computed once at import time; no per-request work.
    """
    mitre_version, mitre_generated = _read_mitre_provenance()
    return {
        "package": __version__,
        "build_sha": _build_sha(),
        "mitre_attack": mitre_version,
        "mitre_generated_at": mitre_generated,
        "sigmahq_corpus_commit": SIGMAHQ_PINNED_COMMIT,
    }


# Computed once at import time so /version is a constant-time lookup.
_VERSION_PAYLOAD: dict[str, str] = build_version_payload()


def version_payload() -> dict[str, str]:
    """Return the cached version manifest. Pure, constant-time."""
    return _VERSION_PAYLOAD


__all__ = [
    "SIGMAHQ_PINNED_COMMIT",
    "build_version_payload",
    "version_payload",
]
