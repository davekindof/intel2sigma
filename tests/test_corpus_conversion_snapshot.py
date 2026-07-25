"""Corpus-wide conversion snapshot — the corpus-refresh safety net.

Where ``test_convert_engine.py`` pins the exact output of one hand-built
rule per backend, this module pins the *conversion outcome* of a
representative slice of the real bundled corpus across every backend in
``data/pipelines.yml``.

The point is corpus refreshes. Bumping ``SIGMAHQ_PINNED_COMMIT`` and
rebuilding ``data/sigmahq_corpus.json`` changes rule content wholesale;
without a snapshot, a change in converted output — a renamed field, a
retagged rule, a logsource move — lands silently. With one, it lands as
a reviewable diff.

Three design points worth knowing before you regenerate:

* **The sample is pinned by rule UUID, not by position.** The manifest
  (``_manifest.json``) records which rules were chosen. After a corpus
  swap the same UUIDs are looked up again, so the diff compares like
  with like. Selecting "first N per category" would silently compare
  different rules on either side of the swap and prove nothing.
* **Failures are snapshotted too.** A rule that cannot convert records
  its error, so a conversion that starts *or stops* working is equally
  a diff. Most of the corpus does not convert on the Kusto backends
  (pySigma has no table mapping for cloud/identity logsources) — that
  is the pre-existing state this snapshot locks in, not an endorsement
  of it.
* **A rule that leaves the corpus is a diff, not a crash.** Upstream
  deletes rules; the snapshot records ``missing`` so the removal is
  visible and explainable rather than an error.

Regenerate with::

    UPDATE_GOLDENS=1 uv run pytest tests/test_corpus_conversion_snapshot.py

Regenerating is a deliberate act: the diff it produces is the artifact
you review during a corpus refresh, per docs/recalibration.md.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Final

import pytest

from intel2sigma._data import data_path
from intel2sigma.core.convert.engine import convert
from intel2sigma.core.convert.pipelines import load_pipeline_matrix
from intel2sigma.core.serialize import from_yaml

GOLDEN_DIR: Final = Path(__file__).parent / "golden" / "corpus_conversion"
MANIFEST_PATH: Final = GOLDEN_DIR / "_manifest.json"

# Okta is called out explicitly because its field names were normalised to
# CamelCase upstream in r2026-07-01 (eventtype -> eventType, and
# target.user.display.name -> target.displayName, which is a replacement
# rather than a recasing). One rule per logsource key would give a single
# Okta sample; that is too thin to characterise a rename sweep.
_OKTA_MIN: Final = 5

# Rules sampled per distinct (product, category, service) key. One is
# enough for a tripwire and keeps the slow suite bounded; the manifest
# makes it obvious which rule stands for each key.
_PER_LOGSOURCE_KEY: Final = 1


def _logsource_key(entry: dict[str, Any]) -> str:
    """Stable ``product/category/service`` label, ``-`` for absent parts."""
    ls = entry.get("logsource") or {}
    return "{}/{}/{}".format(
        ls.get("product") or "-",
        ls.get("category") or "-",
        ls.get("service") or "-",
    )


def _is_okta(entry: dict[str, Any]) -> bool:
    ls = entry.get("logsource") or {}
    return ls.get("product") == "okta" or ls.get("service") == "okta"


def _loadable(entry: dict[str, Any]) -> bool:
    """Whether the bundled parser can turn this entry into a rule.

    ~2.6% of the corpus does not round-trip through :func:`from_yaml`
    (predominantly the keyword-list detection form). Those are excluded
    from *selection* so the sample is all live conversions; a selected
    rule that later stops parsing is still reported, as ``parse_error``.
    """
    # Broad by intent: this is a selection filter, so any failure mode
    # (parse, validation, unsupported detection shape) equally disqualifies.
    try:
        from_yaml(entry["raw_yaml"])
    except Exception:
        return False
    return True


def _select_sample(corpus: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Choose the snapshot sample deterministically.

    Every distinct logsource key contributes its lowest-UUID loadable
    rule, plus enough Okta rules to satisfy :data:`_OKTA_MIN`. Sorting
    by UUID (rather than corpus order) keeps selection stable across
    rebuilds, which is what makes the manifest meaningful.
    """
    by_key: dict[str, list[dict[str, Any]]] = {}
    for entry in corpus:
        by_key.setdefault(_logsource_key(entry), []).append(entry)

    chosen: dict[str, dict[str, Any]] = {}
    for key in sorted(by_key):
        loadable = [e for e in sorted(by_key[key], key=lambda e: e["id"]) if _loadable(e)]
        for entry in loadable[:_PER_LOGSOURCE_KEY]:
            chosen[entry["id"]] = entry

    okta = [e for e in sorted(corpus, key=lambda e: e["id"]) if _is_okta(e) and _loadable(e)]
    for entry in okta[:_OKTA_MIN]:
        chosen[entry["id"]] = entry

    return [
        {"id": e["id"], "title": e["title"], "logsource": _logsource_key(e)}
        for e in sorted(chosen.values(), key=lambda e: e["id"])
    ]


# pySigma accumulates field-name validation errors in state shared across
# conversions: converting rule B after rule A yields an error for B that
# also names A's invalid fields. Verified directly — a ps_script rule's
# error listed ``Device`` from a previously converted raw_access_thread
# rule. That makes raw error text order-dependent, so snapshotting it
# verbatim would produce diffs that reflect test execution order rather
# than any change in the corpus.
#
# Normalising strips the leaked fragments and the pipeline's verbose
# valid-field dump, keeping the parts that are genuinely rule-specific
# and stable: the exception type, the backend/pipeline that failed, and
# the target table. An ok<->error flip, a pipeline change, or a table
# change all still register as diffs.
_LEAKY_FRAGMENT = re.compile(r"Invalid SigmaDetectionItem field name encountered: \S+?\.\s*")
_FIELD_DUMP = re.compile(r"(Please use valid fields for the (?P<table>\w+) table).*", re.DOTALL)


def _normalize_error(exc: Exception) -> str:
    """Reduce a conversion exception to an order-independent signature."""
    msg = _LEAKY_FRAGMENT.sub("", str(exc))
    msg = _FIELD_DUMP.sub(r"invalid field(s) for table \g<table>", msg)
    return f"{type(exc).__name__}: {' '.join(msg.split())}"


def _outcome(entry: dict[str, Any] | None, backend_id: str) -> dict[str, str]:
    """Convert one rule on one backend, reducing it to a snapshottable dict."""
    if entry is None:
        return {"status": "missing"}
    # Both excepts are broad by intent: the failure itself is the value
    # being snapshotted, so it must be recorded rather than propagated.
    try:
        rule = from_yaml(entry["raw_yaml"])
    except Exception as exc:
        return {"status": "parse_error", "error": _normalize_error(exc)}
    try:
        query = convert(rule, backend_id)
    except Exception as exc:
        return {"status": "error", "error": _normalize_error(exc)}
    return {"status": "ok", "output": query}


def _backend_ids() -> list[str]:
    """Backends declared in ``data/pipelines.yml``, sorted.

    Read from the matrix rather than hardcoded so a newly declared
    backend joins the snapshot automatically (CLAUDE.md I-5).
    """
    return sorted(load_pipeline_matrix().backends)


@pytest.fixture(scope="module")
def corpus() -> list[dict[str, Any]]:
    raw = data_path("sigmahq_corpus.json").read_text(encoding="utf-8")
    parsed: list[dict[str, Any]] = json.loads(raw)
    return parsed


@pytest.fixture(scope="module")
def manifest(corpus: list[dict[str, Any]]) -> list[dict[str, str]]:
    """The pinned sample. Regenerated only under ``UPDATE_GOLDENS``."""
    if os.environ.get("UPDATE_GOLDENS"):
        selected = _select_sample(corpus)
        GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
        MANIFEST_PATH.write_text(
            json.dumps(selected, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        return selected
    if not MANIFEST_PATH.is_file():
        pytest.fail(
            f"Missing {MANIFEST_PATH}. Generate it with "
            f"UPDATE_GOLDENS=1 uv run pytest {Path(__file__).name}"
        )
    loaded: list[dict[str, str]] = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return loaded


@pytest.mark.slow
@pytest.mark.parametrize("backend_id", _backend_ids())
def test_corpus_conversion_matches_snapshot(
    backend_id: str,
    corpus: list[dict[str, Any]],
    manifest: list[dict[str, str]],
) -> None:
    """Every sampled rule converts exactly as it did when last snapshotted.

    Regenerate with
    ``UPDATE_GOLDENS=1 uv run pytest tests/test_corpus_conversion_snapshot.py``.
    """
    by_id = {e["id"]: e for e in corpus}
    actual = {row["id"]: _outcome(by_id.get(row["id"]), backend_id) for row in manifest}

    snapshot_path = GOLDEN_DIR / f"{backend_id}.json"
    if os.environ.get("UPDATE_GOLDENS"):
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(
            json.dumps(actual, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        pytest.skip(f"Updated snapshot at {snapshot_path}")

    assert snapshot_path.is_file(), (
        f"Missing snapshot {snapshot_path}. Create it with "
        f"UPDATE_GOLDENS=1 uv run pytest {Path(__file__).name}"
    )
    expected: dict[str, dict[str, str]] = json.loads(snapshot_path.read_text(encoding="utf-8"))

    drifted = sorted(k for k in expected.keys() | actual.keys() if expected.get(k) != actual.get(k))
    if drifted:
        titles = {row["id"]: row["title"] for row in manifest}
        detail = "\n".join(
            f"  {rid} ({titles.get(rid, '?')})\n"
            f"    was: {expected.get(rid)}\n"
            f"    now: {actual.get(rid)}"
            for rid in drifted[:10]
        )
        pytest.fail(
            f"{backend_id}: {len(drifted)} sampled rule(s) changed conversion outcome.\n"
            f"{detail}\n"
            f"{'  ... and more' if len(drifted) > 10 else ''}\n"
            f"If this follows a deliberate corpus refresh, every diff must be "
            f"explainable before regenerating with UPDATE_GOLDENS=1."
        )


@pytest.mark.slow
def test_sample_covers_every_logsource_key(
    corpus: list[dict[str, Any]],
    manifest: list[dict[str, str]],
) -> None:
    """The sample must not silently shrink away from full logsource coverage.

    A corpus refresh that introduces a new ``(product, category, service)``
    key should surface here, prompting a manifest regeneration rather than
    leaving the new logsource untested.
    """
    corpus_keys = {_logsource_key(e) for e in corpus if _loadable(e)}
    sampled_keys = {row["logsource"] for row in manifest}
    missing = sorted(corpus_keys - sampled_keys)
    assert not missing, (
        f"{len(missing)} logsource key(s) present in the corpus but absent from the "
        f"snapshot sample: {missing[:15]}. Regenerate the manifest with "
        f"UPDATE_GOLDENS=1 uv run pytest {Path(__file__).name}"
    )


@pytest.mark.slow
def test_sample_includes_enough_okta_rules(manifest: list[dict[str, str]]) -> None:
    """Okta is the logsource whose field names moved in r2026-07-01."""
    okta = [row for row in manifest if row["logsource"].startswith("okta/")]
    assert len(okta) >= _OKTA_MIN, (
        f"Snapshot sample has {len(okta)} Okta rule(s), expected at least {_OKTA_MIN}."
    )
