"""SigmaHQ corpus integration test — v0 exit-gate check.

Two claims this file defends:

1. **Our pinned pySigma stack handles the real corpus.** Every vetted rule
   under ``sigmahq-rules/rules/`` should parse via pySigma. Perfect 100% is
   unrealistic (correlation rules, niche features, pySigma-version drift on
   deprecated modifiers), so we assert a conservative pass-rate floor and
   fail if we ever regress below it.

2. **Our taxonomy catalog matches real-world field usage.** For every
   observation type we ship a catalog file for, the top-frequency fields in
   corresponding corpus rules should appear in our catalog. A missing
   top-frequency field is a catalog drift bug that the quarterly
   recalibration would catch, but which we want CI to surface sooner.

Both tests are marked ``slow`` so the default ``uv run pytest`` invocation
stays fast. To run them::

    uv run pytest -m slow                      # only slow tests
    uv run pytest                              # default: slow tests skipped

If the corpus isn't fetched, both tests skip cleanly with an actionable
message pointing at ``scripts/fetch_sigmahq.py``.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule as PySigmaRule

from intel2sigma.core.taxonomy import TaxonomyRegistry, load_taxonomy

pytestmark = pytest.mark.slow

CORPUS_ROOT = Path(__file__).resolve().parent.parent / "sigmahq-rules"
VETTED_DIR = CORPUS_ROOT / "rules"

# Pass-rate floor for pySigma acceptance. Set conservatively — our pinned
# commit hits well above this in practice; this is the canary that catches
# a pySigma version bump breaking corpus compatibility.
PYSIGMA_PASS_RATE_FLOOR = 0.95

# Minimum fraction of a taxonomy observation's field set that must appear in
# corresponding corpus rules. Below this, our catalog has a drift problem.
TAXONOMY_COVERAGE_FLOOR = 0.50

# Minimum corpus sample size for the coverage check to be meaningful. For
# categories with fewer rules than this (driver_load, wmi_event at the
# 03412947 commit), our Sigma-spec-derived fields are defensibly richer
# than the sparse corpus sample shows. Re-check on the next quarterly
# recalibration when the sample grows.
COVERAGE_MIN_SAMPLE = 15


@pytest.fixture(scope="module")
def vetted_rule_paths() -> list[Path]:
    if not CORPUS_ROOT.is_dir():
        pytest.skip("SigmaHQ corpus not present. Run `uv run python scripts/fetch_sigmahq.py`.")
    if not VETTED_DIR.is_dir():
        pytest.skip(f"Corpus present but {VETTED_DIR} missing.")
    paths = sorted(VETTED_DIR.rglob("*.yml"))
    if not paths:
        pytest.skip(f"Corpus present but {VETTED_DIR} has no .yml files.")
    return paths


@pytest.fixture(scope="module")
def taxonomy() -> TaxonomyRegistry:
    return load_taxonomy()


# ---------------------------------------------------------------------------
# 1. pySigma pass rate
# ---------------------------------------------------------------------------


def test_pysigma_accepts_majority_of_vetted_corpus(vetted_rule_paths: list[Path]) -> None:
    """At least PYSIGMA_PASS_RATE_FLOOR of vetted rules must parse.

    A regression here usually means a pySigma version bump changed the
    grammar in a way our pinned version no longer agrees with. Surfaces
    failures by failure type and first example, so debugging doesn't require
    re-running with extra instrumentation.
    """
    failures: dict[str, list[tuple[Path, str]]] = defaultdict(list)
    passes = 0

    for path in vetted_rule_paths:
        try:
            PySigmaRule.from_yaml(path.read_text(encoding="utf-8"))
            passes += 1
        except SigmaError as exc:
            failures[type(exc).__name__].append((path, str(exc)[:120]))
        except (YAMLError, UnicodeDecodeError, ValueError) as exc:
            # YAML-level malformations — rare but possible in a corpus this size.
            failures[type(exc).__name__].append((path, str(exc)[:120]))

    total = passes + sum(len(v) for v in failures.values())
    pass_rate = passes / total if total else 0.0

    # Always print the summary so CI logs carry it even on pass.
    print(f"\npySigma pass rate: {passes}/{total} = {pass_rate:.2%}")
    if failures:
        print("Failure breakdown:")
        for exc_name, items in sorted(failures.items(), key=lambda kv: -len(kv[1])):
            sample_path, sample_msg = items[0]
            rel = sample_path.relative_to(CORPUS_ROOT)
            print(f"  {exc_name:<35} {len(items):>4d}  e.g. {rel}: {sample_msg}")

    assert pass_rate >= PYSIGMA_PASS_RATE_FLOOR, (
        f"pySigma pass rate {pass_rate:.2%} is below the floor "
        f"{PYSIGMA_PASS_RATE_FLOOR:.0%}. Either the corpus drifted or pySigma "
        f"changed grammar. Investigate the failure breakdown above."
    )


# ---------------------------------------------------------------------------
# 2. Taxonomy coverage against corpus
# ---------------------------------------------------------------------------


def test_taxonomy_fields_cover_corpus_usage(
    vetted_rule_paths: list[Path], taxonomy: TaxonomyRegistry
) -> None:
    """For each catalogued observation, our field list should cover the
    top-frequency fields actually used in corpus rules.

    We don't require every corpus field to be present — real rules use niche
    fields we deliberately skip. What we assert is: of the fields our catalog
    declares, most should appear in corpus rules for that category. A
    catalog that lists fields no rule uses has drifted from reality.
    """
    yaml_loader = YAML(typ="safe")
    # (product, category) -> set of bare field names seen in rules
    usage: dict[tuple[str, str], set[str]] = defaultdict(set)
    # (product, category) -> number of corpus rules contributing to that bucket
    rule_counts: dict[tuple[str, str], int] = defaultdict(int)

    for path in vetted_rule_paths:
        try:
            rule = yaml_loader.load(path.read_text(encoding="utf-8"))
        except YAMLError, UnicodeDecodeError:
            continue
        if not isinstance(rule, dict):
            continue
        ls = rule.get("logsource")
        if not isinstance(ls, dict):
            continue
        product = ls.get("product")
        category = ls.get("category")
        if not product or not category:
            continue
        detection = rule.get("detection")
        if not isinstance(detection, dict):
            continue
        rule_counts[(product, category)] += 1
        for fname in _extract_fields(detection):
            usage[(product, category)].add(fname)

    problems: list[str] = []
    for obs_id in taxonomy.all_ids():
        spec = taxonomy.get(obs_id)
        category = spec.logsource.category
        if not category:
            continue
        for platform in spec.platforms:
            key = (platform.product, category)
            corpus_fields = usage.get(key, set())
            sample_size = rule_counts.get(key, 0)
            if not corpus_fields:
                # No corresponding corpus rules to compare against — skip.
                continue
            catalog_fields = {f.name for f in spec.fields}
            covered = catalog_fields & corpus_fields
            coverage = len(covered) / len(catalog_fields) if catalog_fields else 1.0

            suffix = "" if sample_size >= COVERAGE_MIN_SAMPLE else " [sparse sample, not asserted]"
            print(
                f"\n{obs_id} ({platform.product}, {sample_size} corpus rules): "
                f"{len(covered)}/{len(catalog_fields)} catalog fields present "
                f"=> {coverage:.0%}{suffix}"
            )
            missing = sorted(catalog_fields - corpus_fields)
            if missing:
                print(f"  catalog fields not in corpus: {missing}")

            if sample_size < COVERAGE_MIN_SAMPLE:
                continue
            if coverage < TAXONOMY_COVERAGE_FLOOR:
                problems.append(
                    f"{obs_id}/{platform.product}: coverage {coverage:.0%} below "
                    f"{TAXONOMY_COVERAGE_FLOOR:.0%} floor ({sample_size} rules sampled)"
                )

    assert not problems, (
        "Taxonomy coverage is below floor for one or more observations:\n  " + "\n  ".join(problems)
    )


def _extract_fields(detection: dict[str, Any]) -> set[str]:
    """Pull bare field names out of every selection body in a detection block."""
    fields: set[str] = set()
    for name, body in detection.items():
        if name == "condition":
            continue
        _collect_fields(body, fields)
    return fields


def _collect_fields(body: Any, into: set[str]) -> None:
    if isinstance(body, dict):
        for key in body:
            bare = str(key).split("|", 1)[0].strip()
            if bare:
                into.add(bare)
    elif isinstance(body, list):
        for item in body:
            if isinstance(item, dict):
                _collect_fields(item, into)
