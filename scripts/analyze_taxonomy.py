"""Stratified field-usage analysis of the SigmaHQ rule corpus.

Produces ``reports/taxonomy_frequencies.json``, the artifact that calibrates
our ``data/taxonomy/*.yml`` catalog. For each ``(product, category)`` pair
seen in the corpus, we record:

* Rule counts per stratum (which top-level SigmaHQ directory the rule comes
  from). Different strata have different usage profiles — vetted ``rules/``
  vs campaign-specific ``rules-emerging-threats/`` vs exploratory
  ``rules-threat-hunting/`` — and aggregating them without stratification
  would mix signal with noise.
* Per-field frequency in each stratum (what fraction of rules in that
  stratum reference this field).
* Per-field modifier-chain distribution, thresholded at 1% to keep the
  long tail out of the report.

Excluded directories: ``rules-placeholder/`` (placeholder values pollute
frequencies), ``deprecated/``, ``unsupported/`` (not the target shape).

Robustness: per-rule parse failures are counted per stratum in
``parse_failures`` but never halt the run. A partial analysis would be worse
than a tolerant one with the failure counts visible.

Run from the project root::

    uv run python scripts/fetch_sigmahq.py && \\
    uv run python scripts/analyze_taxonomy.py

Output: ``reports/taxonomy_frequencies.json`` (git-ignored).
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = PROJECT_ROOT / "sigmahq-rules"
REPORTS_DIR = PROJECT_ROOT / "reports"
OUTPUT_PATH = REPORTS_DIR / "taxonomy_frequencies.json"

# Top-level SigmaHQ directories we analyze, mapped to short stratum labels
# used in the report. Order is output-only; frequency calcs are per-stratum.
STRATA: dict[str, str] = {
    "rules": "rules",
    "rules-emerging-threats": "emerging",
    "rules-threat-hunting": "hunting",
    "rules-compliance": "compliance",
    "rules-dfir": "dfir",
}

# Directories we deliberately skip. See module docstring for rationale.
EXCLUDED_DIRS = {"rules-placeholder", "deprecated", "unsupported"}

MODIFIER_DIST_THRESHOLD = 0.01


# ---------------------------------------------------------------------------
# Report types
# ---------------------------------------------------------------------------


class FieldStats(TypedDict):
    frequency_by_stratum: dict[str, float]
    modifier_distribution: dict[str, float]


class ObservationTypeReport(TypedDict):
    rule_counts_by_stratum: dict[str, int]
    fields: dict[str, FieldStats]


class Report(TypedDict):
    corpus_commit: str
    generated_at: str
    strata_counts: dict[str, int]
    parse_failures: dict[str, int]
    observation_types: dict[str, ObservationTypeReport]


# ---------------------------------------------------------------------------
# In-memory accumulators
# ---------------------------------------------------------------------------


@dataclass
class _ObservationAccumulator:
    """Mutable per-observation-type counts, keyed by stratum."""

    rule_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # (stratum, field_name) -> count of rules that use the field at all
    field_counts: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    # (field_name, modifier_chain) -> count; modifier_chain may be empty string
    modifier_counts: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))


# ---------------------------------------------------------------------------
# YAML walking
# ---------------------------------------------------------------------------


def _iter_rule_files(stratum_dir: Path) -> Iterator[Path]:
    yield from stratum_dir.rglob("*.yml")


def _extract_logsource_key(rule: dict[str, Any]) -> str | None:
    ls = rule.get("logsource")
    if not isinstance(ls, dict):
        return None
    product = ls.get("product") or "unspecified"
    category = ls.get("category") or "unspecified"
    service = ls.get("service")
    # We bucket primarily by (product, category). Service is informational
    # and rolled into the key only when no category is present, so
    # service-centric rules (e.g. windows/powershell_classic) still group.
    if category == "unspecified" and service:
        return f"{product}/service={service}"
    return f"{product}/{category}"


def _walk_detection_pairs(
    detection: dict[str, Any],
) -> Iterator[tuple[str, str]]:
    """Yield ``(field_name, modifier_chain)`` pairs across every selection.

    Handles both flat-mapping selections (``{field|mod: values, ...}``) and
    list-of-mappings selections (``[{field|mod: v}, {field|mod: v}]``), which
    Sigma treats as OR across list items and AND within each item.
    """
    for name, body in detection.items():
        if name == "condition":
            continue
        yield from _walk_selection_body(body)


def _walk_selection_body(body: Any) -> Iterator[tuple[str, str]]:
    if isinstance(body, dict):
        for key in body:
            yield _split_key(str(key))
    elif isinstance(body, list):
        for item in body:
            if isinstance(item, dict):
                for key in item:
                    yield _split_key(str(key))
    # Scalars in a selection body are malformed rules; skip silently.


def _split_key(raw: str) -> tuple[str, str]:
    """Split a Sigma detection key into (field, modifier_chain).

    ``Image|endswith`` → (``Image``, ``endswith``)
    ``CommandLine|contains|all`` → (``CommandLine``, ``contains|all``)
    ``TargetFilename`` → (``TargetFilename``, ``""``)
    """
    field_name, sep, chain = raw.partition("|")
    _ = sep  # readability
    return field_name.strip(), chain.strip()


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def _analyze(corpus_dir: Path) -> tuple[Report, int]:
    yaml = YAML(typ="safe")
    strata_counts: dict[str, int] = defaultdict(int)
    parse_failures: dict[str, int] = defaultdict(int)
    observations: dict[str, _ObservationAccumulator] = defaultdict(_ObservationAccumulator)

    total_ok = 0
    for dir_name, stratum in STRATA.items():
        stratum_dir = corpus_dir / dir_name
        if not stratum_dir.is_dir():
            # Stratum directory missing is acceptable (e.g. future corpus
            # layouts); the stratum simply appears with zero counts.
            continue
        for rule_path in _iter_rule_files(stratum_dir):
            if not _process_rule(rule_path, stratum, yaml, observations, strata_counts):
                parse_failures[stratum] += 1
            else:
                total_ok += 1

    report_observations = {
        key: _finalize_observation(acc, strata_counts) for key, acc in observations.items()
    }
    report: Report = {
        "corpus_commit": _git_head(corpus_dir),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "strata_counts": dict(strata_counts),
        "parse_failures": dict(parse_failures),
        "observation_types": report_observations,
    }
    return report, total_ok


def _process_rule(
    path: Path,
    stratum: str,
    yaml: YAML,
    observations: dict[str, _ObservationAccumulator],
    strata_counts: dict[str, int],
) -> bool:
    try:
        data = yaml.load(path.read_text(encoding="utf-8"))
    except YAMLError, OSError, UnicodeDecodeError:
        return False
    if not isinstance(data, dict):
        return False
    detection = data.get("detection")
    if not isinstance(detection, dict):
        return False
    obs_key = _extract_logsource_key(data)
    if obs_key is None:
        return False

    strata_counts[stratum] += 1
    acc = observations[obs_key]
    acc.rule_counts[stratum] += 1

    # Dedupe within a rule: a field used in three blocks counts once.
    fields_seen: set[str] = set()
    for field_name, chain in _walk_detection_pairs(detection):
        if not field_name:
            continue
        fields_seen.add(field_name)
        acc.modifier_counts[(field_name, chain)] += 1

    for field_name in fields_seen:
        acc.field_counts[(stratum, field_name)] += 1

    return True


def _finalize_observation(
    acc: _ObservationAccumulator,
    strata_counts: dict[str, int],
) -> ObservationTypeReport:
    # Per-field frequency = (count of rules using field in stratum) /
    # (rule count in that stratum for this observation type).
    field_names = {fname for (_s, fname) in acc.field_counts}
    fields: dict[str, FieldStats] = {}
    for fname in sorted(field_names):
        freq: dict[str, float] = {}
        for stratum in STRATA.values():
            denom = acc.rule_counts.get(stratum, 0)
            num = acc.field_counts.get((stratum, fname), 0)
            if denom > 0:
                freq[stratum] = round(num / denom, 4)
        mod_dist = _build_modifier_distribution(acc, fname)
        fields[fname] = {
            "frequency_by_stratum": freq,
            "modifier_distribution": mod_dist,
        }

    # Sort fields by their max cross-stratum frequency so the JSON is easy to
    # scan top-down when picking tiers.
    fields_sorted = dict(
        sorted(
            fields.items(),
            key=lambda kv: -max(kv[1]["frequency_by_stratum"].values(), default=0.0),
        )
    )
    return {
        "rule_counts_by_stratum": {s: acc.rule_counts.get(s, 0) for s in STRATA.values()},
        "fields": fields_sorted,
    }


def _build_modifier_distribution(
    acc: _ObservationAccumulator,
    field_name: str,
) -> dict[str, float]:
    relevant = {
        chain: count for (fname, chain), count in acc.modifier_counts.items() if fname == field_name
    }
    total = sum(relevant.values())
    if total == 0:
        return {}
    dist: dict[str, float] = {}
    for chain, count in sorted(relevant.items(), key=lambda kv: -kv[1]):
        share = count / total
        if share < MODIFIER_DIST_THRESHOLD:
            continue
        label = chain or "(no modifier)"
        dist[label] = round(share, 4)
    return dist


def _git_head(target: Path) -> str:
    """Return the HEAD SHA of the corpus checkout, or ``"unknown"`` on failure."""
    try:
        result = subprocess.run(
            ["git", "-C", str(target), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError, FileNotFoundError:
        return "unknown"


# ---------------------------------------------------------------------------
# CLI summary
# ---------------------------------------------------------------------------


def _summarize(report: Report, top_observations: Iterable[str]) -> str:
    lines = [
        f"corpus commit: {report['corpus_commit'][:12]}",
        f"generated at:  {report['generated_at']}",
        "strata counts (rules analyzed):",
    ]
    for stratum, count in report["strata_counts"].items():
        failed = report["parse_failures"].get(stratum, 0)
        failed_note = f" ({failed} parse failures)" if failed else ""
        lines.append(f"  {stratum:<12} {count:>6d}{failed_note}")

    lines.append("")
    lines.append("Top observation types by rules/ rule count:")
    ranked = sorted(
        report["observation_types"].items(),
        key=lambda kv: -kv[1]["rule_counts_by_stratum"].get("rules", 0),
    )
    for name, obs in ranked[:15]:
        counts = obs["rule_counts_by_stratum"]
        total = sum(counts.values())
        lines.append(f"  {name:<40} rules={counts.get('rules', 0):>4d}  total={total:>4d}")
    _ = top_observations  # hook for future selective-summary flags
    return "\n".join(lines)


def main() -> int:
    if not CORPUS_DIR.is_dir():
        print(
            f"ERROR: corpus directory missing: {CORPUS_DIR}\n"
            f"Run `uv run python scripts/fetch_sigmahq.py` first.",
            file=sys.stderr,
        )
        return 1

    print("Analyzing corpus ...")
    report, ok_count = _analyze(CORPUS_DIR)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Analyzed {ok_count} rules. Wrote {OUTPUT_PATH}.")
    print()
    print(_summarize(report, ()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
