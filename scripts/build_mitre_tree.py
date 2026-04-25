"""Derive a compact MITRE ATT&CK tree from the upstream STIX 2.1 export.

Run once after bumping ``ATTACK_VERSION``; commit the output. The
quarterly recalibration loop (corpus + heuristics + observation
catalog) also re-runs this so the picker stays current with MITRE's
matrix.

Output: ``data/mitre_attack.json`` — Stage 2's tag-picker UI consumes it
directly. Shape:

    {
      "version": "v15.1",
      "generated_at": "2026-04-25",
      "tactics": [
        {
          "id": "TA0002",
          "name": "Execution",
          "tag": "attack.execution",
          "techniques": [
            {
              "id": "T1059",
              "name": "Command and Scripting Interpreter",
              "tag": "attack.t1059",
              "subtechniques": [
                {"id": "T1059.001", "name": "PowerShell",
                 "tag": "attack.t1059.001"},
                ...
              ]
            },
            ...
          ]
        },
        ...
      ]
    }

Only Enterprise ATT&CK for v1.6. Mobile + ICS are easy follow-ons if a
tester asks — the script's `_DOMAINS` table is the single edit needed.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import date as _date
from pathlib import Path
from typing import Any

# Pinned ATT&CK version. Bumping this is a documented PR — update the
# string here, re-run the script, commit the new data file.
ATTACK_VERSION = "v15.1"

# Upstream STIX URLs per domain. We only enable Enterprise for v1.6;
# Mobile + ICS are commented out and easy to enable later.
_DOMAINS: dict[str, str] = {
    "enterprise": (
        f"https://raw.githubusercontent.com/mitre/cti/"
        f"ATT%26CK-{ATTACK_VERSION}/enterprise-attack/enterprise-attack.json"
    ),
    # "mobile": ...,
    # "ics": ...,
}

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "intel2sigma" / "data" / "mitre_attack.json"


def main() -> int:  # noqa: PLR0912, PLR0915 (one-shot build script; flat top-down sequence reads more clearly than splitting into helpers)
    print(f"Building MITRE ATT&CK tree for version {ATTACK_VERSION}...")

    tactics_raw: list[dict[str, Any]] = []
    techniques_raw: list[dict[str, Any]] = []

    for domain, url in _DOMAINS.items():
        print(f"  Fetching {domain}: {url}")
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                stix = json.loads(resp.read())
        except Exception as exc:
            print(f"    FAILED: {exc}", file=sys.stderr)
            return 1
        objects = stix.get("objects", [])
        # x-mitre-tactic objects describe the tactics (Initial Access etc.).
        # attack-pattern objects describe techniques and sub-techniques.
        for obj in objects:
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            if obj.get("type") == "x-mitre-tactic":
                tactics_raw.append(obj)
            elif obj.get("type") == "attack-pattern":
                techniques_raw.append(obj)

    print(f"  Found {len(tactics_raw)} tactics, {len(techniques_raw)} techniques.")

    # Index tactics by their short_name (the "kill_chain_phase" name on
    # techniques refers to this) and capture the human-readable label +
    # external id (TA0002 etc.).
    tactic_by_short: dict[str, dict[str, Any]] = {}
    for tactic in tactics_raw:
        short = tactic.get("x_mitre_shortname", "")
        if not short:
            continue
        ext_id = _external_id(tactic)
        tactic_by_short[short] = {
            "id": ext_id,
            "name": tactic.get("name", ""),
            "tag": _sigma_tag_for_tactic(tactic),
            "techniques": [],  # populated below
            "_short_name": short,
            "_x_mitre_modified_by_ref": tactic.get("modified", ""),
        }

    # Separate parent techniques from sub-techniques. Sub-techniques have
    # ``x_mitre_is_subtechnique=True`` and a parent reference via the
    # external ID (T1059.001 → parent T1059).
    parents: dict[str, dict[str, Any]] = {}
    subtechniques: list[dict[str, Any]] = []
    for tech in techniques_raw:
        ext_id = _external_id(tech)
        if not ext_id:
            continue
        entry = {
            "id": ext_id,
            "name": tech.get("name", ""),
            "tag": _sigma_tag_for_technique(ext_id),
            "subtechniques": [],
            "_kill_chain": tech.get("kill_chain_phases", []),
        }
        if tech.get("x_mitre_is_subtechnique"):
            subtechniques.append(entry)
        else:
            parents[ext_id] = entry

    # Attach sub-techniques to their parents.
    orphan_subs = 0
    for sub in subtechniques:
        parent_id = sub["id"].rsplit(".", 1)[0]  # T1059.001 → T1059
        parent = parents.get(parent_id)
        if parent is None:
            orphan_subs += 1
            continue
        parent["subtechniques"].append({"id": sub["id"], "name": sub["name"], "tag": sub["tag"]})

    if orphan_subs:
        print(f"    NOTE: {orphan_subs} sub-techniques had no parent (skipped).")

    # Sort sub-techniques inside each parent.
    for parent in parents.values():
        parent["subtechniques"].sort(key=lambda s: s["id"])

    # Slot parent techniques under each tactic via kill_chain_phases.
    for tech in parents.values():
        for kc in tech.get("_kill_chain", []):
            if kc.get("kill_chain_name") not in {
                "mitre-attack",
                "mitre-mobile-attack",
                "mitre-ics-attack",
            }:
                continue
            tactic = tactic_by_short.get(kc.get("phase_name", ""))
            if tactic is None:
                continue
            tactic["techniques"].append(
                {
                    "id": tech["id"],
                    "name": tech["name"],
                    "tag": tech["tag"],
                    "subtechniques": tech["subtechniques"],
                }
            )

    # Sort techniques inside each tactic by ID for deterministic output.
    out_tactics: list[dict[str, Any]] = []
    for tactic in sorted(tactic_by_short.values(), key=lambda t: t["id"]):
        tactic["techniques"].sort(key=lambda t: t["id"])
        # Drop the helper fields before serialising.
        for tech in tactic["techniques"]:
            tech.pop("_kill_chain", None)
        out_tactics.append(
            {
                "id": tactic["id"],
                "name": tactic["name"],
                "tag": tactic["tag"],
                "techniques": tactic["techniques"],
            }
        )

    output = {
        "version": ATTACK_VERSION,
        "generated_at": _date.today().isoformat(),
        "tactics": out_tactics,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")

    total_techs = sum(len(t["techniques"]) for t in out_tactics)
    total_subs = sum(len(tech["subtechniques"]) for t in out_tactics for tech in t["techniques"])
    print(
        f"\nWrote {OUTPUT.relative_to(REPO_ROOT)}: "
        f"{len(out_tactics)} tactics, {total_techs} techniques, "
        f"{total_subs} sub-techniques."
    )
    print(f"File size: {OUTPUT.stat().st_size // 1024} KB")
    return 0


def _external_id(obj: dict[str, Any]) -> str:
    """Pull the external_references[0].external_id (e.g. ``TA0002``, ``T1059``)."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}:
            return str(ref.get("external_id", ""))
    return ""


def _sigma_tag_for_tactic(tactic: dict[str, Any]) -> str:
    """Sigma uses ``attack.<tactic-name-with-dashes>`` per SigmaHQ
    conventions. Use the short_name field directly — it's already in
    ``initial-access``/``defense-evasion`` form.
    """
    short = tactic.get("x_mitre_shortname", "")
    return f"attack.{short}" if short else ""


def _sigma_tag_for_technique(external_id: str) -> str:
    """``T1059`` → ``attack.t1059``; ``T1059.001`` → ``attack.t1059.001``.

    Sigma's ATT&CK-tag pattern lowercases the technique ID and prefixes
    with ``attack.``.
    """
    return f"attack.{external_id.lower()}" if external_id else ""


if __name__ == "__main__":
    sys.exit(main())
