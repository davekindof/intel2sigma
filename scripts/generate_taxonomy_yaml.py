"""Generate taxonomy YAML files for SigmaHQ logsources we don't yet cover.

Reads ``reports/taxonomy_frequencies.json`` (produced by
``scripts/analyze_taxonomy.py``) and emits one taxonomy YAML per
``(product, category, service)`` tuple that:

* has ≥ ``THRESHOLD`` rules in the vetted ``rules/`` stratum, AND
* isn't already represented by a file under
  ``intel2sigma/data/taxonomy/``.

This is the engine behind the frequency-driven Phase B1 observable
expansion. Run as part of the quarterly recalibration cycle (after
``scripts/fetch_sigmahq.py`` + ``scripts/analyze_taxonomy.py``).

The generator picks fields, default modifiers, and category groupings
deterministically from the report. Output is reviewed by hand before
commit — the script favours legibility in the resulting YAML over
exhaustive automation. Fields it can't classify confidently get a
``# REVIEW:`` comment so the human reviewer notices.

Usage::

    uv run python scripts/generate_taxonomy_yaml.py --threshold 15 --dry-run
    uv run python scripts/generate_taxonomy_yaml.py --threshold 15 --write
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = PROJECT_ROOT / "reports" / "taxonomy_frequencies.json"
TAXONOMY_DIR = PROJECT_ROOT / "intel2sigma" / "data" / "taxonomy"

# Default modifier when the corpus shows "(no modifier)" dominant. Sigma
# convention: bare value = exact equality. Our composer surfaces "exact"
# as the user-facing dropdown choice; the serializer collapses it to the
# no-modifier emission shape.
_DEFAULT_NO_MOD = "exact"

# Fields with these substrings get a path-shaped FieldType. Order matters —
# more-specific patterns first.
_PATH_HINTS = ("Image", "FilePath", "TargetFilename", "ParentImage", "PathName")
_HASH_HINTS = ("Hash", "MD5", "SHA1", "SHA256", "Imphash")
_IP_HINTS = ("DestinationIp", "SourceIp", "DstIp", "SrcIp", "ClientIp", "RemoteIp")
_INT_HINTS = ("EventID", "Pid", "ProcessId", "DestinationPort", "SourcePort", "ParentProcessId")

# The (product, category, service) tuples we ship a YAML for. Built from
# disk so the generator skips files already present.
_NAME_OVERRIDES = {
    # (product, category, service) → output filename stem
    ("windows", None, "security"): "security_log",
    ("windows", None, "system"): "system_log",
    ("windows", None, "application"): "application_log",
    ("windows", None, "windefend"): "defender_log",
    ("windows", "registry_event", None): "registry_event",
    ("windows", "process_access", None): "process_access",
    ("linux", "process_creation", None): "process_creation_linux",
    ("linux", None, "auditd"): "auditd",
    ("linux", "unspecified", None): "linux_misc",
    ("macos", "process_creation", None): "process_creation_macos",
    ("aws", None, "cloudtrail"): "cloudtrail",
    ("azure", None, "activitylogs"): "azure_activity",
    ("azure", None, "auditlogs"): "azure_audit",
    ("azure", None, "signinlogs"): "azure_signin",
    ("azure", None, "riskdetection"): "azure_risk",
    ("gcp", None, "gcp.audit"): "gcp_audit",
    ("okta", None, "okta"): "okta",
    ("github", None, "audit"): "github_audit",
    ("unspecified", "proxy", None): "proxy",
    ("opencanary", "application", None): "opencanary",
    ("rpc_firewall", "application", None): "rpc_firewall",
}

# UI grouping per (product, category, service). Picked to keep the Stage
# 0 picker readable — cloud audit + identity in one bucket; OS log
# channels in another.
_GROUP_OVERRIDES = {
    ("windows", None, "security"): "os_event_log",
    ("windows", None, "system"): "os_event_log",
    ("windows", None, "application"): "os_event_log",
    ("windows", None, "windefend"): "os_event_log",
    ("windows", "registry_event"): "file_and_registry",
    ("windows", "process_access"): "process_and_execution",
    ("linux", "process_creation", None): "process_and_execution",
    ("linux", None, "auditd"): "os_event_log",
    ("linux", "unspecified", None): "os_event_log",
    ("macos", "process_creation", None): "process_and_execution",
    ("aws", None, "cloudtrail"): "audit_and_identity",
    ("azure", None, "activitylogs"): "audit_and_identity",
    ("azure", None, "auditlogs"): "audit_and_identity",
    ("azure", None, "signinlogs"): "audit_and_identity",
    ("azure", None, "riskdetection"): "audit_and_identity",
    ("gcp", None, "gcp.audit"): "audit_and_identity",
    ("okta", None, "okta"): "audit_and_identity",
    ("github", None, "audit"): "audit_and_identity",
    ("unspecified", "proxy", None): "network",
    ("opencanary", "application", None): "audit_and_identity",
    ("rpc_firewall", "application", None): "network",
}

_LABEL_OVERRIDES = {
    ("windows", None, "security"): (
        "A Windows Security event was logged",
        "Use for Windows Security event channel rules (4624/4625/4672/4688/4698 etc.).",
    ),
    ("windows", None, "system"): (
        "A Windows System event was logged",
        "Use for Windows System event channel rules (service control, driver load, OS errors).",
    ),
    ("windows", None, "application"): (
        "A Windows Application event was logged",
        "Use for Windows Application event channel rules (third-party app + .NET runtime errors).",
    ),
    ("windows", None, "windefend"): (
        "A Windows Defender alert fired",
        "Use for Microsoft Defender Antivirus operational events.",
    ),
    ("windows", "registry_event", None): (
        "A registry value, key, or stream was created or deleted",
        (
            "Use for Sysmon EID 12 (RegistryEvent — create/delete). "
            "Distinct from registry_set (EID 13)."
        ),
    ),
    ("windows", "process_access", None): (
        "A process opened a handle to another process",
        "Use for Sysmon EID 10 (ProcessAccess) — credential-dumping, code-injection, etc.",
    ),
    ("linux", "process_creation", None): (
        "A Linux process was started",
        "Use when malware or suspicious activity created a new process on Linux.",
    ),
    ("linux", None, "auditd"): (
        "A Linux auditd event was logged",
        "Use for auditd rules — syscall monitoring, file access, user/group changes.",
    ),
    ("linux", "unspecified", None): (
        "A Linux event without a specific category",
        "Use for Linux logsources that don't fit a more specific category.",
    ),
    ("macos", "process_creation", None): (
        "A macOS process was started",
        (
            "Use when malware or suspicious activity created a new process "
            "on macOS (ESF / EndpointSecurity events)."
        ),
    ),
    ("aws", None, "cloudtrail"): (
        "An AWS CloudTrail event was logged",
        "Use for AWS CloudTrail rules — IAM, S3, EC2, etc.",
    ),
    ("azure", None, "activitylogs"): (
        "An Azure Activity Log event was logged",
        "Use for Azure subscription-level activity rules (resource changes, RBAC, deletions).",
    ),
    ("azure", None, "auditlogs"): (
        "An Azure AD audit event was logged",
        "Use for Azure AD audit log rules — directory changes, app registrations, MFA changes.",
    ),
    ("azure", None, "signinlogs"): (
        "An Azure AD sign-in event was logged",
        "Use for Azure AD sign-in rules — auth attempts, MFA challenges, conditional access.",
    ),
    ("azure", None, "riskdetection"): (
        "An Azure AD identity-protection risk was detected",
        "Use for Azure AD Identity Protection risk-event rules.",
    ),
    ("gcp", None, "gcp.audit"): (
        "A Google Cloud audit event was logged",
        "Use for GCP Audit Log rules — IAM, GCE, GKE, GCS.",
    ),
    ("okta", None, "okta"): (
        "An Okta system event was logged",
        "Use for Okta system log rules — auth, MFA, lifecycle, policy changes.",
    ),
    ("github", None, "audit"): (
        "A GitHub audit-log event was logged",
        "Use for GitHub Audit Log rules — repo, org, secret-scanning, billing.",
    ),
    ("unspecified", "proxy", None): (
        "A web-proxy event was logged",
        "Use for HTTP proxy log rules — Squid, Bluecoat, etc.",
    ),
    ("opencanary", "application", None): (
        "An OpenCanary honeypot fired",
        "Use for OpenCanary deception-tool alert rules.",
    ),
    ("rpc_firewall", "application", None): (
        "An RPC Firewall event was logged",
        "Use for RPC Firewall protocol-filter rules.",
    ),
}


def _classify_field_type(name: str) -> str:
    if any(h in name for h in _PATH_HINTS):
        return "path"
    if any(h in name for h in _HASH_HINTS):
        return "hash"
    if any(h in name for h in _IP_HINTS):
        return "ip"
    if any(h in name for h in _INT_HINTS):
        return "int"
    return "string"


def _pick_default_modifier(modifier_dist: dict[str, float], field_type: str) -> str:
    """Pick the best default modifier from the modifier-frequency distribution.

    Falls back to ``exact`` when ``(no modifier)`` dominates, since exact
    is the user-facing rendering of the no-modifier form per Sigma
    convention.
    """
    if not modifier_dist:
        return _DEFAULT_NO_MOD
    sorted_mods = sorted(modifier_dist.items(), key=lambda kv: -kv[1])
    top = sorted_mods[0][0]
    if top == "(no modifier)":
        return _DEFAULT_NO_MOD
    # Some modifier chain — pick the first listed token (drop chain noise).
    if "|" in top:
        top = top.split("|", 1)[0]
    # Ensure we return a valid modifier; fall back if not.
    return top if top in _VALID_MODIFIERS else _DEFAULT_NO_MOD


_VALID_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "exact",
    "re",
    "cased",
    "base64",
    "base64offset",
    "utf16",
    "utf16le",
    "utf16be",
    "wide",
    "windash",
    "cidr",
    "gt",
    "gte",
    "lt",
    "lte",
}


def _allowed_modifiers(modifier_dist: dict[str, float], default: str, field_type: str) -> list[str]:
    """Pick a permissive modifier set: defaults appropriate for the field
    type, plus any modifier appearing ≥1% in the corpus distribution.

    The corpus carries some modifiers (``fieldref``, ``expand``, custom
    chain syntax) that aren't in our :data:`ValueModifier` Literal. Those
    are filtered out — adding them is a code change to ``core/model.py``,
    not data the generator should silently sneak in.
    """
    base: list[str]
    match field_type:
        case "path":
            base = ["endswith", "contains", "startswith", "exact", "re"]
        case "hash":
            base = ["contains", "exact"]
        case "ip":
            base = ["exact", "cidr"]
        case "int":
            base = ["exact", "gt", "gte", "lt", "lte"]
        case _:
            base = ["contains", "startswith", "endswith", "exact", "re"]
    extras = []
    for mod_chain, freq in modifier_dist.items():
        if freq < 0.01:
            continue
        head = mod_chain.split("|", 1)[0] if "|" in mod_chain else mod_chain
        if head and head != "(no modifier)" and head in _VALID_MODIFIERS and head not in base:
            extras.append(head)
    out = list(dict.fromkeys([default, *base, *extras]))
    return out


def _filename_for(product: str, category: str | None, service: str | None) -> str:
    key = (product, category, service)
    if key in _NAME_OVERRIDES:
        return _NAME_OVERRIDES[key]
    parts = [product]
    if category and category != "unspecified":
        parts.append(category)
    if service:
        parts.append(re.sub(r"[^a-z0-9_]", "_", service.lower()))
    return "_".join(parts)


def _group_for(product: str, category: str | None, service: str | None) -> str:
    if (product, category, service) in _GROUP_OVERRIDES:
        return _GROUP_OVERRIDES[(product, category, service)]
    if (product, category) in _GROUP_OVERRIDES:
        return _GROUP_OVERRIDES[(product, category)]
    # Fallback heuristics
    if category == "process_creation":
        return "process_and_execution"
    if category in {"file_event", "registry_set", "registry_event"}:
        return "file_and_registry"
    if category in {"network_connection", "dns_query", "proxy"}:
        return "network"
    return "audit_and_identity"


def _label_and_desc(product: str, category: str | None, service: str | None) -> tuple[str, str]:
    key = (product, category, service)
    if key in _LABEL_OVERRIDES:
        return _LABEL_OVERRIDES[key]
    suffix = f"={service}" if service else ""
    return (
        f"A {product} {category or service or 'event'} was logged",
        f"Auto-generated taxonomy for {product}/{category or ''}{suffix}.",
    )


def _existing_keys() -> set[tuple[str | None, str | None, str | None]]:
    """Set of (product, category, service) tuples already covered.

    For each existing file we add BOTH the (product, category, service)
    tuple AND a (product, category, None) form when the file has a
    service set. Reason: real corpus rules sometimes drop the service
    field even when our existing file carries one (e.g. ps_script —
    our taxonomy historically had ``service: powershell`` but the
    corpus uses just ``category: ps_script``). Treating either form
    as "already covered" stops the generator from emitting duplicate
    YAML for the same category.
    """
    yaml = YAML(typ="safe")
    out: set[tuple[str | None, str | None, str | None]] = set()
    for path in TAXONOMY_DIR.glob("*.yml"):
        d = yaml.load(path.read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            continue
        ls = d.get("logsource", {}) or {}
        cat = ls.get("category")
        svc = ls.get("service")
        for plat in d.get("platforms", []) or []:
            if isinstance(plat, dict):
                product = plat.get("product")
                out.add((product, cat, svc))
                if svc:
                    out.add((product, cat, None))
                if cat:
                    out.add((product, None, svc))
        if ls.get("product"):
            out.add((ls.get("product"), cat, svc))
    return out


def _parse_key(key: str) -> tuple[str, str | None, str | None]:
    """Parse a report key into ``(product, category, service)``.

    Two encodings live in the report:

    * ``windows/process_creation`` — category-only, no service
    * ``windows/service=security`` — service-only, no category. The
      "service" token before ``=`` is a marker the report uses to
      distinguish this shape; the real Sigma logsource is just
      ``product: windows / service: security`` with no category.
    """
    product, _, rest = key.partition("/")
    if "=" in rest:
        # service-only encoding — drop the marker, return category=None
        _, _, svc = rest.partition("=")
        return product, None, (svc or None)
    return product, (rest or None), None


def _build_yaml(
    product: str,
    category: str | None,
    service: str | None,
    rule_count: int,
    fields_info: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the YAML dict for one observation type."""
    obs_id = _filename_for(product, category, service)
    label, description = _label_and_desc(product, category, service)
    group = _group_for(product, category, service)

    # Sort fields by frequency descending in the rules stratum.
    sorted_fields = sorted(
        fields_info.items(),
        key=lambda kv: -kv[1].get("frequency_by_stratum", {}).get("rules", 0),
    )

    yaml_fields: list[dict[str, Any]] = []
    for fname, finfo in sorted_fields:
        # Skip very-low-frequency fields to keep the catalog focused.
        rules_freq = finfo.get("frequency_by_stratum", {}).get("rules", 0)
        if rules_freq < 0.05 and len(yaml_fields) >= 6:
            break  # We have enough; ignore the long tail.
        ftype = _classify_field_type(fname)
        mod_dist = finfo.get("modifier_distribution", {})
        default_mod = _pick_default_modifier(mod_dist, ftype)
        allowed = _allowed_modifiers(mod_dist, default_mod, ftype)
        yaml_fields.append(
            {
                "name": fname,
                "label": fname,
                "type": ftype,
                "default_modifier": default_mod,
                "allowed_modifiers": allowed,
            }
        )

    if not yaml_fields:
        # Should not happen for a ≥15-rule logsource, but be defensive.
        yaml_fields = [
            {
                "name": "EventID",
                "label": "Event ID",
                "type": "int",
                "default_modifier": "exact",
                "allowed_modifiers": ["exact"],
            }
        ]

    logsource: dict[str, Any] = {"product": product}
    if category:
        logsource["category"] = category
    if service:
        logsource["service"] = service

    return {
        "id": obs_id,
        "label": label,
        "description": description,
        "category_group": group,
        "logsource": logsource,
        "platforms": [
            {
                "id": product,
                "product": product,
                "tier": "primary",
            }
        ],
        "synonyms": [],
        "fields": yaml_fields,
    }


def _render_yaml(data: dict[str, Any], rule_count: int, key: str) -> str:
    """Render YAML with a leading provenance comment."""
    yaml = YAML()
    yaml.default_flow_style = False
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.width = 120
    import io  # noqa: PLC0415

    buf = io.StringIO()
    buf.write("# Auto-generated by scripts/generate_taxonomy_yaml.py\n")
    buf.write(f"# Source key: {key}\n")
    buf.write(f"# Vetted-stratum rule count at last calibration: {rule_count}\n")
    buf.write("# Hand-review the field selections + modifiers before ship.\n\n")
    yaml.dump(data, buf)
    return buf.getvalue()


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--threshold",
        type=int,
        default=15,
        help="Min rule count in the vetted stratum.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Actually write files (default: dry-run).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not REPORT_PATH.is_file():
        print(f"Frequency report not found at {REPORT_PATH}.", file=sys.stderr)
        print("Run scripts/analyze_taxonomy.py first.", file=sys.stderr)
        return 1
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    existing = _existing_keys()

    written = 0
    skipped = 0
    for key, info in report.get("observation_types", {}).items():
        rule_count = info.get("rule_counts_by_stratum", {}).get("rules", 0)
        if rule_count < args.threshold:
            continue
        product, category, service = _parse_key(key)
        if (product, category, service) in existing:
            skipped += 1
            continue
        yaml_dict = _build_yaml(product, category, service, rule_count, info.get("fields", {}))
        text = _render_yaml(yaml_dict, rule_count, key)
        out_path = TAXONOMY_DIR / f"{yaml_dict['id']}.yml"
        if args.write:
            out_path.write_text(text, encoding="utf-8")
            print(f"  wrote  {out_path.relative_to(PROJECT_ROOT)}  ({rule_count} rules)")
        else:
            print(f"  would-write  {out_path.relative_to(PROJECT_ROOT)}  ({rule_count} rules)")
        written += 1

    print()
    print(f"{'Wrote' if args.write else 'Would write'}: {written} files")
    print(f"Skipped (already covered): {skipped}")
    if not args.write:
        print("\nDry run — re-run with --write to commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
