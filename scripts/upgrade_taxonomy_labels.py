#!/usr/bin/env python
"""One-shot: humanize field labels across the 25 auto-generated taxonomies.

Loads every ``intel2sigma/data/taxonomy/*.yml`` and rewrites field
``label`` entries that are either a verbatim copy of the Sigma field
name (PascalCase, single word, abbreviation patterns) into plain
English per the verbiage contract in ``docs/taxonomy.md``.

Strategy:

1. Apply a curated mapping for famous Sigma fields where the obvious
   transform isn't right ("Image" -> "Executable path", not
   "Image"; "Hashes" -> "File hashes"; etc.).
2. For everything else, fall back to a generic PascalCase splitter
   that produces "Destination IP" / "Source user" / "Logon ID" /
   etc. — preserving common all-caps abbreviations (IP, ID, URL,
   DNS, GUID, etc.) and Microsoft-style compound suffixes
   ("FileName" -> "filename", "FilePath" -> "path").
3. Hand-curated `name == label` collisions get the same treatment.

Roundtrip via ruamel.yaml (preserves comments, indentation, ordering
of mapping keys). Diff goes to a single commit; spot-check the diff
before pushing.

Run via:
    uv run python scripts/upgrade_taxonomy_labels.py
"""

from __future__ import annotations

import re
import sys
from io import StringIO
from pathlib import Path

from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[1]
TAX_DIR = ROOT / "intel2sigma" / "data" / "taxonomy"

# Curated transforms. Keyed by Sigma field name. The label is what users
# see in the dropdown; aim for noun phrase + parenthetical context where
# the field is non-obvious. Values pulled from process_creation.yml /
# file_event.yml / network_connection.yml etc. (the hand-curated
# originals) for consistency.
CURATED: dict[str, str] = {
    # Process / image / command-line
    "Image": "Executable path",
    "CommandLine": "Command line",
    "ParentImage": "Parent process path",
    "ParentCommandLine": "Parent command line",
    "OriginalFileName": "Original filename (PE metadata)",
    "Description": "File description (PE metadata)",
    "Product": "Product name (PE metadata)",
    "Company": "Company name (PE metadata)",
    "IntegrityLevel": "Process integrity level",
    "CurrentDirectory": "Working directory",
    "User": "User account",
    "LogonId": "Logon session ID",
    "ProcessId": "Process ID",
    "ParentProcessId": "Parent process ID",
    "ProcessGuid": "Process GUID",
    "ParentProcessGuid": "Parent process GUID",
    "Hashes": "File hashes",
    "Imphash": "Import hash (PE metadata)",
    # File / target
    "TargetFilename": "Target file path",
    "TargetObject": "Target object (path or registry key)",
    "Details": "Value details",
    "ObjectName": "Object name (path or registry key)",
    "ObjectType": "Object type",
    # Identity
    "SubjectUserName": "Subject user name",
    "SubjectDomainName": "Subject domain name",
    "TargetUserName": "Target user name",
    "TargetDomainName": "Target domain name",
    "AccountName": "Account name",
    "AccountDomain": "Account domain",
    # Network
    "DestinationIp": "Destination IP",
    "DestinationPort": "Destination port",
    "DestinationHostname": "Destination hostname",
    "DestinationIsIpv6": "Destination is IPv6?",
    "SourceIp": "Source IP",
    "SourcePort": "Source port",
    "SourceHostname": "Source hostname",
    "SourceIsIpv6": "Source is IPv6?",
    "Initiated": "Outbound connection?",
    "Protocol": "Protocol",
    "QueryName": "Queried domain name",
    "QueryResults": "Query result(s)",
    "QueryStatus": "Query status",
    # Host context
    "Computer": "Computer name",
    "ComputerName": "Computer name",
    "Hostname": "Hostname",
    "Channel": "Event channel",
    "EventID": "Event ID",
    "Provider_Name": "Provider name",
    "ProviderName": "Provider name",
    # Auditd
    "syscall": "System call",
    "exe": "Executable path",
    "comm": "Command name",
    "key": "Audit rule key",
    "uid": "User ID (uid)",
    "auid": "Audit user ID (auid)",
    "euid": "Effective user ID (euid)",
    "gid": "Group ID (gid)",
    "tty": "Terminal device",
    "type": "Audit event type",
    # Cloud — AWS
    "eventName": "Event name",
    "eventSource": "Event source",
    "userIdentity": "User identity",
    "errorCode": "Error code",
    "errorMessage": "Error message",
    "awsRegion": "AWS region",
    "sourceIPAddress": "Source IP",
    # Cloud — Azure / GCP / Okta
    "operationName": "Operation name",
    "category": "Category",
    "ResultType": "Result type",
    "ResultDescription": "Result description",
    "userPrincipalName": "User principal name",
    "appDisplayName": "Application display name",
    "ipAddress": "IP address",
    "riskLevel": "Risk level",
    "riskState": "Risk state",
    "riskEventType": "Risk event type",
    "methodName": "Method name",
    "serviceName": "Service name",
    "principalEmail": "Principal email",
    "displayMessage": "Display message",
    "outcome.result": "Outcome",
    # PowerShell
    "ScriptBlockText": "Script block text",
    "ContextInfo": "Context info",
    "Payload": "Payload",
    # Generic Windows
    "ImagePath": "Service binary path",
    "ServiceName": "Service name",
    "ServiceFileName": "Service file name",
    "StartType": "Start type",
    "ImageLoaded": "Loaded image path",
    "Signed": "Signed?",
    "Signature": "Signature subject",
    "SignatureStatus": "Signature status",
    "PipeName": "Named pipe path",
    "TargetImage": "Target process path",
    "SourceImage": "Source process path",
    "GrantedAccess": "Granted access mask",
    "CallTrace": "Call trace",
    "StartModule": "Calling module",
    "StartFunction": "Calling function",
    "Device": "Raw device path",
    "EventType": "Registry operation type",
}

# Common all-caps abbreviations to preserve when generic-splitting.
# These stay uppercase even after camel split.
ABBR = {
    "IP",
    "ID",
    "URL",
    "DNS",
    "GUID",
    "UUID",
    "PID",
    "TID",
    "CPU",
    "GPU",
    "RAM",
    "OS",
    "AD",
    "SQL",
    "TLS",
    "SSL",
    "HTTP",
    "HTTPS",
    "TCP",
    "UDP",
    "ARN",
    "IAM",
    "RBAC",
    "MFA",
    "SAML",
    "OIDC",
    "JWT",
    "API",
    "XML",
    "CSV",
    "PE",
    "EID",
}


_CAMEL_SPLIT_RE = re.compile(r"(?<!^)(?=[A-Z])")


def _humanize(name: str) -> str:
    """Generic PascalCase / camelCase / lowercase Sigma name -> noun phrase.

    Splits on capital boundaries, lowercases each token unless it's a
    known abbreviation, and joins with spaces. First letter
    capitalised. Underscores become spaces and follow the same rule.
    """
    if not name:
        return name
    # Pre-split underscores (auditd uses snake_case, others use PascalCase).
    chunks = name.split("_")
    out_tokens: list[str] = []
    for chunk in chunks:
        if not chunk:
            continue
        # Camel-split each chunk.
        for tok in _CAMEL_SPLIT_RE.split(chunk):
            if not tok:
                continue
            if tok.upper() in ABBR:
                out_tokens.append(tok.upper())
            elif len(tok) <= 3 and tok.isupper():
                # Probably a recognised abbreviation we missed; keep as-is.
                out_tokens.append(tok)
            else:
                out_tokens.append(tok.lower())
    if not out_tokens:
        return name
    out = " ".join(out_tokens)
    # Capitalise the first letter, preserving subsequent capitalisations
    # produced by the abbreviation handling above.
    return out[0].upper() + out[1:]


def _is_raw_label(name: str, label: str) -> bool:
    """True if ``label`` is just a copy of the Sigma field name."""
    if label == name:
        return True
    # PascalCase, single word, no spaces — almost certainly a raw Sigma
    # field name slipped through.
    if " " not in label and re.match(r"^[A-Z][a-z]+([A-Z][a-z]*)+$", label):
        return True
    return bool(" " not in label and re.match(r"^[A-Z][a-z]*[A-Z][a-zA-Z]*$", label))


def upgrade_label(name: str, current_label: str) -> str:
    """Return the upgraded label for one field, or current if no change."""
    if not _is_raw_label(name, current_label):
        return current_label
    if name in CURATED:
        return CURATED[name]
    return _humanize(name)


def main() -> int:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096  # don't auto-wrap long lines

    files_changed = 0
    fields_changed = 0

    for f in sorted(TAX_DIR.glob("*.yml")):
        # Read + write explicitly as UTF-8. ruamel.yaml.YAML.load(Path)
        # delegates to Python's open() which on Windows defaults to the
        # system codepage (cp1252) — that quietly corrupts em-dashes
        # and other non-ASCII glyphs the auto-generated taxonomies have
        # in their description fields. Earlier roundtrip ate them all.
        text = f.read_text(encoding="utf-8")
        data = yaml.load(text)
        if not data or "fields" not in data:
            continue
        local_changes = 0
        for fd in data["fields"]:
            name = fd.get("name", "")
            label = fd.get("label", "")
            new_label = upgrade_label(name, label)
            if new_label != label:
                fd["label"] = new_label
                local_changes += 1
        if local_changes:
            buf = StringIO()
            yaml.dump(data, buf)
            f.write_text(buf.getvalue(), encoding="utf-8", newline="\n")
            files_changed += 1
            fields_changed += local_changes
            print(f"  {f.name}: {local_changes} field labels upgraded")

    print(f"\n{files_changed} files changed, {fields_changed} field labels upgraded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
