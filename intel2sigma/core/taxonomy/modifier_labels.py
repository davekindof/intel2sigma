"""User-facing labels and tooltips for Sigma value modifiers.

The Stage 1 detection editor renders a per-field modifier dropdown
(``contains``, ``startswith``, ``endswith``, etc.). The raw Sigma
modifier names are jargon to a non-SIEM audience — ``endswith`` reads
worse than "ends with"; ``windash`` is opaque without explanation.

This module is the single source of truth for the user-facing
presentation of every modifier:

* :data:`MODIFIER_LABELS` — short label shown as the dropdown option
  text. Lifted from the table in ``docs/taxonomy.md`` § "Modifier
  labels" and extended to cover every member of
  :data:`intel2sigma.core.model.ValueModifier`.
* :data:`MODIFIER_TOOLTIPS` — longer, hover-revealing explanation.
  Used as the ``title=`` attribute on ``<option>`` elements (browser-
  native tooltip), since custom hover tooltips can't render over an
  open native ``<select>`` overlay.

Both submitted values are still the canonical Sigma modifier strings
(``endswith``, ``windash``); the user-facing labels are display-only.
This keeps the rule artifact strictly canonical Sigma per
CLAUDE.md I-2 — the labels never travel into the saved YAML.
"""

from __future__ import annotations

# Short labels — what the user sees inside the dropdown option element.
# Per docs/taxonomy.md § "Modifier labels". Plain English; no Sigma
# jargon; consistent across every field that allows a given modifier.
MODIFIER_LABELS: dict[str, str] = {
    "contains": "contains",
    "startswith": "starts with",
    "endswith": "ends with",
    "all": "matches all of (AND list)",
    "exact": "exactly matches",
    "re": "matches regex (advanced)",
    "cased": "case-sensitive match",
    "base64": "matches base64-encoded value",
    "base64offset": "contains base64-encoded substring (offset-safe)",
    "utf16": "UTF-16 encoded value",
    "utf16le": "UTF-16 LE encoded value",
    "utf16be": "UTF-16 BE encoded value",
    "wide": "wide-character (UTF-16 LE) encoded value",
    "windash": "Windows dash variants (-, /, –)",  # noqa: RUF001 — en-dash is the literal character pySigma matches
    "cidr": "IP in CIDR range",
    "gt": "greater than",
    "gte": "greater than or equal to",
    "lt": "less than",
    "lte": "less than or equal to",
}

# Longer, hover-revealing explanations. Used as ``title=`` on the
# ``<option>`` element so the OS-native tooltip surfaces them when
# the user hovers an option in the open dropdown. One sentence each;
# explains the *semantic*, not just restates the label.
MODIFIER_TOOLTIPS: dict[str, str] = {
    "contains": "The field's value contains this substring anywhere.",
    "startswith": "The field's value begins with this substring.",
    "endswith": (
        "The field's value ends with this substring. The Sigma idiom for "
        "path-suffix matches uses a leading backslash to anchor at a "
        "filename boundary (e.g. \\powershell.exe)."
    ),
    "all": (
        "Treats the value list as an AND — all listed values must be "
        "present (vs. the default OR where any one match fires)."
    ),
    "exact": "Exact full-value match. Default for enum and hash fields.",
    "re": (
        "Match against the value as a regular expression. Backend-specific "
        "dialect (PCRE in Splunk/Elastic, .NET regex in Sentinel/MDE) — "
        "test against your target SIEM."
    ),
    "cased": "Case-sensitive match. Sigma is case-insensitive by default.",
    "base64": (
        "Match the value after it has been base64-encoded — useful when "
        "the raw event contains base64 and the rule's value is the "
        "decoded form."
    ),
    "base64offset": (
        "Match a base64-encoded substring at any 0/1/2-byte offset — "
        "handles the case where the substring boundary doesn't align "
        "with the base64 chunk boundary."
    ),
    "utf16": "Match the value after UTF-16 encoding (auto-detect endianness).",
    "utf16le": (
        "Match the value after UTF-16 little-endian encoding "
        "(most common form in Windows event payloads)."
    ),
    "utf16be": (
        "Match the value after UTF-16 big-endian encoding "
        "(rarely needed — most Windows events use LE)."
    ),
    "wide": ("Equivalent to utf16le. Used in PowerShell script-block logging contexts."),
    "windash": (
        "pySigma expands the value to match Windows dash variants — "
        "hyphen-minus (-), slash (/), and en-dash (–) — for command-line "  # noqa: RUF001 — en-dash is the literal character matched
        "flag matching."
    ),
    "cidr": "Match an IP address against a CIDR range (e.g. 10.0.0.0/8). IP-type fields only.",
    "gt": "Numeric: greater than the given value.",
    "gte": "Numeric: greater than or equal to the given value.",
    "lt": "Numeric: less than the given value.",
    "lte": "Numeric: less than or equal to the given value.",
}


def modifier_label(name: str) -> str:
    """User-facing label for a Sigma modifier name.

    Falls back to the canonical Sigma name if not in the table — better
    than crashing if a future modifier is added before this table updates.
    Registered as a Jinja global in ``web/app.py``.
    """
    return MODIFIER_LABELS.get(name, name)


def modifier_tooltip(name: str) -> str:
    """Hover-revealing tooltip text for a Sigma modifier name.

    Returns an empty string if the modifier isn't in the table; the
    template renders ``title=""`` in that case (silently no-tooltip
    rather than crashing). Registered as a Jinja global in
    ``web/app.py``.
    """
    return MODIFIER_TOOLTIPS.get(name, "")


__all__ = [
    "MODIFIER_LABELS",
    "MODIFIER_TOOLTIPS",
    "modifier_label",
    "modifier_tooltip",
]
