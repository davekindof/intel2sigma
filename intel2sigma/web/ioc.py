"""IOC classifier and observation router.

Takes free-form text (a CTI hand-off, a snippet of a threat report, a
markdown table copy-paste), extracts indicators-of-compromise, classifies
them, and routes each to the right observation type. Used by the Stage 0
"Paste IOCs" jump-start.

The classifier is **pure pattern matching** — no model, no LLM, no
network. Per CLAUDE.md I-1, the composer logic path is fully
deterministic. Same text always produces the same classification.

Heuristics are conservative: when an IOC could plausibly route to
multiple observations (e.g., a hash works on file_event, image_load, or
process_creation), we pick the *primary* mapping. Secondary mappings
land in v1.7 if testers ask.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from intel2sigma.web.draft import DetectionItemDraft

# ---------------------------------------------------------------------------
# IOC categories — what the classifier emits.
# ---------------------------------------------------------------------------

# Stable category strings used in JSON, in routing tables, and in the UI.
# Add a new category by extending IOCCategory + adding patterns +
# updating the routing table at the bottom of this module.
IOCCategory = Literal[
    "hash_md5",
    "hash_sha1",
    "hash_sha256",
    "ip",
    "domain",
    "path_exe",
    "path_dll_sys",
    "path_other",
    "registry_key",
    "pdb_path",
    "email",
    "cert_serial",
]


@dataclass(frozen=True)
class IOC:
    """One classified indicator extracted from raw text.

    ``raw`` is the original string as it appeared in the user's paste,
    preserved verbatim for display. ``value`` is the canonicalised form
    used by the routing logic and in detection items (e.g. an IP+port
    string keeps both pieces; a domain is lowercased; a hash is downcased).
    ``category`` and ``observation`` together determine which match-block
    item the IOC becomes when a rule is built from it.
    """

    raw: str
    value: str
    category: IOCCategory
    observation: str  # the catalog observation id this IOC routes to

    @property
    def is_metadata_only(self) -> bool:
        """``True`` for categories that don't map to a Sigma observation.

        Metadata-only IOCs (email senders, cert serials) get carried into
        the rule's references/falsepositives if the user wants, but no
        detection item is generated.
        """
        return self.observation == ""


@dataclass(frozen=True)
class CategorySummary:
    """Per-category aggregation used by the UI to render the picker buttons."""

    category: IOCCategory
    label: str  # human-readable
    observation: str  # routing target ("" for metadata-only)
    count: int


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Many CTI sources defang IOCs with brackets ("evil[.]com", "1.2.3[.]4").
# Strip those before regex matching so the user doesn't have to clean the
# paste manually. Done line-by-line so we don't accidentally flatten
# unrelated brackets in surrounding prose.
_DEFANG = re.compile(r"\[\.\]")
_DEFANG_HXXP = re.compile(r"hxxp(s?)://", re.IGNORECASE)


def _undefang(line: str) -> str:
    line = _DEFANG.sub(".", line)
    return _DEFANG_HXXP.sub(r"http\1://", line)


# Hash patterns, longest-first so SHA256 wins over SHA1/MD5 when ambiguous.
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")

# IPv4 + optional port.
_RE_IPV4 = re.compile(
    r"\b(?P<ip>(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})"
    r"(?::(?P<port>\d{1,5}))?\b"
)

# IPv6 (simple — covers the most common shapes; full RFC 4291 not needed
# for IOC extraction since CTI sources usually paste canonical forms).
_RE_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")

# File extensions that pull a string into the bare-filename / path-other
# categorisation. ``com`` is intentionally absent — it's overwhelmingly a
# TLD in modern usage (rare DOS .COM executables hand-pasted into a CTI
# table can be re-routed by the user in the UI).
_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "ps1",
        "psm1",
        "psd1",
        "vbs",
        "vbe",
        "bat",
        "cmd",
        "msi",
        "msp",
        "scr",
        "pif",
        "cpl",
        "lnk",
        "hta",
        "js",
        "jse",
        "wsf",
        "wsh",
        "msc",
        "dat",
        "db",
        "log",
        "tmp",
        "bak",
        "old",
        "ini",
        "cfg",
        "conf",
        "txt",
        "csv",
        "tsv",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "pdf",
        "rtf",
        "zip",
        "rar",
        "7z",
        "tar",
        "gz",
        "iso",
        "img",
        "vhd",
        "pdb",
        "py",
        "rb",
        "pl",
        "sh",
    }
)

# Common TLDs that win over the file-extension check. A domain match
# whose last label is in this set is treated as a domain regardless of
# whether the same label appears in _FILE_EXTENSIONS. Conservative
# (~50 entries) — covers the dominant cases without becoming a TLD
# database.
_KNOWN_TLDS: frozenset[str] = frozenset(
    {
        # Generic
        "com",
        "net",
        "org",
        "info",
        "biz",
        "edu",
        "gov",
        "mil",
        "int",
        # New gTLDs commonly seen in CTI
        "io",
        "co",
        "ai",
        "app",
        "dev",
        "cloud",
        "online",
        "site",
        "tech",
        "store",
        "shop",
        "blog",
        "news",
        "xyz",
        "club",
        "live",
        "world",
        "today",
        "email",
        "media",
        "agency",
        "pro",
        # Common ccTLDs
        "us",
        "uk",
        "de",
        "fr",
        "jp",
        "cn",
        "ru",
        "br",
        "in",
        "ca",
        "au",
        "nl",
        "se",
        "no",
        "fi",
        "dk",
        "es",
        "it",
        "pl",
        "ch",
        "be",
        "at",
        "kr",
        "tw",
        "hk",
        "sg",
        "tr",
        "ar",
        "mx",
        "ie",
        "nz",
        "za",
        "id",
        "il",
        "ua",
        "cz",
        "ro",
        "gr",
        "pt",
        "vn",
    }
)

# Bare filename — single-dot string ending in a known file extension. We
# route these to file_event with a TargetFilename|endswith pattern, since
# CTI IOC tables often list filenames without their full paths.
_RE_BARE_FILENAME = re.compile(
    r"(?<![A-Za-z0-9./\\:-])"
    r"(?P<name>[A-Za-z0-9_-][A-Za-z0-9._-]*\.[A-Za-z0-9]{1,8})"
    r"(?![A-Za-z0-9./\\-])"
)

# Domain — at least two labels, last label 2-24 chars (TLD-ish), no
# trailing slash. The file-extension blacklist is checked at match time
# (we accept any string the regex matches but reject in classify() if the
# last segment is a known file extension).
_RE_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9.@/\\:-])"
    r"(?P<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24})"
    r"(?![A-Za-z0-9.@-])"
)

# Windows path — drive letter or UNC root, at least one segment. ``\\+``
# accepts one OR two backslashes between segments so the same regex works
# whether the user pasted a literal path (``C:\foo\bar``) or a copy-paste
# from a string literal (``C:\\foo\\bar``).
_RE_WIN_PATH = re.compile(
    r"(?P<path>"
    r"(?:[A-Za-z]:\\+|\\\\)"  # C:\ or C:\\ or UNC \\\\
    r"[^\s'\"<>|]+"
    r")"
)

# Registry root keys, with or without HKEY_ prefix.
_RE_REGISTRY = re.compile(
    r"(?P<key>"
    r"HK(?:LM|CU|CR|U|CC)\\+[^\s'\"<>|]+"
    r"|HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\+[^\s'\"<>|]+"
    r")"
)

# PDB paths look like Windows paths but typically have ``\Projects\`` or
# ``\src\`` and end in nothing or .pdb. Used to surface attacker-tooling
# artifacts compiled with debug info. ``\\+`` accepts both single- and
# double-backslash forms.
_RE_PDB_PATH = re.compile(
    r"(?P<pdb>"
    r"[A-Za-z]:\\+[^\s'\"<>|]*?\\+(Projects?|src|source|Build|build|Debug|Release|"
    r"x64|Win32|out)\\+[^\s'\"<>|]+)",
    re.IGNORECASE,
)

# Email and Authenticode cert serial — these are metadata-only.
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
# Cert serials are hex with optional colons; require a leading "serial"
# context word to avoid false positives on random hex strings. Conservative
# match — better to miss than to mis-classify.
_RE_CERT_SERIAL = re.compile(
    r"(?:certificate\s+serial|cert\s+serial|serial\s+number|authenticode\s+serial)"
    r"\W{0,5}(?P<serial>[A-Fa-f0-9](?:[A-Fa-f0-9:]{6,40}))",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Routing table — IOC category → observation id + short field metadata.
# ---------------------------------------------------------------------------

# (category, observation, field_name, default_modifier).
# An empty observation means the IOC is metadata-only (no detection item).
_ROUTING: dict[IOCCategory, tuple[str, str, str]] = {
    "hash_md5": ("file_event", "Hashes", "contains"),
    "hash_sha1": ("file_event", "Hashes", "contains"),
    "hash_sha256": ("file_event", "Hashes", "contains"),
    "ip": ("network_connection", "DestinationIp", "exact"),
    "domain": ("dns_query", "QueryName", "endswith"),
    "path_exe": ("process_creation", "Image", "endswith"),
    "path_dll_sys": ("image_load", "ImageLoaded", "endswith"),
    "path_other": ("file_event", "TargetFilename", "endswith"),
    "registry_key": ("registry_set", "TargetObject", "contains"),
    "pdb_path": ("process_creation", "CommandLine", "contains"),
    "email": ("", "", ""),
    "cert_serial": ("", "", ""),
}

_CATEGORY_LABELS: dict[IOCCategory, str] = {
    "hash_md5": "MD5 hashes",
    "hash_sha1": "SHA-1 hashes",
    "hash_sha256": "SHA-256 hashes",
    "ip": "IP addresses",
    "domain": "Domains",
    "path_exe": "Executable paths (.exe)",
    "path_dll_sys": "DLL/driver paths (.dll/.sys)",
    "path_other": "Other file paths",
    "registry_key": "Registry keys",
    "pdb_path": "PDB-path strings",
    "email": "Email addresses (metadata)",
    "cert_serial": "Certificate serials (metadata)",
}


# Path extension → category.
_DLL_SYS_EXTS = {".dll", ".sys"}
_EXE_EXTS = {".exe"}


def _categorize_path(path: str) -> IOCCategory:
    lower = path.lower()
    # Match the last extension. Truncate to last segment to avoid hits in
    # earlier directory names that happen to look like extensions.
    last_seg = lower.rsplit("\\", 1)[-1]
    dot = last_seg.rfind(".")
    if dot == -1:
        return "path_other"
    ext = last_seg[dot:]
    if ext in _EXE_EXTS:
        return "path_exe"
    if ext in _DLL_SYS_EXTS:
        return "path_dll_sys"
    return "path_other"


def _categorize_bare_filename(name: str) -> IOCCategory:
    """Bare filename → which path-* category it routes to.

    Same rules as ``_categorize_path`` but applied to a name without
    leading directory components.
    """
    return _categorize_path(name)


def _is_file_extension_tld(domain: str) -> bool:
    """``True`` when a domain match's last label is a file extension and
    NOT also a known TLD.

    Used to suppress false-positive domain matches on bare filenames like
    ``config.db`` or ``digital-document.exe``. The ``_KNOWN_TLDS``
    whitelist wins over ``_FILE_EXTENSIONS`` for ambiguous labels — most
    notably ``.com``, which is overwhelmingly a TLD in modern usage even
    though it's also a (rare) DOS executable extension.
    """
    last_label = domain.rsplit(".", 1)[-1].lower()
    if last_label in _KNOWN_TLDS:
        return False
    return last_label in _FILE_EXTENSIONS


def _is_likely_filename(name: str) -> bool:
    """``True`` when a bare-filename match's extension is unambiguously a
    file extension (not also a TLD).

    Mirror of ``_is_file_extension_tld`` for the bare-filename pattern.
    Without this, ``mggsjvip.com`` would route to ``path_other`` instead
    of being left for the domain matcher.
    """
    last = name.rsplit(".", 1)[-1].lower()
    if last in _KNOWN_TLDS:
        return False
    return last in _FILE_EXTENSIONS


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify(text: str) -> list[IOC]:  # noqa: PLR0912, PLR0915 (one branch per IOC category is the dispatch table)
    """Extract and classify IOCs from free-form text.

    Conservative: each character region is consumed by the first matching
    pattern, so a string can't be classified as both an IP and a domain.
    Order: hashes (fixed-length, unambiguous) → IPs (anchored) → domains →
    paths → registry keys → PDB paths → email/cert metadata.

    Output is deduplicated by ``(category, value)`` so a paste with the
    same hash listed twice produces one IOC, not two.
    """
    if not text or not text.strip():
        return []

    # Walk the text line-by-line so we can defang each line independently
    # (avoids tripping over surrounding brackets in prose).
    found: list[IOC] = []
    # Tuple keys typed as (str, str) so Literal narrowing on the
    # category isn't required; the category strings are validated
    # implicitly through the routing table at construction time.
    seen: set[tuple[str, str]] = set()

    for raw_line in text.splitlines():
        line = _undefang(raw_line)
        consumed: list[tuple[int, int]] = []  # spans claimed by earlier patterns

        def consume(span: tuple[int, int], _consumed: list[tuple[int, int]] = consumed) -> bool:
            """Return False if ``span`` overlaps a region already consumed.

            ``_consumed`` is bound to the per-line list as a default
            argument, side-stepping ruff's late-binding-closure warning
            (B023). This is intentional — we want each line to have its
            own consumed-spans list, exactly what the closure naturally
            captures.
            """
            for s, e in _consumed:
                if span[0] < e and s < span[1]:
                    return False
            _consumed.append(span)
            return True

        # Hashes — longest first.
        for regex, category in (
            (_RE_SHA256, "hash_sha256"),
            (_RE_SHA1, "hash_sha1"),
            (_RE_MD5, "hash_md5"),
        ):
            for m in regex.finditer(line):
                if not consume(m.span()):
                    continue
                value = m.group(0).lower()
                key = (category, value)
                if key in seen:
                    continue
                seen.add(key)
                # ``category`` comes from the for-loop over IOCCategory keys; mypy
                # widens it to str across the closure. Both ignores are safe because
                # _ROUTING is keyed on the same Literal set the classifier emits.
                found.append(
                    IOC(
                        raw=m.group(0),
                        value=value,
                        category=category,  # type: ignore[arg-type]
                        observation=_ROUTING[category][0],  # type: ignore[index]
                    )
                )

        # IPs (with optional port). Capture full match (including :port) as
        # the value so DestinationPort can be split out at routing time.
        for m in _RE_IPV4.finditer(line):
            if not consume(m.span()):
                continue
            value = m.group(0)
            key = ("ip", value)
            if key in seen:
                continue
            seen.add(key)
            found.append(IOC(raw=value, value=value, category="ip", observation=_ROUTING["ip"][0]))
        for m in _RE_IPV6.finditer(line):
            if not consume(m.span()):
                continue
            value = m.group(0)
            key = ("ip", value)
            if key in seen:
                continue
            seen.add(key)
            found.append(IOC(raw=value, value=value, category="ip", observation=_ROUTING["ip"][0]))

        # Registry keys — match before domain/path to avoid capturing key
        # prefixes that look domain-ish (HKLM\Software... could otherwise
        # bleed into Windows-path or domain matches).
        for m in _RE_REGISTRY.finditer(line):
            if not consume(m.span()):
                continue
            value = m.group("key")
            key = ("registry_key", value)
            if key in seen:
                continue
            seen.add(key)
            found.append(
                IOC(raw=value, value=value, category="registry_key", observation="registry_set")
            )

        # PDB paths before generic paths so the more specific pattern wins.
        for m in _RE_PDB_PATH.finditer(line):
            if not consume(m.span()):
                continue
            value = m.group("pdb")
            key = ("pdb_path", value)
            if key in seen:
                continue
            seen.add(key)
            found.append(
                IOC(raw=value, value=value, category="pdb_path", observation="process_creation")
            )

        # Generic Windows paths (after PDB + registry).
        for m in _RE_WIN_PATH.finditer(line):
            if not consume(m.span()):
                continue
            value = m.group("path")
            cat = _categorize_path(value)
            key = (cat, value)
            if key in seen:
                continue
            seen.add(key)
            found.append(IOC(raw=value, value=value, category=cat, observation=_ROUTING[cat][0]))

        # Emails MUST run before domains so we don't pick up the email's
        # domain part (`outlook.com` from `alice@outlook.com`) as a separate
        # IOC.
        for m in _RE_EMAIL.finditer(line):
            if not consume(m.span()):
                continue
            value = m.group(0).lower()
            key = ("email", value)
            if key in seen:
                continue
            seen.add(key)
            found.append(IOC(raw=value, value=value, category="email", observation=""))

        # Bare filenames (single dot, no path) — must run before domains
        # so things like `digital-document.exe` route to path_exe instead
        # of being misclassified as a domain. ``_is_likely_filename``
        # rejects matches whose extension is actually a TLD (e.g.
        # ``mggsjvip.com``), letting the domain matcher catch them
        # later. We prepend a leading backslash to the value so the
        # resulting TargetFilename|endswith rule matches the file
        # regardless of directory.
        for m in _RE_BARE_FILENAME.finditer(line):
            name = m.group("name")
            if not _is_likely_filename(name):
                continue
            if not consume(m.span()):
                continue
            cat = _categorize_bare_filename(name)
            value = "\\" + name  # endswith pattern
            key = (cat, value)
            if key in seen:
                continue
            seen.add(key)
            found.append(IOC(raw=name, value=value, category=cat, observation=_ROUTING[cat][0]))

        # Domains — only after emails + bare filenames so we don't double-
        # match. Reject matches whose last label is a known file extension
        # (those got picked up by bare-filename above).
        for m in _RE_DOMAIN.finditer(line):
            if not consume(m.span()):
                continue
            value = m.group("domain").lower()
            if _is_file_extension_tld(value):
                continue
            key = ("domain", value)
            if key in seen:
                continue
            seen.add(key)
            found.append(IOC(raw=value, value=value, category="domain", observation="dns_query"))

        # Cert serials (metadata).
        for m in _RE_CERT_SERIAL.finditer(line):
            if not consume(m.span()):
                continue
            value = m.group("serial")
            key = ("cert_serial", value)
            if key in seen:
                continue
            seen.add(key)
            found.append(IOC(raw=value, value=value, category="cert_serial", observation=""))

    return found


def summarise(iocs: Iterable[IOC]) -> list[CategorySummary]:
    """Group IOCs by category and return ordered summaries for the picker.

    Order: routing-bearing categories first (the user wants those), then
    metadata-only categories (informational). Within each group, ordered
    by count descending so the dominant category surfaces at the top.
    """
    counts: dict[IOCCategory, int] = {}
    for ioc in iocs:
        counts[ioc.category] = counts.get(ioc.category, 0) + 1

    routing: list[CategorySummary] = []
    metadata: list[CategorySummary] = []
    for cat, count in counts.items():
        obs = _ROUTING[cat][0]
        summary = CategorySummary(
            category=cat,
            label=_CATEGORY_LABELS[cat],
            observation=obs,
            count=count,
        )
        (routing if obs else metadata).append(summary)

    routing.sort(key=lambda s: -s.count)
    metadata.sort(key=lambda s: -s.count)
    return routing + metadata


def build_detection_items(iocs: Iterable[IOC], observation: str) -> list[DetectionItemDraft]:
    """Convert all IOCs that route to ``observation`` into detection items.

    Used by the "Build <observation> rule" jump-start: the resulting items
    populate a single ``match_1`` block with combinator=any_of, since IOC
    packs OR over their indicators.

    IPs with embedded ports produce two items (one DestinationIp, one
    DestinationPort) so users get the port match for free.
    """
    items: list[DetectionItemDraft] = []
    for ioc in iocs:
        if ioc.observation != observation:
            continue
        if ioc.category == "ip":
            host, _, port = ioc.value.partition(":")
            items.append(
                DetectionItemDraft(
                    field="DestinationIp",
                    modifiers=["exact"],
                    values=[host],
                )
            )
            if port:
                items.append(
                    DetectionItemDraft(
                        field="DestinationPort",
                        modifiers=["exact"],
                        values=[port],
                    )
                )
            continue
        _obs, field, modifier = _ROUTING[ioc.category]
        items.append(
            DetectionItemDraft(
                field=field,
                # _ROUTING values are str at the type level but always one of
                # the ValueModifier Literal members at runtime.
                modifiers=[modifier],  # type: ignore[list-item]
                values=[ioc.value],
            )
        )
    return items


__all__ = [
    "IOC",
    "CategorySummary",
    "IOCCategory",
    "build_detection_items",
    "classify",
    "summarise",
]
