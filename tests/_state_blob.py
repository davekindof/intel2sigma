"""Shared helpers for extracting the hidden ``#rule-state`` JSON blob from
composer responses.

Every htmx-driven composer route round-trips the :class:`RuleDraft` through
a hidden ``<textarea id="rule-state">`` element. Tests assert against the
state by parsing the textarea contents back into a Python dict — this
module is the single place that pattern lives, used by all composer-route
tests.
"""

from __future__ import annotations

import json
import re
from typing import Any

STATE_BLOB_RE = re.compile(
    r'<textarea id="rule-state"[^>]*>([^<]*)</textarea>',
    re.DOTALL,
)


def extract_state(html: str) -> dict[str, Any]:
    """Pull the RuleDraft JSON back out of the composer response HTML.

    Asserts that the textarea is present so callers don't have to. FastAPI's
    Jinja2 escapes quotes/angle-brackets/ampersands when emitting HTML; we
    reverse those five common escapes to recover valid JSON before parsing.
    """
    match = STATE_BLOB_RE.search(html)
    assert match, f"Response did not include a #rule-state textarea:\n{html[:500]}"
    raw = match.group(1)
    decoded = (
        raw.replace("&#34;", '"')
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
    )
    parsed: dict[str, Any] = json.loads(decoded)
    return parsed


__all__ = ["STATE_BLOB_RE", "extract_state"]
