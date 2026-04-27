"""Regression tests that lock the verbiage contract from docs/taxonomy.md.

Every taxonomy YAML in ``intel2sigma/data/taxonomy/`` must follow the
"Label writing guidelines" section of ``docs/taxonomy.md``. These tests
encode the parts a regex can catch — observation label shape, "Use "
description prefix, synonyms populated, field labels are plain English
not raw Sigma names, top-3 fields have notes + examples (with enum
fields exempt from examples per the contract).

If a test in this file fails, either:

  1. The taxonomy YAML drifted from the contract — fix the YAML.
  2. The contract needs updating — discuss in the PR, update both
     ``docs/taxonomy.md`` AND this file in lockstep so the docs
     and the gate agree.

Tests run against the live ``TaxonomyRegistry`` (post-loader, post-
schema-validation), so anything wrong with the YAML schema itself
fails earlier in ``test_taxonomy_loader.py``.
"""

from __future__ import annotations

import re

import pytest

from intel2sigma.core.taxonomy import load_taxonomy
from intel2sigma.core.taxonomy.loader import TaxonomyRegistry

# ---------------------------------------------------------------------------
# Fixture: the loaded registry, shared across every test
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def registry() -> TaxonomyRegistry:
    """Load every taxonomy YAML under ``data/taxonomy/`` once for the suite."""
    return load_taxonomy()


# ---------------------------------------------------------------------------
# Observation-level invariants
# ---------------------------------------------------------------------------


# Observation labels follow Pattern A (active "A process was started") or
# Pattern B (passive "A Windows Security event was logged") per
# docs/taxonomy.md. Both start with ``A `` or ``An `` — and the next
# letter can be lowercase (Pattern A: "A process…") or uppercase
# (Pattern B / proper nouns: "A Windows Security event…"). We don't
# try to parse verb form because Pattern B is the explicit fallback
# for cases where active voice would force a misleading verb.
_LABEL_PREFIX_RE = re.compile(r"^An? [a-zA-Z]")


# Field labels must NOT be a single PascalCase / camelCase word that
# looks like the underlying Sigma field name (``EventID``, ``TargetObject``,
# ``CommandLine``, etc.). Plain-English noun phrases pass; raw Sigma
# names fail. The two PascalCase shapes we check:
#
#   ``Foo`` + ``Bar``       — two-or-more capitalised tokens, no spaces
#   ``Foo`` + ``BAR``       — capitalised + abbrev (e.g. ``IPv4``)
#
# Single short tokens like ``Status`` or ``Action`` are accepted (they
# ARE plain English even though they're single capitalised words).
_PASCAL_RE = re.compile(r"^[A-Z][a-z]+([A-Z][a-z]*)+$")
_PASCAL_ABBREV_RE = re.compile(r"^[A-Z][a-z]*[A-Z]{2,}[a-zA-Z]*$")


def test_every_observation_has_a_pattern_compliant_label(
    registry: TaxonomyRegistry,
) -> None:
    """Every label must start with 'A ' or 'An ' followed by a capitalised noun."""
    failures: list[str] = []
    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        if not _LABEL_PREFIX_RE.match(spec.label):
            failures.append(f"  {obs_id}: label {spec.label!r} doesn't match pattern A/B")
    assert not failures, "label-pattern violations:\n" + "\n".join(failures)


def test_every_observation_description_starts_with_use(
    registry: TaxonomyRegistry,
) -> None:
    """Every description starts with 'Use ' per docs/taxonomy.md."""
    failures: list[str] = []
    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        if not spec.description.startswith("Use "):
            failures.append(
                f"  {obs_id}: description {spec.description[:60]!r} doesn't start with 'Use '"
            )
    assert not failures, "description-prefix violations:\n" + "\n".join(failures)


def test_every_observation_has_synonyms_populated(
    registry: TaxonomyRegistry,
) -> None:
    """Synonyms is required (3+ entries). Empty ``synonyms: []`` silently breaks Stage 0 search."""
    failures: list[str] = []
    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        if len(spec.synonyms) < 3:
            failures.append(
                f"  {obs_id}: only {len(spec.synonyms)} synonyms "
                f"(need ≥3 for Stage 0 search relevance)"
            )
    assert not failures, "synonym-coverage violations:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# Field-level invariants
# ---------------------------------------------------------------------------


# Earlier drafts had a ``test_no_field_label_equals_its_raw_sigma_name``
# that failed when ``field.label == field.name`` for any reason. Removed:
# false-positive-prone for fields whose Sigma names happen to be plain-
# English single nouns (``Path``, ``Reason``, ``Value``, ``Protocol``,
# ``Operation``, ``Action``, ``Status``, etc.). When the Sigma name IS
# plain English, ``label == name`` is fine — the user sees a plain-English
# word in the dropdown either way. The PascalCase test below is what
# actually catches the leaks-from-auto-generation case (``TargetObject``,
# ``EventID``, ``ScriptBlockText``, etc.) without the false-positive tax.


def test_no_field_label_is_a_single_pascalcase_word(
    registry: TaxonomyRegistry,
) -> None:
    """Field labels must be plain English, not single-word PascalCase / camelCase.

    A label like ``Eventtype`` (PascalCase, no spaces) is a clear sign
    a raw Sigma name leaked through. Single short tokens like ``Status``
    or ``Action`` are acceptable — those are plain English nouns even
    if they happen to be one word.
    """
    failures: list[str] = []
    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        for field in spec.fields:
            label = field.label
            # Multi-word labels with spaces are always fine.
            if " " in label:
                continue
            # Single-token labels — only fail if they're PascalCase /
            # camelCase compound words, not plain single nouns.
            if _PASCAL_RE.match(label) or _PASCAL_ABBREV_RE.match(label):
                failures.append(f"  {obs_id}/{field.name}: label {label!r} is PascalCase")
    assert not failures, "PascalCase-label violations:\n" + "\n".join(failures)


def test_top3_fields_have_notes(registry: TaxonomyRegistry) -> None:
    """The first 3 fields per observation must have a ``note``.

    Top-3 fields are the ones surfaced first in the Stage 1 dropdown
    (declaration order, frequency-ranked at calibration). Helper
    tooltips display the ``note`` content, so a missing note means a
    hollow tooltip — ship-blocker per docs/taxonomy.md.
    """
    failures: list[str] = []
    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        if len(spec.fields) < 2:
            continue  # Single-field observations are exempt.
        for field in spec.fields[:3]:
            if not field.note:
                failures.append(f"  {obs_id}/{field.name}: top-3 field missing 'note'")
    assert not failures, "top-3 note violations:\n" + "\n".join(failures)


def test_top3_non_enum_fields_have_examples(registry: TaxonomyRegistry) -> None:
    """The first 3 fields per observation must have an ``example`` unless enum.

    Per docs/taxonomy.md: "For enum-typed fields, the YAML's ``values:``
    list is sufficient documentation; ``note`` is optional but
    ``example`` should be omitted (the dropdown shows the choices)."
    So enum fields are exempt from this test; everything else must
    have a real-looking example value the user can click-to-insert.
    """
    failures: list[str] = []
    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        if len(spec.fields) < 2:
            continue  # Single-field observations are exempt.
        for field in spec.fields[:3]:
            if field.type == "enum":
                continue
            if not field.example:
                failures.append(
                    f"  {obs_id}/{field.name} (type={field.type}): "
                    f"top-3 non-enum field missing 'example'"
                )
    assert not failures, "top-3 example violations:\n" + "\n".join(failures)


# Earlier drafts of this file had a third anti-jargon test that flagged
# any field where ``field.name`` appeared as a substring of ``field.label``.
# Removed: too false-positive-prone — common English words that happen to
# match Sigma field names (``type`` → "Audit record type",
# ``User`` → "User account", ``Action`` → "GitHub action name",
# ``Device`` → "Device path", ``Path`` → "Task executable path",
# ``Product`` / ``Company`` → "Product name (PE metadata)" / "Company
# name (PE metadata)") all triggered the test legitimately. The two
# earlier tests (label != name, label is not single-PascalCase word)
# cover the actual concern; the substring check just punished
# perfectly fine plain-English phrasings.
