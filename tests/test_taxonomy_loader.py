"""Tests for the taxonomy schema and loader.

The loader is fail-fast; every invariant violation should raise
:class:`TaxonomyLoadError` with a message that names the offending file. These
tests drive synthetic YAML into a temp directory — the bundled
``data/taxonomy/`` is covered by a separate integration test once the 15 real
files exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from intel2sigma.core.taxonomy import (
    TaxonomyLoadError,
    TaxonomyRegistry,
    load_taxonomy,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

VALID_PROCESS_CREATION = """\
id: process_creation
label: "A process was started"
description: "Use when malware or suspicious activity created a new process."
category_group: process_and_execution
logsource:
    category: process_creation
    product: windows
platforms:
    - id: windows
      product: windows
      tier: primary
synonyms:
    - "process launched"
fields:
    - name: Image
      label: "Executable path"
      type: path
      default_modifier: endswith
      allowed_modifiers: [endswith, startswith, contains, re, exact]
      example: "\\\\evil.exe"
    - name: CommandLine
      label: "Command line"
      type: string
      default_modifier: contains
      allowed_modifiers: [contains, startswith, endswith, re, all, exact]
"""

VALID_FILE_EVENT = """\
id: file_event
label: "A file was created or modified"
description: "Use when malware wrote or modified a file on disk."
category_group: file_and_registry
logsource:
    category: file_event
    product: windows
platforms:
    - id: windows
      product: windows
      tier: primary
fields:
    - name: TargetFilename
      label: "File path"
      type: path
      default_modifier: endswith
      allowed_modifiers: [endswith, contains, startswith, exact, re]
"""


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_load_one_file_succeeds(tmp_path: Path) -> None:
    _write(tmp_path / "process_creation.yml", VALID_PROCESS_CREATION)
    registry = load_taxonomy(tmp_path)
    assert isinstance(registry, TaxonomyRegistry)
    assert registry.all_ids() == ["process_creation"]
    spec = registry.get("process_creation")
    assert spec.label == "A process was started"
    assert len(spec.fields) == 2


def test_load_multiple_files_groups_by_category(tmp_path: Path) -> None:
    _write(tmp_path / "process_creation.yml", VALID_PROCESS_CREATION)
    _write(tmp_path / "file_event.yml", VALID_FILE_EVENT)
    registry = load_taxonomy(tmp_path)
    assert registry.all_ids() == ["file_event", "process_creation"]
    grouped = registry.by_group()
    assert grouped["process_and_execution"] == ["process_creation"]
    assert grouped["file_and_registry"] == ["file_event"]


def test_loader_is_deterministic(tmp_path: Path) -> None:
    _write(tmp_path / "process_creation.yml", VALID_PROCESS_CREATION)
    r1 = load_taxonomy(tmp_path)
    r2 = load_taxonomy(tmp_path)
    assert r1.all_ids() == r2.all_ids()
    assert r1.get("process_creation") == r2.get("process_creation")


def test_unknown_id_raises_keyerror(tmp_path: Path) -> None:
    _write(tmp_path / "process_creation.yml", VALID_PROCESS_CREATION)
    registry = load_taxonomy(tmp_path)
    with pytest.raises(KeyError, match="Unknown observation type"):
        registry.get("does_not_exist")


# ---------------------------------------------------------------------------
# Loader-level failures (directory / file-system)
# ---------------------------------------------------------------------------


def test_missing_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(TaxonomyLoadError, match="not found"):
        load_taxonomy(tmp_path / "nonexistent")


def test_empty_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(TaxonomyLoadError, match=r"No .* files found"):
        load_taxonomy(tmp_path)


def test_filename_must_match_id(tmp_path: Path) -> None:
    # File claims id=process_creation but is named wrong_name.yml.
    _write(tmp_path / "wrong_name.yml", VALID_PROCESS_CREATION)
    with pytest.raises(TaxonomyLoadError, match="does not match filename stem"):
        load_taxonomy(tmp_path)


def test_yaml_parse_error_surfaces_filename(tmp_path: Path) -> None:
    _write(tmp_path / "broken.yml", "id: broken\n  indented_wrong: [unclosed\n")
    with pytest.raises(TaxonomyLoadError, match=r"broken\.yml"):
        load_taxonomy(tmp_path)


def test_non_mapping_top_level_raises(tmp_path: Path) -> None:
    _write(tmp_path / "list_top.yml", "- 1\n- 2\n- 3\n")
    with pytest.raises(TaxonomyLoadError, match="must be a mapping"):
        load_taxonomy(tmp_path)


# ---------------------------------------------------------------------------
# Schema-level failures (cross-field invariants)
# ---------------------------------------------------------------------------


def test_default_modifier_not_in_allowed_raises(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION.replace(
        "default_modifier: endswith",
        "default_modifier: cidr",  # cidr is a valid ValueModifier but not listed in allowed
        1,
    )
    _write(tmp_path / "process_creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="default_modifier"):
        load_taxonomy(tmp_path)


def test_enum_without_values_raises(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION.replace(
        """    - name: CommandLine
      label: "Command line"
      type: string
      default_modifier: contains
      allowed_modifiers: [contains, startswith, endswith, re, all, exact]
""",
        """    - name: IntegrityLevel
      label: "Integrity level"
      type: enum
      default_modifier: exact
      allowed_modifiers: [exact]
""",
    )
    _write(tmp_path / "process_creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="type=enum requires"):
        load_taxonomy(tmp_path)


def test_values_on_non_enum_raises(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION.replace(
        """    - name: CommandLine
      label: "Command line"
      type: string
      default_modifier: contains
      allowed_modifiers: [contains, startswith, endswith, re, all, exact]
""",
        """    - name: CommandLine
      label: "Command line"
      type: string
      default_modifier: contains
      allowed_modifiers: [contains, startswith, endswith, re, all, exact]
      values: [a, b]
""",
    )
    _write(tmp_path / "process_creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="only valid on type=enum"):
        load_taxonomy(tmp_path)


def test_unknown_category_group_raises(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION.replace(
        "category_group: process_and_execution",
        "category_group: ransomware_prevention",
    )
    _write(tmp_path / "process_creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="category_group"):
        load_taxonomy(tmp_path)


def test_unknown_modifier_raises(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION.replace(
        "allowed_modifiers: [endswith, startswith, contains, re, exact]",
        "allowed_modifiers: [endswith, made_up_modifier]",
    )
    _write(tmp_path / "process_creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="allowed_modifiers"):
        load_taxonomy(tmp_path)


def test_empty_platforms_raises(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION.replace(
        """platforms:
    - id: windows
      product: windows
      tier: primary
""",
        "platforms: []\n",
    )
    _write(tmp_path / "process_creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="platforms"):
        load_taxonomy(tmp_path)


def test_duplicate_platform_ids_raises(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION.replace(
        """platforms:
    - id: windows
      product: windows
      tier: primary
""",
        """platforms:
    - id: windows
      product: windows
      tier: primary
    - id: windows
      product: windows
      tier: secondary
""",
    )
    _write(tmp_path / "process_creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="duplicate platform id"):
        load_taxonomy(tmp_path)


def test_duplicate_field_names_raises(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION.replace(
        """    - name: CommandLine
      label: "Command line"
      type: string
      default_modifier: contains
      allowed_modifiers: [contains, startswith, endswith, re, all, exact]
""",
        """    - name: Image
      label: "Duplicate"
      type: path
      default_modifier: exact
      allowed_modifiers: [exact]
""",
    )
    _write(tmp_path / "process_creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="duplicate field name"):
        load_taxonomy(tmp_path)


def test_extra_field_rejected(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION + "unknown_top_level_key: true\n"
    _write(tmp_path / "process_creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="Extra inputs"):
        load_taxonomy(tmp_path)


def test_bad_observation_id_pattern_raises(tmp_path: Path) -> None:
    bad = VALID_PROCESS_CREATION.replace(
        "id: process_creation",
        "id: Process-Creation",  # uppercase + dashes rejected
    )
    _write(tmp_path / "Process-Creation.yml", bad)
    with pytest.raises(TaxonomyLoadError, match="id"):
        load_taxonomy(tmp_path)


# ---------------------------------------------------------------------------
# Integration: the bundled data/taxonomy/ directory loads end-to-end.
# ---------------------------------------------------------------------------


EXPECTED_IDS = frozenset(
    {
        "process_creation",
        "image_load",
        "create_remote_thread",
        "raw_access_thread",
        "pipe_created",
        "file_event",
        "file_event_linux",
        "registry_set",
        "network_connection",
        "dns_query",
        "create_task",
        "wmi_event",
        "driver_load",
        "ps_script",
        "ps_module",
    }
)


def test_bundled_catalog_loads() -> None:
    """Every bundled observation file must load without any schema errors.

    Uses the default (bundled) data directory so the whole pipeline is
    exercised end-to-end — failure here means a file in ``data/taxonomy/``
    drifted from the schema and caught CI rather than production.
    """
    registry = load_taxonomy()
    assert set(registry.all_ids()) == EXPECTED_IDS


def test_bundled_catalog_has_five_ui_groups() -> None:
    registry = load_taxonomy()
    groups = registry.by_group()
    assert set(groups) == {
        "process_and_execution",
        "file_and_registry",
        "network",
        "scheduled_and_system",
        "powershell_and_scripting",
    }
    # Every group must have at least one observation; empty groups suggest
    # a broken category_group on one of the files.
    for group_members in groups.values():
        assert group_members


def test_bundled_catalog_fields_are_internally_consistent() -> None:
    """Every field in the bundled catalog satisfies its own invariants.

    Pydantic enforces these on load, but running them here gives a single
    clear failure per file instead of a stack trace buried in the loader.
    """
    registry = load_taxonomy()
    for obs_id in registry.all_ids():
        spec = registry.get(obs_id)
        assert spec.fields, f"{obs_id}: no fields declared"
        for f in spec.fields:
            assert f.default_modifier in f.allowed_modifiers, (
                f"{obs_id}.{f.name}: default_modifier {f.default_modifier!r} "
                f"not in allowed_modifiers {f.allowed_modifiers!r}"
            )
            if f.type.value == "enum":
                assert f.values, f"{obs_id}.{f.name}: enum field missing values"
