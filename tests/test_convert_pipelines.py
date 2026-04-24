"""Unit tests for ``core.convert.pipelines`` resolution algorithm.

Golden conversion tests (which actually run pySigma) live in
``test_convert_engine.py``. This file covers the pure resolution logic with
synthetic in-memory matrices so the tests are fast and isolated.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from intel2sigma.core.convert.pipelines import (
    BackendSpec,
    LogsourceMatch,
    LogsourceMatrixEntry,
    PipelineMatrix,
    PipelineMatrixError,
    UnknownBackendError,
    all_backend_ids,
    backend_label,
    load_pipeline_matrix,
    resolve,
)
from intel2sigma.core.model import LogSource


def _matrix() -> PipelineMatrix:
    return PipelineMatrix(
        backends={
            "kusto_sentinel": BackendSpec(
                sigma_backend="kusto",
                baseline_pipelines=["microsoft_xdr"],
                label="Microsoft Sentinel (KQL)",
            ),
            "splunk": BackendSpec(
                sigma_backend="splunk",
                baseline_pipelines=[],
                label="Splunk (SPL)",
            ),
        },
        logsource_matrix=[
            LogsourceMatrixEntry(
                match=LogsourceMatch(product="windows", category="process_creation"),
                backends={"splunk": ["splunk_windows", "sysmon"]},
            ),
            LogsourceMatrixEntry(
                match=LogsourceMatch(product="windows", category="file_event"),
                backends={"splunk": ["splunk_windows", "sysmon"]},
            ),
        ],
    )


# ---------------------------------------------------------------------------
# resolve()
# ---------------------------------------------------------------------------


def test_resolve_baseline_only_when_no_matrix_match() -> None:
    r = resolve(
        LogSource(product="linux", category="process_creation"),
        "kusto_sentinel",
        matrix=_matrix(),
    )
    assert r.backend_id == "kusto_sentinel"
    assert r.sigma_backend == "kusto"
    assert r.pipelines == ("microsoft_xdr",)


def test_resolve_matrix_entry_extends_baseline() -> None:
    r = resolve(
        LogSource(product="windows", category="process_creation"),
        "splunk",
        matrix=_matrix(),
    )
    assert r.pipelines == ("splunk_windows", "sysmon")


def test_resolve_baseline_preserved_when_matrix_adds() -> None:
    r = resolve(
        LogSource(product="windows", category="process_creation"),
        "kusto_sentinel",
        matrix=_matrix(),
    )
    # kusto_sentinel has no matrix override for any entry here — only splunk does.
    assert r.pipelines == ("microsoft_xdr",)


def test_resolve_unknown_backend_raises() -> None:
    with pytest.raises(UnknownBackendError, match="Unknown backend id"):
        resolve(LogSource(category="process_creation"), "qradar", matrix=_matrix())


def test_resolve_first_match_wins() -> None:
    # Add a more-general entry after a specific one; the specific match
    # should still win because it appears first.
    matrix = PipelineMatrix(
        backends={
            "splunk": BackendSpec(
                sigma_backend="splunk",
                baseline_pipelines=[],
                label="Splunk",
            ),
        },
        logsource_matrix=[
            LogsourceMatrixEntry(
                match=LogsourceMatch(product="windows", category="process_creation"),
                backends={"splunk": ["specific"]},
            ),
            LogsourceMatrixEntry(
                match=LogsourceMatch(product="windows"),
                backends={"splunk": ["generic"]},
            ),
        ],
    )
    r = resolve(
        LogSource(product="windows", category="process_creation"),
        "splunk",
        matrix=matrix,
    )
    assert r.pipelines == ("specific",)


def test_resolve_missing_logsource_field_does_not_match_required_match() -> None:
    r = resolve(
        LogSource(category="process_creation"),  # no product
        "splunk",
        matrix=_matrix(),
    )
    # Matrix entries both require product=windows; none match.
    assert r.pipelines == ()


# ---------------------------------------------------------------------------
# load_pipeline_matrix()
# ---------------------------------------------------------------------------


def test_load_bundled_matrix_succeeds() -> None:
    m = load_pipeline_matrix()
    assert "kusto_sentinel" in m.backends
    assert "splunk" in m.backends
    assert len(m.logsource_matrix) > 0


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PipelineMatrixError, match="not found"):
        load_pipeline_matrix(tmp_path / "nope.yml")


def test_load_rejects_empty_match(tmp_path: Path) -> None:
    path = tmp_path / "pipelines.yml"
    path.write_text(
        """
backends:
    x:
        sigma_backend: kusto
        baseline_pipelines: []
        label: "X"
logsource_matrix:
    - match: {}
      backends:
          x: [foo]
""",
        encoding="utf-8",
    )
    with pytest.raises(PipelineMatrixError, match="empty match"):
        load_pipeline_matrix(path)


def test_load_rejects_undeclared_backend_in_matrix(tmp_path: Path) -> None:
    path = tmp_path / "pipelines.yml"
    path.write_text(
        """
backends:
    x:
        sigma_backend: kusto
        baseline_pipelines: []
        label: "X"
logsource_matrix:
    - match: { product: windows }
      backends:
          y: [foo]
""",
        encoding="utf-8",
    )
    with pytest.raises(PipelineMatrixError, match="unknown"):
        load_pipeline_matrix(path)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def test_all_backend_ids_returns_sorted_declared_ids() -> None:
    ids = all_backend_ids(_matrix())
    assert ids == sorted(ids)
    assert "kusto_sentinel" in ids
    assert "splunk" in ids


def test_backend_label_returns_declared_label() -> None:
    assert backend_label("kusto_sentinel", _matrix()) == "Microsoft Sentinel (KQL)"


def test_backend_label_unknown_raises() -> None:
    with pytest.raises(UnknownBackendError):
        backend_label("qradar", _matrix())


def test_bundled_matrix_declares_all_five_backends() -> None:
    ids = all_backend_ids()
    assert set(ids) >= {"kusto_sentinel", "kusto_mde", "splunk", "elasticsearch", "crowdstrike"}
