"""Tests for the /healthz and /version provenance endpoints.

/version surfaces build + pinned-data provenance for ops + tester bug
reports. The shape is contractual: ops dashboards and Cloudflare health
checks read these fields, so changing them is a breaking change.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from intel2sigma import __version__
from intel2sigma._version import SIGMAHQ_PINNED_COMMIT
from intel2sigma.web.app import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_healthz_returns_ok(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_version_returns_required_fields(client: TestClient) -> None:
    """Each field below is a contract: ops + Cloudflare + tester reports
    rely on them. Adding fields is fine; renaming or removing is breaking.
    """
    r = client.get("/version")
    assert r.status_code == 200
    body = r.json()
    for key in (
        "package",
        "build_sha",
        "mitre_attack",
        "mitre_generated_at",
        "sigmahq_corpus_commit",
    ):
        assert key in body, f"/version payload missing {key!r}"


def test_version_package_matches_dunder(client: TestClient) -> None:
    body = client.get("/version").json()
    assert body["package"] == __version__


def test_version_sigmahq_commit_matches_pinned(client: TestClient) -> None:
    """Source of truth lives in intel2sigma._version; /version surfaces it."""
    body = client.get("/version").json()
    assert body["sigmahq_corpus_commit"] == SIGMAHQ_PINNED_COMMIT


def test_version_mitre_fields_populated_in_repo(client: TestClient) -> None:
    """The bundled tree should resolve to a real version, not "?".

    Catches the case where data/mitre_attack.json gets corrupted or the
    helper fails silently.
    """
    body = client.get("/version").json()
    assert body["mitre_attack"] != "?"
    assert body["mitre_generated_at"] != "?"


def test_version_build_sha_defaults_to_dev(client: TestClient) -> None:
    """In an in-repo run with no INTEL2SIGMA_BUILD_SHA env var, /version
    should show "dev" — the Dockerfile is the only place that sets it.
    """
    if "INTEL2SIGMA_BUILD_SHA" in os.environ:
        pytest.skip("env var INTEL2SIGMA_BUILD_SHA is set; default not exercised")
    body = client.get("/version").json()
    assert body["build_sha"] == "dev"
