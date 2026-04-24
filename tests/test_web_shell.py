"""Tests for the M1.2 web shell — routes, template rendering, static assets.

Uses FastAPI's TestClient so no separate uvicorn process is required. These
are the first tests to exercise ``intel2sigma.web``; subsequent milestones
(M1.3+) will add composer route tests alongside.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from intel2sigma import __version__
from intel2sigma.web.app import app
from intel2sigma.web.highlight import yaml_to_html


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def test_healthz_returns_ok_json(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    payload = r.json()
    assert payload["status"] == "ok"
    assert payload["version"] == __version__


def test_root_redirects_to_guided(client: TestClient) -> None:
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert r.headers["location"].endswith("/mode/guided")


def test_guided_mode_renders_shell(client: TestClient) -> None:
    r = client.get("/mode/guided")
    assert r.status_code == 200
    body = r.text
    assert "intel2" in body and "sigma" in body  # wordmark
    assert 'data-mode="guided"' in body
    assert "app-header" in body
    assert "composer-panel" in body
    assert "preview-panel" in body
    assert "health-drawer" in body


def test_expert_mode_renders_shell(client: TestClient) -> None:
    r = client.get("/mode/expert")
    assert r.status_code == 200
    assert 'data-mode="expert"' in r.text


def test_shell_includes_all_five_conversion_tabs(client: TestClient) -> None:
    r = client.get("/mode/guided")
    body = r.text
    for label in ("Sentinel", "MDE", "Splunk", "Elastic", "CrowdStrike"):
        assert label in body, f"Missing conversion tab label: {label}"


# ---------------------------------------------------------------------------
# Static assets
# ---------------------------------------------------------------------------


def test_css_is_served(client: TestClient) -> None:
    r = client.get("/static/intel2sigma.css")
    assert r.status_code == 200
    assert "--color-accent" in r.text
    assert r.headers["content-type"].startswith("text/css")


def test_vendored_htmx_is_served(client: TestClient) -> None:
    r = client.get("/static/vendor/htmx.min.js")
    assert r.status_code == 200
    assert "htmx=function" in r.text  # first bytes of htmx 2.0.x


# ---------------------------------------------------------------------------
# Pygments YAML highlighting
# ---------------------------------------------------------------------------


def test_yaml_to_html_wraps_tokens() -> None:
    html = yaml_to_html('title: "hello world"\nid: abc123\n')
    # We use HtmlFormatter(nowrap=True), so the output is raw spans — no
    # outer <div class="highlight"> wrapper, but the token spans should
    # carry the classes our CSS styles.
    assert '<span class="' in html
    # YAML key (nt = Name.Tag) and string (s2) classes should appear.
    assert "nt" in html or "k" in html
