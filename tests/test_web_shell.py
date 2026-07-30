"""Tests for the M1.2 web shell — routes, template rendering, static assets.

Uses FastAPI's TestClient so no separate uvicorn process is required. These
are the first tests to exercise ``intel2sigma.web``; subsequent milestones
(M1.3+) will add composer route tests alongside.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from intel2sigma import __version__
from intel2sigma.web.app import app, create_app
from intel2sigma.web.highlight import yaml_to_html
from intel2sigma.web.routes.composer import _content_disposition


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


def test_guided_renders_shell(client: TestClient) -> None:
    r = client.get("/mode/guided")
    assert r.status_code == 200
    body = r.text
    assert "intel2" in body and "sigma" in body  # wordmark
    assert "app-header" in body
    assert "composer-panel" in body
    assert "preview-panel" in body
    # The health drawer was removed in 2026-07: it never rendered
    # anything but a placeholder promising "Rule health checks land in
    # M2.1", a milestone that no longer exists in ROADMAP.md, while rule
    # health actually shipped as the Stage 3 advisories. Asserting its
    # absence keeps the dead scaffolding from reappearing.
    assert "health-drawer" not in body


def test_expert_url_redirects_to_guided(client: TestClient) -> None:
    """``/mode/expert`` was the now-pruned dual-mode toggle. Old bookmarks
    should redirect, not 404 — preserves any tester URL.
    """
    r = client.get("/mode/expert", follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"].endswith("/mode/guided")


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


# ---------------------------------------------------------------------------
# Error-surface hardening
# ---------------------------------------------------------------------------


def test_openapi_schema_is_not_served(client: TestClient) -> None:
    """No machine-readable schema, matching the no-API-surface decision.

    ``create_app`` disables Swagger and ReDoc with the comment "this
    isn't an API surface", but ``openapi_url`` defaulted on, so
    /openapi.json served the full route table of a stateless HTML app in
    production. Not a secret with a public repo, but it contradicted the
    decision beside it.
    """
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_download_survives_a_non_latin1_title() -> None:
    """A Cyrillic or CJK rule title must not 500 the download.

    HTTP header values are latin-1. ``_download_filename`` sanitises with
    the unicode-aware ``str.isalnum()``, so those letters survived into
    ``Content-Disposition`` and Starlette raised ``UnicodeEncodeError``
    — a 500 on the product's final step for anyone naming rules in a
    non-Latin script. Emoji and accented Latin hid it: emoji fail
    isalnum() and are replaced, and "é" is inside latin-1.

    RFC 6266 carries the real name in ``filename*`` and an ASCII
    fallback in ``filename``.
    """
    for title in ("Обнаружение.yml", "恶意软件检测.yml", "café.yml", "plain.yml"):
        header = _content_disposition(title)
        # The header must be transmittable at all — this is what raised.
        header.encode("latin-1")
        assert "filename*=UTF-8''" in header, "extended form carries the real name"
        assert header.startswith('attachment; filename="'), "ASCII fallback comes first"


def test_unhandled_exception_becomes_a_message_not_a_traceback() -> None:
    """The last-resort handler returns 500 without leaking rule content.

    Two classes of unhandled exception have already reached users — pySigma
    raising non-SigmaError types out of convert(), and a non-latin-1 rule
    title breaking Content-Disposition. Both are fixed at source; this is
    the net for the next one.

    The assertion that matters is what is NOT in the body. Tracebacks and
    exception text can carry rule contents, which web/logging.py already
    works to keep out of logs; an error page that printed them would
    defeat that.
    """
    app = create_app()

    @app.get("/_boom")
    async def boom() -> None:
        raise RuntimeError("secret detection content: CommandLine=hunter2")

    # raise_server_exceptions=False so the handler's response is observable
    # rather than the exception propagating into the test.
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/_boom")

    assert r.status_code == 500
    assert "hunter2" not in r.text, "exception text must not reach the user"
    assert "Traceback" not in r.text
    assert "RuntimeError" not in r.text
    assert "Nothing was saved" in r.text, "should say the app is stateless"
    assert "Quote this id" in r.text, "should give a correlation handle"
