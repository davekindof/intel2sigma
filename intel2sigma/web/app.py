"""FastAPI application entry point.

Wires together:

* Static asset serving (``/static/*`` -> ``intel2sigma/web/static/``)
* Jinja2 templates (``intel2sigma/web/templates/``)
* Guided + Expert mode shells — both render the same base template with
  different ``mode`` values, per the design in docs/web-state-model.md.
* ``/healthz`` — liveness probe for container platforms.

Zero composer logic at this stage — routes for the five Guided stages and
Expert-mode detail land in M1.3 and M1.4. This module's job is to make the
chrome render and prove the FastAPI + Jinja2 + static wiring is correct.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from intel2sigma import __version__
from intel2sigma._version import _build_sha, version_payload
from intel2sigma.web.logging import configure_logging, request_logging_middleware
from intel2sigma.web.routes import composer as composer_routes

configure_logging()

_WEB_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _WEB_DIR / "static"
_TEMPLATES_DIR = _WEB_DIR / "templates"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def create_app() -> FastAPI:
    """Application factory. Kept separate from module-level ``app`` so tests
    can instantiate a fresh app without process-wide side effects.
    """
    app = FastAPI(
        title="intel2sigma",
        version=__version__,
        docs_url=None,  # no Swagger UI; this isn't an API surface
        redoc_url=None,
    )
    app.middleware("http")(request_logging_middleware)
    app.mount(
        "/static",
        StaticFiles(directory=str(_STATIC_DIR)),
        name="static",
    )

    # Shared objects route modules reach through ``request.app.state``:
    app.state.templates = templates
    app.state.taxonomy = composer_routes.prime_taxonomy()

    app.include_router(composer_routes.router)

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        """Liveness probe. Container platforms hit this to know we're up."""
        return JSONResponse({"status": "ok", "version": __version__})

    @app.get("/version")
    async def version() -> JSONResponse:
        """Build provenance — package version, git SHA, pinned data versions.

        For ops visibility ("which build is live, what data ships with it")
        and bug reports ("the MITRE picker showed me X — which version?").
        Constant payload, computed at import time.
        """
        return JSONResponse(version_payload())

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request) -> RedirectResponse:
        """Default landing: send to the composer."""
        return RedirectResponse(url=request.url_for("guided_home"))

    @app.get("/mode/guided", response_class=HTMLResponse, name="guided_home")
    async def guided_home(request: Request) -> HTMLResponse:
        """Render the composer shell.

        Originally one of two modes (Guided / Expert). The dual-mode
        story was deferred without a tester ask, then formally pruned —
        the breadcrumb (commit ``04d2a2a``), freeform observation entry
        (``f9bc057``), and SigmaHQ corpus browse (``0b40988``) cover
        the "power user" cases the docs envisioned for Expert mode.
        See SPEC.md decision log for the full rationale.

        ``/mode/guided`` is kept as the canonical URL since it's been
        public; ``/mode/expert`` redirects here so old bookmarks still
        work.
        """
        return templates.TemplateResponse(request, "base.html", _shell_context(request))

    @app.get("/mode/expert")
    async def expert_redirect(request: Request) -> RedirectResponse:
        """Backward-compatible redirect for the now-removed Expert mode."""
        return RedirectResponse(url=request.url_for("guided_home"), status_code=301)

    @app.get("/rule/download", name="rule_download")
    async def rule_download(rule_state: str = "") -> PlainTextResponse:
        """Top-level download endpoint. Stage 4's download button links here.

        Kept outside the /composer router because downloading isn't a
        composer state transition; it's a terminal artifact fetch.
        """
        return composer_routes.build_download_response(rule_state)

    return app


def _shell_context(request: Request) -> dict[str, Any]:
    """Variables passed to every shell render. Kept in one place so stage
    partials that inherit from ``base.html`` get the same defaults.
    """
    initial = composer_routes.initial_composer_context(request, request.app.state.taxonomy)
    return {
        "version": __version__,
        # Static-asset cache-bust key. The earlier scheme was
        # ``?v={{ version }}``, which only changed on package version
        # bumps (~quarterly) and let Cloudflare cache stale CSS for
        # hours after every deploy of an unrelated commit. Switch to
        # ``build_sha`` (set by the Dockerfile via the BUILD_SHA build-
        # arg → INTEL2SIGMA_BUILD_SHA env var per docs/architecture.md)
        # so every deploy gets a fresh URL automatically. Local dev
        # gets the literal "dev" — hard-refresh once on a CSS change is
        # standard practice. Same env var feeds /version, so the asset
        # query string and the build-provenance endpoint always agree.
        "build_sha": _build_sha(),
        "initial_composer_html": initial["initial_composer_html"],
        "initial_state_json": initial["initial_state_json"],
        # Spread preview context (conversion_tabs, conversion_outputs,
        # preview_yaml, preview_yaml_html, preview_issues) so the base
        # template's included partials render the same way the oob swap
        # path does.
        **initial["initial_preview_context"],
    }


# Module-level app object for ``uvicorn intel2sigma.web.app:app``.
app = create_app()
