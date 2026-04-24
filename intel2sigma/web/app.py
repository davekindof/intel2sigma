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
from intel2sigma.web.routes import composer as composer_routes

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

    @app.get("/", response_class=HTMLResponse)
    async def root(request: Request) -> RedirectResponse:
        """Default landing: send first-time users to Guided mode.

        In v1.1 this will consult the mode preference cookie or localStorage;
        for now it's a fixed redirect.
        """
        return RedirectResponse(url=request.url_for("guided_home"))

    @app.get("/mode/guided", response_class=HTMLResponse, name="guided_home")
    async def guided_home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "base.html", _shell_context(request, "guided"))

    @app.get("/mode/expert", response_class=HTMLResponse, name="expert_home")
    async def expert_home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "base.html", _shell_context(request, "expert"))

    @app.get("/rule/download", name="rule_download")
    async def rule_download(rule_state: str = "") -> PlainTextResponse:
        """Top-level download endpoint. Stage 4's download button links here.

        Kept outside the /composer router because downloading isn't a
        composer state transition; it's a terminal artifact fetch.
        """
        return composer_routes.build_download_response(rule_state)

    return app


def _shell_context(request: Request, mode: str) -> dict[str, Any]:
    """Variables passed to every shell render. Kept in one place so stage
    partials that inherit from ``base.html`` get the same defaults.
    """
    initial = composer_routes.initial_composer_context(request, request.app.state.taxonomy)
    return {
        "mode": mode,
        "version": __version__,
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
