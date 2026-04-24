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

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from intel2sigma import __version__
from intel2sigma.core.convert import all_backend_ids, backend_label

_WEB_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _WEB_DIR / "static"
_TEMPLATES_DIR = _WEB_DIR / "templates"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


@dataclass(frozen=True)
class ConversionTab:
    """One conversion-output tab in the preview pane.

    ``short`` is the chip label (fits in a tab); ``label`` is the tooltip /
    accessible name. Ordering in the UI follows the order of
    :func:`all_backend_ids`, which returns sorted ids.
    """

    backend_id: str
    short: str
    label: str


_SHORT_LABELS: dict[str, str] = {
    "kusto_sentinel": "Sentinel",
    "kusto_mde": "MDE",
    "splunk": "Splunk",
    "elasticsearch": "Elastic",
    "crowdstrike": "CrowdStrike",
}


def _conversion_tabs() -> list[ConversionTab]:
    tabs: list[ConversionTab] = []
    for backend_id in all_backend_ids():
        short = _SHORT_LABELS.get(backend_id, backend_id)
        tabs.append(ConversionTab(backend_id, short, backend_label(backend_id)))
    return tabs


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
        return templates.TemplateResponse(request, "base.html", _shell_context("guided"))

    @app.get("/mode/expert", response_class=HTMLResponse, name="expert_home")
    async def expert_home(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "base.html", _shell_context("expert"))

    return app


def _shell_context(mode: str) -> dict[str, Any]:
    """Variables passed to every shell render. Kept in one place so stage
    partials that inherit from ``base.html`` get the same defaults.
    """
    return {
        "mode": mode,
        "version": __version__,
        "conversion_tabs": _conversion_tabs(),
    }


# Module-level app object for ``uvicorn intel2sigma.web.app:app``.
app = create_app()
