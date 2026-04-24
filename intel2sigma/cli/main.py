"""Typer CLI wrapping the core library.

Subcommands shipped so far:

* ``convert`` — read a Sigma YAML file, run it through pySigma for the
  chosen backend, print the resulting SIEM query.
* ``backends`` — list declared backend ids for use with ``convert``.
* ``serve`` — start the FastAPI web app via uvicorn. Hot-reload optional.

Validation (``validate``) subcommand lands alongside the Guided composer
in M1.3 so both share the same issue-rendering code path.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from intel2sigma.core.convert import (
    ConversionFailedError,
    UnknownBackendError,
    all_backend_ids,
    backend_label,
    convert,
)
from intel2sigma.core.serialize import from_yaml

app = typer.Typer(
    name="intel2sigma",
    help="Observation-driven Sigma rule composer and SIEM-query converter.",
    add_completion=False,
    no_args_is_help=True,
)


@app.command(name="backends")
def cmd_backends() -> None:
    """List declared backend ids and their human-readable labels."""
    for backend_id in all_backend_ids():
        label = backend_label(backend_id)
        typer.echo(f"  {backend_id:<20} {label}")


@app.command(name="convert")
def cmd_convert(
    rule_path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Path to a Sigma rule YAML file.",
        ),
    ],
    backend: Annotated[
        str,
        typer.Option(
            "--backend",
            "-b",
            help="Target backend id (use `intel2sigma backends` to list).",
        ),
    ],
) -> None:
    """Convert a Sigma rule to a SIEM query for the given backend.

    Reads the rule, runs it through pySigma via the ``core/convert`` layer,
    and prints the converted query to stdout. Exits non-zero on any error.
    """
    try:
        rule = from_yaml(rule_path.read_text(encoding="utf-8"))
    except OSError as exc:
        typer.echo(f"ERROR: cannot read {rule_path}: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except (ValueError, TypeError) as exc:
        typer.echo(f"ERROR: rule parse failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        query = convert(rule, backend)
    except UnknownBackendError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        typer.echo("Run `intel2sigma backends` to see declared ids.", err=True)
        raise typer.Exit(code=3) from exc
    except ConversionFailedError as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=4) from exc

    typer.echo(query)


@app.command(name="serve")
def cmd_serve(
    host: Annotated[
        str,
        typer.Option("--host", help="Interface to bind. Use 0.0.0.0 in Docker."),
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="TCP port.")] = 8000,
    reload: Annotated[
        bool,
        typer.Option("--reload/--no-reload", help="Auto-reload on source changes."),
    ] = False,
) -> None:
    """Start the FastAPI web app via uvicorn.

    Equivalent to ``uv run uvicorn intel2sigma.web.app:app --host ... --port ...``
    but bundled as a subcommand so ``intel2sigma serve`` is the one-liner
    for anyone who installed via ``pip install intel2sigma``.
    """
    # Imported lazily so the CLI stays importable on boxes without uvicorn
    # (e.g. a future slim `intel2sigma-core` wheel with no web deps).
    import uvicorn  # noqa: PLC0415 (lazy import is intentional)

    uvicorn.run(
        "intel2sigma.web.app:app",
        host=host,
        port=port,
        reload=reload,
    )


def main() -> None:
    """Entrypoint for the ``intel2sigma`` script defined in pyproject.toml."""
    app()


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(app())
