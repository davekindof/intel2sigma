"""Typer CLI wrapping the core library.

Subcommands shipped so far:

* ``convert`` — read a Sigma YAML file, run it through pySigma for the
  chosen backend, print the resulting SIEM query.
* ``backends`` — list declared backend ids for use with ``convert``.

Web server (``serve``) subcommand lands with M1.5 when the FastAPI app
exists. Validation (``validate``) subcommand lands alongside as a
non-web library entry point.
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


def main() -> None:
    """Entrypoint for the ``intel2sigma`` script defined in pyproject.toml."""
    app()


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(app())
