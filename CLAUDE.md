# CLAUDE.md

Project-level instructions for contributors — human and AI — working on intel2sigma. These are not suggestions. They are the rules that keep the project coherent. If any rule conflicts with a task, stop and ask rather than work around it.

## Read order (every session)

Before touching any code:

1. `SPEC.md` — what the system is
2. This file
3. `docs/architecture.md` — how it fits together at runtime
4. `docs/ui.md` — presentation layer contract
5. Domain docs (`docs/taxonomy.md`, `docs/heuristics.md`) if your task touches those areas

SPEC.md is the authoritative source for product and architecture decisions. If SPEC and code disagree, update whichever is wrong — do not silently reconcile by changing only one side.

## Architectural invariants (non-negotiable)

These rules exist because violating them breaks the project's core guarantees. Do not violate them under any circumstances. If you think you have a reason to, stop and ask.

### I-1: Deterministic composer path

The guided rule-building flow must not use LLMs, random number generators, time-dependent logic, or any non-deterministic computation. Given the same inputs, the composer must always produce the same rule. LLMs may be used only in explicitly-labeled auxiliary features (e.g., auto-generating a description *from* a completed rule), and never in a way that influences detection contents.

Rationale: The output is a CTI artifact that other organizations will run in production. Non-determinism breaks trust and reproducibility.

### I-2: Canonical Sigma is the output

The saved and shared artifact is always canonical, pipeline-independent Sigma YAML. Pipelines transform rules only for the preview and conversion panes. The tool must never save or export a pipeline-transformed rule as the primary artifact.

Rationale: Portability is the whole point. Pipeline-transformed rules are not portable.

### I-3: Stateless server

No database. No sessions. No auth. No server-side per-user storage of any kind. Every request carries the complete state it needs. If you find yourself reaching for persistence, stop and ask.

Rationale: Matches the deployment model (single Docker image, horizontally scalable, scale-to-zero). Adding state reverses all of those properties.

### I-4: No YAML textarea in the primary flow

The canonical YAML is shown in a read-only preview pane. A user-editable YAML textarea may exist only as an explicit "advanced: edit raw YAML" escape hatch, gated behind a warning, and only in Expert mode. The Guided mode flow must never expose raw YAML editing.

Rationale: The target audience cannot be trusted (and should not have to be trusted) to edit YAML correctly. Exposing the textarea inverts the value proposition.

### I-5: Data-driven everything

All observation catalogs, field definitions, modifier mappings, pipeline selections, and heuristic configurations live in data files (YAML or JSON), not in Python code. Adding a new observation type, field, pipeline mapping, or heuristic default must not require editing Python source.

The only things that live in code are:
- The schemas that validate the data files (Pydantic models)
- The logic that interprets the data
- The heuristic *functions themselves* (but their severities and enablement state live in data)

Rationale: The catalog and rules will evolve faster than the codebase. Non-coders should be able to propose catalog changes via PRs that don't touch Python.

### I-6: No npm, no node, no JS build step

The project does not use npm, node, yarn, pnpm, or any JavaScript package manager. There is no `package.json`, no `node_modules`, no build toolchain for frontend assets. JavaScript dependencies (htmx, and anything added later) are vendored as pinned single files in `web/static/vendor/` with SHA-256 integrity hashes recorded in `web/static/vendor/HASHES.md`. Upgrades are manual, reviewed diffs — not automated bumps.

Rationale: The npm ecosystem has repeatedly demonstrated that dependency chains are a supply-chain attack surface (see: TeamPCP-era compromises). This project produces security artifacts; its own supply chain must be minimal and auditable.

### I-7: Strict module dependency direction

```
web/ and cli/   →   core/   →   pysigma + stdlib + pinned deps
```

`core/` must not import from `web/` or `cli/`. `web/` and `cli/` must not import from each other. Nothing in `core/` may depend on a web framework, a CLI library, or any user-interface concern. `core/` must be usable from a Jupyter notebook with zero additional setup beyond `pip install intel2sigma`.

Rationale: Separating the rule engine from the presentation layers is what makes the tool reusable as a library, testable in isolation, and portable to future UIs.

### I-8: Pure functions in `core/validate/`, `core/heuristics/`, and `core/convert/`

Validators and heuristics must be pure functions of their input. No I/O. No network. No filesystem access. No time-of-day dependencies. No mutable module-level state. Conversions wrap pySigma, which is effectively pure, and cache results by content hash.

Rationale: Testability, determinism, and the ability to run the same logic identically from web handlers, CLI, and notebooks.

## Code conventions

### Python

- **Python 3.14 base.** Use modern stdlib features where they clarify intent.
- **Type hints on every public function, method, and model field.** `mypy --strict` must pass in CI.
- **Pydantic v2** for anything crossing a boundary (HTTP, disk, sandbox parsers, data-file loaders). Plain dataclasses internally where Pydantic is overkill.
- **`ruff` for formatting and linting.** Config in `pyproject.toml`. No `# noqa` or `# type: ignore` without an inline comment explaining why.
- **Docstrings** on all public classes, functions, and modules. Google-style or reST, consistent across the project. One-liners are fine for obvious cases.
- **Comments explain *why*, not *what*.** Self-documenting code first; comments as supplement. Link external specs or issues where relevant.
- **Prefer composition over inheritance.** Abstract base classes only when there are already ≥2 implementations. Avoid deep class hierarchies.
- **`async def` for I/O-bound handlers. Sync for pure computation, including pySigma conversions.** pySigma conversion is CPU-bound (~100ms cold, effectively free on cache hit per SPEC.md), so `core/convert/` is sync. Web handlers that call into it are `async def` themselves and invoke the sync converter directly. If concurrent-conversion load ever becomes a problem, wrap the call in `asyncio.to_thread` at the handler boundary — don't contaminate `core/` with async. Do not mix styles within a single module without clear reason.
- **No star imports.** `from x import *` is banned. Explicit names only.
- **Exceptions are typed.** Use specific exception classes (`InvalidRuleError`, `UnknownBackendError`, etc.), not bare `Exception` or `ValueError` for domain errors.

### Project structure

```
intel2sigma/
├── core/                  # Pure Python. No web deps. Importable standalone.
│   ├── model.py           # Pydantic models: SigmaRule, LogSource, etc.
│   ├── serialize.py       # Rule ↔ canonical YAML (ruamel.yaml)
│   ├── validate/
│   │   ├── tier1.py       # Pydantic model validation
│   │   ├── tier2.py       # pySigma schema validation
│   │   └── tier3.py       # SigmaHQ conventions (advisory)
│   ├── convert/
│   │   ├── engine.py      # pySigma wrapper
│   │   └── pipelines.py   # Pipeline matrix loader
│   ├── heuristics/
│   │   ├── base.py        # HeuristicResult, registry
│   │   └── checks/        # One module per category
│   ├── taxonomy/
│   │   └── loader.py      # Loads data/taxonomy/*.yml
│   └── parsers/           # v1.1+ sandbox parsers
├── web/                   # FastAPI app. Depends on core.
│   ├── app.py
│   ├── routes/
│   ├── templates/         # Jinja2
│   └── static/
│       └── vendor/        # Vendored JS/CSS with HASHES.md
├── cli/                   # Typer CLI. Depends on core.
├── _data.py               # data_path() — single helper for resolving bundled files
├── _version.py            # SIGMAHQ_PINNED_COMMIT + /version payload builder
└── data/                  # Data-driven config. Edit freely without touching code.
    ├── taxonomy/          # One YAML per observation type
    ├── examples/          # Curated SigmaHQ rules (v1.5 load modal)
    ├── pipelines.yml      # Backend/pipeline selection matrix
    ├── mitre_attack.json  # ATT&CK tree (built by scripts/build_mitre_tree.py)
    └── heuristics.yml     # Per-heuristic severity + enablement (v1.0 MVP)

tests/
docs/
scripts/                   # One-shot tools (not shipped in the wheel)
Dockerfile                 # Multi-stage build; ACA-ready
.dockerignore
```

`data/` lives **inside** the package (`intel2sigma/data/`) so it ships
with the wheel automatically — no special hatch config needed. Anything
that needs to read a data file calls ``intel2sigma._data.data_path("…")``,
not its own ``Path(__file__).parents[N]`` math.

### Testing

- **Every validator, heuristic, and pipeline mapping has tests.** No exceptions.
- **Every heuristic requires two test cases**: one proving it fires on a triggering rule, one proving it does not false-fire on a benign rule.
- **Fixtures** live in `tests/fixtures/` as YAML rule files and JSON event files. Reuse fixtures aggressively; do not inline rules in test code.
- **Integration test** against the SigmaHQ rule corpus: fetch via a script (do not vendor the corpus), every rule must parse and tier-1+2 validate.
- **Golden tests** for the pipeline matrix: known input rule → expected query output per (logsource, backend) pair. Golden files live in `tests/golden/`.
- **`pytest` + `pytest-asyncio`.** Prefer real pySigma calls over mocks. Mock only external I/O (HTTP, filesystem writes).
- **Coverage floor: 80%** on `core/`. CI enforces.

### Git and PRs

- **Conventional Commits**: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `perf:`, `build:`, `ci:`.
- **One concern per commit.** Split unrelated changes.
- **PR descriptions explain *why*, not *what*.** The diff shows what; the description explains motivation.
- **Link to the relevant SPEC.md or docs/ section** when a PR implements a specified behavior.
- **If your PR changes behavior documented in SPEC.md or docs/, update those docs in the same PR.**

## Things you must not do

This list is not exhaustive, but these are the most common and most harmful violations. If in doubt, ask.

- **Do not** introduce an ORM, database, or any form of persistent server-side storage.
- **Do not** add npm, node, yarn, package.json, or any JavaScript build toolchain.
- **Do not** add authentication, accounts, or user sessions.
- **Do not** add LLM API calls to the composer logic path. Auxiliary features only, explicitly labeled, never influencing detection contents.
- **Do not** expose a YAML textarea in Guided mode under any circumstances.
- **Do not** hardcode field definitions, observation types, pipeline mappings, or heuristic severities in Python. Those live in `data/`.
- **Do not** hard-pin pySigma backend versions with `==`. Use compatible ranges (`>=x.y,<x+1.0`).
- **Do not** edit files under `data/taxonomy/` without updating `docs/taxonomy.md` in the same commit.
- **Do not** add a heuristic without the required two test cases and the entry in `docs/heuristics.md`.
- **Do not** import from `web/` or `cli/` inside `core/`.
- **Do not** use `# type: ignore` or `# noqa` without an inline reason comment.
- **Do not** bump vendored frontend assets (htmx etc.) without updating `HASHES.md` and documenting the upgrade in the PR.
- **Do not** add new third-party dependencies without stating why in the PR and checking that the package is maintained (last release within 12 months, not deprecated, reasonable maintainer reputation).
- **Do not** add Tailwind, Bootstrap, or any CSS framework. CSS is hand-written in `web/static/intel2sigma.css` using CSS custom properties for theming.
- **Do not** use icon libraries. Inline SVG in templates only.
- **Do not** introduce global mutable state in `core/`.
- **Do not** commit secrets, API keys, or credentials. There shouldn't be any in this project — it calls no external APIs.

## Frontend asset policy (detailed)

Because supply-chain risk is a recurring concern for this project's audience:

- **CSS**: hand-written, single file at `web/static/intel2sigma.css`. CSS custom properties for all colors, spacings, and radii so themes can swap in a single file edit.
- **JavaScript**: vendored at `web/static/vendor/`. Each file has a corresponding entry in `web/static/vendor/HASHES.md` with SHA-256 and upstream source URL.
- **htmx**: the only JS dependency for v1. Pinned version, vendored, hashed.
- **Syntax highlighting**: server-side via Pygments (Python dep, not JS). Pygments emits classed `<span>` tags; colors come from `intel2sigma.css`.
- **Icons**: inline SVG, stored in templates or in a small `web/static/icons/` directory. No icon fonts, no `@iconify`, no lucide, no feather.
- **Fonts**: system font stack for UI. `JetBrains Mono` as a progressive enhancement from a pinned SRI-hashed Google Fonts (or self-hosted if avoiding third-party fonts becomes a requirement). `ui-monospace, monospace` fallback guarantees functionality without the webfont.

When adding a new JS dependency (which should be rare):
1. Download the exact single-file distribution.
2. Compute SHA-256. Record in `HASHES.md` with the upstream source URL and version.
3. Commit the vendored file.
4. Reference it in templates with a relative path (no CDN URLs in production).
5. Open a PR explaining why the dependency is needed and what was evaluated as an alternative.

## Local development

Use `uv` for everything. Do not create venvs manually, do not use `pip` directly, do not use `python -m venv`. `uv` manages the Python interpreter itself — no system install of Python 3.14 is required.

### Standard commands

```bash
uv sync                                           # install all deps including dev group
uv run pytest                                     # run tests
uv run pytest -m "not slow"                       # skip slow integration tests
uv run mypy intel2sigma --strict
uv run ruff check && uv run ruff format --check
uv run uvicorn intel2sigma.web.app:app --reload   # dev server with hot reload
```

### Project conventions

- **`uv.lock` must be committed.** It is the reproducibility guarantee.
- **`.python-version` must be committed** and pinned to `3.14`.
- **Dev deps live under `[dependency-groups]`** in `pyproject.toml` (PEP 735), not under `[project.optional-dependencies]`. `uv sync` installs them by default; `uv sync --no-dev` is used for production container builds.
- **Mark slow integration tests** (SigmaHQ corpus parse, network-dependent tests) with `@pytest.mark.slow` so the default `uv run pytest` stays fast. Register the marker in `pyproject.toml` under `[tool.pytest.ini_options]`.
- **`.gitignore` must cover**: `.venv/`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.coverage`, `htmlcov/`, `dist/`, `build/`, `*.egg-info/`.

### Running the web app locally

Three equivalent options, ordered by iteration speed:

```bash
# Fastest iteration: uvicorn directly with --reload
uv run uvicorn intel2sigma.web.app:app --reload --port 8000

# Via the CLI: matches production invocation
uv run intel2sigma serve

# Via Docker: tests the actual production container
docker build -t intel2sigma:dev .
docker run -p 8000:8000 intel2sigma:dev
```

## When uncertain

If a design decision isn't specified in SPEC.md and isn't obvious from context: stop and ask. Record the answer in SPEC.md's decision log (or propose an addition to SPEC in the PR) so the next session doesn't re-ask.

If you find an existing pattern in the codebase that contradicts these rules, it's a bug. Flag it and either fix it in the current PR or file an issue.

## Verification before declaring done

Every PR must pass, locally and in CI:

- `uv run pytest` — all green
- `uv run mypy intel2sigma --strict` — clean
- `uv run ruff check` — clean
- `uv run ruff format --check` — clean
- Coverage ≥80% on `core/`
- If the PR touches `web/`: a manual smoke test of the changed flow
- If the PR touches `data/`: the data loader and relevant consumers were re-run
- SPEC.md and relevant docs updated if behavior changed

A PR that passes CI but leaves docs out of sync with behavior is not done.
