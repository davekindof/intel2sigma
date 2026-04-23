# ROADMAP.md

Phased delivery plan. Each phase has an exit gate. Do not start the next phase until the current one passes its gate.

## v0 — Foundations

**Goal**: Core library exists and is tested. No UI.

**Scope**:
- `uv` project scaffold with Python 3.14
- `pyproject.toml` with pinned direct deps and dev tooling (ruff, mypy strict, pytest, pytest-asyncio, pytest-cov)
- `core/model.py` — Pydantic v2 rule model (SigmaRule, LogSource, DetectionBlock, DetectionItem, ConditionExpression)
- `core/serialize.py` — canonical YAML round-trip via ruamel.yaml
- `core/validate/tier1.py` and `tier2.py`
- `core/taxonomy/loader.py` — loads `data/taxonomy/*.yml` files
- Taxonomy catalog YAML for all 15 observation types (see `docs/taxonomy.md`)
- Test suite with ≥80% coverage on `core/`
- Script to fetch the SigmaHQ rule corpus; integration test that parses the full corpus through tier 1+2

**Exit gate**: A Python user can `from intel2sigma.core import SigmaRule`, construct a rule, serialize it, have pySigma parse the result without errors, and run all taxonomy-driven field validations. All tests green, mypy clean, ruff clean.

## v1 — MVP

**Goal**: Hosted web app takes an analyst from "I observed this" to "here is my Sigma rule and its KQL/SPL/ES|QL/FQL equivalents."

**Scope**:
- `core/convert/` — pySigma wrapper with `data/pipelines.yml`-driven matrix for 5 conversion targets (Sentinel KQL, MDE KQL, Splunk, Elastic, CrowdStrike)
- Golden tests for all (logsource, backend) pairs in the matrix
- `core/heuristics/` — 60–80 quality checks with severity/enablement driven from `data/heuristics.yml`
- Heuristic calibration against the SigmaHQ corpus
- `core/validate/tier3.py` — SigmaHQ conventions advisory
- `web/` — FastAPI app with htmx + Jinja2
  - Both Guided and Expert modes (see `docs/ui.md`)
  - 5-stage composer flow
  - Rule health bottom drawer
  - Primary YAML pane + tabbed conversion outputs
  - Mode toggle in header, localStorage-persisted
- Plain-English rule summary generator on the review screen
- Hand-written CSS with green-forward dark palette (CSS custom properties)
- Vendored htmx with SHA-256 hashes
- Server-side Pygments for syntax highlighting
- Dockerfile (multi-stage, slim base, no node layer)
- `cli/` — Typer wrapper exposing core + `serve` command

**Exit gate**: A non-Sigma-native user can build a process_creation rule with at least one match and one filter block, copy the KQL output, and run it in Sentinel Advanced Hunting without modification. Confirmed by dogfooding with ≥2 testers not previously familiar with Sigma. Docker image boots in <5 seconds on Fly.io or Cloud Run.

## v1.1 — Sandbox ingestion: CAPE

**Goal**: CAPE JSON import produces a draft rule.

**Scope**:
- `core/parsers/cape.py` — CAPE JSON → `ObservationGraph`
- Observation-to-DetectionItem mapping layer
- New composer entry: "upload sandbox report" produces a pre-populated draft at stage 2
- User tunes the draft, flows through the standard v1 review/output
- Keyboard shortcuts: `Ctrl+K` (observation search), `Ctrl+D` (download), `` Ctrl+` `` (toggle health drawer), `Ctrl+/` (toggle mode)

**Exit gate**: A CAPE report for a known sample produces a non-trivial draft rule that, after minimal user tuning, matches the sample's distinctive behaviors and passes tier 1+2 validation.

## v1.2 — Sandbox breadth

**Goal**: Triage, Joe Sandbox, ANY.RUN parsers.

**Scope**:
- Three additional parsers in `core/parsers/`
- Auto-detect report format where possible (fall back to explicit selection)

**Exit gate**: Each parser has a golden test with a real sandbox report for a known malware family producing the expected `ObservationGraph`.

## v1.3 — Event matcher

**Goal**: "Does my rule fire on this event?" without a SIEM.

**Scope**:
- Integrate `nsmithuk/sigma-rule-matcher` (vendor or fork if modifier coverage is incomplete)
- Event normalizers: EVTX XML, Sysmon JSON (Chainsaw schema), auditd, Zeek JSON, CEF
- New review-screen panel: paste event → match/no-match + which detection block matched
- Automatic self-test: sandbox-derived rules run against their source observations at draft time

**Exit gate**: Every normalizer has golden tests. Matcher produces identical hit/miss results to the same event run through the converted query in a real SIEM (sample-based validation against at least Sentinel and Splunk, 10+ rules each).

## v2 — Aspirational

Not committed. Prioritize based on v1 usage and IFIN feedback. Candidates:

- SigmaHQ PR integration (produce and push a properly formatted PR for rules the user wants to contribute upstream)
- Rule-corpus similarity search (dedup/learn-from-existing before submitting)
- Correlation rule support (when pySigma's correlation spec stabilizes in backend plugins)
- Additional backends: QRadar AQL, Chronicle/SecOps, Panther, Sentinel ASim explicitly
- MISP object wrapping, STIX 2.1 SDO output
- Additional telemetry schemas: OCSF, ECS-specific composer modes
- Observation catalog for macOS unified log (currently coarse in the Sigma ecosystem)
