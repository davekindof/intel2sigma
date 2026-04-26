# SPEC.md — intel2sigma architectural specification

Source of truth for what intel2sigma is and how it's put together. If it's not documented here and not reflected in code, it's not part of the project.

## Purpose

Convert observed malware behaviors into canonical, shareable Sigma rules and target SIEM queries, without requiring knowledge of Sigma syntax, YAML, or SIEM query languages.

**Primary user**: a malware analyst or CTI producer who has observations (from a sandbox report, memory forensics, DFIR notes, or direct observation) and wants to produce a detection that other organizations can consume.

**Success criterion**: a user who has never written Sigma can, within a single session, produce a canonical Sigma rule that converts cleanly to their target SIEM's query language and represents the behavior they observed.

## Non-goals

- In-SIEM rule deployment, management, or lifecycle
- Rule testing at scale against historical event corpora
- Multi-user or multi-tenant workflows
- Correlation rules (Sigma correlation spec deferred to v2)
- Persistent server-side state
- Organization-specific pipeline authoring
- Mobile or tablet form factors

## High-level architecture

Three-layer design with strict dependency direction:

```
┌──────────────────────────────────────────────┐
│  web/ (FastAPI + htmx + Jinja2)              │
│  cli/ (Typer)                                │
└──────────────────┬───────────────────────────┘
                   │ imports only
                   ↓
┌──────────────────────────────────────────────┐
│  core/                                       │
│  model · serialize · validate · convert      │
│  heuristics · taxonomy · parsers             │
└──────────────────┬───────────────────────────┘
                   │ imports only
                   ↓
┌──────────────────────────────────────────────┐
│  pySigma + backends + pipelines              │
│  ruamel.yaml · pydantic · pygments           │
└──────────────────────────────────────────────┘
```

`core/` has no dependency on web frameworks. It must be usable from a notebook or a CLI.

See `docs/architecture.md` for the runtime view and request flow.

## The rule model

Pydantic v2 models representing a Sigma rule in memory.

```python
class SigmaRule:
    # Metadata
    title: str
    id: UUID
    status: Literal["stable", "test", "experimental", "deprecated", "unsupported"]
    description: str
    references: list[str]
    author: str
    date: date
    modified: date | None
    tags: list[str]
    level: Literal["informational", "low", "medium", "high", "critical"]
    falsepositives: list[str]

    # Logsource
    logsource: LogSource

    # Detection
    detections: list[DetectionBlock]
    condition: ConditionExpression
```

`DetectionBlock`: a named selection containing `DetectionItem` entries (field + modifiers + value(s)) or nested subgroups. Each block is marked as either a *match* block or a *filter* block. The composer uses this marking to auto-assemble the condition.

`ConditionExpression`: built *from* the detection blocks by the composer, not parsed from a user-entered string. The composer assembles expressions based on block types and user-chosen combinators (all-of-match / one-of-match, all-except-filter / any-except-filter).

The model is extensible for correlation rules (v2) without breaking v1 consumers.

## Serialization

`ruamel.yaml` with explicit top-level key order: `title, id, status, description, references, author, date, modified, tags, logsource, detection, falsepositives, level`.

The Sigma condition is emitted as a string *inside* the `detection` block (the shape pySigma expects), not as a top-level key. The in-memory model carries a `ConditionExpression` that the serializer renders to that nested string.

**Round-trip guarantee**: parsing a canonical rule and re-serializing produces byte-identical output (modulo normalization of user-provided whitespace).

The `from_yaml` loader is intentionally narrow: it parses only the condition-string shapes the composer itself emits (leaf, `not`, flat `and`/`or`, `all of <glob>`, `1 of <glob>`, one-level parenthesized groupings). Hand-written Sigma rules with arbitrary condition grammar should enter through pySigma's own loader, not this round-trip path.

## Validation tiers

Three tiers, run in order. Each higher tier presupposes the lower passed.

### Tier 1 — Model validation (Pydantic)

Types, enums, required fields, UUID format, date format, tag structure. Synchronous, runs on every model change. Errors are blocking.

### Tier 2 — Sigma schema (pySigma)

Serialize to YAML, call `SigmaRule.from_yaml()`, catch and translate exceptions to user-facing messages. Catches malformed conditions, references to undefined selections, invalid modifier chains, value type mismatches. Synchronous, sub-second. Errors are blocking.

### Tier 3 — SigmaHQ conventions (advisory)

Filename pattern, title length, description prose quality minimums, required ATT&CK tags per category, author/date formatting, UUID uniqueness against a local corpus. Ported from SigmaHQ CI test scripts. Produces warnings, never blocks.

## Quality heuristics

Separate from validation. Runs after Tier 2 passes. Advisory-only.

Each heuristic is a **pure function** `(SigmaRule) -> HeuristicResult | None`. No I/O, no network, no time-dependent behavior. Heuristics are registered via a decorator and loaded dynamically.

Severity and enablement state live in `data/heuristics.yml` — not in code. The function itself is code; its configuration is data.

Full catalog: see `docs/heuristics.md`.

Categories:
- IOC vs. behavior balance
- Overbroad selection detection
- Lab-artifact detection
- Path specificity
- Known FP-prone patterns
- Condition integrity
- Metadata completeness
- Value quality

## Composer state machine

Five logical stages, each owning a partial template rendered by htmx:

1. **Observation selection** — user picks an observation type from the taxonomy catalog. Sets `logsource`.
2. **Detection block composition** — user adds match and filter blocks, each with field/modifier/value triples drawn from the taxonomy for the chosen observation type.
3. **Metadata** — title, description, tags, level, falsepositives. Auto-populated where possible.
4. **Review** — rendered rule + heuristic warnings + plain-English summary.
5. **Output** — canonical YAML + target-format conversions.

State lives in the client (hidden form fields, htmx `hx-vals`). Server is pure compute.

## Presentation modes

See `docs/ui.md` for the full presentation specification. Two modes share the same state and partials:

- **Guided mode** (default): linear, one stage at a time, Next/Back navigation. Target: first-time and non-native users.
- **Expert mode**: single-page layout with all stages visible in a left panel, live preview always visible on the right. Target: returning users who know what they want.

Mode switch is prominent in the header. User's preference persists in localStorage.

## Pipeline matrix

Mapping `(logsource.product, logsource.category, logsource.service, target_backend)` → `list[pipeline_name]`. Lives in `data/pipelines.yml`.

Example entry:

```yaml
- match: {product: windows, category: process_creation, service: "*"}
  backends:
    kusto_sentinel: [microsoft_xdr]
    kusto_mde: [microsoft_xdr]
    splunk: [splunk_windows, sysmon]
    elasticsearch: [ecs_windows]
    crowdstrike: [crowdstrike_falcon]
```

Changes to the matrix require updates to the golden tests in `tests/golden/pipelines/`.

## Output formats

**Primary**: canonical Sigma YAML (download as `.yml`, copy to clipboard).

**Conversion targets (v1)**:
- KQL for Microsoft Sentinel
- KQL for Microsoft Defender for Endpoint (advanced hunting)
- SPL for Splunk (with Sysmon pipeline)
- ES|QL for Elastic (with ECS pipeline)
- FQL for CrowdStrike Falcon

Conversions use pySigma in-process. Results cached by `sha256(canonical_yaml) + backend + pipeline_set`. `functools.lru_cache` size 256.

Output UI: primary YAML pane always visible; conversion targets presented as tabs below. See `docs/ui.md`.

## Sandbox report ingestion (v1.1+)

Parses vendor sandbox JSON into a canonical `ObservationGraph`:

```python
class ObservationGraph:
    processes: list[ProcessObservation]
    file_events: list[FileEventObservation]
    registry_events: list[RegistryEventObservation]
    network: list[NetworkObservation]
    image_loads: list[ImageLoadObservation]
```

Each observation maps to candidate `DetectionItem` entries the user can select and tune.

- v1.1 supports CAPE
- v1.2 adds Triage, Joe Sandbox, ANY.RUN

## Deployment

Single Docker image, multi-stage build: Python 3.14-slim base, deps installed via `uv`, uvicorn serving FastAPI on port 8000. Image is stateless; same image serves hosted and local.

**Targets**:
- Hosted: **Azure Container Apps**, fronted by **Cloudflare** for TLS termination, WAF, rate limiting, and DDoS protection. Container Apps' built-in scale-to-zero + per-request scaling matches the bursty, request-driven workload — there is no background work to keep a warm replica alive for.
- Local: `docker run` / `docker compose up`
- Native: `pip install intel2sigma && intel2sigma serve`

No persistent volumes. No database. No Redis. No external services. Cloudflare in front means the application code does not implement TLS, WAF rules, or rate limiting — those are edge concerns.

## Out of scope (reminder)

- User accounts, auth, sessions
- Rule persistence server-side
- LLMs in the composer logic path
- Correlation rules (v1 and v1.x)
- Direct SIEM API integration
- Organization-specific pipelines
- Multi-tenant concerns
- Mobile form factors

## Decision log

Append-only log of significant decisions not otherwise captured in this spec. Format: `YYYY-MM-DD: decision and rationale`.

- 2026-04-23: Project initialized with scope and architecture as documented above. No code yet.
- 2026-04-23: Selected Python 3.14 as base; verified ecosystem compatibility via sigconverter.io's own 3.14 adoption.
- 2026-04-23: Selected FastAPI + htmx + Jinja2 over Streamlit or SPA frameworks. Rationale: stateless server model, no JS build toolchain, matches target audience's supply-chain concerns.
- 2026-04-23: No npm, no node, no JS build step. Vendored htmx with SHA-256 hashes. Hand-written CSS with custom properties. Pygments for server-side syntax highlighting.
- 2026-04-23: Dual-mode presentation (Guided / Expert), Guided as default.
- 2026-04-23: Green-forward color palette (GitHub-dark-inspired) as placeholder; replaceable via CSS custom properties when davidsharp.io palette is finalized.
- 2026-04-23: v0 foundations scaffolded. Python 3.14 via `uv`; pinned `pysigma>=0.11,<1.0`, `pysigma-backend-{kusto,splunk,elasticsearch,crowdstrike}`, `pysigma-pipeline-{sysmon,windows,crowdstrike}`. Microsoft XDR / Sentinel / MDE pipelines ship bundled inside `pysigma-backend-kusto`, not as standalone dists.
- 2026-04-23: Sigma `condition` is serialized *inside* the `detection` block, not as a top-level key. Prior SPEC wording listed `condition` in top-level key order; corrected to match canonical Sigma and pySigma expectations. The in-memory model still carries `SigmaRule.condition: ConditionExpression`.
- 2026-04-23: `core/serialize.from_yaml` parses only the condition-string shapes `to_yaml` emits. Hand-written rules with arbitrary condition grammar are a pySigma-loader concern, not an intel2sigma round-trip concern. Recorded as an explicit non-goal.
- 2026-04-23: Modifier set is dual-sourced. The in-memory `ValueModifier` Literal in `core/model.py` enumerates the Sigma modifier grammar primitives the system can represent (closed set, ~20 names). The per-field subset offered to users lives in `data/taxonomy/*.yml` as each field's `allowed_modifiers`. Rationale: the modifier alphabet is language grammar (code); the per-field policy is catalog (data).
- 2026-04-23: Cross-platform detections are modeled as **rule pairs**, one per platform, not as polymorphic single rules. Sigma's `logsource` block supports only one `(product, category)` tuple, and field names diverge enough across platforms (Windows Sysmon `Image` vs Linux auditd `comm`/`a0`) that a single selection block cannot match events from both. The v1.x composer will offer a "create counterpart for another platform" convenience flow that clones metadata and prompts the user to translate fields; each rule is still authored and shipped independently.
- 2026-04-23: v1 composer UX gap logged: the Stage 1 flow currently models flat "match" + "filter" blocks joined by `match and not filter`. Real Sigma rules routinely mix quantifier clauses with direct selections in a single condition (e.g. `1 of selection_parent_* and selection_child`, from the CVE-2025-59287 detection). The composer needs a way to **subgroup match blocks** so a user can express "one of these parent-process selections AND this child-process selection". Until that lands, v0 `from_yaml` supports parsing such conditions (see the serializer parser ordering fix) even though the composer itself cannot emit them.
- 2026-04-24: Observation catalog ships `registry_set.yml` instead of `registry_event.yml`. Frequency analysis against SigmaHQ at commit 03412947 shows `windows/registry_set` at 204 vetted rules vs `windows/registry_event` at 32 — the Sysmon `registry_set` (EventID 13) category is the dominant shape in real detection engineering. `docs/taxonomy.md` updated to match. Adding `registry_event.yml` (and the sibling `registry_add`/`registry_delete` categories) later is a one-file addition; we ship what users will actually write.
- 2026-04-24: Sigma has no `|exact` modifier — exact match is the default no-modifier form. The in-memory `ValueModifier` Literal still lists `exact` so the composer UI can surface "exactly matches" as a dropdown choice without schema gymnastics, and taxonomy files reference it naturally in `default_modifier` / `allowed_modifiers`. The composer (v1) will translate an "exact" selection to `DetectionItem.modifiers=[]` when constructing rules, and the serializer will collapse `modifiers=["exact"]` to the no-modifier emission form if it ever sees one. Not a blocking v0 concern since the composer doesn't exist yet.
- 2026-04-24: Dropped the `core` / `advanced` field-tier classification in favor of **declaration-order-is-the-signal**. Taxonomy YAML files list fields in real-world frequency order (primary: vetted `rules/` stratum). The composer decides presentation — Guided mode surfaces the top few above an expander; Expert mode renders an IDE-style searchable picker where all fields are equal citizens. Removing the binary classification eliminates noise-driven judgment calls at the 5% threshold boundary and keeps the calibration signal expressive without forcing a UX primitive. Schema, tests, catalog file, and `docs/taxonomy.md` updated in one commit. The IDE-style picker for Expert mode is a future-state implementation detail, not a v0 deliverable.
- 2026-04-26: **Version bump 0.0.1 → 0.1.0.** v0.0.1 was the pre-deploy placeholder. v0.1.0 marks the first version testers are actually using: hosted on Azure Container Apps behind Cloudflare at `intel2sigma.davidsharp.io`, with the full Phase 0–5 surface live (heuristics MVP, IOC paste/classify, MITRE picker, "Build similar", "New rule", live YAML preview, Stage 1 prose summary, breadcrumb navigation, Stage 0 usability pass). Still pre-1.0 — the v1.0 exit gate (≥2 testers building rules end-to-end + the full observable catalog + heuristics catalog completion + corpus search) is the next milestone. Bumping minor signals "real progress, real tester feedback loop" without overpromising stability. Bumped in both `intel2sigma/__init__.py` and `pyproject.toml`; `/version` endpoint will surface the new value on next deploy.
- 2026-04-25: **Heuristics MVP shipped.** v1.0 ships 8 heuristics: ``h-001`` (IOC-only rule), ``h-021`` (RFC1918 in match block), ``h-030`` (hardcoded user-profile path), ``h-050`` (undefined selection in condition — ``critical``), ``h-051`` (orphaned selection block), ``h-060`` (title length out of range), ``h-061`` (description too short), ``h-062`` (no ATT&CK tags). Spans 5 of 8 catalog categories. Engine in ``core/heuristics/``: registry + decorator + ``run_all`` in ``base.py``; per-heuristic config (severity + enablement) loaded from ``intel2sigma/data/heuristics.yml`` per CLAUDE.md I-5. ``core/validate/tier3.py`` adapts ``HeuristicResult`` to ``ValidationIssue`` with ``H_<SEVERITY>_<id>`` codes so the composer's existing issue-rendering template handles advisories without changes. Composer Stage 3 renders advisories below the tier-1/2 issues with severity-coloured left borders. 27 tests (two per heuristic + engine + composer integration), coverage on ``core/`` rises to 92%.
- 2026-04-25: **Heuristics catalog split for v1.0.** v1.0 ships an MVP set of 5–8 highest-leverage heuristics picked by frequency analysis against the SigmaHQ corpus, not the full ~22-check catalog originally listed in `docs/heuristics.md`. Rationale: the full catalog is several weeks of careful work (each heuristic needs two test cases, severity calibration, "show where" wiring, suggestion text); the MVP set captures the patterns that actually fire on real rules, lets testers see the "expert review" experience without waiting on the long tail, and gives us calibration data to prioritise the v1.7 backlog. Schema and decorator are stable from v1.0 — adding the deferred entries is purely additive. Specific MVP picks recorded against ROADMAP §v1.7 once the frequency analysis runs.
- 2026-04-25: **`/version` endpoint and structured JSON access logs implemented.** SPEC.md §Observability previously described both as aspirational. They now exist: `/version` returns ``{package, build_sha, mitre_attack, mitre_generated_at, sigmahq_corpus_commit}`` (computed at import time, constant-time response). JSON logging via stdlib only (`intel2sigma/web/logging.py`, ~150 lines, no third-party dep). Rule contents are explicitly dropped from log records via a denylist. Per-request `X-Request-Id` header echoed back to the client for bug-report correlation. Verified live in the local Docker build at commit `8403eae`.
- 2026-04-25: **`data/` lives inside the package** at `intel2sigma/data/` (not at repo root). Reasoning: hatch's default VCS-based file selection silently produces an empty wheel inside a Docker build context (`.git` excluded by `.dockerignore`). The original `[tool.hatch.build.targets.wheel.force-include]` workaround failed because force-include and the package detection collided. Moving `data/` into the package eliminates the failure mode entirely — hatch's `include` patterns ship the bundled YAML/JSON files automatically, no special config needed. ``intel2sigma._data.data_path()`` is the single helper for resolving bundled files; the four runtime sites (`web/load.py`, `web/mitre.py`, `core/convert/pipelines.py`, `core/taxonomy/loader.py`) use it instead of doing `parents[N]/"data"` math. Verified: built wheel and Docker image both contain a fully-populated `intel2sigma/data/` tree.
- 2026-04-25: **Container build + run verified locally.** Multi-stage Dockerfile (`ghcr.io/astral-sh/uv:python3.14-bookworm-slim` builder → `python:3.14-slim-bookworm` runtime) builds in ~30s clean / ~5s cached, image size 278MB, cold-starts to `/healthz 200` in **0.84s** (budget: <5s). Critical `uv sync` flag: `--no-editable`. Without it, uv installs an editable `.pth` pointing at `/build/`, which dangles in the runtime stage that only copies `/opt/venv` across — the pattern that ships across multi-stage uv builds. Container runs as non-root uid 10001. Build SHA propagates from `--build-arg BUILD_SHA=…` through `INTEL2SIGMA_BUILD_SHA` to `/version`. Recorded as commit `f1c98c9`.
- 2026-04-25: Project identity locked. Source repo: **`github.com/davekindof/intel2sigma`**. Container registry: **`intel2sigma.azurecr.io/intel2sigma`** (Azure Container Registry, Basic tier; chosen over GHCR so Azure Container Apps pulls via managed identity rather than a long-lived service-principal credential). Hosted instance: **`intel2sigma.davidsharp.io`** (Cloudflare-fronted CNAME to the ACA ingress FQDN). README, in-app Help link, and architecture docs updated to match. Migration cost is low if any of these change later — GitHub redirects, registry retags, and DNS swaps are cheap.
- 2026-04-24: Hosted deployment target is **Azure Container Apps behind Cloudflare**. Container Apps gives stateless container hosting with native scale-to-zero, per-revision rollouts, and managed mTLS for ingress; Cloudflare in front handles TLS, DDoS protection, WAF rules, and rate limiting (a recurring concern for any tool that produces detection content other organisations will trust). The application code retains its rate-limit-naive posture per architecture invariant — those policies live at the Cloudflare edge, not in FastAPI middleware. Earlier candidates Fly.io and Cloud Run remain technically viable; chosen Azure Container Apps for its alignment with the davidsharp.io infrastructure footprint and Cloudflare's better-developed Azure-origin tooling.
