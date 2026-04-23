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

`ruamel.yaml` with explicit key order: `title, id, status, description, references, author, date, modified, tags, logsource, detection, condition, falsepositives, level`.

**Round-trip guarantee**: parsing a canonical rule and re-serializing produces byte-identical output (modulo normalization of user-provided whitespace).

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
- Hosted: Fly.io (primary) or Google Cloud Run (alternative; matches sigconverter.io's stack)
- Local: `docker run` / `docker compose up`
- Native: `pip install intel2sigma && intel2sigma serve`

No persistent volumes. No database. No Redis. No external services.

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
