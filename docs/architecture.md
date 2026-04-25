# Runtime architecture

How the pieces fit at runtime. SPEC.md describes the logical structure; this describes the physical flow.

## Request flow — Guided mode composer

```
1. GET /                   → renders shell + stage 0 partial (observation picker)
2. User selects observation → hx-post /composer/observation
                             → server validates, returns stage 1 partial
                               (detection block editor) + updated preview pane
3. User adds detection item → hx-post /composer/item/add
                             → tier-1 validates → re-renders block partial
4. User clicks Next         → hx-post /composer/advance
                             → server returns next stage partial
                               + updated preview + health drawer
5. At stage 4 (review)     → server runs tier 2 + heuristics + conversions
                             → renders review partial, health drawer, output panes
6. User downloads YAML     → GET /rule/download with rule state as query or POST body
                             → returns Content-Type: application/yaml
```

The full rule model travels with every request (hidden form fields, htmx `hx-vals`). Server is stateless.

## Request flow — Expert mode composer

Same state, same endpoints, different shell. Expert mode renders all stage partials in a scrollable left column and the preview panel on the right. Each field edit triggers an htmx partial update targeting the preview pane, so conversions update live as the user types.

Mode switch (`GET /mode/guided` or `GET /mode/expert`) returns a full-page re-render because the shell structure differs. The rule state travels in the query string or a POST body so no data is lost.

## Presentation regions

Three logical regions, present in both modes:

1. **Composer panel** (left): the stages. In Guided, one at a time. In Expert, all stacked.
2. **Preview panel** (right): primary YAML pane + tabbed conversion outputs + plain-English summary.
3. **Health drawer** (bottom, collapsible): heuristic warnings grouped by severity.

See `docs/ui.md` for complete region specifications and markup contracts.

## Internal flow: validate and convert

```
SigmaRule (pydantic)
    │
    ├─ tier1_validate()                 # pure pydantic
    │       (if fails: return errors, stop)
    │
    ├─ serialize_to_yaml()              # ruamel.yaml
    │       │
    │       └─ tier2_validate()         # pySigma SigmaRule.from_yaml
    │               (if fails: return errors, stop)
    │               │
    │               ├─ tier3_advisory() # SigmaHQ conventions → warnings
    │               │
    │               ├─ heuristics.run_all()  # → warnings
    │               │
    │               └─ convert(backend) # pySigma + pipeline matrix
    │                       │
    │                       └─ cached by (rule_hash, backend, pipeline_set)
```

Conversion is the expensive step. Cache key: `sha256(canonical_yaml) + backend + sorted pipeline names`. `functools.lru_cache` size 256. Cold conversion ~100ms; warm effectively free.

## Module dependency graph

```
web/routes/composer.py
    → core.model
    → core.serialize
    → core.validate.tier1, tier2, tier3
    → core.heuristics
    → core.convert
    → core.taxonomy

core.convert
    → pysigma
    → pysigma_backend_kusto          (bundles the Microsoft XDR / Sentinel / MDE
                                       pipelines internally — no separate dist)
    → pysigma_backend_splunk
    → pysigma_backend_elasticsearch
    → pysigma_backend_crowdstrike
    → pysigma_pipeline_sysmon
    → pysigma_pipeline_windows
    → pysigma_pipeline_crowdstrike
    (plus others per data/pipelines.yml; some pipelines ship inside their
     backend's package rather than as a standalone `pysigma-pipeline-*` dist)

core.heuristics
    → core.model              (no external deps)
    → data/heuristics.yml     (severity and enablement)

core.taxonomy
    → core.model
    → data/taxonomy/*.yml     (loaded at import)

core.validate
    → core.model
    → pysigma (tier 2 only)
```

Violation of this graph (e.g., `core/` importing from `web/`) is an architectural invariant violation — see CLAUDE.md I-7.

## Deployment topology

Single container, single process. Hosted runs on **Azure Container Apps fronted by Cloudflare**; local runs the same image directly.

```
                        ┌─────────────────────────┐
   user browser ──────► │ Cloudflare              │
                        │  - TLS termination      │
                        │  - WAF / rate limiting  │
                        │  - DDoS protection      │
                        └────────────┬────────────┘
                                     │ HTTPS to origin
                                     ▼
                        ┌─────────────────────────┐
                        │ Azure Container Apps    │
                        │  ┌───────────────────┐  │
                        │  │ Docker container  │  │
                        │  │  uvicorn          │  │
                        │  │   └─ FastAPI      │  │
                        │  │       └─ core     │  │
                        │  │       └─ pySigma  │  │
                        │  └───────────────────┘  │
                        │  port 8000              │
                        │  scale-to-zero          │
                        └─────────────────────────┘
```

Scale horizontally by raising the Container Apps replica ceiling. No shared state, no coordination. Scale-to-zero is supported by default because startup is fast (cold start <5s) and nothing needs to warm up. For local and CLI use the Cloudflare layer is absent and the container talks directly to the user (`docker run -p 8000:8000`); the application is identical in both topologies.

## Local and CLI modes

Same image runs via `docker run -p 8000:8000 intel2sigma:latest`. Or `pip install intel2sigma && intel2sigma serve` spawns the uvicorn+FastAPI process directly.

CLI-only usage (`intel2sigma convert rule.yml --backend kusto`) uses `core/` modules without starting a server. This is the usage pattern for library consumers and notebook users.

## Caching strategy

- **Conversion cache**: in-process `functools.lru_cache` keyed by rule content hash + backend + pipeline set. Size 256. Per-worker, not shared.
- **Taxonomy cache**: loaded once at process start, kept in memory. Data files are small (<1 MB total).
- **Pipeline matrix**: same pattern as taxonomy.
- **Heuristic configuration**: same pattern as taxonomy.

No external cache (Redis etc.). If horizontal scale produces cache-miss pressure, the right answer is a bigger `lru_cache`, not a shared cache layer.

## Error handling

- **Tier 1/2 validation failures**: returned as structured errors to the template, rendered inline next to the offending field.
- **Conversion failures** (pySigma error): surfaced in the affected conversion tab with the raw pySigma error message and a "this rule cannot currently be converted to [backend] with the detected logsource" explanation.
- **Unexpected exceptions**: logged with stack trace, user sees a generic "something went wrong" message. No stack traces exposed to users.
- **Rate limits / abuse**: handled at the Cloudflare edge (rate-limiting rules + WAF), not in application code.

## Observability

- **Structured logs** to stdout (JSON). Fields: request ID, route, duration, outcome. No rule contents logged.
- **No user tracking, no analytics beacons, no third-party telemetry.** The hosted deployment may opt into anonymous request-count metrics via the hosting platform's built-in tooling; nothing beyond that.
- **Health endpoint** at `/healthz` returning `{"status": "ok", "version": "..."}`. Used by container platforms for readiness checks.
