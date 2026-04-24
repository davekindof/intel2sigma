# Pipeline matrix

Design doc for `data/pipelines.yml` and `core/convert/pipelines.py`. Defines how the conversion layer picks a pySigma backend and pipeline set given a rule's logsource.

## The decision this doc freezes

Every conversion request resolves `(rule.logsource, target_backend) → (pysigma backend class, ordered list of pipeline instances)`. Where does that resolution live?

**Decision**: a two-level data-driven resolver. The backend identifier selects a pySigma backend class and its baseline pipelines; the logsource matrix adds per-logsource pipelines on top. Both layers live in `data/pipelines.yml`; code just reads and composes.

Rationale: pySigma backends each ship their own pipeline plugins. `pysigma-backend-kusto` alone exposes `microsoft_xdr`, `microsoft_defender_for_endpoint`, and a few vendor-specific ones — all inside one Python package. Coupling "which SIEM is the target" to "which Python class loads" in code makes adding backends a code change; keeping it in data makes it a PR to a single YAML file.

## Backend identifiers

Backend ids are intel2sigma-internal slugs, not pySigma class names. One id per distinct target SIEM/EDR:

| id | pySigma backend | Baseline pipelines | Target |
|---|---|---|---|
| `kusto_sentinel` | `sigma.backends.kusto.KustoBackend` | `microsoft_xdr` | Microsoft Sentinel Advanced Hunting |
| `kusto_mde` | `sigma.backends.kusto.KustoBackend` | `microsoft_defender_for_endpoint` | Microsoft Defender for Endpoint |
| `splunk` | `sigma.backends.splunk.SplunkBackend` | (none baseline) | Splunk SPL |
| `elasticsearch` | `sigma.backends.elasticsearch.LuceneBackend` | `ecs_windows` | Elastic Common Schema / ES\|QL |
| `crowdstrike` | `sigma.backends.crowdstrike.CrowdStrikeBackend` | `crowdstrike_falcon` | CrowdStrike Falcon FQL |

Backends mapping to the same pySigma class (Sentinel and MDE both on Kusto) are distinct ids because their pipelines and output flavors differ. This resolves the Sentinel-vs-MDE disambiguation from the v1 plan.

Backend identifier → class resolution lives in `data/pipelines.yml` under a `backends:` block. Adding a new backend to the project is a data-only change if the pySigma package is already pinned as a dep.

## Logsource-to-pipeline matrix

The second layer: given the rule's logsource, which additional pipelines does the backend need?

```yaml
# data/pipelines.yml (proposed)

backends:
  kusto_sentinel:
    sigma_class: sigma.backends.kusto.KustoBackend
    format: default
    baseline_pipelines: [microsoft_xdr]
  kusto_mde:
    sigma_class: sigma.backends.kusto.KustoBackend
    format: default
    baseline_pipelines: [microsoft_defender_for_endpoint]
  splunk:
    sigma_class: sigma.backends.splunk.SplunkBackend
    format: default
    baseline_pipelines: []
  elasticsearch:
    sigma_class: sigma.backends.elasticsearch.LuceneBackend
    format: default
    baseline_pipelines: [ecs_windows]
  crowdstrike:
    sigma_class: sigma.backends.crowdstrike.CrowdStrikeBackend
    format: default
    baseline_pipelines: [crowdstrike_falcon]

logsource_matrix:
  - match: { product: windows, category: process_creation }
    backends:
      splunk: [splunk_windows, sysmon]
  - match: { product: windows, category: file_event }
    backends:
      splunk: [splunk_windows, sysmon]
  - match: { product: windows, category: image_load }
    backends:
      splunk: [splunk_windows, sysmon]
  # ... etc
```

Each `logsource_matrix` entry adds pipelines on top of the backend's baseline. Final pipeline list for a conversion: `baseline_pipelines + matrix_pipelines` (baseline first so logsource-specific transforms override baseline defaults).

## Resolution algorithm

```
def resolve(rule, backend_id) -> (backend_class, pipelines):
    backend_cfg = pipelines_data.backends[backend_id]  # raises if unknown
    pipelines = list(backend_cfg.baseline_pipelines)

    for entry in pipelines_data.logsource_matrix:
        if _matches(rule.logsource, entry.match):
            pipelines.extend(entry.backends.get(backend_id, []))
            break  # first-match wins; order matters in the YAML

    backend_class = _import(backend_cfg.sigma_class)
    return backend_class, pipelines
```

**Matching rules**:
- All keys in `match:` must equal (or match `"*"`) the rule's corresponding logsource field.
- Missing keys on the rule side are treated as `""`; a `match:` without that key doesn't require it.
- First matching entry wins. Entries are ordered most-specific-to-least-specific in the YAML; author discipline. If that becomes error-prone we add a specificity score, but not in v1.

**Cache key** (per SPEC): `sha256(canonical_yaml) + backend_id + sorted(pipeline_names)`. Cache size 256 per `@functools.lru_cache`.

**Unknown logsource**: no matrix entry matches → only baseline pipelines apply. That produces a conversion anyway (often less optimal, but honest). If the baseline-only conversion raises a `SigmaConversionError`, the error is surfaced to the UI with the pipeline set tried. Not every rule for every backend must succeed.

## Golden tests

One fixture per matrix entry per backend: `tests/golden/pipelines/<logsource>_<backend>.yml` holds input YAML, expected output string. Regenerating goldens is a deliberate act (script writes them), not automatic on test run.

## What this doc does NOT decide

- UI presentation of conversion errors (lives in `web/` docs when we get there).
- Per-backend output-formatting options like Sentinel's `default` vs `csl` vs `kql` — v1 uses `default` everywhere; per-format selection deferred to v1.1.
- Pipeline-authoring (user-defined pipelines) — explicit non-goal in SPEC.
