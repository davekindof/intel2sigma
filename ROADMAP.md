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

## v1.5 — Rule loading

**Goal**: an analyst can start from someone else's rule, not just from scratch.

**Scope**:
- `web/load.py` — pySigma → `RuleDraft` translator. Reuses pySigma's permissive parser; we translate its model into ours.
- Header `Load rule` button + modal with two tabs: **paste YAML** and **examples**.
- ~12–15 curated SigmaHQ rules under `data/examples/` (vendored with attribution and SHA pin to the SigmaHQ commit they came from). Categorized by observation type so a user looking for "what does a polished file_event rule look like" finds three.
- `POST /composer/load` accepts pasted YAML, parses, populates a draft, jumps the composer to Stage 1 (or Stage 3 if the loaded rule is fully valid).
- Tests + browser smoke.

**Exit gate**: Paste any rule from `rules-emerging-threats/` and edit it through the Guided flow.

## v1.6 — Multi-observation composer + MITRE ATT&CK picker

**Goal**: handle real IOC sets that span observation types, with first-class ATT&CK navigation.

**Motivating scenario** (real-world example from a CTI hand-off):

> Friend extracts IOCs from a malware sample they were emailed. The set contains five SHA256 hashes (initial zip, first-stage exe, encoded DLL, two dropped DLLs, two `.dat` payloads), one C2 domain, one IP+port, four System32 filenames (legitimate-DLL hijacks like `TimeBrokerClient.dll`), a Windows registry persistence key (`HKCU\SOFTWARE\HHClient`), an email sender, an Authenticode certificate serial, and a PDB-path string baked into the loader (`D:\CFILES\Projects\WinSSL`).
>
> Today: the user has to manually figure out which observation type each IOC belongs to, then build a separate rule for each, repeating shared metadata (title prefix, description, ATT&CK tags, references) every time.
>
> v1.6 should let them paste the IOC list, see the composer route each IOC to the right observation type, and produce a *rule pack* — multiple Sigma rules with shared metadata, exported as one zip or one multi-document YAML.

**Scope**:

- **Multi-observation composer**. The current `RuleDraft` carries one observation. v1.6 introduces `RuleSetDraft` carrying a list of `RuleDraft`s plus shared metadata (title prefix, description, references, ATT&CK tags, author, date). Stage 0 lets the user pick *one or more* observations; Stage 1+ shows a tabbed editor — one tab per observation. Stage 4 outputs a zip or a multi-document YAML.
- **IOC paste-and-route helper.** A textarea/CSV/free-text input on Stage 0 (or via the load modal). Heuristic routing of each IOC to the right observation:
    - `[a-f0-9]{32|40|64}` → Hashes on file_event/image_load (and process_creation if no separate file event)
    - IPv4/IPv6 (with optional port) → DestinationIp on network_connection
    - DNS-shaped → QueryName on dns_query
    - `\\Device\\HarddiskVolume…` or `[A-Z]:\\…` paths → TargetFilename on file_event (or Image on process_creation, depending on extension)
    - `HK[CL][UM]\\…` → TargetObject on registry_set
    - `\\AppData\\…\\foo.exe` → Image on process_creation
    - PDB-path strings (`X:\\…\\Projects\\…`) → CommandLine pattern on process_creation
    - Email addresses, Authenticode cert serials → carry through as metadata fields when no Sigma observation maps cleanly
- **Hierarchical MITRE ATT&CK tag picker.** Stage 2's tags input today is free-text + a ~24-entry datalist. v1.6 replaces it with a collapsible tactics → techniques → sub-techniques tree. Click adds the corresponding `attack.tNNNN` / `attack.tNNNN.NNN` tag. Data source: ATT&CK STIX 2.1 export, derived into a small JSON tree at build time and shipped under `data/mitre_attack.json`. Free-text input stays as the escape hatch for tags outside ATT&CK.
- Tests + dogfooding round with the IOC scenario above.

**Exit gate**: an analyst pastes the motivating-scenario IOC set, the composer produces 4–6 well-formed Sigma rules across the right observation types, the user reviews + tweaks them in tabbed Stage 1 panels, and downloads them as a rule pack.

## v1.x — Smaller post-v1.0 polish

Doesn't fit a milestone:

- **Rule upload (`.yml` file picker).** v1.5 ships paste + curated examples; the file picker is a small follow-up using the browser File API (read client-side, POST text body to the existing load endpoint).
- **Rule download UX**: progress indicator + last-N rules list (client-side localStorage, *not* server persistence).
- **Keyboard shortcuts** (deferred from v1 per docs/ui.md).

## v2 — Aspirational

Not committed. Prioritize based on v1 usage and IFIN feedback. Candidates:

- SigmaHQ PR integration (produce and push a properly formatted PR for rules the user wants to contribute upstream).
- Rule-corpus similarity search (dedup/learn-from-existing before submitting).
- **Multi-observation-type rules.** A single Sigma rule has exactly one logsource; expressing "this Python script is malicious whether seen in process_creation or file_event" requires either Sigma correlation rules or a rule pack. Worth designing once correlation lands.
- Correlation rule support (when pySigma's correlation spec stabilizes in backend plugins).
- Additional backends: QRadar AQL, Chronicle/SecOps, Panther, Sentinel ASim explicitly.
- MISP object wrapping, STIX 2.1 SDO output.
- Additional telemetry schemas: OCSF, ECS-specific composer modes.
- Observation catalog for macOS unified log (currently coarse in the Sigma ecosystem).
