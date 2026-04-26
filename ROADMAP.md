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

**Scope** (✅ shipped / ⏳ in progress / ⏸️ deferred):
- ✅ `core/convert/` — pySigma wrapper with `data/pipelines.yml`-driven matrix for 5 conversion targets (Sentinel KQL, MDE KQL, Splunk, Elastic, CrowdStrike)
- ✅ Golden tests for all (logsource, backend) pairs in the matrix
- ✅ `core/heuristics/` — **MVP set of 8 checks** shipped: `h-001 h-021 h-030 h-050 h-051 h-060 h-061 h-062` (IOC-vs-behavior, lab artifacts, path specificity, condition integrity, metadata completeness). Severity/enablement driven from `intel2sigma/data/heuristics.yml`. Full catalog deferred to v1.7.
- ✅ `core/validate/tier3.py` — runs the heuristic registry over a complete rule, returns advisories as `ValidationIssue` records with `H_<SEVERITY>_<id>` codes. Composer Stage 3 renders them with severity-coloured borders.
- ✅ `web/` — FastAPI app with htmx + Jinja2
  - ✅ Guided mode (Stage 0 → 4)
  - 🪦 Expert mode — pruned (see SPEC.md decision log 2026-04-26); the breadcrumb, freeform observation entry, and SigmaHQ corpus browse cover the use cases Expert was envisioned for
  - ✅ 5-stage composer flow
  - ✅ Rule health bottom drawer
  - ✅ Primary YAML pane + tabbed conversion outputs
  - ✅ Mode toggle in header
- ⏳ Plain-English rule summary generator on the review screen (basic version exists; richer prose in v1.7)
- ✅ Hand-written CSS with green-forward dark palette (CSS custom properties)
- ✅ Vendored htmx with SHA-256 hashes (`tests/test_vendor_hashes.py` enforces)
- ✅ Server-side Pygments for syntax highlighting
- ✅ Dockerfile (multi-stage, slim base, no node layer) — **verified building + cold-starting at 0.84s**
- ✅ `cli/` — Typer wrapper exposing core + `serve` command
- ✅ `/healthz` and `/version` endpoints, structured JSON access logs with X-Request-Id correlation
- ✅ v1.5 (rule loading: paste YAML + curated examples) — shipped commit `6d1d13f`
- ✅ v1.6 (IOC paste-and-classify, Build similar, MITRE ATT&CK picker) — shipped commits `85de80d` / `7a9b17e` / `2bb652a`

**Exit gate**: A non-Sigma-native user can build a process_creation rule with at least one match and one filter block, copy the KQL output, and run it in Sentinel Advanced Hunting without modification. Confirmed by dogfooding with ≥2 testers not previously familiar with Sigma. Docker image cold-starts in <5 seconds on Azure Container Apps (locally measured at **0.84s** post-`f1c98c9`).

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

## v1.6 — IOC paste-and-classify, "Build similar rule", MITRE ATT&CK picker

**Goal**: make CTI-style IOC ingestion fast and ATT&CK tagging discoverable, without changing the one-rule-per-session architecture.

**Motivating scenario** (real-world example from a CTI hand-off):

> Friend extracts IOCs from a malware sample they were emailed. The set contains five SHA256 hashes, one C2 domain, one IP+port, four System32 filenames (legitimate-DLL hijacks), a Windows registry persistence key, an email sender, an Authenticode certificate serial, and a PDB-path string baked into the loader.
>
> Today: the user has to manually figure out which observation type each IOC belongs to, then build a separate rule for each, retyping shared metadata each time.
>
> v1.6: paste the IOC list once, the classifier groups by observation type, the user clicks one category to jump-start a rule (Stage 1 prepopulated with detection items in `any_of` form). They build → download → click "Build similar rule" — metadata carries forward; the IOC panel re-appears with already-used categories struck through. They pick the next category and repeat. Five rules in a campaign take ~30 minutes instead of a long copy-and-paste session.

**Why not multi-observation composer?** Earlier drafts of this milestone proposed a tabbed multi-observation editor producing a single rule pack. The SigmaHQ corpus shows real practice is overwhelmingly single-rule-per-logsource (the example Axios rule itself was one file_event rule using within-block `any_of`, not a multi-rule pack). Multi-observation would have been a large architectural change touching every existing flow for a use case the corpus suggests is rare. Cut in favor of the simpler IOC classifier + "Build similar" pattern, which captures most of the value at a fraction of the complexity. Revisit in v2 with tester feedback driving the design.

**Scope**:

- **IOC paste-and-classify** (Stage 0 addition). A regex-based classifier identifies SHA256/SHA1/MD5 hashes, IPv4/IPv6 (with optional port), domains, Windows paths (split by extension into process_creation / image_load / file_event candidates), registry keys, and PDB-path strings. Email addresses and Authenticode cert serials surface as metadata-only candidates. The classifier returns a per-category breakdown with one button per category that jumps the composer into Stage 1 with the relevant IOCs prepopulated as `any_of` detection items.
- **"Build similar rule" button** (Stage 4 addition). Resets the observation and detection blocks but carries metadata (title prefix, description, references, tags, author, date, level, falsepositives) and the IOC session forward, so each rule of a campaign starts halfway-completed.
- **Hierarchical MITRE ATT&CK tag picker** (Stage 2 replacement of the free-text tags input's datalist). Tactics → techniques → sub-techniques tree backed by `data/mitre_attack.json`, derived from MITRE's STIX 2.1 ATT&CK export by `scripts/build_mitre_tree.py`. Click adds the matching `attack.tNNNN` / `attack.tNNNN.NNN` tag. Free-text input retained for tags outside ATT&CK.
- The IOC `any_of` default is visually called out so users notice when an IOC-pack rule's semantics differ from a hand-authored rule's defaults: accent-green outline on the toggle, prose update ("any of these IOCs match"), and a one-time inline hint after build.
- Tests + dogfooding round with the IOC scenario above.

**Exit gate**: an analyst pastes the motivating-scenario IOC set, the classifier groups it correctly, the user builds 5 rules sequentially using "Build similar" between each, and the campaign metadata is identical across all 5 .yml files without manual copy-paste.

**Deferred to v1.7 / post-tester**:

- Auto cross-references between rules built in the same session (`references:` linking).
- Local rule-pack export — localStorage tracks the rules a user has downloaded this session, Stage 4 offers an `Export all as zip` button. Lands when testers ask for it.
- Multi-observation composer — revisit only if testers express a clear need for side-by-side editing of related rules.

## v1.7 — Heuristics catalog completion + observation catalog expansion

Two parallel maintenance tracks tracked together because they're both
quarterly-recalibration-driven and both purely additive (no schema
changes, no new dependencies).

### Heuristics catalog — fill out from MVP to full set

v1.0 ships an **MVP set of 5–8 heuristics** chosen by frequency analysis
against the SigmaHQ corpus (the patterns that actually fire on real
rule submissions, not the ones that look most thorough on paper). The
`docs/heuristics.md` catalog lists ~22 candidates total.

v1.7 expands the shipped set toward the full catalog as testers tell us
which categories matter:

- New heuristics land as one (function, two test cases, ``data/heuristics.yml`` entry, ``docs/heuristics.md`` row) per PR.
- Each addition is purely additive — no schema change, no new dependency, no breaking change to the existing rule API.
- The ``HeuristicResult`` shape and the registry decorator are stable from v1.0.

Specific MVP picks for v1.0 will be recorded here once the SigmaHQ
frequency analysis is run; the deferred remainder becomes the v1.7
backlog at that point.

### Observation catalog expansion

The v0/v1.0 catalog ships **15** observation types covering the most common Windows + Linux detection surfaces. Real Sigma rule corpora cover many more — `file_change`, `file_delete`, `file_access`, `process_access` (Sysmon EventID 10), `create_stream_hash` (EventID 15), `registry_event` / `registry_add` / `registry_delete`, Windows Security channel events (4624/4625/4672/4688/4698 etc.), Defender events, DNS-server-side logs, macOS unified-log categories, AWS / Azure / GCP cloudtrail-style sources, web-app categories (apache, nginx, kubernetes), and more.

Approach: every quarterly recalibration cycle (already scheduled for taxonomy frequency analysis + heuristic severity tuning) also reviews the corpus for high-frequency uncatalogued logsources and adds catalog files for any with ≥50 vetted rules. Each addition is a data-only change per CLAUDE.md I-5 — no Python edits.

Tracked here so the work doesn't get lost. No specific exit gate — it's recurring maintenance.

## v1.x — Smaller post-v1.0 polish

Doesn't fit a milestone:

- **Rule upload (`.yml` file picker).** v1.5 ships paste + curated examples; the file picker is a small follow-up using the browser File API (read client-side, POST text body to the existing load endpoint).
- **Rule download UX**: progress indicator + last-N rules list (client-side localStorage, *not* server persistence).
- **Keyboard shortcuts** (deferred from v1 per docs/ui.md).
- **Stage 1 field helpers for the non-SIEM audience.** Once a user picks an observation, each field row should explain in plain English what the field actually is — "*Image* is the path of the executable that ran" — plus a one-tap "use a typical value" suggestion drawn from the SigmaHQ corpus (e.g. for `Image` on `process_creation`, the top-N most-cited paths). Optional inline "what does this modifier do" tooltip on the modifier dropdown for the same reason. The data is already in `data/taxonomy/*.yml` (`label`, `note`, `example`); this is wiring + UX, not new data. Feeds the broader product thesis: testers shouldn't need to know Sigma jargon to write Sigma rules.
- **Long-rule layout regression on load.** Loading a long rule (paste tab or corpus browse) breaks the composer-panel's scroll behaviour and the breadcrumb navigation in some cases — the panel's `overflow-y: auto` and the breadcrumb's sticky-or-flow positioning don't survive certain post-load DOM shapes. Reproduce: load any rule with ≥6 detection items, scroll the composer panel, click a breadcrumb step. Suspected: the composer-panel's scroll height isn't being reset after the htmx swap, or one of the loaded-rule partials adds a stray `overflow: visible` that escapes the panel. Layout-only fix; should land in the same PR as a targeted regression test that loads a long rule and asserts both `#composer-panel` is the scroll container and that breadcrumb buttons remain clickable after scroll.
- **Load modal hardens against non-canonical rules.** Today, pasting a SigmaHQ rule that fails canonical-Sigma validation (legacy modifier order, unusual condition syntax, missing required field) can 500 the load endpoint instead of degrading gracefully. The contract should be: *any* YAML that pySigma's permissive parser can ingest must produce a `RuleDraft` and land in the composer at the highest stage it can reach, with the validation issues surfaced in the health drawer — never a crash. Implementation likely lives in `web/load.py`: catch every parse / coercion exception, downgrade to a `LoadResult.with_issues(...)` shape, and let Stage 1 (or Stage 0 if even the logsource is unparseable) render with the partial draft + a tier-1 issue list. Belongs with a fixture set of "weird-but-real" rules from the SigmaHQ corpus that exercise this path.

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
- **sigconverter.io-style pipeline picker** — a power-user view that lets the user pick (target × format × N pipelines) and see the converted query, mirroring the [sigconverter.io](https://sigconverter.io/) UI (target dropdown, format dropdown, multi-select pipeline list, CLI-mirror display showing the equivalent `sigma convert -t … -f … -p … rule.yml` invocation). Useful when the bundled `data/pipelines.yml` matrix doesn't cover what the user wants — e.g. they have a custom pipeline installed in their environment, or they want to *combine* sysmon + windows-audit + a vendor pipeline that our automatic matrix wouldn't compose. **Constraints driving the design:**
  - **I-2 still holds**: the pipeline-picked output is *only* a preview of the converted query; the canonical Sigma YAML pane never reflects pipeline transformations. Any "save" / "download" path emits the untransformed canonical YAML, period. The picker UI must make that distinction visible — probably with the canonical YAML pane labelled and the pipeline-picked query pane in a clearly secondary / "advanced" tab.
  - **Gated, not visible by default.** The non-SIEM audience must never encounter this control by accident — pipeline picking is the exact opposite of the product thesis. Plausible gates: a `?advanced=1` URL flag, a "Show advanced converter" disclosure inside the Stage 4 output pane, or a separate `/advanced/convert` route entirely. The CLI is also a natural home — `intel2sigma convert rule.yml -t kusto -p sysmon -p windows-audit` slots in alongside the existing `convert` subcommand without surfacing in the web UI at all, and that may be the right answer for v2.0.
  - **Pipeline catalog is data-driven.** The pipeline list in the dropdown comes from the same place `core/convert/engine.py` already pulls from — every `ProcessingPipeline` registered with pySigma's entry-point system, plus our bundled `data/pipelines.yml` overrides. No new data file.
  - **Caching extends cleanly.** The conversion `lru_cache` key already hashes `(rule_content, backend, sorted pipeline names)` — adding user-picked pipelines is just a different value for the third element. No cache invalidation logic needed.
  - **Composability with our matrix.** When the user picks pipelines manually, the automatic `data/pipelines.yml` matrix should be *replaced*, not augmented — that's the `--without-pipeline` semantic in the sigconverter.io screenshot. Our default flow stays the matrix-driven one; the picker is "I want full control over what runs."

  Belongs in v2 because it's tester-feedback-driven: until users tell us the matrix is missing something they need, exposing the picker is unjustified added surface area. Worth a thin discovery prototype if and when sandbox ingestion (v1.1) starts producing rules whose target backend has multiple plausible pipeline stacks.
