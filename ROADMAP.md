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

## 🪦 v1.x — Load-path corpus-wide hardening sweep *(SHIPPED in 0.3.0, 2026-04-29)*

The "load any SigmaHQ rule" feature was producing bugs at a steady drip — one
or two per dogfood session — because each rule shape that breaks is a different
combination of (logsource shape × condition shape × field-name leak × multi-
value items × oob-swap class survival × stage gating × …). Patch-when-found
was no longer the right cadence. The sweep audits every corpus rule
programmatically once and produces a single coherent fix-list, plus catches
anything that still breaks at runtime instead of letting the user discover it.

**Result against the 3,708-rule corpus**: clean 88.75% → **96.60%**
(+291 rules / +7.85 pp), exceptions 146 → **0**, desync /
silent_data_loss held at 0 throughout. The remaining 126 degraded
rules are 100 LOAD_CONDITION_UNUSUAL (captured for v2's structured
condition editor) plus ~16 long-tail single-rule logsources where
the freeform path is the right answer.

Three phases, each shipped independently:

**🪦 L1 — Audit script (one-shot, kept).** *Shipped as
`scripts/audit_corpus_loads.py` in `e9a040b` (0.2.12).* Walks every entry
in `intel2sigma/data/sigmahq_corpus.json` (3,708 rules at the current
pin), runs each through `web/load.draft_from_yaml`, and categorises
outcomes:
  * **clean** — loads, lands at the expected stage, all internal state
    consistent.
  * **degraded** — loads with `LOAD_*` issues; the issue list surfaces in
    the preview pane and the user sees a usable draft. Acceptable.
  * **desync** — observation_id desynced from rendered stage. The user-
    visible symptom is "breadcrumb says X, content shows Y" — exactly
    the historical bitbucket / filter-only / antivirus failure shape.
  * **silent_data_loss** — load succeeds but the round-trip drops fields.
  * **exception** — any code path that throws.

  Output: `reports/corpus_load_audit.json`. Initial baseline:
  88.75% clean / 0 desync / 0 silent_data_loss / 146 exceptions / 271
  degraded — confirming the regressive triage work that preceded the
  sweep already paid off; the remaining failures are real
  feature/category gaps, not crashes.

**🪦 L2-P1 — Round-trip behaviour fixes (idiom support).** *Shipped as
four sub-commits across 0.2.13.* Each cleared a specific Sigma idiom
the composer was silently losing on load:
  * `781faea` (P1a) — preserve literal whitespace in detection values.
  * `cebaa00` (P1b) — first-class support for keyword-search blocks
    (`filter_keywords: [samr, lsarpc, winreg]`).
  * `4100c67` (P1c) — filter-only rule condition composition + a latent
    NOT-paren precedence bug (`not a or b` was rendering without
    parens).
  * `625776e` (P1d) — `Field: null` (`SigmaNull`) + `Field: ''` as
    first-class round-trippable values.

  Cumulative: clean 88.75% → 91.64%, exceptions 146 → 0, desync /
  silent_data_loss held at 0.

**🪦 L2-P2 — Catalog expansion.** *Shipped across `eeecb61` →
`397fcc5` (0.3.0).* 12 new taxonomy files (`application_jvm`,
`application_kubernetes`, `webserver`, `dns`, `antivirus`,
`file_delete`, `file_access`, `ps_classic_start`,
`registry_delete`, `registry_add`, `create_stream_hash`,
`file_change`) plus secondary-platform extensions on
`network_connection` (linux) and `file_event` (macos). Cleared
184 `LOAD_OBSERVATION_UNKNOWN` rules. Loader's platform-routing
fix (`_translate_observation` now picks the platform whose
product matches the loaded rule, not always the first platform)
landed alongside.

**L2-P3 — Structured condition editor.** *Reframed as a v2 candidate;
see "## v2 — Composer fidelity" below.* The `LOAD_CONDITION_UNUSUAL`
class is real detection-engineering nuance the auto-composer can't
reproduce — accepting the lossy save is wrong; the right answer is a
tree-builder UI for `ConditionExpression` that stays within I-4 (no
editable YAML). Out of scope for v1.

**🪦 L3 — Audit-as-test.** *Shipped as `tests/test_corpus_load_audit
_ratchet.py` in `543a3bd` (0.3.0).* Three slow-marked checks
(exception/desync/silent_data_loss must stay 0; clean count must
not drop below `MIN_CLEAN_COUNT`; soft-stale-floor check that
catches PRs improving the count without bumping the constant).
Audit categorisation refactored into `intel2sigma._audit` so the
script and the test share one implementation. Floor at v0.3.0:
**3582**.

**Status**: complete. L2-P3 lives in v2 below.

## v1.x — Smaller post-v1.0 polish

Doesn't fit a milestone:

- **Rule upload (`.yml` file picker).** v1.5 ships paste + curated examples; the file picker is a small follow-up using the browser File API (read client-side, POST text body to the existing load endpoint).
- **Rule download UX**: progress indicator + last-N rules list (client-side localStorage, *not* server persistence).
- **Keyboard shortcuts** (deferred from v1 per docs/ui.md).
- **🪦 Stage 1 field helpers for the non-SIEM audience** — *shipped as F1 → F2 → F3 in 0.2.6 through 0.2.10.* The verbiage audit (F1) populated every observation's top-3 fields with hand-curated `note` + corpus-mined `example`; F2 swapped raw Sigma modifier names for plain-English labels in the modifier dropdown; F3 wired up the hover-revealed tooltip per `docs/ui.md` § "Field-row helper tooltip". Contract is regression-tested in `tests/test_taxonomy_verbiage.py`, `tests/test_modifier_labels.py`, and `tests/test_field_tooltips.py`.

- **Stage 1 field helpers — "Learn more" definition links** (post-v1.1, follow-on to F3). Each tooltip's helper text gets an optional `Learn more →` link pointing out to authoritative documentation. Three plausible link targets:
    - **MITRE ATT&CK technique pages** when a field maps to a specific technique (e.g. `OriginalFileName` ↔ Masquerading T1036, `Hashes` ↔ Indicator-removal T1070.004). The mapping data already partly exists in `data/mitre_attack.json` for the Stage 2 ATT&CK picker — extend with a per-field cross-reference layer.
    - **SigmaHQ field reference** for canonical Sigma field semantics — slow-moving, mostly-stable target.
    - **Internal glossary page** for jargon terms ("PE metadata", "integrity level", "named pipe") that don't have an obvious external authoritative source. Lives at `web/templates/glossary.html`; one shared shell, anchor-linked sections per term.

  Out of scope for v1 because (1) the per-field link mappings aren't curated yet (would need a hand-pass across all 36 observation types), (2) link-target stability isn't guaranteed for the external sources (MITRE pages especially move around), (3) the helper UI ships value without it. Worth doing once we have ≥10 testers asking "what is X" repeatedly and the answers consolidate around a small set of definitions.

  Implementation hint when the time comes: extend the field schema in `intel2sigma/core/taxonomy/schema.py` with optional `learn_more: str | None = None` (URL or anchor-link to the glossary). Render in `_block.html` next to the example chip. Same hover lifecycle, no JS additions. ~30 lines of code + the curation work for the link map.

  *Accessibility cousin:* the same time we add `Learn more`, also wire `aria-describedby` from each field input to its tooltip element so screen readers narrate the helper text on focus. Today the tooltip has `role="tooltip"` but no `aria-describedby` link, so screen readers fall back to the input's `aria-label`. Five-line change once we touch the template.
- **Long-rule layout regression on load.** Loading a long rule (paste tab or corpus browse) breaks the composer-panel's scroll behaviour and the breadcrumb navigation in some cases — the panel's `overflow-y: auto` and the breadcrumb's sticky-or-flow positioning don't survive certain post-load DOM shapes. Reproduce: load any rule with ≥6 detection items, scroll the composer panel, click a breadcrumb step. Suspected: the composer-panel's scroll height isn't being reset after the htmx swap, or one of the loaded-rule partials adds a stray `overflow: visible` that escapes the panel. Layout-only fix; should land in the same PR as a targeted regression test that loads a long rule and asserts both `#composer-panel` is the scroll container and that breadcrumb buttons remain clickable after scroll.
- **Load modal hardens against non-canonical rules.** Today, pasting a SigmaHQ rule that fails canonical-Sigma validation (legacy modifier order, unusual condition syntax, missing required field) can 500 the load endpoint instead of degrading gracefully. The contract should be: *any* YAML that pySigma's permissive parser can ingest must produce a `RuleDraft` and land in the composer at the highest stage it can reach, with the validation issues surfaced in the health drawer — never a crash. Implementation likely lives in `web/load.py`: catch every parse / coercion exception, downgrade to a `LoadResult.with_issues(...)` shape, and let Stage 1 (or Stage 0 if even the logsource is unparseable) render with the partial draft + a tier-1 issue list. Belongs with a fixture set of "weird-but-real" rules from the SigmaHQ corpus that exercise this path.
- **Stage 2 metadata edits don't refresh the YAML preview pane.** Reported via dogfooding 2026-04-26: editing the title / description / level / tags / author / date / falsepositives / references on Stage 2 mutates the draft (right-pane state blob updates correctly) but the rendered YAML in the preview pane stays stale until the user navigates away and back. Likely a missing `hx-include` / `hx-trigger` on the metadata form, OR `_render_stage` is firing but the preview-pane partial isn't rebuilding from the draft's current metadata. Quick diagnostic: edit a metadata field, inspect the `/composer/update` POST response in DevTools Network — confirm whether the response contains the oob preview-pane swap with the new title and whether htmx is actually applying it. If the swap is present and applied, the bug is in the preview-pane render context not picking up the metadata change. Five-minute fix once the diagnostic localises it.
- **Draggable row splitter between YAML pane and conversion-tabs region.** Today the conversion tabs are capped at `max-height: 50%` of the preview panel, which feels tight when the converted query has more than two lines or when the YAML is short and the user wants more room for the SIEM output. Solution: mirror the existing column splitter (`.pane-splitter` between composer + preview, drag JS in `base.html`) for the row direction. Insert a `<div class="preview-row-splitter">` between `.preview-pane-primary` and `#conversion-tabs-region` in `base.html`; switch `#conversion-tabs-region` from `flex: 0 1 auto; max-height: 50%` to `flex: 0 0 var(--tabs-height, 40%)`; add a parallel drag-handler IIFE that updates `--tabs-height` on `.preview-panel` and persists ratio in `localStorage["intel2sigma:tabs-pct"]`. Pattern is proven (the column splitter has been working since 2026-04-26). Risk analysis recorded in chat transcript: layout-regression risk is low (only `#conversion-tabs-region`'s flex declaration changes), oob-swap interaction is safe (splitter is a static sibling, never an oob target), drag-handler interference is impossible (per-IIFE local `dragging` flag). Empty-state UX caveat: with `flex: 0 0 40%` the tabs region is always 40% even with no rule loaded, making Stage 0 show a slightly larger empty placeholder area — accepted tradeoff because the loaded-rule state matters more. Bumps patch version on ship; supersedes the older "bump conversion-tabs cap" follow-up.

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
- **Structured condition editor** — first-class UI support for arbitrary Sigma condition shapes that today get flagged as `LOAD_CONDITION_UNUSUAL` and silently downgraded to the auto-composed `all of match_* and not 1 of filter_*` shape on save. The L1 corpus audit (`e9a040b`) found **94 vetted SigmaHQ rules** in this category — real rules with thoughtful conditions like `(s1 and s2) or (s3 and not f1)`, `1 of (a*) and 2 of (b*)`, mixed-prefix selection groupings — that today's composer can't preserve through round-trip.

  This isn't a YAML textarea — **CLAUDE.md I-4 holds, the non-SIEM audience must never have to read or write Sigma YAML.** It's a *visual* tree-builder for the `ConditionExpression`: nested AND/OR/NOT/quantifier nodes that the user manipulates by clicking nodes and dropping in selection-block references from a side palette. Same product thesis as the rest of the composer (structure-not-text) — just with the structure rich enough to express what real rules need.

  The successor to the cut Guided/Expert dual-mode story, but staying within I-4. Where Expert mode would have given power users a YAML escape hatch, this gives them a richer structural surface that still keeps non-SIEM users out of the YAML weeds. The detection-engineering nuance survives the round-trip; the user authoring intent isn't silently flattened.

  Design questions for v2:
  - **Default vs. opt-in surface?** Most rules need only `selection and not filter`; surfacing the full tree-builder by default could intimidate. Plausible: keep today's default auto-compose for ≤2 match + ≤2 filter rules; surface the tree-builder when the loaded rule's condition exceeds that, OR via an "Advanced" disclosure on Stage 1.
  - **Granularity of the editor.** Sub-tree drag-and-drop is rich but expensive to build accessibly. A simpler "add operator → add child" wizard might cover 80% of real rules.
  - **Existing infrastructure to reuse.** `ConditionExpression` already models the full shape recursively; `core/serialize.py::_render_condition` handles every operator. The gap is purely UI — the model and serializer can render whatever the editor produces.

  Belongs in v2 because (1) the F1/F2/F3 helper-UI line takes priority for the non-SIEM audience that v1 is sized for, (2) building a tree-builder UI accessibly is a real chunk of work, (3) the count is "94 of 3,708" — meaningful but not load-bearing for v1's exit gate. Re-evaluate after v1.1 sandbox ingestion lands and we see what condition shapes auto-derived rules need.

- **sigconverter.io-style pipeline picker** — a power-user view that lets the user pick (target × format × N pipelines) and see the converted query, mirroring the [sigconverter.io](https://sigconverter.io/) UI (target dropdown, format dropdown, multi-select pipeline list, CLI-mirror display showing the equivalent `sigma convert -t … -f … -p … rule.yml` invocation). Useful when the bundled `data/pipelines.yml` matrix doesn't cover what the user wants — e.g. they have a custom pipeline installed in their environment, or they want to *combine* sysmon + windows-audit + a vendor pipeline that our automatic matrix wouldn't compose. **Constraints driving the design:**
  - **I-2 still holds**: the pipeline-picked output is *only* a preview of the converted query; the canonical Sigma YAML pane never reflects pipeline transformations. Any "save" / "download" path emits the untransformed canonical YAML, period. The picker UI must make that distinction visible — probably with the canonical YAML pane labelled and the pipeline-picked query pane in a clearly secondary / "advanced" tab.
  - **Gated, not visible by default.** The non-SIEM audience must never encounter this control by accident — pipeline picking is the exact opposite of the product thesis. Plausible gates: a `?advanced=1` URL flag, a "Show advanced converter" disclosure inside the Stage 4 output pane, or a separate `/advanced/convert` route entirely. The CLI is also a natural home — `intel2sigma convert rule.yml -t kusto -p sysmon -p windows-audit` slots in alongside the existing `convert` subcommand without surfacing in the web UI at all, and that may be the right answer for v2.0.
  - **Pipeline catalog is data-driven.** The pipeline list in the dropdown comes from the same place `core/convert/engine.py` already pulls from — every `ProcessingPipeline` registered with pySigma's entry-point system, plus our bundled `data/pipelines.yml` overrides. No new data file.
  - **Caching extends cleanly.** The conversion `lru_cache` key already hashes `(rule_content, backend, sorted pipeline names)` — adding user-picked pipelines is just a different value for the third element. No cache invalidation logic needed.
  - **Composability with our matrix.** When the user picks pipelines manually, the automatic `data/pipelines.yml` matrix should be *replaced*, not augmented — that's the `--without-pipeline` semantic in the sigconverter.io screenshot. Our default flow stays the matrix-driven one; the picker is "I want full control over what runs."

  Belongs in v2 because it's tester-feedback-driven: until users tell us the matrix is missing something they need, exposing the picker is unjustified added surface area. Worth a thin discovery prototype if and when sandbox ingestion (v1.1) starts producing rules whose target backend has multiple plausible pipeline stacks.
