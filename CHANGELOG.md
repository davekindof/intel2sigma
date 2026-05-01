# Changelog

What shipped, when. Pair this with `ROADMAP.md` (what's planned).

## Versioning policy

Loose SemVer:

- **Patch** (`0.x.Y`) — small changes. Bug fixes, individual feature
  additions, single hand-review batches, polish, doc updates. The
  default cadence — most commits will live under a patch bump.
- **Minor** (`0.X.0`) — major changes. A milestone landing in full
  (a complete v1.x ROADMAP entry, or a coherent multi-week effort
  like the Phase B2 heuristics catalogue completion).
- **Major** (`1.0.0`) — when we're happy with the product as a whole.
  Triggered by ROADMAP §v1 exit gate ("≥2 non-Sigma testers walked
  through Stage 0 → 4 with a real rule") landing AND no obvious
  rough edges remaining. Until then, we stay on `0.x.y`.
- **Major** (`>=2.0.0`) — reserved for genuine breaking changes
  (taxonomy schema migration, dropped backend, etc.).

The cache-bust mechanism uses the build SHA, not the package version
(per `intel2sigma/web/templates/base.html` and commit `8471db8`), so
version bumps are decoupled from deploy correctness — they exist for
human communication, not for forcing browsers to reload assets.

## 0.3.2 — 2026-05-01

Patch bump — v1.x **emit-path corpus-wide hardening sweep complete**.

> *Versioning note: an earlier draft of this entry was tagged 0.4.0
> on the assumption that the sweep's milestone scope justified a
> minor bump. On review the actual diff is bug fixes + new test/audit
> infrastructure (zero new user-facing features), which sits firmly
> in the patch tier per the policy in this file's preamble. Corrected
> to 0.3.2 in the same release commit. The next genuinely user-facing
> milestone — Pattern II / III / V or a new feature — will be the
> next minor bump.*

The mirror of the load-path sweep that closed in 0.3.0. The load
sweep gave the project a corpus-driven ratchet for **what we
ingest**; the emit path (composer → strict YAML output) had no
equivalent until now. The composer could author rules downstream
pySigma can't parse (`|exact` modifier, B2), with dropped operators
or doubly-escaped regex values, and we'd ship them — and the audit
ratchet would never catch it.

The 0.3.1 patch fixed the four bugs from 0.3.0 dogfood testing,
but the L4 corpus walk found that those four were the visible tip:
**350+ silent emit-side regressions** across the full corpus that
no individual user had reported yet. The L5 fix wave cleared
nearly all of them.

### Sweep result against the SigmaHQ corpus (3,708 rules)

| | L4 v1 (baseline) | 0.3.2 | Δ |
| --- | --- | --- | --- |
| **clean** | 3247 (87.57%) | **3578 (96.49%)** | **+331 / +8.92 pp** |
| degraded | 99 | 126 | +27 |
| **structural_drift** | 358 | **4 (0.11%)** | **-354** |
| **emit_exception** | 4 | **0** | **-4** |
| skipped_no_strict_rule | 0 | 0 | held |

### Phases shipped

- **L4** (`9d29157`) — `scripts/audit_corpus_emits.py`. Walks every
  corpus rule through load → strict → emit → re-parse → compare,
  categorises into clean / degraded / structural_drift /
  emit_exception / skipped_no_strict_rule. Output:
  `reports/corpus_emit_audit.json`. Categorisation logic in
  `intel2sigma._audit` shares helpers with the L3 ratchet.

- **L5 a–e** — five sub-fixes, each commit referencing a specific
  L4 category from the audit report:
  * `5bec168` (L5-A) — audit's own SigmaNull stringification bug
    (`<sigma.types.SigmaNull object at 0x...>` non-deterministic
    repr false-flagged 21+ rules as drift).
  * `8631a72` (L5-B) — loader's `_modifier_name(cls)` did class-
    name munging, producing `windowsdash` instead of pySigma's
    canonical `windash` token. Fix uses pySigma's
    `modifier_mapping` inversely. Cleared 50+ structural_drift
    + all 4 emit_exception cases.
  * `dc4101b` (L5-C) — `'no'` is a YAML 1.1 boolean (`False`)
    but a plain scalar string in YAML 1.2. Ruamel emit (1.2)
    unquoted, pySigma read (1.1) parsed as bool. Fix wraps
    YAML 1.1 boolean literal strings in
    `SingleQuotedScalarString` to force quoting.
  * `65cb708` (L5-D) — `str(SigmaString)` doubles backslashes
    around wildcard metacharacters; every round-trip multiplied
    backslashes, drifting regex/wildcard values. Fix uses
    `SigmaString.original` (the user's literal input). ~115
    structural_drift cases cleared.
  * `14b29cd` (L5-E) — keyword-search blocks with item-level
    modifiers (`keywords: { '|all': [pkexec, ...] }`) were
    flattened to bare list, silently changing all-of semantics
    to any-of. Fix groups by modifier chain and emits
    `'|mod1|mod2': [values]` when modifiers are present. ~16
    cases cleared.

- **L6** (`8920d39`) — `tests/test_corpus_emit_audit_ratchet.py`.
  Three slow-marked checks sharing one module-scoped audit pass:
  emit_exception must stay 0; clean count >=
  `MIN_EMIT_CLEAN_COUNT` (3578); stale-floor soft check
  (tolerance +100). The CI gate that locks in the 96.49% floor
  for every future PR.

### Remaining audit residual (4 structural_drift, all benign)

Rules using pySigma modifiers our model doesn't represent —
`|fieldreference` (3 cases) and one `userIdentity` field shape.
These are real fidelity gaps but <0.11% of the corpus. L7-class
follow-up if they accumulate; for now the freeform-observation
path covers them.

### Coming next

- **Pattern II** — converge to a single YAML emit path (preview
  vs canonical). Architectural cleanup; the sweep work makes the
  emit path correct, but two paths still exist.
- **Pattern III** — handler-sequence test pass + minimum-mutation
  audit (B1's handler over-reach is one instance of a class).
- **Pattern V** — Jinja macro for the "—" sentinel pattern
  applied across every `<select>` / radio group / pre-filled
  input.
- **B2d–B2g** — remaining 10 heuristics (parallel work).

Symmetric ratchets are now in place: every regression on what we
ingest (L1-L3, floor 3582) OR what we emit (L4-L6, floor 3578)
fails CI immediately.

## 0.3.1 — 2026-04-29

Patch bump — four bugs filed during 0.3.0 deploy testing
(see ROADMAP § "Bugs from 0.3.0 testing"). Each fix is concrete
and locally scoped; the systemic patterns they surfaced (Patterns
I–V in ROADMAP) are tracked separately as the next major effort.

### Shipped

- **B1 — operator modifier dropped from emitted YAML** (`c85ee09`,
  HIGH correctness). `_set_item_field` was resetting
  `item.modifiers = []` on every call, including the redundant
  ones htmx fires on `change, keyup delay:300ms`. User picks
  "contains" → edits field name → modifier silently dropped → YAML
  emits bare `field: value` → silent no-op rule. Fix narrows the
  reset: only fire when the new field's allowed-modifier list
  excludes the current modifier; for freeform observations or
  uncatalogued field names, never reset. Four regression tests
  pin all four branches (catalogued+allowed, freeform, no-op
  same-field, catalogued+disallowed).

- **B2 — `|exact` modifier emitted, non-standard Sigma**
  (`0610794`, MEDIUM spec compliance). Sigma has no `|exact`
  modifier — bare `field: value` IS exact match by definition.
  SPEC.md decision log (2026-04-24) documented the planned
  collapse but only the composer translation was supposed to be
  there; the serializer side was missed. Fix: filter `"exact"`
  out of the modifier chain in `_detection_item_key` before
  joining. Load preserves the user's lexical input (so the editor
  reflects what they wrote); emit normalizes (so the saved
  artifact is canonical Sigma). Round-trip is idempotent after
  one normalization pass.

- **B3 — auditd taxonomy missing SOCKADDR-record fields**
  (`49bbd93`, MEDIUM coverage). User authoring a network-syscall
  detection had no path to `saddr` other than the freeform
  observation fallback (which loses validation / autocomplete /
  modifier defaults). Pure-data fix: extends `auditd.yml` with
  `saddr`, `success`, `auid` plus a top-of-file note explaining
  auditd's record-pair pattern (SYSCALL + SOCKADDR / PATH /
  EXECVE / CWD context records). Pattern IV in ROADMAP — pure
  frequency-driven catalog inclusion would never have surfaced
  this (zero corpus rules use `saddr` precisely because the
  catalog didn't expose it; feedback loop).

- **B4 — UI dropdown defaults visually mask empty state**
  (`b7601b0`, LOW UX, but the visibility compound for B1).
  HTML `<select>` defaults to the first `<option>` whenever none
  is `selected`. An item with `modifiers=[]` displayed the first
  allowed modifier ("contains") as if the user picked it. Fix
  renders a leading sentinel `<option value="">—</option>` with
  `selected` when state is empty. The dropdown now visually
  distinguishes "user explicitly picked contains" from "user
  hasn't picked anything." Two render-side regression tests pin
  the contract.

### Known follow-up patterns (tracked in ROADMAP)

- **Pattern I (largest)** — emit-path corpus-wide hardening sweep
  (L4/L5/L6). The mirror of the now-shipped load-path sweep. Will
  surface emit-side correctness gaps we don't yet know about.
- **Pattern II** — converge to a single YAML emit path (preview
  vs canonical have already drifted twice now: `8329d04`, B4).
- **Pattern III** — handler-sequence test pass + minimum-mutation
  audit (B1's handler over-reach is one instance of a class).
- **Pattern V** — Jinja macro for the "—" sentinel, applied
  across every `<select>` / radio group / pre-filled input
  (B4 fixes the most visible instance; the macro extends the
  pattern across the surface).

## 0.3.0 — 2026-04-29

Minor bump — v1.x **load-path corpus-wide hardening sweep complete**.

Captures the cumulative L1 + L2-P1 + L2-P2 + L3 work landed across
0.2.12 → 0.3.0. The "load any SigmaHQ rule" feature was producing
bug-of-the-week dogfood reports because each rule shape that broke
was a different combination of (logsource × condition × field-name
leak × multi-value items × oob-swap class survival × stage gating).
Patch-when-found is over; the audit-driven sweep replaces it.

### Sweep result against the SigmaHQ corpus (3,708 rules)

|              | baseline (0.2.11) | 0.3.0       | Δ           |
| ------------ | ----------------- | ----------- | ----------- |
| **clean**    | 3291 (88.75%)     | **3582 (96.60%)** | **+291 (+7.85 pp)** |
| degraded     | 271               | 126         | -145        |
| **exception**| 146               | **0**       | **-146**    |
| desync       | 0                 | 0           | held        |
| silent_data_loss | 0             | 0           | held        |

### Phases shipped

- **L1** (`e9a040b`, 0.2.12) — `scripts/audit_corpus_loads.py`. Walks
  every corpus rule through the load path, categorises into clean /
  degraded / desync / silent_data_loss / exception. Output:
  `reports/corpus_load_audit.json`.

- **L2-P1 a–d** (`781faea` / `cebaa00` / `4100c67` / `625776e`,
  0.2.13) — four load-path round-trip fixes. Literal whitespace
  preservation, Sigma keyword-search blocks (`filter_keywords:
  [samr, lsarpc, winreg]`), filter-only rules + the latent NOT-of-OR
  paren precedence bug, Sigma null + explicit empty-string values.
  Cleared 146 → 0 exceptions, +107 clean.

- **Filter-only preview parity** (`8329d04`, 0.2.14) — fixed the
  preview/strict asymmetry that L2-P1c missed, where the preview
  pane showed `condition: filter_main_floppy` while the saved rule
  was `condition: not (filter_main_floppy or filter_main_servicing)`.

- **L2-P2** (`eeecb61` → `397fcc5`, 0.3.0) — catalog expansion. 9
  new taxonomy files (`application_jvm`, `application_kubernetes`,
  `webserver`, `dns`, `antivirus`, `file_delete`, `file_access`,
  `ps_classic_start`, `registry_delete`, `registry_add`,
  `create_stream_hash`, `file_change`) plus secondary-platform
  extensions on `network_connection` (linux) and `file_event`
  (macos). Loader's platform-routing fix (`_translate_observation`
  now picks the platform whose product matches the loaded rule
  instead of always returning the first platform) covered along
  the way. Cleared 184 LOAD_OBSERVATION_UNKNOWN rules.

- **L3** (`543a3bd`, 0.3.0) — audit-as-test. Refactored the
  categorisation logic into `intel2sigma._audit` (importable
  module) so `tests/test_corpus_load_audit_ratchet.py` could lock
  in the floor as a `@pytest.mark.slow` ratchet. Three checks:
  (1) exception/desync/silent_data_loss must stay at 0,
  (2) clean count must not drop below `MIN_CLEAN_COUNT`,
  (3) soft check that `MIN_CLEAN_COUNT` doesn't lag actual by >100
  (catches PRs that improve the count but forget to bump the
  constant). Floor at v0.3.0: **3582**.

### Remaining audit degradation (126 rules, all benign)

- **~100 LOAD_CONDITION_UNUSUAL** — captured for v2 design effort:
  *structured condition editor* (ROADMAP). These are real
  detection-engineering nuance the auto-composer can't reproduce —
  the right answer is a tree-builder UI for `ConditionExpression`
  that stays within I-4 (no editable YAML), not "accept the lossy
  save." Out of scope for v1.x.
- **~16 long-tail single-rule logsources** — firewall (2),
  application+spring/+ruby_on_rails/+velocity/+python/+sql/+nodejs
  (each 1–2), sysmon_status (1), sysmon_error (1),
  file_executable_detected (1), file_event+paloalto (1),
  process_tampering (1), file_rename (2). The freeform-observation
  path covers these without bloating the catalog.

### Coming next

- **B2d–B2g** — 10 remaining heuristics. Parallel work, not on the
  load-path critical path; pairs naturally with the next quarterly
  recalibration cycle.
- **L2-P3 (v2 candidate)** — structured condition editor.

## 0.2.14 — 2026-04-28

Patch bump — preview/strict parity fix surfaced by the post-L2-P1
documentation sweep.

### Shipped

- **Filter-only rule preview/strict condition parity** (this commit).
  When the L2-P1c work added the filter-only branch to
  `_compose_condition` (composing `not (filter_a or filter_b)` for
  rules with no match blocks), the partial-preview path
  (`_partial_condition_string`) was missed. The preview pane was
  emitting the bare first filter name (`condition: filter_main_floppy`)
  while the saved rule contained the actual SigmaHQ idiom — a real
  round-trip lie the user would only catch by comparing the preview
  to the downloaded YAML. Caught by the post-L2-P1 staleness sweep.
  `_partial_condition_string` now mirrors `_compose_condition` for
  filter-only rules: `not <filter>` for one filter, `not (f1 or f2 or
  …)` for multiple. Two regression tests pin the parity contract.

- **Doc/comment staleness sweep** (`eb614f7`). Post-L2-P1 audit of
  docs and inline comments to catch superseded statements. ROADMAP's
  v1.x load-path-sweep section rewritten to mark L1 + L2-P1 shipped
  with the audit clean-rate movement (88.75% → 91.64%) and L2-P2
  promoted to "active". SPEC.md grew a 2026-04-28 decision-log entry
  capturing the L2-P1 model contract changes (values widened to
  include None, field's min_length=1 dropped, str_strip_whitespace
  off, filter-only composition, NOT-paren precedence). Smaller
  fixes: web-state-model.md's DetectionItemDraft.values type signature
  (now `list[str | None]`), the heuristic comment in
  `overbroad_selection.py` citing the pre-P1d type, and `web/app.py`'s
  module docstring still claiming "Guided + Expert mode shells"
  despite Expert mode being pruned in 2026-04-26.

### Known issues / future work (logged from the sweep)

- `web/load.py:460,507` — bare `except Exception` blocks on the
  example-manifest reader without inline rationale comments.
  Defensive (return empty list when the manifest is malformed) but
  worth a one-line "why" each.
- `core/heuristics/checks/metadata_completeness.py:19–24` — title /
  description thresholds (`_TITLE_MIN=10`, `_TITLE_MAX=100`,
  `_DESC_MIN=30`) are hardcoded. Borderline I-5 violation —
  arguably tuning parameters of the function rather than catalog
  data, so leaving in code for now.
- pySigma v0.x → v1.x migration risk. Pin is `>=0.11,<1.0`; v1.0
  may move `SigmaDetection` / `SigmaDetectionItem` / `SigmaNull`
  import paths. Plan the migration when upstream cuts a release
  candidate.

## 0.2.13 — 2026-04-27

Patch bump.

### Shipped — L2-P1: load-path round-trip hardening (corpus-driven)

Four-part sweep against the 3,708-rule SigmaHQ corpus, driven by the
L1 audit script (`e9a040b`). Cumulative result: **88.75% → 91.64%
clean**, **146 → 0 exceptions**, **0 desync / 0 silent_data_loss
maintained**. Each part fixes a distinct Sigma idiom the composer
silently lost on load.

- **L2-P1a — preserve literal whitespace** (`781faea`). `DetectionItem`
  / `DetectionItemDraft` override the project-wide
  `str_strip_whitespace=True` to `False`. Tier-1's `values_set` check
  switched from `v.strip() != ""` to `v != ""` so a single-space value
  (`CommandLine|endswith: ' '` — the macOS masquerading-via-trailing-
  space pattern at SigmaHQ rule b6e2a2e3-…) survives load. +5 clean,
  -4 exceptions.

- **L2-P1b — Sigma keyword-search blocks** (`cebaa00`). `DetectionItem.field`
  dropped its `min_length=1` constraint to permit the empty string as a
  keyword-search marker. The `is_keyword` property + `_field_well_formed`
  validator together still reject whitespace-only field names as typos.
  Loader and tier-1 keep keyword items; serializer detects pure-keyword
  blocks and emits them as bare lists (`filter_keywords: [samr,
  lsarpc, winreg]`). +70 clean, -106 exceptions.

- **L2-P1c — filter-only rules + NOT-of-OR paren precedence** (`4100c67`).
  `_compose_condition` grew a filter-only branch: a rule with no match
  blocks (e.g. SigmaHQ db809f10-… APT27 raw-disk-access) now composes
  to `not filter_a` / `not (filter_a or filter_b)` instead of returning
  `None` and tripping `DRAFT_CONDITION_EMPTY`. Discovered and fixed a
  latent paren-precedence bug in `_render_condition` while testing:
  Sigma's NOT binds tighter than AND/OR, so `not filter_a or filter_b`
  parses as `(not filter_a) or filter_b`; `_render_condition` now wraps
  non-atomic NOT operands in parens. +1 clean, -1 exception, plus the
  precedence fix that would have produced wrong queries for any user-
  composed multi-filter rule.

- **L2-P1d — Sigma null + explicit empty-string values** (this commit).
  Final 34 exceptions all carried `Field: null` or `Field: ''` filter
  blocks (macOS / process-creation rules excluding events with no
  command line, e.g. SigmaHQ 0250638a-…). `DetectionItem.values`
  extended from `list[str | int | bool]` to `list[str | int | bool |
  None]`; loader's `_stringify_value` translates pySigma `SigmaNull`
  to Python `None` instead of the broken `<sigma.types.SigmaNull
  object at 0x…>` repr; tier-1 simplified to `values_set =
  bool(item.values)` since the composer textarea filters blank lines
  server-side, so any value (including `None` or `""`) reaching tier-1
  is explicit user intent. ruamel emits `None` as a bare colon
  (`CommandLine:`) and `""` as `''`; both round-trip through pySigma.
  +31 clean, -34 exceptions.

The cumulative L2-P1 changes are additive at the model layer (the
`values` type widened from `list[str | int | bool]` to `list[str |
int | bool | None]`; the `field` constraint relaxed from `min_length=1`
to "non-empty if not whitespace") and pure additions at the serializer
layer (pure-keyword block detection, NOT-paren wrapping). Existing
strict-rule consumers continue to work; previously-rejected loader
inputs now build cleanly.

### Coming next

- **L2-P2** — catalog expansion for ~9 observation types (webserver,
  file_delete, file_access, generic dns, ps_classic_start,
  registry_delete, k8s/application, create_stream_hash, antivirus).
  Each adds 7–82 rules to the clean column.
- **L2-P3** — structured condition editor (v2 design effort, captured
  in ROADMAP). LOAD_CONDITION_UNUSUAL fires on 100 corpus rules whose
  conditions are real detection-engineering nuance the composer's
  auto-condition can't reproduce. Solution stays within I-4 (no
  editable YAML): a tree-builder UI for `ConditionExpression`.
- **L3** — convert audit script to a `@pytest.mark.slow` test with
  ratchet-down-only thresholds so future regressions trip CI.
- **B2d–B2g** — 10 remaining heuristics.

## 0.2.12 — 2026-04-27

Patch bump.

### Shipped

- **Draggable YAML / conversion-tabs row splitter** (`cd710d4`) — closes
  the row-splitter follow-up tracked since 2026-04-26. Mirrors the
  existing column splitter between composer + preview: a 6px drag
  handle between the YAML pane and the SIEM/EDR conversion-tabs region,
  with the position persisted in `localStorage["intel2sigma:tabs-pct"]`
  and a double-click reset to the 40% default. Replaces the hardcoded
  `max-height: 50%` cap with user-controlled drag — every analyst's
  monitor / rule-length combination wants a different ratio, so
  self-service beats a guessed-at constant.

  Per-IIFE local `dragging` flag means the row splitter and column
  splitter can't interfere with each other (only one mouse active at
  a time anyway). The 943f131 oob-swap class-preservation work still
  covers `#preview-pane` and `#conversion-tabs-region`; the splitter
  sits between them as a static sibling that's never an oob target.

  Empty-state UX caveat (acknowledged in the ROADMAP entry): with
  `flex: 0 0 40%` the tabs region is always 40% even when no rule is
  loaded, so Stage 0 shows a slightly larger empty-placeholder area
  at the bottom of the preview panel. Accepted tradeoff because the
  loaded-rule state matters more for actual use.

### Coming next

- **L1/L2/L3 load-path corpus-wide hardening sweep** — strategic answer
  to the load-rule bug-of-the-week pattern. L1 audit script first.
- **B2d–B2g** — 10 remaining heuristics.

## 0.2.11 — 2026-04-27

Patch bump. **F-series helper-UI plan complete.**

### Shipped

- **F4** (`b84f1d1`) — docs catch-up. New `docs/ui.md` § "Field-row
  helper tooltip (F3)" documents the full F3 contract: source of
  truth, render rules, behaviour, accessibility, design rationale.
  Existing Stage-1 paragraph updated to mention F2's modifier
  dropdown labels and per-option tooltips. ROADMAP entry for the
  shipped helper-UI work marked 🪦 *shipped* with cross-references
  to the F1 → F2 → F3 commits, plus a new future-state entry for
  "Learn more →" definition links (post-v1.1) — link tooltips out
  to MITRE ATT&CK, SigmaHQ field reference, or an internal glossary
  page once curation is justified.

### F-series totals (0.2.6 → 0.2.11)

- **F1** — verbiage audit: 36 / 36 observations meet the
  `docs/taxonomy.md` contract; 6 regression tests lock it.
- **F2** — modifier dropdown shows plain-English labels;
  per-option `title=` tooltips; 8 tests for completeness vs.
  `ValueModifier` Literal.
- **F3** — hover tooltips on Stage 1 field rows surface the
  hand-curated note + corpus-mined example for every populated
  top-3 field; 4 structural tests.
- **F4** — `docs/ui.md` and `ROADMAP.md` catch-up.

The non-SIEM-audience product thesis is materially advanced: a
user who's never written a Sigma rule can now hover any populated
field and read what it actually means without leaving the
composer.

### Coming next

- **L1/L2/L3 load-path corpus-wide hardening sweep** (per ROADMAP
  §v1.x) — strategic answer to the load-rule bug-of-the-week
  pattern. L1 audit script first.
- **B2d–B2g** — 10 remaining heuristics (FP-prone patterns,
  condition integrity, metadata, value quality).

## 0.2.10 — 2026-04-27

Patch bump.

### Shipped

- **F3** (`f75423b`) — **hover tooltips on Stage 1 field rows**. The
  marquee feature the F1 verbiage audit + F2 modifier-label work was
  building toward. Hover any detection-item row → small dark-themed
  tooltip appears below showing the field's note text and an Example
  chip with a corpus-derived value.
  - Pure CSS via `:hover` and `:focus-within` on `.detection-item`.
    Keyboard-accessible (tabbing reveals the tooltip on the focused
    row).
  - 300ms appearance delay, immediate fade-out. Asymmetric
    `transition-delay` produces the show-delay / hide-immediate
    behaviour with a single property — no JS.
  - `pointer-events: none` so tooltips never block clicks on
    adjacent rows.
  - Tooltip renders only when the field has a populated note OR
    example — empty tooltips would be a hollow promise.
  - Freeform-logsource path renders zero tooltips (no field
    catalogue → no helper text). Correct degradation.
  - 4 new structural tests in `tests/test_field_tooltips.py`.
  - Smoke-tested server-side: tooltips for `process_creation`'s
    `Image|endswith` and `CommandLine|contains` items contain the
    expected hand-curated note text and example values from
    `data/taxonomy/process_creation.yml`.

### Coming next

- **F4** — docs/ui.md update describing the field-tooltip contract +
  ROADMAP entry for a "Learn more" definition-links future-state
  enhancement (link tooltips out to MITRE ATT&CK / SigmaHQ field
  reference / internal glossary, post-v1.1).
- **L1/L2/L3 load-path corpus-wide hardening sweep** (per ROADMAP
  §v1.x) — the strategic answer to the load-rule bug-of-the-week
  pattern. Subsumes the three currently-open load follow-ups
  (filter-only Stage-2 inaccessible, missing-category P2 regression,
  Stage-2 metadata edits don't refresh preview).

## 0.2.9 — 2026-04-26

Patch bump.

### Shipped

- **F2** (`0555433`) — friendly modifier labels in the Stage 1 dropdown.
  Replaces raw Sigma modifier names (`endswith`, `windash`, `base64offset`)
  with plain-English labels per `docs/taxonomy.md` § "Modifier labels"
  (`ends with`, `Windows dash variants (-, /, –)`, `contains base64-encoded
  substring (offset-safe)`). Browser-native `title=` tooltips on each
  `<option>` carry longer hover-revealing explanations. Submitted form
  values stay canonical Sigma — display-only change. New helpers in
  `intel2sigma/core/taxonomy/modifier_labels.py` registered as Jinja
  globals; 8 new tests covering completeness against `ValueModifier`
  Literal + end-to-end Stage 1 render.
- **ROADMAP** — captured the **load-path corpus-wide hardening sweep**
  as a coherent v1.x milestone (L1 audit script → L2 fix list → L3
  user-facing surfacing). Replaces the patch-when-found cadence on
  load-rule bugs with a single corpus-wide audit pass that runs every
  bundled rule through the loader and categorises desyncs / exceptions
  / clean-loads. CI-gated via a slow regression test once L1 lands.

### Known follow-ups (rolled into the L2 fix list)

- Filter-only loaded rules make Stage 2 (Metadata) inaccessible
  (repro: SigmaHQ rule `db809f10-56ce-4420-8c86-d6a7d793c79c`).
- Logsource with no category (only product/service) escapes the
  `_freeform` fallback (repro: `34d81081-03c9-4a7f-91c9-5e46af625cde`,
  Bitbucket Unauthorized Full Data Export Triggered).
- Stage 2 metadata edits don't refresh the YAML preview pane.

These three are no longer "fix individually next" — they're inputs
to the L1 audit. Don't patch them piecemeal; the sweep will catch
them and any siblings as a coherent fix.

## 0.2.8 — 2026-04-26

Patch bump. **F1 verbiage audit complete.** All 36 observation types
now meet the contract documented in `docs/taxonomy.md`, and the
contract is machine-enforced going forward.

### Shipped

- **F1d-γ** — verbiage hand-review of 5 small-issue files (proxy,
  ps_module, wmi_event, network_connection, raw_access_thread). The
  proxy file got the biggest rework: full W3C-ELF-prefix label
  cleanup, header decoder, top-3 corpus-mined examples (TruffleHog /
  sqlmap user-agents, CONNECT-method-as-tunnel-signal).
- **F1d-δ** — consistency pass on the 11 originally-curated taxonomies
  (create_remote_thread, create_task, dns_query, driver_load,
  file_event, file_event_linux, image_load, pipe_created, ps_script,
  registry_set + a missing example on gcp_audit's alt-form
  method_name field). Every multi-field observation now has top-3
  notes + examples per the contract.
- **F1e** — six regression tests in `tests/test_taxonomy_verbiage.py`
  that lock the contract: label-pattern compliance, "Use " description
  prefix, synonyms ≥ 3, no PascalCase field labels, top-3 notes
  populated, top-3 non-enum examples populated. Future contributions
  that drift fail at test time.

### F1 totals

- 21 auto-generated taxonomies fully hand-reviewed (F1d-α / -β / -γ).
- 11 hand-curated taxonomies polished to the contract (F1d-δ).
- 36 / 36 observations pass the verbiage gate.
- 6 new regression tests; total suite at 326 tests.

### Coming next

- F2 — modifier label table (`endswith` → "ends with") + dropdown.
- F3 — hover tooltips on field rows (the actual helper UI).
- F4 — docs/ui.md update + ROADMAP definition-links future-state.

## 0.2.7 — 2026-04-26

Patch bump per the small-changes-bump-patch versioning policy.

### Shipped

- **F1d-α** (`22bafb8`) — verbiage hand-review of 10 OS event-log + Linux/macOS observation types (security_log, process_creation_linux, auditd, system_log, defender_log, application_log, process_access, registry_event, linux_misc, process_creation_macos). 59 synonyms, 31 notes, 29 examples. Fixes auditd's `a0`/`a1`/`a2` → "Syscall argument N" and `SYSCALL` → "Syscall name" labels that the F1c camel-splitter mangled. Adds `comm` field to auditd (used in real corpus rules but missing from auto-generated field list).
- **F1d-β** (`86f4f9d`) — verbiage hand-review of 10 cloud/SaaS observation types (cloudtrail, azure_activity, azure_audit, azure_signin, azure_risk, gcp_audit, okta, github_audit, opencanary, rpc_firewall). 64 synonyms, 24 notes, 23 examples — every example mined from real corpus rules. Renames "Azure AD" → "Azure AD / Entra ID" in labels for the modern Microsoft branding. Adds `gcp.audit.service_name` field (ECS-flattened pair to `data.protoPayload.serviceName` that most rules use).
- **Snyk false-positive cleanup** (`e815963`) — hardcode redirect destination in `web/app.py` to silence the open-redirect static-analysis flag. Threat model documented inline.
- **Roadmap entries** — draggable YAML/conversion-tabs row splitter (`8fe7e01`); supersedes the older "bump conversion-tabs cap" follow-up.

### Known follow-ups

- F1d-γ — 5 more YAMLs to hand-review (ps_module, wmi_event, network_connection, raw_access_thread, proxy).
- F1e — regression tests locking the verbiage contract.
- F2 + F3 — modifier labels + hover tooltips on field rows (the actual helper UI).
- B2d–B2g — 10 remaining heuristics.
- Stage 2 metadata edits don't refresh the YAML preview pane.
- Filter-only loaded rules make Stage 2 (Metadata) inaccessible (repro: SigmaHQ rule `db809f10-56ce-4420-8c86-d6a7d793c79c`).
- Draggable YAML/conversion-tabs row splitter (plan in ROADMAP §v1.x).

## 0.2.6 — 2026-04-26

First version bump since the project started at `0.1.0`. Captures the
considerable body of work shipped between then and now. From this
point forward, follow the policy above.

### Shipped since 0.1.0

- **Phase B1** — observation-catalogue expansion 15 → 36 types
  (cloud / SaaS / OS-event-log families).
- **Phase B2 a/b/c** — heuristics catalogue: 8 → 15 advisory checks
  (h-002, h-003 IOC top-up; h-010, h-011, h-012 overbroad-selection;
  h-022, h-032 lab-artifacts + path top-up).
- **Phase B3** — data-driven category-override pipeline lights up
  9 Sysmon-only categories on the Microsoft XDR backend.
- **Phase C** — SigmaHQ corpus browse + load (3,708 rules indexed).
- **Dual-mode prune** — Expert mode formally removed; corpus browse
  + freeform observation entry + breadcrumb cover the use cases.
- **Load-rule hardening** — preserves block names verbatim, routes
  unknown logsources to `_freeform`, multi-value editor, oob-swap
  preserves CSS classes, layout calc fixes, per-deploy cache-bust.
- **F1 (verbiage audit)** — partial: contract documented in
  `docs/taxonomy.md`; 106 raw-Sigma field labels mechanically
  humanized across 20 YAMLs; 10 OS-event-log + Linux/macOS files
  hand-reviewed for synonyms / notes / examples.
- **Snyk false-positive cleanup** — open-redirect refactor.

### Known follow-ups

- F1d-β / F1d-γ — 15 more YAMLs to hand-review.
- F1e — regression tests locking the verbiage contract.
- F2 + F3 — modifier labels + hover tooltips on field rows.
- B2d–B2g — 10 remaining heuristics.
- Long-rule layout: EDR conversion-tabs region wants to be slightly
  taller (50% cap feels tight when YAML is short).
- Stage 2 metadata edits don't refresh the YAML preview pane.
- Filter-only loaded rules make Stage 2 (Metadata) inaccessible
  (repro: SigmaHQ rule `db809f10-56ce-4420-8c86-d6a7d793c79c`).

## 0.1.0 — initial development

Project scaffold, MVP composer, 5-backend conversion matrix, 8
heuristics, hosted at intel2sigma.davidsharp.io. See git history
between project start and 2026-04-26.
