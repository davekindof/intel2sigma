# UI specification

Contract for the presentation layer. Backend behavior is specified in SPEC.md and docs/architecture.md; this document specifies screen regions, interactions, and visual design.

## Single-mode composer

One mode: a five-stage flow with structured input on the left, live YAML preview on the right. Earlier drafts of this doc described two modes (Guided / Expert); the dual-mode story was pruned without ever shipping the second mode — see SPEC.md decision log entry dated 2026-04-26. Power-user paths that Expert mode would have served are now covered by:

* The breadcrumb at the top of every stage — click any reachable stage to jump there directly without going through Next/Back.
* The freeform observation entry on Stage 0 — bypass the catalog when your logsource is unusual.
* The SigmaHQ corpus browse tab on the load modal — search ~3700 vetted rules and edit one in place of starting from scratch.
* The CLI (``intel2sigma convert rule.yml --backend kusto``) — text-editor-driven workflow for users who'd rather not touch a UI.

## Screen regions

Three logical regions plus the app header.

### Header

Fixed to the top. Contains:

- **Left**: wordmark "intel2sigma" and a compact version tag
- **Right**: "Load rule" button (opens load modal), "New rule" button (confirms if current rule is non-empty), help link

Height: 48px. Background: `--color-surface`. Border-bottom: 1px `--color-border`.

### Composer panel (left)

Stage breadcrumb at top — five clickable steps with the current one highlighted in accent green. Then the active stage partial: single stage at a time, centered, max-width ~720px. Below the partial: Back button (left-aligned) and Next button (right-aligned, primary color). Back is disabled on Stage 0; Next is disabled until the stage's prerequisites are met.

### Preview panel (right)

Always visible. Updates on every keystroke (300ms debounce) so the user sees the rule taking shape live, not as a finale.

Contains:

- **Primary pane**: canonical Sigma YAML, syntax-highlighted via Pygments, monospace. When the draft is incomplete, a best-effort "partial YAML" renders alongside the tier-1 issue list — better than a blank pane.
- **Conversion tabs**: one tab per target backend (Sentinel KQL, MDE KQL, Splunk SPL, Elastic Lucene, CrowdStrike LogScale). Each tab shows the converted query; populated only once the rule is fully valid (tier-1 + tier-2 clean).
- **Plain-English summary**: also shown inside Stage 1 and Stage 3 partials so users see "what does this rule do" without reading YAML.

Width: 40% of viewport.

### Health drawer (bottom)

IDE-style collapsible drawer spanning the full width of the viewport. Fixed to the bottom edge.

**Collapsed state**: 32px tall bar showing counts by severity with icons:

```
[ ⛔ 1 critical   ⚠ 3 warnings   ℹ 2 info ]                        [ ^ expand ]
```

Zero issues: shows `✓ Rule is clean` in accent color.

**Expanded state**: 240px tall. Scrollable list grouped by severity, critical first. Each row:

- Severity icon
- Heuristic ID (e.g., `h-011`)
- One-line message
- "Show where" link that scrolls the composer to the relevant field and briefly highlights it (2-second glow)
- "Suggestion" button that expands an inline detail with the proposed fix

Toggle by clicking the bar or the expand/collapse button. `` Ctrl+` `` keybind added in v1.1.

### Inline error decoration (IDE-esque)

The health drawer is the aggregate view; in addition, validation errors decorate the **specific field** they blame in the composer. The presentation is "squiggle equivalent" — an IDE-style inline signal users recognize without having to read documentation:

- **Field-level error ring**: when a tier-1 issue has a `location` pointing at a specific input (e.g. `detections[0].items[2]`), that input renders with a 2px accent-red outline (`--color-critical`) instead of the default focus ring. The outline persists until the field is edited.
- **Inline error message**: a one-line `--color-critical` text block appears immediately below the offending field — short, specific, actionable ("Field 'Image' uses modifier 'cidr' which isn't valid for paths"). Clicking it expands the full `ValidationIssue.message`.
- **Tier-1 vs. tier-2 distinction**: tier-1 errors decorate the specific input; tier-2 errors (pySigma-level, often about the rule as a whole) decorate the preview pane's YAML line with a red gutter mark and a tooltip on hover.
- **Heuristic warnings** (tier-3 + heuristics, non-blocking) use `--color-warn` for the outline and message — visually subordinate to errors.
- **Hover tooltip**: hovering the decorated input shows the full error message plus the error code (e.g. `T1_MODIFIER_NOT_ALLOWED`) in a small tooltip. This mirrors IDE diagnostic tooltips.
- **Health drawer is still canonical**: the drawer's "Show where" link still scrolls + highlights the field with the 2-second glow; inline decoration and drawer entries are views of the same underlying issue list.

Server side, the errors arrive with the htmx response as part of the state blob (see [docs/web-state-model.md](web-state-model.md)). Each partial that renders a potentially-errored field looks up its own location in the issue list and applies the decoration.

**No squiggly-underline rendering** — that requires either SVG overlays or a CSS trick that doesn't degrade well without JS. The solid red outline + inline text carries the same information without the implementation tax.

## Stage partials

Each stage is a Jinja2 partial template loaded via htmx. The `web/templates/composer/` directory holds them:

- `stage0_observation.html`
- `stage1_detection.html`
- `stage2_metadata.html`
- `stage3_review.html`
- `stage4_output.html`

### Stage 0 — Observation selection

Card grid grouped under five section headers:

- **Process & Execution**: process_creation, image_load, create_remote_thread, raw_access_thread, pipe_created
- **File & Registry**: file_event, registry_event
- **Network**: network_connection, dns_query
- **Scheduled & System**: create_task, wmi_event, driver_load
- **PowerShell & Scripting**: ps_script, ps_module

Search bar at top: filters cards by display name and by taxonomy synonyms (e.g., "process launched" → process_creation).

Each card:
- Display name (e.g., "A process was started")
- One-sentence description
- Platform chips: Windows / Linux / macOS
- Inline SVG glyph (minimal, no external icon library)

Selecting a card advances to stage 1. Selection is remembered if the user returns to stage 0.

### Stage 1 — Detection block composition

Two stacked regions: **Match blocks** and **Filter blocks** (except-when). Each block has:

- A name (auto-generated, user-editable: "match_1", "filter_suspicious_parent")
- A block-level combinator toggle: "all of these must be true" / "any of these can be true"
- A list of detection items, each a row with: field dropdown → modifier dropdown → value input(s)
- An "Add item" button

Field dropdown is populated from the taxonomy for the chosen observation type. Core fields shown by default; "Show advanced fields" expander adds the rest. Modifier dropdown shows **plain-English labels** ("ends with" instead of `endswith`) per the table in `docs/taxonomy.md` § "Modifier labels"; the canonical Sigma string is still the submitted form value. Each `<option>` carries a `title=` attribute with a one-sentence explanation as a browser-native tooltip (the only path to per-option help text inside a native `<select>` overlay).

Value input is type-aware: paths get path normalization hints, hashes get length validation, IPs get IP validation, regex gets a "regex mode — backend-dependent dialect" warning.

Auto-composed condition is shown below the blocks as read-only prose ("Match when all of `match_1`'s items are true, except when any of `filter_1`'s items are true"). The composer never exposes a manually-editable condition string per CLAUDE.md I-4 — the structured block view is the source of truth.

#### Field-row helper tooltip (F3)

Hovering any populated detection-item row reveals a small dark-themed tooltip below it showing the field's plain-English explanation and a real-looking example value. The tooltip is the user-facing payoff of the F1 verbiage audit and drives the non-SIEM-audience product thesis: a user who's never written a Sigma rule can hover any field and read what it actually means without leaving the composer.

**Source of truth.** Each tooltip's content comes from the field's `note` and `example` entries in `data/taxonomy/<id>.yml`. The F1b contract requires every observation's top-3 fields (the most-used per corpus calibration) to populate both; lower-frequency fields populate them as quality permits. Tests in `tests/test_taxonomy_verbiage.py` enforce the contract — adding a field to a top-3 slot without populating the helper data fails CI.

**Render rules.**

- Tooltip renders only when the field has a populated `note` OR `example`. Empty tooltips are a hollow promise; graceful skip is correct.
- Freeform-logsource path (no observation_spec) renders no tooltips — there's no field catalog to draw helper text from.
- Composer-default rows (`match_1` with no field picked yet) render no tooltip — the user hasn't committed to a field, there's nothing to explain.

**Behaviour.**

- Pure CSS show/hide via `:hover` and `:focus-within` on `.detection-item`. No JS. Keyboard-accessible — tabbing onto the field / modifier / value reveals the tooltip via focus-within.
- 300ms appearance delay (intentional-hover threshold) before fade-in; immediate fade-out on mouse leave. Asymmetric `transition-delay` on the `:hover` rule produces this with one CSS property.
- `pointer-events: none` on the tooltip — it overlays adjacent rows visually but never blocks clicks. The user can move the cursor across the form unimpeded.
- Tooltip anchored `top: calc(100% + 4px); left: 0` of its row — appears below the row, indented to the row's left edge. `max-width: min(480px, 100%)` so it can't push past the panel edge.

**Visual.**

```
┌───────────────────────────────────────────┐
│ [Image ▾]  [ends with ▾]  [\powershell.exe]  ✕│
└───────────────────────────────────────────┘
   ┌────────────────────────────────────────┐
   │ Path suffix with leading backslash     │
   │ matches the executable regardless of   │
   │ directory.                             │
   │                                        │
   │ ┌──────────────────────┐               │
   │ │ Example: \powershell.exe │  ← accent green chip
   │ └──────────────────────┘               │
   └────────────────────────────────────────┘
```

**Accessibility.** Keyboard users get the same tooltip on focus via `:focus-within`. The tooltip's `role="tooltip"` is semantic-only (no `aria-describedby` link to the input — adding that is a future enhancement; tracked in the "Stage 1 field helpers — definition links" ROADMAP entry). Screen readers fall back to the field's existing `aria-label` ("Field" / "Modifier" / "Value(s) — one per line").

**Why hover instead of click-to-expand.** Earlier drafts proposed a click-to-expand `ⓘ` icon next to each field with a persistent expand-state in localStorage. Pruned in favour of hover because: (1) hover is more discoverable than icons, (2) zero DOM cost when not engaged means veterans never see the helper, (3) no state to persist (every htmx swap re-renders fresh), (4) `:focus-within` covers keyboard users. The icon-click approach is a fallback if user testing finds the hover threshold too short / too long.

### Stage 2 — Metadata

Form with: title, description (multi-line, min 30 chars suggested), ATT&CK tag picker (auto-complete against a bundled MITRE ATT&CK technique list), level dropdown, false-positives list (multi-value), references list, author, date (auto-filled to today, editable).

Heuristic warnings about metadata completeness update live as the user fills in fields.

### Stage 3 — Review

Read-only rendering of the rule in prose ("This rule matches when…") with clickable references back to the blocks that produced each clause. Full health drawer contents shown. Copy of canonical YAML available in the preview pane.

### Stage 4 — Output

Expands the preview pane to full width. Focus on copy/download actions. "Build another rule" and "Build similar rule" buttons.

## Color palette

Green-forward dark theme, GitHub-dark-inspired, designed to be contrast-accessible and visually distinct from vendor-branded tools (Splunk orange, Sentinel blue, CrowdStrike red).

All colors live in `:root` as CSS custom properties in `web/static/intel2sigma.css`. Swapping the palette is a single-file edit.

```css
:root {
  --color-bg:           #0d1117;
  --color-surface:      #161b22;
  --color-surface-alt:  #1f2630;
  --color-border:       #2d333b;
  --color-border-muted: #21262d;

  --color-text:         #e6edf3;
  --color-text-muted:   #8b949e;
  --color-text-dim:     #6e7681;

  --color-accent:       #3fb950;  /* Primary green */
  --color-accent-hover: #56d364;
  --color-accent-active: #2ea043;
  --color-accent-muted: #1a3a1e;  /* For subtle green backgrounds */

  --color-critical:     #f85149;
  --color-warn:         #d29922;
  --color-info:         #58a6ff;
  --color-success:      #3fb950;  /* Same as accent */

  --color-code-bg:      #0d1117;
  --color-code-border:  #30363d;

  /* Typography */
  --font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, "SF Mono", Consolas, monospace;

  /* Spacing (multiples of 4) */
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-6: 24px;
  --space-8: 32px;
  --space-12: 48px;

  /* Radii */
  --radius-sm: 4px;
  --radius-md: 6px;
  --radius-lg: 8px;

  /* Shadows — subtle, never flashy */
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.3);
  --shadow-md: 0 4px 8px rgba(0, 0, 0, 0.4);
}
```

Light mode is not supported in v1. Target audience works in dark environments; light mode adds design work without matching user demand.

## Typography

- **UI**: system font stack for fast rendering and native OS feel
- **Code**: JetBrains Mono as progressive enhancement (pinned SRI-hashed Google Fonts, or self-hosted if third-party fonts become a concern), with `ui-monospace, monospace` fallback
- **Sizes**: 14px base, 16px for primary inputs, 13px for secondary labels, 12px for helper text. `rem` everywhere; never hardcoded pixel values in components.

## Responsive behavior

- **≥1280px**: default layout, both panels and drawer fully visible
- **1024px – 1279px**: narrower preview panel, composer remains workable
- **768px – 1023px**: stacked layout (composer above, preview below) with a notice explaining the tool is designed for larger screens
- **<768px**: full-page notice: "intel2sigma is a desktop tool. Please resize your window or use a larger screen."

No effort goes into true mobile support.

## Interaction patterns

- **htmx everywhere.** Form submissions are htmx requests that replace a specific target region. No full-page reloads except on mode switch and initial load.
- **Debounce field edits.** Free-text inputs that trigger server-side re-conversion are debounced at 300ms. Structural changes (adding/removing blocks, changing observation type) trigger immediately.
- **Optimistic UI where safe.** Adding a detection item shows the new row immediately; the server response updates the preview.
- **Loading states are subtle.** A thin accent-colored bar at the top of the target region indicates in-flight requests. No spinners, no skeleton screens (the app is too fast for them to be worth building).

## Accessibility

- **Tab order follows visual order.** Every interactive element reachable via keyboard.
- **Labels and ARIA where appropriate.** Dropdowns have visible labels; icon-only buttons have `aria-label`.
- **Color-blind friendly.** Severity icons always accompany severity colors; the critical/warn/info distinction is never communicated by color alone.
- **Focus rings visible.** `:focus-visible` styles use the accent color with a 2px offset.
- **No motion where it doesn't help.** Transitions ≤150ms. No parallax, no autoplay, no marquee anything.

## Keyboard shortcuts (v1.1)

Deferred from v1. Planned:

- `Ctrl+K` — focus observation search in stage 0 / open observation picker
- `Ctrl+D` — download canonical YAML
- `` Ctrl+` `` — toggle health drawer
- `Ctrl+Enter` — advance to next stage

Standard browser shortcuts (Ctrl+F, Ctrl+C, Ctrl+V) are never intercepted.

## Branding placeholder

The color palette above is a placeholder pending finalization of davidsharp.io's brand palette. When that lands, swapping this palette is a single-file edit in `web/static/intel2sigma.css`. The "precision, preparation, pressure" ethos suggests a restrained, utilitarian aesthetic — monospace-forward, sharp edges (small radii), minimal ornamentation, no gradients or glass effects. This palette is designed to be consistent with that direction.
