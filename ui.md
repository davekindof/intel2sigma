# UI specification

Contract for the presentation layer. Backend behavior is specified in SPEC.md and docs/architecture.md; this document specifies screen regions, interactions, and visual design.

## Modes

Two modes, same state, same endpoints, different shell templates.

### Guided mode (default for first-time users)

One stage at a time. Header shows "Step 2 of 5" and the stage name. Next and Back buttons at the bottom. Preview panel on the right is present but secondary. Health drawer collapsed by default, expands automatically when there is a critical-severity warning.

Target: users who have never written a Sigma rule and want to be walked through.

### Expert mode

All five stages stacked in a scrollable left column. Preview panel on the right is prominent and always updating. Health drawer collapsed by default with counts always visible in the bar.

Target: users who already know what they want and need the composer to stay out of their way.

### Mode switch

Prominent toggle in the header, labeled "Guided / Expert" with the current mode visually indicated. Clicking switches mode immediately, preserving current rule state. Preference persists in localStorage under the key `intel2sigma:mode`.

First-time users land in Guided. Returning users (localStorage key set) land in their last mode.

## Screen regions

Three logical regions plus the app header.

### Header

Fixed to the top. Contains:

- **Left**: wordmark "intel2sigma" and a compact version tag
- **Center**: breadcrumb of current stage (Guided) or nothing (Expert)
- **Right**: mode toggle, "New rule" button (confirms if current rule is non-empty), help link

Height: 48px. Background: `--color-surface`. Border-bottom: 1px `--color-border`.

### Composer panel (left)

In Guided mode: single stage partial, centered, max-width ~720px. Below the partial: Back button (left-aligned) and Next button (right-aligned, primary color). Back is disabled on stage 0; Next is disabled until the stage's required inputs are valid.

In Expert mode: all five stage partials stacked in a scrollable column. Width: 50% of viewport (minimum 480px). Each stage has a collapsible header showing completion state.

### Preview panel (right)

Always visible in Expert mode; collapsible in Guided mode (starts visible on stage ≥3, collapsed on stages 0–2 where there's little to preview).

Contains:

- **Primary pane**: canonical Sigma YAML, syntax-highlighted via Pygments, monospace. Copy button in the top right. Download button.
- **Conversion tabs**: one tab per target backend (Sentinel KQL, MDE KQL, Splunk SPL, Elastic ES|QL, CrowdStrike FQL). The last-used tab is remembered in localStorage. Each tab shows the converted query with a copy button and a small "Pipeline: microsoft_xdr" indicator.
- **Plain-English summary** (review stage onward): one-paragraph prose describing what the rule matches.

Width in Expert mode: 50% of viewport. In Guided mode: 40% of viewport when visible.

### Health drawer (bottom)

IDE-style collapsible drawer spanning the full width of the viewport. Fixed to the bottom edge.

**Collapsed state**: 32px tall bar showing counts by severity with icons:

```
[ ⛔ 1 critical   ⚠ 3 warnings   ℹ 2 info ]                        [ ^ expand ]
```

Zero issues: shows `✓ Rule is clean` in accent color.

**Expanded state**: 240px tall (resizable in Expert mode). Scrollable list grouped by severity, critical first. Each row:

- Severity icon
- Heuristic ID (e.g., `h-011`)
- One-line message
- "Show where" link that scrolls the composer to the relevant field and briefly highlights it (2-second glow)
- "Suggestion" button that expands an inline detail with the proposed fix

Toggle by clicking the bar or the expand/collapse button. `` Ctrl+` `` keybind added in v1.1.

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

Field dropdown is populated from the taxonomy for the chosen observation type. Core fields shown by default; "Show advanced fields" expander adds the rest. Modifier dropdown is populated from the field's `allowed_modifiers` list. Value input is type-aware: paths get path normalization hints, hashes get length validation, IPs get IP validation, regex gets a "regex mode — backend-dependent dialect" warning.

Auto-composed condition is shown below the blocks as read-only prose ("Match when all of `match_1`'s items are true, except when any of `filter_1`'s items are true"). An "edit condition manually" escape hatch exists in Expert mode only.

### Stage 2 — Metadata

Form with: title, description (multi-line, min 30 chars suggested), ATT&CK tag picker (auto-complete against a bundled MITRE ATT&CK technique list), level dropdown, false-positives list (multi-value), references list, author, date (auto-filled to today, editable).

Heuristic warnings about metadata completeness update live as the user fills in fields.

### Stage 3 — Review

Read-only rendering of the rule in prose ("This rule matches when…") with clickable references back to the blocks that produced each clause. Full health drawer contents shown. Copy of canonical YAML available in the preview pane.

### Stage 4 — Output

Expands the preview pane to full width (Guided mode) or highlights it (Expert mode). Focus on copy/download actions. "Build another rule" and "Export as…" buttons.

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

- **≥1280px**: default layout, both panels and drawer fully visible in Expert mode
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
- `Ctrl+/` — toggle Guided/Expert mode
- `Ctrl+Enter` — advance to next stage (Guided mode)

Standard browser shortcuts (Ctrl+F, Ctrl+C, Ctrl+V) are never intercepted.

## Branding placeholder

The color palette above is a placeholder pending finalization of davidsharp.io's brand palette. When that lands, swapping this palette is a single-file edit in `web/static/intel2sigma.css`. The "precision, preparation, pressure" ethos suggests a restrained, utilitarian aesthetic — monospace-forward, sharp edges (small radii), minimal ornamentation, no gradients or glass effects. This palette is designed to be consistent with that direction.
