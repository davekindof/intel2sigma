# Web state model

Design doc for how the in-progress rule travels between htmx requests and stages. Frozen because it dictates the shape of every composer route.

## The constraints this has to live within

1. **Stateless server** (CLAUDE.md I-3): no sessions, no per-user server storage.
2. **No JS build toolchain** (CLAUDE.md I-6): no React/Vue/npm; only htmx, server-rendered partials, server-side Pygments.
3. **htmx is the sole JS dependency** — anything beyond htmx's vocabulary (`hx-post`, `hx-include`, `hx-target`, etc.) needs to be handwritten, vendored, and SRI-hashed.
4. **Rule state is stateful but never complete** during composition. A stage-0 user has no title yet; a stage-1 user has no metadata; a stage-3 review has everything. The model must represent in-progress shapes without choking on missing fields.
5. **Guided mode and Expert mode share state, not templates.** A user switching mode mid-session keeps their rule.

## Options considered

**A. Hidden YAML textarea**
Serialize full rule as canonical Sigma YAML into a hidden `<textarea>`. `hx-include="#rule-state"` attaches it to every post. Server deserializes via `from_yaml`, mutates, re-serializes, returns a partial that re-injects the textarea.
- Pro: uses the serializer we already have; single source of truth.
- Con: canonical YAML is strict — an in-progress rule with a blank title or missing date is invalid, can't round-trip.
- Con: hidden textarea containing a full rule is a visible DOM element; size grows with block count.

**B. Hidden form fields per model path**
`<input hidden name="title" value="...">` for each scalar; `detections[0].items[1].field=Image` encoding for nested. On each post, parse the flattened form payload back into a rule model.
- Pro: Rails-style form handling is well-understood.
- Con: nested detection blocks with deletions and insertions need careful array-index management; lots of bookkeeping.
- Con: forms don't naturally roundtrip structured values (list of strings on `values:`).

**C. Hidden JSON blob**
Serialize rule as **JSON** (not YAML) into a hidden `<textarea>` or `<input>`. Unlike canonical YAML, JSON doesn't care whether the shape is a valid `SigmaRule` yet — it's just nested dicts/lists.
- Pro: permissive during composition; strict only when the user advances stages.
- Pro: single element, single source of truth, minimal DOM.
- Pro: JSON parse is cheap and well-defined.
- Con: users could in principle edit the JSON in devtools — but so could they edit any form field; no different from other options.

**D. `localStorage` + `hx-headers`**
Client stores rule in `localStorage` as JSON; a tiny script sends it as a `X-Rule-State` header on each htmx request.
- Pro: keeps the DOM clean.
- Con: requires handwritten JS beyond htmx — exactly what we're trying to minimize.
- Con: some proxies cap headers at 8KB; a rule with many detection blocks could overflow.
- Con: reloading the page with no server-side state needs a client-side bootstrapper that reconstructs the UI from localStorage on load — that's a meaningful chunk of custom JS.

**E. Session cookie + server stash**
Rejected: violates I-3.

## Decision

**Option C — hidden JSON blob.**

One `<textarea hidden name="rule_state">` element in the shell, containing a JSON-serialized draft of the rule. Every htmx request that can mutate state uses `hx-include="#rule-state"` to attach it. Every response is a partial that re-renders both the targeted region *and* the textarea, so state flows forward after each mutation.

We do **not** carry a fully-validated `SigmaRule` in the blob. The blob is a **draft**.

The draft models mirror the `core/model.py` shape but with everything permissive — blank strings, empty lists, and `None` are allowed intermediate states. The composer mutates the draft; conversion to a real `SigmaRule` only happens at stage transitions or when the preview pane needs to render.

```python
# intel2sigma/web/draft.py (lives in web/, not core/)

from __future__ import annotations
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field

from intel2sigma.core.model import (
    ConditionOp,
    ValueModifier,
    RuleLevel,
    RuleStatus,
)
from intel2sigma.core.validate.issues import ValidationIssue


class LogSourceDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str | None = None
    product: str | None = None
    service: str | None = None


class DetectionItemDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str = ""
    modifiers: list[ValueModifier] = Field(default_factory=list)
    values: list[str] = Field(default_factory=list)  # drafts hold raw strings;
                                                     # coercion to int/bool is
                                                     # core.model's concern


class DetectionBlockDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = ""
    is_filter: bool = False
    items: list[DetectionItemDraft] = Field(default_factory=list)


# Composer-owned condition representation. A node is either a leaf (selection
# name or glob) or an internal node (op + children). Serialized as nested
# dicts so it round-trips through the JSON blob without Pydantic gymnastics.
#
#   {"selection": "match_1"}
#   {"op": "and", "children": [{"selection": "match_1"}, {"op": "not",
#                              "children": [{"selection": "filter_1"}]}]}
#   {"op": "all_of", "children": [{"selection": "selection_*"}]}
#
# Validation into a core.model.ConditionExpression happens at .to_sigma_rule()
# time, not during composer mutation.
ConditionTreeDraft = dict


class RuleDraft(BaseModel):
    """Permissive intermediate carried in the hidden JSON blob.

    Every field is optional or has a harmless default so an in-progress rule
    at stage 0 (no metadata yet, no detection blocks) is still
    representable. The one thing we do validate strictly: the observation
    type id, if set, must match a catalogued taxonomy entry — that's how the
    composer knows which fields to offer.
    """

    model_config = ConfigDict(extra="forbid")

    # Metadata
    title: str = ""
    id: UUID | None = None
    status: RuleStatus = "experimental"
    description: str = ""
    references: list[str] = Field(default_factory=list)
    author: str = ""
    date: str = ""           # stored as ISO string in the draft to survive
                             # round-trips through JSON without date parsing
    modified: str = ""
    tags: list[str] = Field(default_factory=list)
    level: RuleLevel = "medium"
    falsepositives: list[str] = Field(default_factory=list)

    # Observation + logsource
    observation_id: str = ""     # taxonomy key, e.g. "process_creation"
    platform_id: str = ""         # "windows" / "linux" / "macos"
    logsource: LogSourceDraft = Field(default_factory=LogSourceDraft)

    # Detection
    detections: list[DetectionBlockDraft] = Field(default_factory=list)
    condition_tree: ConditionTreeDraft | None = None

    # Stage the composer is currently on — convenience for routing
    stage: int = 0

    def to_sigma_rule(self) -> "SigmaRule | list[ValidationIssue]":
        """Attempt conversion to a strict ``core.model.SigmaRule``.

        Returns the validated rule on success, or a list of
        ``ValidationIssue`` describing every reason it can't be built.
        Both preview rendering and stage transitions call this.
        """
        ...
```

`condition_tree` is stored as nested dicts rather than a Pydantic model because its shape is recursive and would force `model_rebuild()` gymnastics every time the draft JSON round-trips. The validation into `ConditionExpression` happens at `to_sigma_rule()` time, along with all the other strict-model coercion (UUIDs, dates, empty-string-to-None).

## Lifecycle of a request

```
1. GET /                         → shell + empty RuleDraft blob + stage-0 partial
2. POST /composer/observation    → hx-include rule_state
                                    deserialize → mutate logsource → reserialize
                                    return stage-1 partial + updated state blob
                                    Target: #composer-panel
3. POST /composer/item/add       → same pattern, adds a DetectionBlockDraft item
                                    Target: #match-blocks (partial region)
                                    Side effect: preview pane ALSO updates via
                                    hx-swap-oob (out-of-band)
4. POST /composer/advance        → same pattern; stage-1 → stage-2 transition
                                    Before transition: draft.to_sigma_rule() runs;
                                    if it fails, stage-1 rerenders with errors and
                                    the advance is blocked
```

State blob ships in every request, even read-only GETs if they need to render the preview.

## htmx patterns used

- `hx-include="#rule-state"` — attach the blob to a request.
- `hx-target` + `hx-swap="outerHTML"` — replace a specific region.
- `hx-swap-oob="true"` on elements in the response — update multiple regions (composer + preview + health drawer) from one response.
- No `hx-boost`, no custom event handlers, no extensions. If a feature feels like it needs an extension, first check whether we can re-render differently.

## Size considerations

A realistic maxed-out rule is ~4 KB of canonical YAML. JSON-as-draft is ~1.3× that. A POST payload with a 5 KB hidden blob + htmx metadata is well under every conceivable proxy limit. No paging/chunking needed.

## What this doc does NOT decide

- Stage-partial template structure (covered by [docs/ui.md](docs/ui.md)).
- How mode switching (Guided ↔ Expert) preserves state: same blob, different shell template. Confirmed here; detailed in the UI doc.
- Client-side draft persistence across page reloads: **not in v1**. A reload wipes in-progress state. v1.1 could add `localStorage` hydration as a small follow-up if users complain, with a vendored single-file script.
