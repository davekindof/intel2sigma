"""htmx-driven composer routes.

State flow (see docs/web-state-model.md):

1. Every request that mutates the rule includes the hidden ``rule_state``
   textarea via ``hx-include="#rule-state"``.
2. The server deserializes it into a :class:`RuleDraft`, applies the
   mutation indicated by ``action``, then returns the composer partial +
   an out-of-band updated state blob + an out-of-band updated preview
   pane.

Keeping every mutation in one route (``/composer/update``) means adding a
new action is a single switch-case branch plus maybe a helper on
:class:`RuleDraft`, not a whole new HTTP endpoint. Observation selection
and "restart" (return to stage 0) get their own routes because they
change the stage number, which affects which template renders.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from intel2sigma.core.convert import all_backend_ids, backend_label
from intel2sigma.core.serialize import to_yaml
from intel2sigma.core.taxonomy import (
    TaxonomyRegistry,
    load_taxonomy,
)
from intel2sigma.core.validate.issues import ValidationIssue
from intel2sigma.web.draft import (
    DetectionItemDraft,
    RuleDraft,
)
from intel2sigma.web.highlight import yaml_to_html

router = APIRouter(prefix="/composer")


# ---------------------------------------------------------------------------
# Dependency-like helpers
# ---------------------------------------------------------------------------


def _templates(request: Request) -> Jinja2Templates:
    """Pull the Jinja2Templates object off the FastAPI app state.

    The app factory attaches it in ``create_app``; keeping it on app state
    lets route modules fetch it without a circular import back to
    ``intel2sigma.web.app``.
    """
    return request.app.state.templates  # type: ignore[no-any-return]


def _taxonomy(request: Request) -> TaxonomyRegistry:
    return request.app.state.taxonomy  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Observation-selection helpers (used by stage 0 render path)
# ---------------------------------------------------------------------------


GROUP_LABELS: dict[str, str] = {
    "process_and_execution": "Process & Execution",
    "file_and_registry": "File & Registry",
    "network": "Network",
    "scheduled_and_system": "Scheduled & System",
    "powershell_and_scripting": "PowerShell & Scripting",
}
GROUP_ORDER: tuple[str, ...] = tuple(GROUP_LABELS.keys())


def _build_observation_groups(
    taxonomy: TaxonomyRegistry,
) -> list[tuple[str, str, list[dict[str, Any]]]]:
    """Shape the taxonomy for the stage-0 card grid.

    Returns a list of ``(group_id, group_label, entries)`` triples in the
    fixed order from ``docs/ui.md``. Each entry dict carries what the
    template needs to render one card.
    """
    grouped = taxonomy.by_group()
    result: list[tuple[str, str, list[dict[str, Any]]]] = []
    for group_id in GROUP_ORDER:
        # ``grouped`` keys are a Literal CategoryGroup; iterating our own
        # GROUP_ORDER tuple of strs means mypy can't prove the key is valid
        # at call time even though we declared the same literals.
        obs_ids: list[str] = list(grouped.get(group_id, []))  # type: ignore[call-overload]
        entries: list[dict[str, Any]] = []
        for obs_id in obs_ids:
            spec = taxonomy.get(obs_id)
            search_text = " ".join([spec.id, spec.label, *spec.synonyms, spec.description])
            entries.append(
                {
                    "id": spec.id,
                    "label": spec.label,
                    "description": spec.description,
                    "platforms": [p.id for p in spec.platforms],
                    "search_text": search_text,
                }
            )
        if entries:
            result.append((group_id, GROUP_LABELS[group_id], entries))
    return result


# ---------------------------------------------------------------------------
# Rendering helpers — build the context dict each stage needs
# ---------------------------------------------------------------------------


def _render_stage(request: Request, draft: RuleDraft) -> HTMLResponse:
    """Render the composer-panel contents for the draft's current stage.

    Out-of-band swaps for the state blob and the preview pane are
    concatenated into the same response so one htmx POST updates three
    regions at once.
    """
    templates = _templates(request)
    taxonomy = _taxonomy(request)

    composer_html = _render_composer_panel(request, draft, taxonomy)
    preview_context = _preview_context(draft)
    preview_html = templates.get_template("partials/preview_pane.html").render(
        request=request, **preview_context
    )
    state_html = templates.get_template("partials/state_blob.html").render(
        request=request, draft_json=draft.to_json()
    )

    # Wrap oob targets. htmx reads `hx-swap-oob` on the outer element and
    # swaps the matching id on the page. For the state blob the element
    # IS the target (id=rule-state), so it already has hx-swap-oob on it.
    # For the preview, we wrap the rendered content in a fresh
    # #preview-pane / #conversion-tab-body outer so the oob swap replaces
    # the right region.
    preview_oob = f'<div id="preview-pane" hx-swap-oob="true">{preview_html}</div>'

    body = f"{composer_html}\n{preview_oob}\n{state_html}"
    return HTMLResponse(body)


def _render_composer_panel(request: Request, draft: RuleDraft, taxonomy: TaxonomyRegistry) -> str:
    """Render the stage partial appropriate for the draft's current stage."""
    templates = _templates(request)

    if draft.stage == 0 or not draft.observation_id:
        return templates.get_template("composer/stage0_observation.html").render(
            request=request,
            observation_groups=_build_observation_groups(taxonomy),
        )

    try:
        spec = taxonomy.get(draft.observation_id)
    except KeyError:
        # Corrupted blob or taxonomy drift — fall back to stage 0.
        draft.stage = 0
        draft.observation_id = ""
        return templates.get_template("composer/stage0_observation.html").render(
            request=request,
            observation_groups=_build_observation_groups(taxonomy),
        )

    field_specs_by_name = {f.name: f for f in spec.fields}
    return templates.get_template("composer/stage1_detection.html").render(
        request=request,
        observation_spec=spec,
        platform_id=draft.platform_id or (spec.platforms[0].id if spec.platforms else ""),
        match_blocks=[b for b in draft.detections if not b.is_filter],
        filter_blocks=[b for b in draft.detections if b.is_filter],
        field_specs_by_name=field_specs_by_name,
        composed_condition=_describe_condition(draft),
    )


def _describe_condition(draft: RuleDraft) -> str:
    """Plain-English auto-composed condition for the stage-1 footer.

    Mirrors what :meth:`RuleDraft._compose_condition` builds so the user
    sees the same logic the serializer will emit. Kept as prose here
    rather than the raw Sigma string — that's for the preview pane.
    """
    matches = [b for b in draft.detections if not b.is_filter]
    filters = [b for b in draft.detections if b.is_filter]
    if not matches:
        return ""
    if len(matches) == 1:
        match_desc = f"the match block '{matches[0].name}' matches"
    else:
        match_desc = "all match blocks match"
    if not filters:
        return match_desc
    if len(filters) == 1:
        filter_desc = f"the filter '{filters[0].name}' does not"
    else:
        filter_desc = "no filter block matches"
    return f"{match_desc}, and {filter_desc}"


def _preview_context(draft: RuleDraft) -> dict[str, Any]:
    """Canonical YAML + any draft-to-rule validation issues for the preview."""
    result = draft.to_sigma_rule()
    if isinstance(result, list):
        # Draft not yet a valid rule — show blank preview + issue list.
        return {
            "preview_yaml": "",
            "preview_yaml_html": "",
            "preview_issues": _sorted_issues(result),
        }
    yaml_text = to_yaml(result)
    return {
        "preview_yaml": yaml_text,
        "preview_yaml_html": yaml_to_html(yaml_text),
        "preview_issues": [],
    }


def _sorted_issues(issues: Iterable[ValidationIssue]) -> list[ValidationIssue]:
    """Stable sort so the preview pane doesn't reorder between identical states."""
    return sorted(issues, key=lambda i: (i.tier, i.code, i.location or ""))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/select-observation", name="select_observation")
async def select_observation(
    request: Request,
    rule_state: Annotated[str, Form()] = "",
    observation_id: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Stage 0 → 1 transition: user clicked an observation card."""
    draft = RuleDraft.from_json(rule_state)
    taxonomy = _taxonomy(request)

    try:
        spec = taxonomy.get(observation_id)
    except KeyError:
        # Silently ignore unknown ids; re-render stage 0.
        return _render_stage(request, draft)

    draft.observation_id = spec.id
    draft.platform_id = spec.platforms[0].id if spec.platforms else ""
    draft.logsource.category = spec.logsource.category
    draft.logsource.product = spec.platforms[0].product if spec.platforms else None
    draft.logsource.service = spec.logsource.service
    draft.stage = 1
    return _render_stage(request, draft)


@router.post("/restart", name="composer_restart")
async def composer_restart(
    request: Request,
    rule_state: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Back button on stage 1 — clear observation selection, return to stage 0."""
    draft = RuleDraft.from_json(rule_state)
    draft.observation_id = ""
    draft.platform_id = ""
    draft.logsource = draft.logsource.__class__()
    draft.detections = []
    draft.condition_tree = None
    draft.stage = 0
    return _render_stage(request, draft)


@router.post("/update", name="composer_update")
async def composer_update(request: Request) -> HTMLResponse:
    """Catch-all mutation route.

    The ``action`` form field selects the branch; remaining form fields
    carry parameters. Unknown actions are treated as no-ops (re-render the
    current stage). Form parsing happens here rather than via typed
    ``Form(...)`` parameters because the set of fields differs per action.
    """
    form = await request.form()
    raw_state = str(form.get("rule_state", ""))
    draft = RuleDraft.from_json(raw_state)
    action = str(form.get("action", "")).strip()

    _apply_action(draft, action, form)
    return _render_stage(request, draft)


def _apply_action(draft: RuleDraft, action: str, form: Any) -> None:
    """Mutate ``draft`` in place based on the action verb.

    Kept as a pure-ish function (no I/O, no template) so tests can drive
    it directly without spinning up a TestClient.
    """
    match action:
        case "add_match":
            draft.add_match_block()
        case "add_filter":
            draft.add_filter_block()
        case "delete_block":
            draft.delete_block(str(form.get("block_name", "")))
        case "rename_block":
            _rename_block(draft, form)
        case "add_item":
            draft.add_item(str(form.get("block_name", "")))
        case "delete_item":
            _delete_item(draft, form)
        case "set_field":
            _set_item_field(draft, form)
        case "set_modifier":
            _set_item_modifier(draft, form)
        case "set_value":
            _set_item_value(draft, form)
        case _:
            # Unknown action — ignore. The stage re-renders as-is.
            pass


def _rename_block(draft: RuleDraft, form: Any) -> None:
    old = str(form.get("old_name", ""))
    # The new name comes from the named input ``block_name::<old>``. Look it
    # up directly to avoid collisions with other fields' ``block_name`` keys.
    new = str(form.get(f"block_name::{old}", "")).strip()
    if not old or not new or old == new:
        return
    # No-op if the rename would collide with another block.
    if any(b.name == new for b in draft.detections):
        return
    for block in draft.detections:
        if block.name == old:
            block.name = new
            break


def _delete_item(draft: RuleDraft, form: Any) -> None:
    block_name = str(form.get("block_name", ""))
    try:
        item_index = int(str(form.get("item_index", "")))
    except ValueError:
        return
    draft.delete_item(block_name, item_index)


def _set_item_field(draft: RuleDraft, form: Any) -> None:
    item = _resolve_item(draft, form)
    if item is None:
        return
    block_name = str(form.get("block_name", ""))
    item_index = _int_or_none(str(form.get("item_index", "")))
    if item_index is None:
        return
    new_field = str(form.get(f"field::{block_name}::{item_index}", "")).strip()
    item.field = new_field
    # Changing the field invalidates the modifier chain — reset it.
    item.modifiers = []


def _set_item_modifier(draft: RuleDraft, form: Any) -> None:
    item = _resolve_item(draft, form)
    if item is None:
        return
    block_name = str(form.get("block_name", ""))
    item_index = _int_or_none(str(form.get("item_index", "")))
    if item_index is None:
        return
    raw = str(form.get(f"modifier::{block_name}::{item_index}", "")).strip()
    # Store as a single-element chain for v0. M1.4+ will model multi-mod
    # composition (e.g. contains|all, contains|windash) via a separate
    # widget; for now one modifier is the expressible shape.
    item.modifiers = [raw] if raw else []  # type: ignore[list-item]  # runtime-validated against ValueModifier


def _set_item_value(draft: RuleDraft, form: Any) -> None:
    item = _resolve_item(draft, form)
    if item is None:
        return
    block_name = str(form.get("block_name", ""))
    item_index = _int_or_none(str(form.get("item_index", "")))
    if item_index is None:
        return
    raw = str(form.get(f"value::{block_name}::{item_index}", ""))
    item.values = [raw] if raw else []


def _resolve_item(draft: RuleDraft, form: Any) -> DetectionItemDraft | None:
    block_name = str(form.get("block_name", ""))
    idx = _int_or_none(str(form.get("item_index", "")))
    if idx is None:
        return None
    block = next((b for b in draft.detections if b.name == block_name), None)
    if block is None or not (0 <= idx < len(block.items)):
        return None
    return block.items[idx]


def _int_or_none(raw: str) -> int | None:
    try:
        return int(raw)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Stage-0 GET used by the shell (via the main app's guided_home route)
# ---------------------------------------------------------------------------


def initial_composer_context(request: Request, taxonomy: TaxonomyRegistry) -> dict[str, Any]:
    """Context dict for the initial shell render.

    ``app.py`` imports this and passes the result to the base template so
    the shell's ``{% block composer %}`` and preview defaults match what
    ``_render_stage`` would produce for an empty draft.
    """
    empty = RuleDraft()
    return {
        "initial_composer_html": _render_composer_panel(request, empty, taxonomy),
        "initial_state_json": empty.to_json(),
        "initial_preview_context": _preview_context(empty),
        "backend_tabs": [{"id": bid, "label": backend_label(bid)} for bid in all_backend_ids()],
    }


# Used by the app factory to eagerly load the taxonomy once at startup so the
# first request doesn't pay the catalog-parse cost.
def prime_taxonomy() -> TaxonomyRegistry:
    return load_taxonomy()
