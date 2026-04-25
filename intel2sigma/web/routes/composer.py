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
from urllib.parse import quote

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from intel2sigma.core.convert import (
    ConversionFailedError,
    UnknownBackendError,
    all_backend_ids,
    backend_label,
    convert,
    resolve,
)
from intel2sigma.core.model import SigmaRule
from intel2sigma.core.serialize import to_yaml
from intel2sigma.core.taxonomy import (
    TaxonomyRegistry,
    load_taxonomy,
)
from intel2sigma.core.validate import validate_tier3
from intel2sigma.core.validate.issues import ValidationIssue
from intel2sigma.web.draft import (
    DetectionBlockDraft,
    DetectionItemDraft,
    IOCSession,
    RuleDraft,
)
from intel2sigma.web.highlight import yaml_to_html
from intel2sigma.web.ioc import (
    build_detection_items,
    classify,
    summarise,
)
from intel2sigma.web.load import (
    draft_from_yaml,
    list_examples,
    load_example,
)
from intel2sigma.web.mitre import load_mitre_tree

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
    # app.state attributes are Any; create_app attaches a Jinja2Templates here.
    return request.app.state.templates  # type: ignore[no-any-return]


def _taxonomy(request: Request) -> TaxonomyRegistry:
    # Same Any-narrowing as _templates: prime_taxonomy() attaches at startup.
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
    tabs_html = templates.get_template("partials/conversion_tabs.html").render(
        request=request, **preview_context
    )
    state_html = templates.get_template("partials/state_blob.html").render(
        request=request, draft_json=draft.to_json()
    )

    # htmx oob-swap semantics: each wrapper carries hx-swap-oob="true" and its
    # own id, telling htmx which region on the page to replace. The state
    # blob template owns its own oob attr; the two preview regions we wrap
    # here because they render plain content-for-region.
    preview_oob = f'<div id="preview-pane" hx-swap-oob="true">{preview_html}</div>'
    tabs_oob = f'<div id="conversion-tabs-region" hx-swap-oob="true">{tabs_html}</div>'

    body = f"{composer_html}\n{preview_oob}\n{tabs_oob}\n{state_html}"
    return HTMLResponse(body)


def _render_composer_panel(request: Request, draft: RuleDraft, taxonomy: TaxonomyRegistry) -> str:  # noqa: PLR0911 (one branch per stage reads clearly as a switch)
    """Render the stage partial appropriate for the draft's current stage."""
    templates = _templates(request)

    if draft.stage == 0 or not draft.observation_id:
        return templates.get_template("composer/stage0_observation.html").render(
            request=request,
            observation_groups=_build_observation_groups(taxonomy),
            ioc_summaries=_ioc_panel_context(draft),
            ioc_total=len(draft.iocs),
            ioc_used_count=sum(1 for i in draft.iocs if i.used),
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
            ioc_summaries=_ioc_panel_context(draft),
            ioc_total=len(draft.iocs),
            ioc_used_count=sum(1 for i in draft.iocs if i.used),
        )

    if draft.stage == 2:
        return templates.get_template("composer/stage2_metadata.html").render(
            request=request,
            draft=draft,
            can_advance=draft.can_advance_to_stage(3),
            attack_tag_suggestions=_ATTACK_TAG_SUGGESTIONS,
            mitre_tree=load_mitre_tree(),
            selected_attack_tags=set(draft.tags),
        )

    if draft.stage == 3:
        rule_or_issues = draft.to_sigma_rule()
        issues = rule_or_issues if isinstance(rule_or_issues, list) else []
        rule = rule_or_issues if isinstance(rule_or_issues, SigmaRule) else None
        # Tier 3 (heuristics) only runs when tier 1 + tier 2 pass — there's
        # no signal in heuristically reviewing an unparseable rule.
        advisories = validate_tier3(rule) if rule is not None else []
        return templates.get_template("composer/stage3_review.html").render(
            request=request,
            draft=draft,
            rule=rule,
            review_issues=_sorted_issues(issues),
            advisories=_sorted_advisories(advisories),
            prose_summary=_prose_summary(rule, draft),
            can_advance=rule is not None,
        )

    if draft.stage == 4:
        rule_or_issues = draft.to_sigma_rule()
        if not isinstance(rule_or_issues, SigmaRule):
            # Shouldn't happen — /composer/advance gates this — but fall back
            # to review rather than silently serving an empty Stage 4.
            draft.stage = 3
            return _render_composer_panel(request, draft, taxonomy)
        rule = rule_or_issues
        return templates.get_template("composer/stage4_output.html").render(
            request=request,
            draft=draft,
            rule=rule,
            prose_summary=_prose_summary(rule, draft),
            rule_state_urlencoded=quote(draft.to_json()),
            download_filename=_download_filename(rule),
        )

    # Default: stage 1 — detection editor.
    field_specs_by_name = {f.name: f for f in spec.fields}
    return templates.get_template("composer/stage1_detection.html").render(
        request=request,
        observation_spec=spec,
        platform_id=draft.platform_id or (spec.platforms[0].id if spec.platforms else ""),
        match_blocks=[b for b in draft.detections if not b.is_filter],
        filter_blocks=[b for b in draft.detections if b.is_filter],
        match_combinator=draft.match_combinator,
        field_specs_by_name=field_specs_by_name,
        composed_condition=_describe_condition(draft),
        # Plain-English summary woven from observation + populated fields.
        # Same helper Stage 3 uses; with rule=None it works on the draft
        # alone, which is what we have on Stage 1. Lets non-Sigma users
        # see "what does this rule actually do?" without reading YAML.
        prose_summary=_prose_summary(None, draft),
        can_advance=draft.can_advance_to_stage(2),
    )


# A small hand-picked set of ATT&CK tactic + technique tags the metadata
# form uses as a datalist for autocomplete. Full technique picker is
# deferred to v1.1 per the milestone plan; this covers the common cases
# for Windows process-creation rules, which is what the MVP demos.
_ATTACK_TAG_SUGGESTIONS: tuple[str, ...] = (
    "attack.execution",
    "attack.persistence",
    "attack.privilege-escalation",
    "attack.defense-evasion",
    "attack.credential-access",
    "attack.discovery",
    "attack.lateral-movement",
    "attack.collection",
    "attack.command-and-control",
    "attack.exfiltration",
    "attack.impact",
    "attack.initial-access",
    "attack.t1059",
    "attack.t1059.001",
    "attack.t1059.003",
    "attack.t1190",
    "attack.t1195.002",
    "attack.t1203",
    "attack.t1218",
    "attack.t1547.001",
    "attack.t1569.002",
    "attack.t1055",
    "attack.t1053.005",
    "attack.t1003",
)


def _prose_summary(rule: SigmaRule | None, draft: RuleDraft) -> str:  # noqa: PLR0912 (branches correspond to distinct prose shapes)
    """One- or two-sentence plain-English description of the rule.

    Mirrors what ``_describe_condition`` does for stage 1, but with the
    observation type and field values woven in. This is also what stage
    3's "summary" paragraph renders.

    Deterministic template-based prose — no LLM per SPEC invariant I-1.
    """
    matches = [b for b in draft.detections if not b.is_filter]
    if not matches:
        return "No match conditions defined yet."

    if rule is not None:
        opening = f"This rule flags {rule.logsource.category or 'events'}"
        if rule.logsource.product:
            opening += f" on {rule.logsource.product}"
    else:
        opening = f"This rule flags {draft.logsource.category or 'events'}"
        if draft.logsource.product:
            opening += f" on {draft.logsource.product}"

    match_phrases: list[str] = []
    for block in matches:
        for item in block.items:
            if not item.field or not item.values:
                continue
            modifier_text = f" {item.modifiers[0]}" if item.modifiers else ""
            value_text = ", ".join(str(v) for v in item.values)
            match_phrases.append(f"{item.field}{modifier_text} {value_text!r}")

    if match_phrases:
        if len(match_phrases) == 1:
            opening += f" where {match_phrases[0]}"
        elif len(match_phrases) == 2:
            opening += f" where {match_phrases[0]} and {match_phrases[1]}"
        else:
            opening += " where " + ", ".join(match_phrases[:-1]) + f", and {match_phrases[-1]}"
    opening += "."

    filters = [b for b in draft.detections if b.is_filter]
    if filters:
        filter_phrases: list[str] = []
        for block in filters:
            names = [item.field for item in block.items if item.field]
            if names:
                filter_phrases.append(f"{block.name} ({', '.join(names)})")
        if filter_phrases:
            opening += " It excludes events matching " + " or ".join(filter_phrases) + "."
    return opening


def _download_filename(rule: SigmaRule) -> str:
    """Derive a SigmaHQ-style filename from the rule's title + uuid."""
    slug = (
        "".join(c if c.isalnum() or c in "-_" else "_" for c in rule.title.lower().strip())[
            :60
        ].strip("_")
        or "rule"
    )
    return f"{slug}.yml"


def _describe_condition(draft: RuleDraft) -> str:
    """Plain-English auto-composed condition for the stage-1 footer.

    Mirrors what :meth:`RuleDraft._compose_condition` builds so the user
    sees the same logic the serializer will emit. Reflects both combinators
    (per-block any-of, and across-match-blocks any-of) so the sentence
    matches what the preview pane's YAML says.
    """
    matches = [b for b in draft.detections if not b.is_filter]
    filters = [b for b in draft.detections if b.is_filter]
    if not matches:
        return ""

    # Per-block: "any field matches" vs "all fields match" (simplified when
    # the block has <= 1 item).
    def _block_phrase(block: Any, label: str) -> str:
        n = len(block.items)
        if n == 0:
            return f"the {label} '{block.name}' is empty"
        if n == 1:
            return f"{label} '{block.name}' matches"
        if block.combinator == "any_of":
            return f"any field in {label} '{block.name}' matches"
        return f"all fields in {label} '{block.name}' match"

    if len(matches) == 1:
        match_desc = _block_phrase(matches[0], "the match block")
    elif draft.match_combinator == "any_of":
        match_desc = "at least one match block matches"
    else:
        match_desc = "every match block matches"

    if not filters:
        return match_desc

    if len(filters) == 1:
        filter_desc = f"the filter '{filters[0].name}' does not"
    else:
        filter_desc = "no filter block matches"
    return f"{match_desc}, and {filter_desc}"


def _preview_context(draft: RuleDraft) -> dict[str, Any]:
    """Canonical YAML + any draft-to-rule validation issues for the preview.

    Also includes ``conversion_tabs`` and ``conversion_outputs`` so the
    tab-bar partial can be rendered consistently across all stages —
    populated once the draft produces a valid rule.
    """
    tabs = [
        {
            "backend_id": bid,
            "label": backend_label(bid),
            "short": _SHORT_BACKEND_LABEL.get(bid, bid),
        }
        for bid in all_backend_ids()
    ]
    result = draft.to_sigma_rule()
    if isinstance(result, list):
        # Tier 1 isn't satisfied yet — render a best-effort partial YAML so
        # the user sees the rule taking shape as they type. The strict
        # validation issues still render alongside; conversion stays gated
        # behind a fully-valid rule.
        partial_yaml = draft.to_partial_yaml()
        return {
            "preview_yaml": partial_yaml,
            "preview_yaml_html": yaml_to_html(partial_yaml) if partial_yaml.strip() else "",
            "preview_issues": _sorted_issues(result),
            "conversion_tabs": tabs,
            "conversion_outputs": None,
        }
    yaml_text = to_yaml(result)
    return {
        "preview_yaml": yaml_text,
        "preview_yaml_html": yaml_to_html(yaml_text),
        "preview_issues": [],
        "conversion_tabs": tabs,
        "conversion_outputs": _convert_all_backends(result),
    }


_SHORT_BACKEND_LABEL: dict[str, str] = {
    "kusto_sentinel": "Sentinel",
    "kusto_mde": "MDE",
    "splunk": "Splunk",
    "elasticsearch": "Elastic",
    "crowdstrike": "CrowdStrike",
}


def _convert_all_backends(rule: SigmaRule) -> dict[str, dict[str, str]]:
    """Run ``convert`` against every declared backend, capturing per-backend
    errors rather than aborting the whole render on a single pipeline failure.

    Returns ``{backend_id: {"query": ..., "pipelines": ..., "error": ...}}``.
    An entry has either ``query`` or ``error`` set, never both. ``pipelines``
    is a comma-joined string of the pipeline names used (for the chip in the
    tab header).
    """
    outputs: dict[str, dict[str, str]] = {}
    for bid in all_backend_ids():
        try:
            resolved = resolve(rule.logsource, bid)
            pipelines_str = ", ".join(resolved.pipelines) if resolved.pipelines else "baseline only"
            query = convert(rule, bid)
            outputs[bid] = {"query": query, "pipelines": pipelines_str, "error": ""}
        except ConversionFailedError as exc:
            outputs[bid] = {
                "query": "",
                "pipelines": "",
                "error": str(exc),
            }
        except UnknownBackendError as exc:
            # Dependency-pinning issue — shouldn't happen in a tested
            # release but surface cleanly if it does.
            outputs[bid] = {"query": "", "pipelines": "", "error": str(exc)}
    return outputs


def _sorted_issues(issues: Iterable[ValidationIssue]) -> list[ValidationIssue]:
    """Stable sort so the preview pane doesn't reorder between identical states."""
    return sorted(issues, key=lambda i: (i.tier, i.code, i.location or ""))


# Severity prefix → display order. Lower value = higher visual priority.
# Encoded in tier3.py as the H_<SEVERITY>_ prefix on the issue code.
_ADVISORY_ORDER: dict[str, int] = {"H_CRITICAL_": 0, "H_WARN_": 1, "H_INFO_": 2}


def _sorted_advisories(issues: Iterable[ValidationIssue]) -> list[ValidationIssue]:
    """Order tier-3 advisories by severity (critical → warn → info), then id.

    Critical advisories surface first so the user resolves real bugs before
    style nudges. Within a severity bucket, sort by code so identical rule
    states render advisories in the same order.
    """

    def _rank(issue: ValidationIssue) -> tuple[int, str, str]:
        for prefix, rank in _ADVISORY_ORDER.items():
            if issue.code.startswith(prefix):
                return (rank, issue.code, issue.location or "")
        return (99, issue.code, issue.location or "")

    return sorted(issues, key=_rank)


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
    """Back button on stage 1 — clear observation selection, return to stage 0.

    Preserves metadata (title, description, tags, references, author, date,
    falsepositives, level), the IOC session, AND the detection blocks the
    user has already authored. The original behaviour cleared detections
    too, which silently destroyed work for users who loaded a rule and
    then explored the observation picker. The "fully reset" path is
    :func:`composer_new` (header "New rule" / Stage 4 "Build another
    rule"); this one is non-destructive on purpose.

    Field names in the preserved detections may not be valid for the
    next observation the user picks. That's a Stage 1 concern — the
    field dropdown's defensive fallback (commit d705e1d) renders an
    unknown field cleanly and lets the user pick a new one without
    losing the value.
    """
    draft = RuleDraft.from_json(rule_state)
    draft.observation_id = ""
    draft.platform_id = ""
    draft.logsource = draft.logsource.__class__()
    draft.condition_tree = None
    draft.stage = 0
    return _render_stage(request, draft)


@router.post("/new", name="composer_new")
async def composer_new(
    request: Request,
) -> HTMLResponse:
    """Discard the current draft entirely; return a fresh Stage 0 composer.

    Wired from the header "New rule" button and Stage 4's "Build another
    rule" button — both have the "I'm done with this rule, start over"
    semantic. Differs from :func:`composer_restart` (Stage 1 back button)
    which preserves metadata so the user can swap observations without
    re-typing title/description/tags. The ``rule_state`` form field is
    intentionally not declared: we don't read whatever the client sent;
    we just emit a brand-new empty draft.
    """
    return _render_stage(request, RuleDraft())


@router.post("/build-similar", name="composer_build_similar")
async def composer_build_similar(
    request: Request,
    rule_state: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Reset for a sibling rule of a campaign.

    Carries forward: title (with `` (related)`` appended), description,
    references, author, date, modified, tags, level, falsepositives, and
    the IOC session (so the user can pick the next category without
    re-pasting). Resets: observation_id, platform_id, logsource,
    detections, condition_tree, match_combinator. Lands on Stage 0.

    Distinct from "Build another rule" (which calls ``composer_restart``
    and clears everything).
    """
    draft = RuleDraft.from_json(rule_state)

    # Title gets a marker so the user notices and edits it on the next
    # round through Stage 2; everything else metadata-side carries.
    if draft.title and "(related)" not in draft.title:
        draft.title = f"{draft.title} (related)"

    # Detection-side reset.
    draft.observation_id = ""
    draft.platform_id = ""
    draft.logsource = draft.logsource.__class__()
    draft.detections = []
    draft.condition_tree = None
    draft.match_combinator = "all_of"

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


def _apply_action(draft: RuleDraft, action: str, form: Any) -> None:  # noqa: PLR0912 (one branch per action verb is the dispatch table)
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
        case "set_metadata":
            _set_metadata(draft, form)
        case "set_block_combinator":
            _set_block_combinator(draft, form)
        case "set_match_combinator":
            _set_match_combinator(draft, form)
        case "classify_iocs":
            _classify_iocs(draft, form)
        case "build_from_iocs":
            _build_from_iocs(draft, form)
        case "discard_iocs":
            _discard_iocs(draft)
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


def _set_block_combinator(draft: RuleDraft, form: Any) -> None:
    """Toggle the per-block AND/OR combinator.

    Unknown values are silently ignored so a stale client POST can't
    corrupt the draft.
    """
    block_name = str(form.get("block_name", ""))
    value = str(form.get("combinator", "")).strip()
    if value not in {"all_of", "any_of"}:
        return
    for block in draft.detections:
        if block.name == block_name:
            block.combinator = value  # type: ignore[assignment]  # narrowed above
            return


def _set_match_combinator(draft: RuleDraft, form: Any) -> None:
    """Toggle the across-match-blocks combinator.

    Only applies to match blocks; filter blocks are always NOT'd in the
    auto-composed condition regardless of this field.
    """
    value = str(form.get("match_combinator", "")).strip()
    if value not in {"all_of", "any_of"}:
        return
    draft.match_combinator = value  # type: ignore[assignment]  # narrowed above


def _classify_iocs(draft: RuleDraft, form: Any) -> None:
    """Run the regex classifier on pasted text and store the result.

    Replaces any previous IOC session — pasting again is a fresh start.
    The composer stays on Stage 0; the panel re-renders with the new
    classification.
    """
    text = str(form.get("iocs_text", ""))
    parsed = classify(text)
    draft.iocs = [
        IOCSession(
            raw=ioc.raw,
            value=ioc.value,
            category=ioc.category,
            observation=ioc.observation,
            used=False,
        )
        for ioc in parsed
    ]


def _build_from_iocs(draft: RuleDraft, form: Any) -> None:
    """Jump-start a rule from the IOCs that route to ``observation_id``.

    Pre-populates a single ``match_1`` block with combinator=any_of
    holding one detection item per IOC. Marks those IOCs as ``used`` so
    the Stage 0 panel can show them struck-through next time the user
    returns (e.g. via "Build similar"). Advances to Stage 1 and sets the
    rule's logsource from the catalogued observation.
    """
    observation_id = str(form.get("observation_id", "")).strip()
    if not observation_id:
        return

    # Check the observation actually exists in our catalog before mutating.
    # Catalogue access goes through prime_taxonomy() at app startup; this
    # function deliberately doesn't import load_taxonomy at module level
    # to avoid the I/O at import time. Lazy here.
    from intel2sigma.core.taxonomy import load_taxonomy  # noqa: PLC0415

    try:
        spec = load_taxonomy().get(observation_id)
    except KeyError:
        return

    # Re-hydrate IOC objects in the form ioc.py expects (so we can use
    # build_detection_items unchanged). Skip already-used IOCs so a
    # subsequent "Build similar" doesn't re-include the same indicators.
    from intel2sigma.web.ioc import IOC  # noqa: PLC0415

    available = [
        # IOCSession persists category/observation as str; the classifier
        # already validated them against the IOC Literal types.
        IOC(raw=i.raw, value=i.value, category=i.category, observation=i.observation)  # type: ignore[arg-type]
        for i in draft.iocs
        if not i.used and i.observation == observation_id
    ]
    if not available:
        return

    items = build_detection_items(available, observation_id)
    if not items:
        return

    # Mark consumed IOCs.
    consumed_values = {ioc.value for ioc in available}
    for entry in draft.iocs:
        if entry.value in consumed_values and entry.observation == observation_id:
            entry.used = True

    # Set the observation + logsource so Stage 1 knows what fields to offer.
    draft.observation_id = spec.id
    draft.platform_id = spec.platforms[0].id if spec.platforms else ""
    draft.logsource.category = spec.logsource.category
    draft.logsource.product = spec.platforms[0].product if spec.platforms else None
    draft.logsource.service = spec.logsource.service

    # Replace the match-block list with a fresh any_of block holding the
    # routed IOCs. We deliberately overwrite rather than append: the rule
    # being built is the IOC-pack rule, not an extension of an existing
    # detection.
    draft.detections = [
        DetectionBlockDraft(
            name="match_1",
            is_filter=False,
            combinator="any_of",
            items=items,
        )
    ]
    draft.condition_tree = None  # auto-composer will produce it
    draft.stage = 1


def _discard_iocs(draft: RuleDraft) -> None:
    """Clear the IOC session entirely — back to a fresh Stage 0."""
    draft.iocs = []


def _ioc_panel_context(draft: RuleDraft) -> list[dict[str, Any]]:
    """Build the per-category data the Stage 0 IOC panel renders.

    Returns one entry per category present in ``draft.iocs``, ordered as
    :func:`web.ioc.summarise` orders them. Each entry carries:
      - label, observation, category
      - total: count of IOCs in this category
      - used: count already consumed by a prior "Build" click
      - remaining: total - used
      - examples: up to 3 sample raw values for the modal preview
    """
    if not draft.iocs:
        return []

    # Re-build the IOC list in ioc.py form so summarise() works.
    from intel2sigma.web.ioc import IOC  # noqa: PLC0415

    rebuilt = [
        # IOCSession persists category/observation as str; the classifier
        # already validated them against the IOC Literal types.
        IOC(raw=i.raw, value=i.value, category=i.category, observation=i.observation)  # type: ignore[arg-type]
        for i in draft.iocs
    ]
    summaries = summarise(rebuilt)

    used_per_category: dict[str, int] = {}
    examples_per_category: dict[str, list[str]] = {}
    for entry in draft.iocs:
        if entry.used:
            used_per_category[entry.category] = used_per_category.get(entry.category, 0) + 1
        examples_per_category.setdefault(entry.category, []).append(entry.raw)

    out: list[dict[str, Any]] = []
    for s in summaries:
        used = used_per_category.get(s.category, 0)
        out.append(
            {
                "category": s.category,
                "label": s.label,
                "observation": s.observation,
                "total": s.count,
                "used": used,
                "remaining": s.count - used,
                "examples": examples_per_category.get(s.category, [])[:3],
            }
        )
    return out


def _set_metadata(draft: RuleDraft, form: Any) -> None:
    """Pull every ``meta_*`` field out of the form and write to the draft.

    Multi-value fields (tags, references, falsepositives) are parsed from
    the text input by splitting on newlines (for textareas) or commas (for
    single-line inputs). Empty lines are dropped.
    """
    if "meta_title" in form:
        draft.title = str(form.get("meta_title", "")).strip()
    if "meta_description" in form:
        draft.description = str(form.get("meta_description", "")).strip()
    if "meta_author" in form:
        draft.author = str(form.get("meta_author", "")).strip()
    if "meta_date" in form:
        draft.date = str(form.get("meta_date", "")).strip()
    if "meta_level" in form:
        level = str(form.get("meta_level", "")).strip()
        if level in {"informational", "low", "medium", "high", "critical"}:
            # ``in`` check above narrows level to the Literal; mypy can't see it.
            draft.level = level  # type: ignore[assignment]
    if "meta_status" in form:
        status = str(form.get("meta_status", "")).strip()
        if status in {"experimental", "test", "stable", "deprecated", "unsupported"}:
            # Same Literal-narrowing pattern as draft.level above.
            draft.status = status  # type: ignore[assignment]
    if "meta_tags" in form:
        raw = str(form.get("meta_tags", ""))
        draft.tags = [t.strip() for t in raw.split(",") if t.strip()]
    if "meta_falsepositives" in form:
        raw = str(form.get("meta_falsepositives", ""))
        draft.falsepositives = [line.strip() for line in raw.splitlines() if line.strip()]
    if "meta_references" in form:
        raw = str(form.get("meta_references", ""))
        draft.references = [line.strip() for line in raw.splitlines() if line.strip()]


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
# Rule loading — paste YAML or pick a bundled example
# ---------------------------------------------------------------------------


@router.get("/load", name="composer_load_modal")
async def composer_load_modal(request: Request) -> HTMLResponse:
    """Render the 'Load rule' modal contents.

    Returned as an htmx partial; the header's Load button drops it into a
    dedicated target region in the shell. The modal has two tabs: paste
    YAML and bundled examples.
    """
    templates = _templates(request)
    return HTMLResponse(
        templates.get_template("composer/load_modal.html").render(
            request=request,
            examples=list_examples(),
        )
    )


@router.post("/load-close", name="composer_load_close")
async def composer_load_close() -> HTMLResponse:
    """Close the load modal by replacing its region with nothing."""
    return HTMLResponse("")


@router.post("/load-paste", name="composer_load_paste")
async def composer_load_paste(
    request: Request,
    yaml_text: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Parse pasted YAML into a RuleDraft and render the resulting composer stage.

    Issues are surfaced as tier-1 warnings on the preview pane. Parse
    failures re-render the modal with the failure inline so the user can
    fix their paste and retry without losing it.
    """
    draft, issues = draft_from_yaml(yaml_text)
    if draft is None:
        templates = _templates(request)
        return HTMLResponse(
            templates.get_template("composer/load_modal.html").render(
                request=request,
                examples=list_examples(),
                paste_text=yaml_text,
                paste_issues=issues,
            )
        )
    return _render_stage_with_load_clear(request, draft, issues)


@router.post("/load-example", name="composer_load_example")
async def composer_load_example(
    request: Request,
    example_id: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Load one of the bundled examples by id."""
    draft, issues = load_example(example_id)
    if draft is None:
        templates = _templates(request)
        return HTMLResponse(
            templates.get_template("composer/load_modal.html").render(
                request=request,
                examples=list_examples(),
                paste_issues=issues,
            )
        )
    return _render_stage_with_load_clear(request, draft, issues)


def _render_stage_with_load_clear(
    request: Request, draft: RuleDraft, load_issues: list[ValidationIssue]
) -> HTMLResponse:
    """Render the loaded draft + close the modal + surface translator warnings.

    The translator's issue list is appended to the preview-pane issue list
    so fidelity-loss warnings are visible right where the user lands.
    """
    response = _render_stage(request, draft)
    # ``HTMLResponse.body`` is bytes-like at runtime; decode for concatenation.
    body_bytes: bytes = bytes(response.body)
    body = body_bytes.decode("utf-8")
    body += '\n<div id="load-modal-region" hx-swap-oob="true"></div>'
    if load_issues:
        templates = _templates(request)
        preview_context = _preview_context(draft)
        preview_context["preview_issues"] = _sorted_issues(
            list(preview_context["preview_issues"]) + list(load_issues)
        )
        preview_html = templates.get_template("partials/preview_pane.html").render(
            request=request, **preview_context
        )
        body += f'\n<div id="preview-pane" hx-swap-oob="true">{preview_html}</div>'
    return HTMLResponse(body)


# ---------------------------------------------------------------------------
# Stage-nav routes — advance/back transitions between numbered stages.
# ---------------------------------------------------------------------------


_MAX_STAGE = 4


@router.post("/advance", name="composer_advance")
async def composer_advance(
    request: Request,
    rule_state: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Move to the next stage if the draft passes that stage's gate.

    Gate failure is silent — the current stage re-renders. The Next button
    is disabled when the gate isn't met, so an advance attempt from a
    valid-UI state should always succeed; silent failure is a safety net
    for edge cases (race conditions, hand-edited DOM).
    """
    draft = RuleDraft.from_json(rule_state)
    target = min(draft.stage + 1, _MAX_STAGE)
    if draft.can_advance_to_stage(target):
        draft.stage = target
    return _render_stage(request, draft)


@router.post("/back", name="composer_back")
async def composer_back(
    request: Request,
    rule_state: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Step back one stage. Below stage 1 is "restart"-equivalent."""
    draft = RuleDraft.from_json(rule_state)
    draft.stage = max(draft.stage - 1, 0)
    if draft.stage == 0:
        draft.observation_id = ""
        draft.platform_id = ""
    return _render_stage(request, draft)


# ---------------------------------------------------------------------------
# Rule download — YAML artifact served with a sensible content-type.
# Lives as a module-level function so app.py can wire it to /rule/download
# at the top-level (outside this router's /composer prefix).
# ---------------------------------------------------------------------------


def build_download_response(rule_state: str) -> PlainTextResponse:
    """Return the canonical Sigma YAML for the given draft.

    If the draft doesn't produce a valid rule we return a 400 with the
    issue list so the browser's default download handling surfaces the
    problem rather than saving a corrupt file.
    """
    draft = RuleDraft.from_json(rule_state)
    result = draft.to_sigma_rule()
    if isinstance(result, list):
        issue_lines = "\n".join(f"  [{i.code}] {i.message}" for i in result)
        return PlainTextResponse(
            content=f"Draft is not a valid rule:\n{issue_lines}\n",
            status_code=400,
            media_type="text/plain",
        )
    yaml_text = to_yaml(result)
    filename = _download_filename(result)
    return PlainTextResponse(
        content=yaml_text,
        media_type="application/yaml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
