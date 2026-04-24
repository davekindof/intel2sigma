# Heuristic severity calibration

Design doc for how initial heuristic severities get picked, how they get tuned against the SigmaHQ corpus, and how the v1-deferred heuristics stay tracked.

## Initial severity rules

Every heuristic lands with a proposed default severity in `data/heuristics.yml`. The proposal rules are:

- **`critical`** — reserved for "this is almost always a bug". Examples: condition references an undefined selection, or required Pydantic field is missing. These are pattern-independent structural defects.
- **`warn`** — the rule has valid Sigma but the shape is problematic: overbroad patterns, IOC-only detections, missing ATT&CK tags on a rule whose title implies a technique, lab-artifact paths.
- **`info`** — educational nudges: "you could make this more portable with an env-var," "this field is rare in the corpus for this category."

Default is `warn`. Picking `critical` or `info` needs a one-line justification in the PR description.

## Calibration workflow

Initial severities are proposals, not facts. They get validated by running every heuristic against the SigmaHQ corpus and checking the fire rate per stratum.

### The script — `scripts/analyze_heuristics.py`

Iterates `sigmahq-rules/rules/` (vetted stratum only for the primary calibration; `rules-emerging-threats/` for secondary signal). For each rule:

1. Parse through pySigma (tolerating parse failures, counting them in the report).
2. Translate the parsed `SigmaRule` into our model via the adapter in `core/validate/tier2.py` (round-trip through `to_yaml` + `from_yaml`; skip rules that don't round-trip).
3. Call `heuristics.run_all(rule, severity_config)`.
4. Record `(heuristic_id, severity, stratum) → count` and `(heuristic_id, stratum) → rule_count`.

Output: `reports/heuristics_calibration.json` with fire rate per (heuristic, stratum), plus a per-heuristic example rule path that caused the fire.

### Fire-rate thresholds for severity adjustment

These thresholds drive a **second-pass tuning commit** after the first run:

| Fire rate on `rules/` (vetted) | Implication | Action |
|---|---|---|
| >30% | Too aggressive — fires on lots of rules SigmaHQ already vetted | Lower to `info`, or re-scope the check to be more specific |
| 5%–30% | Probably well-calibrated | Keep |
| 0.5%–5% | Narrow, catching real edge cases | Keep |
| <0.5% | Too narrow — either the pattern is vanishingly rare or the check is too strict | Verify the pattern exists in real rules; consider removing if it never fires |

A heuristic at `critical` severity firing on >1% of vetted rules is an automatic demotion to `warn`. `critical` is reserved for near-certain bugs.

### Handling corpus-wide systemic issues

Some calibration surprises aren't bugs in our heuristics — they're characteristics of the SigmaHQ corpus. Example: if `h-062` (no ATT&CK tags) fires on 15% of vetted rules, that's either (a) a real gap in SigmaHQ practice or (b) we're over-counting. Before demoting severity, check a sample of fires by hand. If the rules genuinely lack ATT&CK tags despite describing techniques, `warn` is correct even with a 15% fire rate.

The script's per-heuristic example-rule path makes this sanity-check cheap.

## Shipping ≥25 at v1.0; tracking the tail

v1 exit gate requires quality heuristics, not the full catalog. The plan:

1. Ship ≥25 heuristics at v1.0, spanning all eight categories.
2. The remaining ~16 stay enumerated in [docs/heuristics.md](docs/heuristics.md) with status `v1.1` so they're visible, reviewable, and can't silently fall off the backlog.
3. v1.1's scope includes closing that gap. If usage data suggests different heuristics would be higher-value, we promote those and demote the original v1.1 list.

The **Status column** in `docs/heuristics.md` is the load-bearing tracker. Every heuristic in the catalog has one of: `shipped`, `v1.0`, `v1.1`, `deferred`. A heuristic disappearing from the table is a red flag in code review.

## Adding or removing a heuristic

Per CLAUDE.md, adding one requires:

1. Function with `@register` decorator in `core/heuristics/checks/<category>.py`.
2. Two tests: one firing, one not (fixture rules in `tests/fixtures/heuristics/`).
3. Entry in `data/heuristics.yml` with proposed severity.
4. Row in [docs/heuristics.md](docs/heuristics.md) with Status = `shipped` (or `v1.0` if this PR is in the v1.0 range).
5. Severity justification in the PR description.

Removing a heuristic flips its Status to `deferred` with a rationale row in the docs rather than deleting it. This preserves the history — future work can resurrect a deferred check without guessing whether it was considered.

## What this doc does NOT decide

- The heuristic severity wire format (that's `data/heuristics.yml` shape — straightforward, documented in `core/heuristics/base.py`).
- Which specific heuristics land at v1.0 vs v1.1 — [docs/heuristics.md](docs/heuristics.md)'s Status column is the authoritative list, not this doc.
- Per-user severity overrides (explicit non-goal — CLAUDE.md I-3 stateless, no per-user anything).
