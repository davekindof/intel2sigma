# Quarterly recalibration runbook

intel2sigma's catalog files (taxonomy, MITRE ATT&CK tree, SigmaHQ corpus
pin, heuristic severities) drift relative to the upstream sources they
were calibrated against. This runbook is the quarterly cycle that keeps
them in sync.

CLAUDE.md and SPEC.md reference this loop in several places — this file
is the single concrete walkthrough.

## When

Quarterly. Pick a calendar reminder; the work is mostly mechanical and
takes 1–2 hours plus dogfooding time.

## Inputs

Three pinned upstreams, each refreshed independently:

| Upstream | Pin location | Where it lands |
|---|---|---|
| MITRE ATT&CK STIX 2.1 | `ATTACK_VERSION` in `scripts/build_mitre_tree.py` | `intel2sigma/data/mitre_attack.json` |
| SigmaHQ rule corpus | `SIGMAHQ_PINNED_COMMIT` in `intel2sigma/_version.py` | (not vendored — checked out into `sigmahq-rules/` for analysis) |
| Curated SigmaHQ examples | hand-picked SHA-pinned rules | `intel2sigma/data/examples/*.yml` |

## Order

```
1. Refresh SigmaHQ corpus pin
   → 2. Refresh MITRE ATT&CK tree
   → 3. Re-run taxonomy frequency analysis
      → 4. Heuristic severity tuning + new heuristic candidates
         → 5. Curated examples sanity check
            → 6. Doc + version bump
```

Each step has its own gate; don't proceed if the previous step's gate
fails.

## Step-by-step

### 1. Refresh the SigmaHQ corpus pin

```bash
# Inspect current upstream HEAD
git ls-remote https://github.com/SigmaHQ/sigma.git HEAD

# Bump in source
$EDITOR intel2sigma/_version.py
# Update SIGMAHQ_PINNED_COMMIT to the new SHA. Note the date in a comment.

# Fetch + verify the integration test still passes
uv run python scripts/fetch_sigmahq.py
uv run pytest -m slow tests/test_sigmahq_corpus.py
```

**Gate:** every rule in the corpus parses and tier-1+2 validates. If
not, investigate before continuing — usually it's a new rule shape that
needs a parser fix or a taxonomy addition.

### 2. Refresh the MITRE ATT&CK tree

```bash
# Bump in source
$EDITOR scripts/build_mitre_tree.py
# Update ATTACK_VERSION to the latest tag (e.g. v15.1 → v16.0).

# Regenerate the tree
uv run python scripts/build_mitre_tree.py

# Verify
uv run pytest tests/test_mitre_picker.py
```

**Gate:** the test suite passes. Particularly the well-known-techniques
sentinels (T1059 / T1059.001 / T1195 / T1195.002) — if any of those go
missing, MITRE renumbered something and we need to re-check rules in
`intel2sigma/data/examples/` for stale tags.

### 3. Taxonomy frequency analysis

```bash
uv run python scripts/analyze_taxonomy.py --output-dir tmp/recal-$(date +%Y-%m-%d)
```

This dumps frequency tables (per logsource, per field, per modifier)
against the freshly-pinned corpus.

**Review for:**

- New high-frequency `(product, category)` pairs not in `intel2sigma/data/taxonomy/` — candidates for v1.7 catalog expansion (CLAUDE.md I-5: data-only PR).
- Field rank changes within existing observation types — re-order the YAML if a field's frequency rank has moved meaningfully.
- New modifiers seen in the corpus that aren't in `ValueModifier` — extremely rare; investigate.

**Gate:** any catalog change is a separate PR. Don't bundle catalog
edits with the recalibration commit.

### 4. Heuristic severity tuning

```bash
# Run all heuristics against the freshly-pinned corpus
uv run python scripts/run_heuristics_on_corpus.py  # (lands with the heuristics MVP)
```

Compare hit rates per heuristic to last quarter's run (track in
`docs/heuristic-calibration.md`):

- A heuristic that fires on >30% of corpus rules is probably mis-tuned (too noisy → demote to `info`, or refine the function).
- A heuristic that never fires on the corpus is probably broken or specifying a pattern that's already absent — investigate.
- Severity moves go into `intel2sigma/data/heuristics.yml`; no Python edits needed.

**v1.7 milestone:** during this step, also pick the next 2–3 heuristics
to graduate from the v1.7 backlog into the shipped set. Implement,
two-test-cases-each, ship.

### 5. Curated examples sanity check

```bash
uv run python scripts/curate_examples.py --check-only
```

This re-validates each `intel2sigma/data/examples/*.yml` rule against:

- Tier 1 + 2 validation
- The pinned corpus (rule SHA still matches the source file)
- The new MITRE tree (every `attack.*` tag in the example still resolves)

**Gate:** if any example fails validation, either fix the rule or replace
it with a current equivalent from the corpus.

### 6. Doc + version bump

- Bump `__version__` in `intel2sigma/__init__.py` (semver minor for catalog
  changes; major when interfaces change).
- Add a one-line entry in SPEC.md decision log: which upstreams moved,
  what changed in the catalog.
- Tag the recalibration in git: `git tag recal-YYYY-Qn && git push --tags`.
- Open a single PR titled `chore: quarterly recalibration YYYY-Qn` with
  the catalog/data changes; keep separate PRs for any heuristic logic
  changes.

## What NOT to do

- **Don't bundle code changes with the recalibration PR.** This commit
  should be reviewable as "did the data change, do tests still pass."
  Heuristic logic changes, new observation types, new heuristics — all
  separate PRs.
- **Don't bump pinned upstreams without re-running the gate tests.**
  Silent drift is the failure mode this runbook prevents.
- **Don't skip a quarter.** Two-quarter gaps make the diff hard to
  review; one-quarter gaps are mechanical.

## Calibration history

Each recalibration appends a row here with: date, MITRE ATT&CK version
moved to, SigmaHQ commit moved to, catalog deltas, heuristic severity
deltas. Useful for "when did detection X become ambiguous" forensics.

| Date | MITRE | SigmaHQ | Catalog | Heuristics | PR |
|---|---|---|---|---|---|
| _(populated as the cycles run)_ | | | | | |
