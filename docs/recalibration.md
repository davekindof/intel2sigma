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
| SigmaHQ browse index | rebuilt from the synced corpus | `intel2sigma/data/sigmahq_corpus.json` |
| Curated SigmaHQ examples | hand-picked SHA-pinned rules | `intel2sigma/data/examples/*.yml` |

## Order

```
1. Refresh SigmaHQ corpus pin
   → 2. Rebuild SigmaHQ browse index
   → 3. Refresh MITRE ATT&CK tree
   → 4. Re-run taxonomy frequency analysis
      → 5. Heuristic severity tuning + new heuristic candidates
         → 6. Curated examples sanity check
            → 7. Doc + version bump
```

Step 2 is a quick rebuild — ``uv run python scripts/build_sigmahq_corpus.py``
walks the synced corpus and writes the load-modal browse index. Run
after every corpus pin bump so the index doesn't drift.

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

`--check-only` writes nothing. It prints `ok` / `drift` / `MISSING` per
example and exits non-zero if any differ, so it is safe to run in CI or
before deciding whether the step needs doing at all. Drop the flag to
actually refresh them.

*(Implemented 2026-07-30. It had been documented here since the runbook
was written but never existed — the flag parsed as an unknown argument,
was ignored, and the script rewrote every example. That silently
produced seven modified files during the 2026-Q3 cycle from what this
step presents as a read-only check.)*

This re-validates each `intel2sigma/data/examples/*.yml` rule against:

- Tier 1 + 2 validation
- The pinned corpus (rule SHA still matches the source file)
- The new MITRE tree (every `attack.*` tag in the example still resolves)

**Gate:** if any example fails validation, either fix the rule or replace
it with a current equivalent from the corpus.

### 6. Doc + version bump

- Bump `__version__` in `intel2sigma/__init__.py` **and** `pyproject.toml`,
  then `uv lock` so the lockfile's own version entry follows. Per
  CHANGELOG.md's versioning policy this is a **patch** bump: a
  recalibration refreshes pinned data, which is not the "milestone
  landing in full" that policy reserves minor for. Minor when the cycle
  also lands a milestone; major when interfaces change.

  *(This step previously read "semver minor for catalog changes", which
  contradicted CHANGELOG.md. Resolved in favour of CHANGELOG.md during
  the 2026-Q3 cycle — it is the document that defines the policy, and
  this one should only point at it.)*
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
| 2026-07-26 | v15.1 → v19.1 | `03412947` → `552f3fee` (r2026-07-01) | `okta.yml` fields recased to CamelCase | none | _(this branch)_ |

### 2026-07-26 — notes

Three things this cycle taught, worth carrying into the next one.

**The corpus pin and the ATT&CK pin are not independent.** r2026-07-01
adopted the ATT&CK v18 tactic split: `attack.defense-evasion` was retired
in favour of `attack.stealth` (1,088 corpus occurrences) and
`attack.defense-impairment` (410), and the T1562 family was renumbered
into T1685/T1686. Refreshing the corpus alone would have left 18.2% of
corpus tag occurrences unresolvable against the bundled tree. Step 3 is
not optional when a SigmaHQ release crosses an ATT&CK major version —
check the release notes for retagging before assuming the steps are
independent. ATT&CK version was chosen by scoring v17.1/v18.1/v19.1
against the actual corpus tag set, not by taking the newest tag.

**Okta field renames — why this needed a catalog fix.** Upstream recased
every Okta field (`eventtype` → `eventType`, `actor.alternateid` →
`actor.alternateId`, and `target.user.display.name` → `target.displayName`,
which is a replacement rather than a recasing). Tracing the full path
found *no* Okta field name hardcoded or mapped anywhere — no
`pipelines.yml` entry, no Python reference. Names pass verbatim from the
catalog into the emitted query, so nothing breaks loudly; instead
`okta.yml` silently becomes the only place a wrong spelling can live, and
a composer user picking `eventtype` gets a rule that matches nothing.
Conversion output changed for 4 Okta rules × 3 backends, all faithful
passthrough. Both Kusto backends were unaffected because they already
fail on Okta — pySigma has no table mapping for it.

**Pin to the release tag, not to HEAD.** The previous pin was
HEAD-at-the-time and sat 30 commits past r2026-04-01, so "calibrated
against release X" was only ever approximate. Step 1's `git ls-remote
HEAD` example encourages this; prefer the tag commit.

Two problems found in passing and deliberately **not** fixed here:

* The load-audit and emit-audit clean-count ratchets were already failing
  on `main` before this refresh (verified by running both at the previous
  pin): load clean 3,180 vs floor 3,582, emit clean 3,176 vs floor 3,578.
  This refresh improves both by +32. The floors were left untouched —
  lowering them would mask a pre-existing ~400-rule regression unrelated
  to the corpus.
* `scripts/curate_examples.py` ignores `--check-only` and always writes.
  Step 5 above documents a flag the script does not implement.
