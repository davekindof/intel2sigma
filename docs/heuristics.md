# Quality heuristics

Heuristics catch rule-quality issues that are valid Sigma but bad detection. They produce advisory warnings, never blocking errors.

Per CLAUDE.md I-5, heuristic severities and enablement live in `data/heuristics.yml`, not in code. The functions themselves live in `core/heuristics/checks/`.

## Heuristic definition

Each heuristic is a pure function:

```python
from intel2sigma.core.model import SigmaRule
from intel2sigma.core.heuristics.base import HeuristicResult, register


@register("h-001", category="ioc_vs_behavior")
def ioc_only_rule(rule: SigmaRule) -> HeuristicResult | None:
    """Rule contains only IOC-type values with no behavioral context."""
    indicator_fields = {
        "Hashes", "md5", "sha1", "sha256",
        "DestinationIp", "dst_ip", "DestinationHostname",
    }
    for detection in rule.detections:
        if detection.is_filter:
            continue
        for item in detection.items:
            if item.field not in indicator_fields:
                return None
    return HeuristicResult(
        heuristic_id="h-001",
        message=(
            "This rule contains only IOCs (hashes, IPs, domains). "
            "Consider adding behavioral context so the rule survives "
            "indicator rotation."
        ),
        suggestion=(
            "Add a selection block for the process, command line, or "
            "file path pattern associated with this behavior."
        ),
    )
```

The `@register` decorator adds the heuristic to a central registry that `heuristics.run_all()` iterates. Severity is looked up from `data/heuristics.yml` at run time:

```yaml
# data/heuristics.yml
heuristics:
  h-001:
    severity: warn
    enabled: true
  h-010:
    severity: warn
    enabled: true
  h-050:
    severity: critical
    enabled: true
  # ...
```

This keeps the function pure (severity is not part of its logic) and makes calibration a data-file change, not a code change.

## Severity levels

- `info`: educational nudge; not blocking, low visual prominence.
- `warn`: should be addressed; user can acknowledge and proceed.
- `critical`: almost always wrong; user must explicitly override.

Default calibration is conservative. `critical` is reserved for things that are nearly always bugs (e.g., condition references an undefined selection).

## Catalog

Heuristic IDs use category-based numbering with gaps to allow insertion within a category without renumbering.

### IOC vs. behavior

| ID | Default | Description |
|---|---|---|
| h-001 | warn | IOC-only rule (no behavioral context) |
| h-002 | info | Hash field without behavioral context |
| h-003 | info | IP/domain-only rule |

### Overbroad selection

| ID | Default | Description |
|---|---|---|
| h-010 | warn | Single-field selection on high-cardinality field |
| h-011 | warn | Single common keyword (e.g., `CommandLine|contains: powershell` alone) |
| h-012 | warn | `Image|endswith` with value <5 characters |
| h-013 | warn | `User|contains` with fragment <3 characters |
| h-014 | info | Selection matches >50% of a sampled corpus (when corpus available) |

### Lab artifacts

| ID | Default | Description |
|---|---|---|
| h-020 | warn | Path contains apparent researcher handle or username |
| h-021 | warn | Value contains RFC1918 IP address |
| h-022 | warn | Hostname matches sandbox patterns (`DESKTOP-`, `WIN-`, VM prefixes) |
| h-023 | warn | Hash matches known-benign corpus (when corpus available) |
| h-024 | info | Path references common researcher-lab paths (`\tools\`, `\analysis\`) |

### Path specificity

| ID | Default | Description |
|---|---|---|
| h-030 | warn | User-profile path without wildcard (`C:\Users\name\` vs `C:\Users\*\`) |
| h-031 | info | Program Files path without architecture wildcard |
| h-032 | warn | Drive letter other than `C:` hardcoded (portability concern) |
| h-033 | info | Absolute path where env-var expansion would be more portable |

### Known FP-prone patterns

| ID | Default | Description |
|---|---|---|
| h-040 | info | PowerShell target without common-admin / SCCM / MDT exclusions |
| h-041 | info | rundll32 target without signed-DLL exclusions |
| h-042 | info | wmic target without monitoring-tool exclusions |
| h-043 | info | schtasks target without Windows Update / Microsoft exclusions |
| h-044 | info | cmd.exe target without script-host exclusions |
| h-045 | info | regsvr32 target without signed-binary exclusions |

### Condition integrity

| ID | Default | Description |
|---|---|---|
| h-050 | critical | Condition references undefined selection |
| h-051 | warn | Selection block defined but not referenced in condition |
| h-052 | warn | Condition is just `selection` with no filters, rule level is high/critical |
| h-053 | warn | Negation of broad selection (`not selection` where selection is overbroad) |

### Metadata completeness

| ID | Default | Description |
|---|---|---|
| h-060 | warn | Title <10 or >100 characters |
| h-061 | warn | Description <30 characters |
| h-062 | warn | No ATT&CK technique tags |
| h-063 | info | `falsepositives` missing or only "unknown"/"none" |
| h-064 | warn | `level` missing |
| h-065 | info | `status: experimental` for polished rules (suggest `status: test`) |
| h-066 | warn | Title starts with "Detects" (SigmaHQ convention violation) |
| h-067 | info | No `references` despite the rule describing a known technique |
| h-068 | info | `author` is empty or placeholder |

### Value quality

| ID | Default | Description |
|---|---|---|
| h-070 | warn | CommandLine contains apparent PID or TID |
| h-071 | warn | Value contains specific timestamp |
| h-072 | info | Bare filename without path context |
| h-073 | warn | Value appears to be specific to a single sample (GUID, random string) |
| h-074 | info | Value contains likely lab-specific hostname |

## Calibration methodology

Initial severities are proposals. Calibrate via:

1. **Run all heuristics against the full SigmaHQ corpus.** Review fire rates:
   - >30% fire rate → too noisy; re-scope the check or lower severity
   - <0.5% fire rate → too narrow; verify the pattern exists in real rules, otherwise remove
2. **Non-native user test.** Have a tester unfamiliar with Sigma build 10 rules from scratch. Count which heuristics fire on legitimate intent → lower severity or improve suggestion text.
3. **Re-calibrate quarterly** or after significant changes to the SigmaHQ corpus.

Calibration changes update `data/heuristics.yml`, not Python code.

## Adding a heuristic

Required in a single PR:

1. Function implementation in `core/heuristics/checks/<category>.py` with `@register` decorator.
2. Test case proving it fires on a triggering rule (`tests/heuristics/test_<id>_fires.py`).
3. Test case proving it does not false-fire on a benign rule (`tests/heuristics/test_<id>_no_fire.py`).
4. Entry in `data/heuristics.yml` with proposed default severity.
5. Entry in this document under the correct category.
6. Severity justification in the commit message or PR description.

Violating any of these blocks merge. See CLAUDE.md.
