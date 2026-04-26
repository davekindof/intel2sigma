# Taxonomy catalog

The observation catalog is the data asset that drives the guided composer. Changes here change the UI.

Per CLAUDE.md I-5, the taxonomy is data, not code. The loader in `core/taxonomy/loader.py` reads these files; no observation type, field, or modifier is hardcoded in Python.

## Structure

Taxonomy lives in `data/taxonomy/` as YAML, one file per observation type plus platform variants where fields diverge:

```
data/taxonomy/
├── process_creation.yml
├── file_event.yml
├── file_event_linux.yml       # auditd schema
├── registry_set.yml           # dominant registry category in the corpus
├── network_connection.yml
├── dns_query.yml
├── image_load.yml
├── pipe_created.yml
├── driver_load.yml
├── create_remote_thread.yml
├── wmi_event.yml
├── create_task.yml
├── ps_script.yml
├── ps_module.yml
└── raw_access_thread.yml
```

## File format

```yaml
id: process_creation
label: "A process was started"
description: "Use when malware or suspicious activity created a new process."
category_group: process_and_execution   # for UI grouping
logsource:
  category: process_creation
  # product is set per platform variant
platforms:
  - id: windows
    product: windows
    tier: primary
  - id: linux
    product: linux
    tier: primary
  - id: macos
    product: macos
    tier: secondary
synonyms:
  - "process launched"
  - "executable ran"
  - "new process"
fields:
  # Fields are listed in real-world frequency order (most common first, least common last)
  # so the composer can surface the top-N as the default dropdown and keep the tail in a
  # secondary list without a binary core/advanced classification.
  - name: Image
    label: "Executable path"
    type: path
    default_modifier: endswith
    allowed_modifiers: [endswith, startswith, contains, re, exact]
    example: "\\evil.exe"
    note: "Path suffix with leading backslash matches filename only."
  - name: CommandLine
    label: "Command line"
    type: string
    default_modifier: contains
    allowed_modifiers: [contains, startswith, endswith, re, all, exact]
    example: "-encodedcommand"
  - name: ParentImage
    label: "Parent process path"
    type: path
    default_modifier: endswith
    allowed_modifiers: [endswith, startswith, contains, re, exact]
  - name: ParentCommandLine
    label: "Parent command line"
    type: string
    default_modifier: contains
    allowed_modifiers: [contains, startswith, endswith, re, all, exact]
  - name: OriginalFileName
    label: "Original filename (PE metadata)"
    type: string
    default_modifier: exact
    allowed_modifiers: [exact, contains, endswith]
  - name: User
    label: "User account"
    type: string
    default_modifier: contains
    allowed_modifiers: [contains, exact, endswith, startswith]
  - name: IntegrityLevel
    label: "Integrity level"
    type: enum
    values: [Low, Medium, High, System]
    default_modifier: exact
    allowed_modifiers: [exact]
  - name: Hashes
    label: "File hashes"
    type: hash
    default_modifier: contains
    allowed_modifiers: [contains, exact]
    note: "Sigma uses comma-separated hash type prefixes (MD5=..., SHA256=...)."
  - name: CurrentDirectory
    label: "Working directory"
    type: path
    default_modifier: startswith
    allowed_modifiers: [startswith, endswith, contains, exact]
```

## Field attributes

### Field ordering

Fields within an observation type are listed in real-world frequency order, derived from the SigmaHQ corpus via `scripts/analyze_taxonomy.py`. The composer consumes this ordering for the Stage 1 field dropdown — most-frequent fields appear first, so the common-case selection is one click away. The catalog doesn't commit to a binary tier classification; the dropdown surfaces the full list in a single ordered control.

### `type`

Drives input validation and the default modifier:

- `path` — path normalization, backslash handling, default `|endswith`
- `string` — plain string, default `|contains` for non-exact matches
- `hash` — validates MD5 / SHA1 / SHA256 length; supports comma-separated multi-hash syntax
- `ip` — IP validation, CIDR modifier allowed
- `int` — integer input
- `enum` — values defined in the field's `values:` list
- `regex` — regex-only field

### `allowed_modifiers`

Subset of Sigma modifiers permitted on this field. The composer hides other modifiers for this field. Adding a modifier here requires confirming pySigma's backend support for it per target.

## Platform variants

Where a logsource category has substantially different fields across platforms, create a separate file with a platform-qualified ID. Example: `file_event_linux.yml` for auditd-style file events, which have fields like `syscall`, `euid`, `auid` not present in Windows `file_event`.

The UI presents all platform variants under the same card; selecting the card prompts the user to choose a platform, which then loads the correct variant.

## Modifier labels

Used consistently across all fields:

| Sigma modifier | UI label | Notes |
|---|---|---|
| (none) | "exactly matches" | default for enum and hash fields |
| `contains` | "contains" | |
| `startswith` | "starts with" | |
| `endswith` | "ends with" | |
| `re` | "matches regex (advanced)" | warns about backend-specific dialect |
| `all` | "matches all of (AND list)" | ANDs list values |
| `cased` | "case-sensitive match" | |
| `base64` | "matches base64-encoded value" | |
| `base64offset\|contains` | "contains base64-encoded substring (offset-safe)" | |
| `utf16le` | "UTF-16 LE encoded value" | |
| `windash` | "Windows dash variants (-, /, –)" | pySigma expands to all dash characters |
| `cidr` | "IP in CIDR range" | IP-type fields only |

Modifier availability per field is determined by `allowed_modifiers` in the taxonomy entry.

## Curation methodology

### v0 bootstrap

1. Fetch the SigmaHQ `sigma` corpus at a pinned commit via `scripts/fetch_sigmahq.py`.
2. Run `scripts/analyze_taxonomy.py` — stratified per-field frequency and modifier-distribution analysis. Excludes `rules-placeholder/`, `deprecated/`, and `unsupported/`; weights `rules/` (vetted) as the primary calibration stratum, with `rules-emerging-threats/` and `rules-threat-hunting/` as secondary signal.
3. Include fields that appear in ≥1% of rules for the observation type in any stratum. Fields below 1% are excluded unless a detection engineer explicitly justifies inclusion.
4. Order fields within each file by frequency in the vetted `rules/` stratum, with small ordering nudges where a lower-frequency field is strictly more useful for behavioral detection than an adjacent PE-metadata field.
5. Pick `default_modifier` = dominant modifier chain's leading token in the `rules/` stratum. Pick `allowed_modifiers` = modifiers that appear in ≥1% of rules for that field in any stratum, plus a type-appropriate baseline (`exact` always; `re` for string/path; `cidr` for IP).

### Ongoing

- Re-run frequency analysis quarterly against the latest SigmaHQ corpus. Bumping `PINNED_COMMIT` in `scripts/fetch_sigmahq.py` is a commit that records when the catalog was last calibrated.
- New field inclusion requires a justification comment at the top of the YAML file.
- Labels and examples must be reviewed by a human detection engineer — no auto-generation.

## Label writing guidelines

The whole product thesis is "non-SIEM users build Sigma rules without
knowing Sigma jargon." Labels and notes are the front line of that
promise. This section is the contract every taxonomy YAML follows;
``tests/test_taxonomy_verbiage.py`` enforces the parts a regex can
catch.

### Observation `label`

The label is what shows on the Stage 0 card and at the top of every
later stage. It tells the user *what kind of activity* this taxonomy
entry represents.

**Pattern A — Active (preferred).** Use whenever there's a clear
actor + verb pair:

> "A process was started"
> "A process resolved a DNS name"
> "A user signed in to Azure AD"
> "A scheduled task was created"
> "A driver was loaded"

**Pattern B — Passive (fallback).** Only when the actor is the OS,
the audit pipeline itself, or otherwise genuinely actor-less:

> "A Windows Security event was logged"
> "An AWS CloudTrail event was logged"
> "A Linux auditd event was logged"

**Accuracy beats voice.** If Pattern A would force a misleading verb
choice ("A subscription deleted itself"), use Pattern B even though
it's less narrative. Examples that needed Pattern B because A was
inaccurate are a feature, not a regression — record the reason in a
YAML comment if it isn't obvious.

### Observation `description`

One sentence, starts with **"Use "**:

> "Use when malware or suspicious activity created a new process."
> "Use for AWS CloudTrail rules — IAM, S3, EC2, etc."
> "Use to detect kernel-mode driver loads, including BYOVD-style abuse."

### Observation `synonyms`

A short list (3–6 entries) of alternate phrasings the user might type
into the Stage 0 search bar. Include both casual phrasings ("process
launched") and SIEM/EDR jargon they might know ("EID 1", "Sysmon
event 1") so search hits both audiences. Required for every
observation — empty `synonyms: []` is a contract violation; it
silently breaks Stage 0 search relevance.

### Field `label`

Plain English noun phrase. **Never the raw Sigma field name.**

| Bad (raw Sigma) | Good (plain English) |
|---|---|
| `Image` | `Executable path` |
| `CommandLine` | `Command line` |
| `TargetFilename` | `Target file path` |
| `EventID` | `Event ID` |
| `IntegrityLevel` | `Process integrity level` |
| `ObjectName` | `Object name (path or registry key)` |

The analyst should not need to know the Sigma field name to pick the
right dropdown entry. Auto-generated labels that copy the Sigma name
verbatim (PascalCase, single-word, etc.) are a contract violation
and the verbiage tests catch them.

### Field `note`

One short sentence. Calls out a common pitfall, a non-obvious
semantic, or a tip that meaningfully changes how the user fills the
field. Skip if there's nothing useful to say — a hollow note is worse
than no note.

> "Path suffix with leading backslash matches the executable regardless of directory."
> "Sigma expects a comma-separated string with algorithm prefixes, e.g. 'MD5=…, SHA256=…'."
> "'true' = process initiated an outbound connection; 'false' = inbound."

### Field `example`

A real-looking value drawn from the SigmaHQ corpus where possible.
Used as the placeholder text in the value input *and* as the click-to-
insert chip in the helper tooltip (Stage 1 hover UX). A fake example
("foo") is worse than no example.

### Field-level coverage rules

- Every observation's **top-3 fields** (the first three in declaration
  order, which is corpus-frequency order per the file headers) must
  have **both `note` and `example`**. These are the fields a user is
  most likely to interact with on Stage 1.
- Below the top-3, `note` and `example` are optional — quality beats
  completeness. A rich helper for `Image` and `CommandLine` is more
  valuable than mediocre boilerplate for `LogonId`.
- For enum-typed fields, the YAML's `values:` list is sufficient
  documentation; `note` is optional but `example` should be omitted
  (the dropdown shows the choices).

## Adding a new observation type

1. Create `data/taxonomy/<id>.yml` following the format above.
2. Bootstrap fields from SigmaHQ corpus analysis where possible.
3. Add an entry to the appropriate `category_group` so it renders in the correct UI section.
4. Add at least one fixture rule in `tests/fixtures/taxonomy/<id>.yml` demonstrating the observation type in use.
5. Add a parser test proving `core/taxonomy/loader.py` ingests the file correctly.
6. Update this document with any notes specific to the new type.
