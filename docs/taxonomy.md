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
├── registry_event.yml
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
  - name: Image
    label: "Executable path"
    type: path
    tier: core
    default_modifier: endswith
    allowed_modifiers: [endswith, startswith, contains, re, exact]
    example: "\\evil.exe"
    note: "Path suffix with leading backslash matches filename only."
  - name: CommandLine
    label: "Command line"
    type: string
    tier: core
    default_modifier: contains
    allowed_modifiers: [contains, startswith, endswith, re, all, exact]
    example: "-encodedcommand"
  - name: ParentImage
    label: "Parent process path"
    type: path
    tier: core
    default_modifier: endswith
    allowed_modifiers: [endswith, startswith, contains, re, exact]
  - name: ParentCommandLine
    label: "Parent command line"
    type: string
    tier: core
    default_modifier: contains
    allowed_modifiers: [contains, startswith, endswith, re, all, exact]
  - name: User
    label: "User account"
    type: string
    tier: core
    default_modifier: contains
    allowed_modifiers: [contains, exact, endswith, startswith]
  - name: IntegrityLevel
    label: "Integrity level"
    type: enum
    tier: core
    values: [Low, Medium, High, System]
    default_modifier: exact
    allowed_modifiers: [exact]
  - name: OriginalFileName
    label: "Original filename (PE metadata)"
    type: string
    tier: advanced
    default_modifier: exact
    allowed_modifiers: [exact, contains, endswith]
  - name: Hashes
    label: "File hashes"
    type: hash
    tier: advanced
    default_modifier: contains
    allowed_modifiers: [contains, exact]
    note: "Sigma uses comma-separated hash type prefixes (MD5=..., SHA256=...)."
  - name: CurrentDirectory
    label: "Working directory"
    type: path
    tier: advanced
    default_modifier: startswith
    allowed_modifiers: [startswith, endswith, contains, exact]
```

## Field attributes

### `tier`

- `core`: shown by default in the composer
- `advanced`: behind an "advanced fields" expander

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

1. Load the SigmaHQ `sigma-specification` taxonomy as the authoritative field list per logsource category.
2. Analyze the SigmaHQ `sigma` rule corpus for field usage frequency per logsource.
3. Fields appearing in ≥5% of rules for that category → `tier: core`.
4. Fields appearing in ≥1% → `tier: advanced`.
5. Fields appearing in <1% → excluded unless a detection engineer explicitly justifies inclusion.

### Ongoing

- Re-run frequency analysis quarterly against the latest SigmaHQ corpus.
- New field inclusion requires a justification comment at the top of the YAML file.
- Labels and examples must be reviewed by a human detection engineer — no auto-generation.

## Label writing guidelines

- **Plain English, not Sigma jargon.** "Executable path" not "Image". "Command line" not "CommandLine". The analyst should not need to know the Sigma field name to pick the right dropdown entry.
- **Descriptions are one sentence.** If you need more, reconsider whether the field is relevant at this tier.
- **Examples are real.** Prefer values from actual rules in the SigmaHQ corpus.
- **Notes call out common pitfalls.** "Paths normalize backslashes automatically — don't escape them." "Windows paths: use the leading `\` + executable name pattern."

## Adding a new observation type

1. Create `data/taxonomy/<id>.yml` following the format above.
2. Bootstrap fields from SigmaHQ corpus analysis where possible.
3. Add an entry to the appropriate `category_group` so it renders in the correct UI section.
4. Add at least one fixture rule in `tests/fixtures/taxonomy/<id>.yml` demonstrating the observation type in use.
5. Add a parser test proving `core/taxonomy/loader.py` ingests the file correctly.
6. Update this document with any notes specific to the new type.
