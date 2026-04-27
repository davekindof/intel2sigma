# Changelog

What shipped, when. Pair this with `ROADMAP.md` (what's planned).

## Versioning policy

Loose SemVer:

- **Patch** (`0.x.Y`) — small changes. Bug fixes, individual feature
  additions, single hand-review batches, polish, doc updates. The
  default cadence — most commits will live under a patch bump.
- **Minor** (`0.X.0`) — major changes. A milestone landing in full
  (a complete v1.x ROADMAP entry, or a coherent multi-week effort
  like the Phase B2 heuristics catalogue completion).
- **Major** (`1.0.0`) — when we're happy with the product as a whole.
  Triggered by ROADMAP §v1 exit gate ("≥2 non-Sigma testers walked
  through Stage 0 → 4 with a real rule") landing AND no obvious
  rough edges remaining. Until then, we stay on `0.x.y`.
- **Major** (`>=2.0.0`) — reserved for genuine breaking changes
  (taxonomy schema migration, dropped backend, etc.).

The cache-bust mechanism uses the build SHA, not the package version
(per `intel2sigma/web/templates/base.html` and commit `8471db8`), so
version bumps are decoupled from deploy correctness — they exist for
human communication, not for forcing browsers to reload assets.

## 0.2.8 — 2026-04-26

Patch bump. **F1 verbiage audit complete.** All 36 observation types
now meet the contract documented in `docs/taxonomy.md`, and the
contract is machine-enforced going forward.

### Shipped

- **F1d-γ** — verbiage hand-review of 5 small-issue files (proxy,
  ps_module, wmi_event, network_connection, raw_access_thread). The
  proxy file got the biggest rework: full W3C-ELF-prefix label
  cleanup, header decoder, top-3 corpus-mined examples (TruffleHog /
  sqlmap user-agents, CONNECT-method-as-tunnel-signal).
- **F1d-δ** — consistency pass on the 11 originally-curated taxonomies
  (create_remote_thread, create_task, dns_query, driver_load,
  file_event, file_event_linux, image_load, pipe_created, ps_script,
  registry_set + a missing example on gcp_audit's alt-form
  method_name field). Every multi-field observation now has top-3
  notes + examples per the contract.
- **F1e** — six regression tests in `tests/test_taxonomy_verbiage.py`
  that lock the contract: label-pattern compliance, "Use " description
  prefix, synonyms ≥ 3, no PascalCase field labels, top-3 notes
  populated, top-3 non-enum examples populated. Future contributions
  that drift fail at test time.

### F1 totals

- 21 auto-generated taxonomies fully hand-reviewed (F1d-α / -β / -γ).
- 11 hand-curated taxonomies polished to the contract (F1d-δ).
- 36 / 36 observations pass the verbiage gate.
- 6 new regression tests; total suite at 326 tests.

### Coming next

- F2 — modifier label table (`endswith` → "ends with") + dropdown.
- F3 — hover tooltips on field rows (the actual helper UI).
- F4 — docs/ui.md update + ROADMAP definition-links future-state.

## 0.2.7 — 2026-04-26

Patch bump per the small-changes-bump-patch versioning policy.

### Shipped

- **F1d-α** (`22bafb8`) — verbiage hand-review of 10 OS event-log + Linux/macOS observation types (security_log, process_creation_linux, auditd, system_log, defender_log, application_log, process_access, registry_event, linux_misc, process_creation_macos). 59 synonyms, 31 notes, 29 examples. Fixes auditd's `a0`/`a1`/`a2` → "Syscall argument N" and `SYSCALL` → "Syscall name" labels that the F1c camel-splitter mangled. Adds `comm` field to auditd (used in real corpus rules but missing from auto-generated field list).
- **F1d-β** (`86f4f9d`) — verbiage hand-review of 10 cloud/SaaS observation types (cloudtrail, azure_activity, azure_audit, azure_signin, azure_risk, gcp_audit, okta, github_audit, opencanary, rpc_firewall). 64 synonyms, 24 notes, 23 examples — every example mined from real corpus rules. Renames "Azure AD" → "Azure AD / Entra ID" in labels for the modern Microsoft branding. Adds `gcp.audit.service_name` field (ECS-flattened pair to `data.protoPayload.serviceName` that most rules use).
- **Snyk false-positive cleanup** (`e815963`) — hardcode redirect destination in `web/app.py` to silence the open-redirect static-analysis flag. Threat model documented inline.
- **Roadmap entries** — draggable YAML/conversion-tabs row splitter (`8fe7e01`); supersedes the older "bump conversion-tabs cap" follow-up.

### Known follow-ups

- F1d-γ — 5 more YAMLs to hand-review (ps_module, wmi_event, network_connection, raw_access_thread, proxy).
- F1e — regression tests locking the verbiage contract.
- F2 + F3 — modifier labels + hover tooltips on field rows (the actual helper UI).
- B2d–B2g — 10 remaining heuristics.
- Stage 2 metadata edits don't refresh the YAML preview pane.
- Filter-only loaded rules make Stage 2 (Metadata) inaccessible (repro: SigmaHQ rule `db809f10-56ce-4420-8c86-d6a7d793c79c`).
- Draggable YAML/conversion-tabs row splitter (plan in ROADMAP §v1.x).

## 0.2.6 — 2026-04-26

First version bump since the project started at `0.1.0`. Captures the
considerable body of work shipped between then and now. From this
point forward, follow the policy above.

### Shipped since 0.1.0

- **Phase B1** — observation-catalogue expansion 15 → 36 types
  (cloud / SaaS / OS-event-log families).
- **Phase B2 a/b/c** — heuristics catalogue: 8 → 15 advisory checks
  (h-002, h-003 IOC top-up; h-010, h-011, h-012 overbroad-selection;
  h-022, h-032 lab-artifacts + path top-up).
- **Phase B3** — data-driven category-override pipeline lights up
  9 Sysmon-only categories on the Microsoft XDR backend.
- **Phase C** — SigmaHQ corpus browse + load (3,708 rules indexed).
- **Dual-mode prune** — Expert mode formally removed; corpus browse
  + freeform observation entry + breadcrumb cover the use cases.
- **Load-rule hardening** — preserves block names verbatim, routes
  unknown logsources to `_freeform`, multi-value editor, oob-swap
  preserves CSS classes, layout calc fixes, per-deploy cache-bust.
- **F1 (verbiage audit)** — partial: contract documented in
  `docs/taxonomy.md`; 106 raw-Sigma field labels mechanically
  humanized across 20 YAMLs; 10 OS-event-log + Linux/macOS files
  hand-reviewed for synonyms / notes / examples.
- **Snyk false-positive cleanup** — open-redirect refactor.

### Known follow-ups

- F1d-β / F1d-γ — 15 more YAMLs to hand-review.
- F1e — regression tests locking the verbiage contract.
- F2 + F3 — modifier labels + hover tooltips on field rows.
- B2d–B2g — 10 remaining heuristics.
- Long-rule layout: EDR conversion-tabs region wants to be slightly
  taller (50% cap feels tight when YAML is short).
- Stage 2 metadata edits don't refresh the YAML preview pane.
- Filter-only loaded rules make Stage 2 (Metadata) inaccessible
  (repro: SigmaHQ rule `db809f10-56ce-4420-8c86-d6a7d793c79c`).

## 0.1.0 — initial development

Project scaffold, MVP composer, 5-backend conversion matrix, 8
heuristics, hosted at intel2sigma.davidsharp.io. See git history
between project start and 2026-04-26.
