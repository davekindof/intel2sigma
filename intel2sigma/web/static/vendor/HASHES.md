# Vendored JavaScript integrity hashes

Every file in `intel2sigma/web/static/vendor/` has a SHA-256 hash recorded here alongside its upstream source URL, per CLAUDE.md invariant I-6. Upgrades are manual, reviewed diffs — not automated bumps. A mismatch between a file's on-disk hash and the hash listed here should fail CI.

## htmx

| Field | Value |
|---|---|
| File | `htmx.min.js` |
| Version | 2.0.4 |
| Upstream URL | https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js |
| SHA-256 | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` |
| Size | 50917 bytes |
| License | BSD-2-Clause ([htmx](https://github.com/bigskysoftware/htmx)) |
| Vendored | 2026-04-24 |

## How to upgrade

1. Download the new version from its upstream URL.
2. Compute SHA-256 and update this file:

   ```bash
   python -c "import hashlib; print(hashlib.sha256(open('intel2sigma/web/static/vendor/htmx.min.js','rb').read()).hexdigest())"
   ```

3. Commit the new file, the updated hash row, and a PR description stating why the bump is needed and what was evaluated as an alternative.

## How to verify

`tests/test_vendor_hashes.py` reads this document, recomputes each file's hash on disk, and fails CI on any mismatch or missing entry. Runs on every `uv run pytest`, no separate script needed.
