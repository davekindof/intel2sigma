# intel2sigma

Turn observed malware behaviors into shareable Sigma rules, then convert to the SIEM query language of your choice — without writing YAML or learning Sigma's condition syntax first.

## What it does

intel2sigma is a guided composer for Sigma rules targeted at malware analysts, CTI producers, and anyone who observes suspicious behavior but doesn't live in a SIEM. You describe what you observed through structured forms (a process started, a file was written, a registry value was set, etc.), and the tool produces canonical Sigma YAML plus ready-to-run queries for the major SIEM and EDR backends.

## Who it's for

- Malware analysts producing behavioral detections alongside the usual IOCs (hashes, IPs, domains)
- CTI teams in information-sharing networks (IFIN, ISACs, MISP communities)
- Detection engineers at organizations running out-of-the-box SIEM or EDR who want portable detections
- Anyone learning Sigma who doesn't want to start with a YAML spec

## What it isn't

- Not a SIEM or detection management platform
- Not an LLM-powered tool — the composer is fully deterministic; no model decides what your rule contains
- Not a replacement for sigma-cli or pySigma for users already fluent in Sigma

## Quick start

### Hosted

Go to the hosted instance. No account needed. Sessions are ephemeral; the server keeps nothing. The hosted deployment runs as a stateless container on Azure Container Apps behind Cloudflare (TLS, WAF, rate limiting); your inputs never touch a database.

### Local (user install)

```bash
pip install intel2sigma
intel2sigma serve
```

Then open `http://localhost:8000`.

### Local (development)

Requires `uv` (install: `curl -LsSf https://astral.sh/uv/install.sh | sh`, or on Windows: `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`).

```bash
git clone https://github.com/[org]/intel2sigma
cd intel2sigma
uv sync                                           # install all deps
uv run pytest                                     # run the test suite
uv run mypy intel2sigma --strict                  # typecheck
uv run ruff check && uv run ruff format --check   # lint and format
uv run uvicorn intel2sigma.web.app:app --reload   # dev server (v1+)
```

Python 3.14 is downloaded and managed by `uv` — no system Python install needed. `uv.lock` is committed and reproduces the environment exactly.

v0 smoke test (core library only):

```bash
uv run pytest tests/test_model_smoke.py tests/test_pysigma_integration.py
```

See `CLAUDE.md` for the full development workflow and architectural rules.

### Docker

```bash
docker run -p 8000:8000 ghcr.io/[org]/intel2sigma:latest
```

All three options run the same stateless app.

## Documentation

- [`SPEC.md`](SPEC.md) — architectural source of truth
- [`ROADMAP.md`](ROADMAP.md) — phased delivery plan
- [`docs/architecture.md`](docs/architecture.md) — runtime view
- [`docs/ui.md`](docs/ui.md) — presentation layer specification
- [`docs/taxonomy.md`](docs/taxonomy.md) — observation catalog and field mapping
- [`docs/heuristics.md`](docs/heuristics.md) — rule quality checks
- [`CLAUDE.md`](CLAUDE.md) — instructions for contributors (human and AI)

## License

MIT.
