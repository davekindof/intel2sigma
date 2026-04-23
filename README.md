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

Go to the hosted instance. No account needed. Sessions are ephemeral; the server keeps nothing.

### Local (user install)

```bash
pip install intel2sigma
intel2sigma serve
```

Then open `http://localhost:8000`.

### Local (development)

Requires `uv` (install: `curl -LsSf https://astral.sh/uv/install.sh | sh`).

```bash
git clone https://github.com/[org]/intel2sigma
cd intel2sigma
uv sync
uv run uvicorn intel2sigma.web.app:app --reload
```

Python 3.14 is downloaded and managed by `uv` — no system Python install needed. See `CLAUDE.md` for the full development workflow.

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
