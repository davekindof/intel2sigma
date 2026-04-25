# Multi-stage build for intel2sigma.
#
# Stage 1 (``builder``) installs the locked production dependencies into a
# virtualenv using uv. ``--no-dev --frozen`` guarantees the same uv.lock
# resolution the developer committed; no surprise version drift.
#
# Stage 2 (``runtime``) copies just the venv and the package into a slim
# Python image, runs as a non-root user, and serves uvicorn on port 8000.
#
# Pinned-data files (taxonomy YAMLs, MITRE ATT&CK tree, pipeline matrix,
# curated examples) live under intel2sigma/data/ and ship with the package
# automatically — no separate COPY needed.
#
# Build:
#   docker build --build-arg BUILD_SHA=$(git rev-parse --short HEAD) \
#                -t intel2sigma:dev .
# Run:
#   docker run -p 8000:8000 intel2sigma:dev
#
# Cold-start budget (per ROADMAP v1.0 exit gate): <5s on warm host.

# -----------------------------------------------------------------------------
# Stage 1 — builder
# -----------------------------------------------------------------------------
# Use the official Astral uv image with Python 3.14 already installed, so we
# don't have to install uv from the network at build time.
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# Install just the dependency closure first so a code-only change re-uses the
# layer cache. uv.lock + pyproject.toml is the dependency manifest pair.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Install the package itself as a NON-editable install. ``uv sync`` defaults
# to editable (a .pth pointing at the source tree); for the runtime stage we
# only copy /opt/venv across, so an editable install would dangle. Building
# the wheel and installing it gives a self-contained venv.
COPY intel2sigma ./intel2sigma
COPY README.md ./
RUN uv sync --frozen --no-dev --no-editable


# -----------------------------------------------------------------------------
# Stage 2 — runtime
# -----------------------------------------------------------------------------
FROM python:3.14-slim-bookworm AS runtime

ARG BUILD_SHA=dev
ENV INTEL2SIGMA_BUILD_SHA=${BUILD_SHA} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:${PATH}"

# Non-root user. UID/GID 10001 is conventional for "service" users and
# avoids colliding with any host-user numbering.
RUN groupadd --system --gid 10001 intel2sigma \
    && useradd  --system --uid 10001 --gid intel2sigma \
                --home-dir /home/intel2sigma --create-home \
                --shell /usr/sbin/nologin intel2sigma

# Copy the resolved venv from the builder stage. Nothing else from the build
# context is needed at runtime — the wheel inside the venv already carries
# the package + bundled data/.
COPY --from=builder --chown=intel2sigma:intel2sigma /opt/venv /opt/venv

USER intel2sigma
WORKDIR /home/intel2sigma

EXPOSE 8000

# Healthcheck hits /healthz; the app exposes it from web/app.py. Container
# Apps' built-in liveness probe will use this same path.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; \
                    sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else sys.exit(1)"

# Single-process uvicorn. ACA scales by replicas, not by intra-container
# workers, so one process per container keeps the cache (taxonomy, MITRE
# tree, pipeline matrix) hot per-replica.
CMD ["uvicorn", "intel2sigma.web.app:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
