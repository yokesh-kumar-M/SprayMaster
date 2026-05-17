# syntax=docker/dockerfile:1.7

# ---------- Stage 1: builder ----------
# Build wheels (including native deps like pymssql, impacket, psycopg2-binary)
# in a stage with full toolchain, so the runtime image stays slim.
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Native build deps for: cryptography (paramiko), psycopg2, pymssql, impacket, ldap3.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
        libssl-dev \
        libpq-dev \
        libldap2-dev \
        libsasl2-dev \
        freetds-dev \
        freetds-bin \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml MANIFEST.in README.md LICENSE CHANGELOG.md ./
COPY spraymaster ./spraymaster

# Install the package WITH all optional protocol extras into an isolated prefix.
RUN pip install --prefix=/install ".[all]"


# ---------- Stage 2: runtime ----------
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    PATH=/usr/local/bin:$PATH

LABEL org.opencontainers.image.title="SprayMaster" \
      org.opencontainers.image.description="Multi-protocol network login auditor for authorized pentesting" \
      org.opencontainers.image.source="https://github.com/yokesh-kumar-M/SprayMaster" \
      org.opencontainers.image.licenses="MIT"

# Minimal runtime libs only (matching the build deps for native extensions).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libffi8 \
        libssl3 \
        libpq5 \
        libldap-2.5-0 \
        libsasl2-2 \
        libsybdb5 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash --uid 1000 sprayer

COPY --from=builder /install /usr/local

USER sprayer
WORKDIR /workspace

# Persist SQLite history outside the container by mounting a volume to
# /home/sprayer/.spraymaster — both TUI and Web read/write to that path.
VOLUME ["/home/sprayer/.spraymaster"]

# Default to the CLI. Override CMD to switch front-ends:
#   docker run -p 8000:8000 spraymaster spraymaster-web --host 0.0.0.0 --allow-public
#   docker run -it          spraymaster spraymaster-tui
ENTRYPOINT []
CMD ["spraymaster", "--help"]
