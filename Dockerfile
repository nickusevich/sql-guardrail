# syntax=docker/dockerfile:1.7

# ---- Builder stage --------------------------------------------------------
# Builds a wheel of sql-guardrail. Kept separate so the runtime image doesn't
# carry build tooling.
FROM python:3.13-slim AS builder

WORKDIR /build

# Install the PEP 517 frontend only; the rest comes from pyproject.toml.
RUN pip install --no-cache-dir build==1.2.2.post1

# Copy only what's needed to build the wheel. Source first, then build.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m build --wheel --outdir /dist


# ---- Runtime stage --------------------------------------------------------
FROM python:3.13-slim AS runtime

# Default policy mount point. Overridable at run time.
ENV SQLGUARD_POLICY_PATH=/etc/sqlguard/policy.yml \
    SQLGUARD_HOST=0.0.0.0 \
    SQLGUARD_PORT=8000 \
    SQLGUARD_LOG_LEVEL=info \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install the wheel with the [server] extra in a single layer.
COPY --from=builder /dist/*.whl /tmp/
RUN pip install /tmp/*.whl[server] \
    && rm -f /tmp/*.whl

# Non-root user. uid:gid intentionally non-zero; matches the K8s
# `runAsNonRoot: true` security context most clusters enforce.
RUN groupadd --system --gid 10001 sqlguard \
    && useradd  --system --uid 10001 --gid sqlguard --no-create-home --shell /sbin/nologin sqlguard \
    && mkdir -p /etc/sqlguard \
    && chown -R sqlguard:sqlguard /etc/sqlguard

USER sqlguard:sqlguard
WORKDIR /home/sqlguard

EXPOSE 8000

# urllib is in the stdlib so we don't need curl/wget in the slim image.
# The check writes nothing to disk; a non-2xx response exits non-zero.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=2).status == 200 else 1)" \
    || exit 1

CMD ["sqlguard-server"]
