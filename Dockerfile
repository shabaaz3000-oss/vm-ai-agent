FROM python:3.14.4-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system --gid 10001 vmagent \
    && useradd --system \
        --uid 10001 \
        --gid 10001 \
        --create-home \
        --home-dir /home/vmagent \
        vmagent

WORKDIR /app

COPY requirements.txt ./requirements.txt

RUN python -m pip install \
    --no-cache-dir \
    --requirement requirements.txt

# Application code is common to both final targets.
COPY --chown=10001:10001 app ./app


# ------------------------------------------------------------
# POSTGRESQL TLS INITIALIZATION TARGET
# ------------------------------------------------------------

# This target contains no application runtime or deployment
# database authority. It prepares TLS material in a named volume
# and exits before PostgreSQL starts.
FROM postgres:17-alpine AS postgres-tls-init

USER root

RUN apk add --no-cache openssl

COPY --chown=root:root     deploy/postgresql_tls_init.sh     /usr/local/bin/postgresql_tls_init.sh

RUN chmod 0755     /usr/local/bin/postgresql_tls_init.sh

ENTRYPOINT ["/usr/local/bin/postgresql_tls_init.sh"]


# ------------------------------------------------------------
# DEPLOYMENT / BOOTSTRAP TARGET
# ------------------------------------------------------------

FROM base AS bootstrap

# Deployment authority is intentionally isolated from the
# long-running application runtime image.
COPY --chown=10001:10001 deploy ./deploy

USER 10001:10001

CMD ["python", "-m", "deploy.postgresql_bootstrap"]


# ------------------------------------------------------------
# LONG-RUNNING APPLICATION TARGET
# ------------------------------------------------------------

FROM base AS runtime

# Runtime data is not required by the deployment bootstrap
# target and remains scoped to the application image.
COPY --chown=10001:10001 data ./data

USER 10001:10001

EXPOSE 8000

# v1.0.0 security metrics and alerts remain process-local.
# Keep one application worker until centralized telemetry exists.
CMD ["python", "-m", "uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
