# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0

FROM python:3.13-slim

LABEL org.opencontainers.image.title="Tacua backend" \
      org.opencontainers.image.description="Self-hosted SDK capture transport and processing queue" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/services/backend/src \
    TMPDIR=/var/lib/tacua/tmp

RUN groupadd --gid 10001 tacua \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tacua \
    && install -d -o tacua -g tacua -m 0700 /var/lib/tacua /var/lib/tacua/tmp

WORKDIR /app
COPY --chown=root:root services/backend/src/ /app/services/backend/src/
COPY --chown=root:root contracts/sdk-backend-protocol/src/ /app/contracts/sdk-backend-protocol/src/
COPY --chown=root:root contracts/sdk-backend-protocol/schemas/ /app/contracts/sdk-backend-protocol/schemas/
COPY --chown=root:root contracts/runtime/src/ /app/contracts/runtime/src/
COPY --chown=root:root contracts/runtime/schemas/ /app/contracts/runtime/schemas/
COPY --chown=root:root contracts/ticket-candidate/src/ /app/contracts/ticket-candidate/src/
COPY --chown=root:root contracts/ticket-candidate/schemas/ /app/contracts/ticket-candidate/schemas/

USER 10001:10001
VOLUME ["/var/lib/tacua"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

ENTRYPOINT ["python", "-m", "tacua_backend"]
CMD ["--config-file", "/run/tacua/config.json", "--admin-secret-file", "/run/secrets/tacua_admin"]
