# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0

FROM python:3.13-slim

LABEL org.opencontainers.image.title="Tacua pilot backend" \
      org.opencontainers.image.description="Non-production SDK upload-boundary vertical slice" \
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
COPY --chown=root:root contracts/runtime/src/ /app/contracts/runtime/src/
COPY --chown=root:root contracts/runtime/schemas/ /app/contracts/runtime/schemas/

USER 10001:10001
VOLUME ["/var/lib/tacua"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

ENTRYPOINT ["python", "-m", "tacua_backend"]
CMD ["--config-file", "/run/tacua/config.json", "--admin-secret-file", "/run/secrets/tacua_admin"]
