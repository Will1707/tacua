# SPDX-License-Identifier: Apache-2.0

FROM python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

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
COPY --chown=root:root LICENSE NOTICE /app/
COPY --chown=root:root services/backend/src/tacua_backend/*.py /app/services/backend/src/tacua_backend/
COPY --chown=root:root services/backend/config.example.json services/backend/config.template.example.json /app/services/backend/
COPY --chown=root:root contracts/sdk-backend-protocol/src/*.py /app/contracts/sdk-backend-protocol/src/
COPY --chown=root:root contracts/sdk-backend-protocol/schemas/*.schema.json /app/contracts/sdk-backend-protocol/schemas/
COPY --chown=root:root contracts/runtime/src/*.py /app/contracts/runtime/src/
COPY --chown=root:root contracts/runtime/schemas/*.schema.json /app/contracts/runtime/schemas/
COPY --chown=root:root contracts/ticket-candidate/src/*.py /app/contracts/ticket-candidate/src/
COPY --chown=root:root contracts/ticket-candidate/schemas/*.schema.json /app/contracts/ticket-candidate/schemas/
COPY --chown=root:root contracts/approved-handoff/src/*.py /app/contracts/approved-handoff/src/
COPY --chown=root:root contracts/approved-handoff/schemas/*.schema.json /app/contracts/approved-handoff/schemas/

USER 10001:10001
VOLUME ["/var/lib/tacua"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import json,urllib.request; d=json.load(urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)); assert d['status']=='ok' and d['retention_worker_running'] and d['pending_deletions']==0 and d['retention_last_failed_sessions']==0"]

ENTRYPOINT ["python", "-m", "tacua_backend"]
CMD ["--config-file", "/run/tacua/config.json", "--admin-secret-file", "/run/secrets/tacua_admin"]
