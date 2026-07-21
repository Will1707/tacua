# SPDX-License-Identifier: Apache-2.0

FROM python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0

ARG PROBE_VERSION=0.1.0
ARG SOURCE_REVISION=uncommitted-workspace
ARG BUILD_TIME=unknown

LABEL org.opencontainers.image.title="Tacua EXP-007 Docker topology probe" \
      org.opencontainers.image.description="Disposable, non-production packaging contract probe" \
      org.opencontainers.image.version="${PROBE_VERSION}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${BUILD_TIME}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      tacua.experiment="tacua-exp007" \
      tacua.production="false"

RUN addgroup -S -g 65532 tacuaprobe \
    && adduser -S -D -H -u 65532 -G tacuaprobe tacuaprobe \
    && mkdir -p /opt/tacua-probe /data /backup \
    && chown -R 65532:65532 /opt/tacua-probe /data /backup

WORKDIR /opt/tacua-probe
COPY --chown=65532:65532 probe.py LICENSE ./

USER 65532:65532

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TACUA_PROBE_VERSION="${PROBE_VERSION}"

EXPOSE 8707

HEALTHCHECK --interval=2s --timeout=1s --start-period=1s --retries=10 \
  CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8707/healthz', timeout=0.8).read()"]

ENTRYPOINT ["python3", "/opt/tacua-probe/probe.py"]
CMD ["serve"]
