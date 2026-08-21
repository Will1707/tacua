# SPDX-License-Identifier: Apache-2.0

FROM python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

LABEL org.opencontainers.image.title="Tacua reviewer web" \
      org.opencontainers.image.description="Authority-free static reviewer for a self-hosted Tacua deployment" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN groupadd --gid 10002 tacua-reviewer \
    && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tacua-reviewer \
    && install -d -o root -g root -m 0555 \
      /srv/tacua-reviewer \
      /srv/tacua-reviewer/_expo \
      /srv/tacua-reviewer/_expo/static \
      /srv/tacua-reviewer/_expo/static/js \
      /srv/tacua-reviewer/_expo/static/js/web \
      /srv/tacua-reviewer/assets \
      /srv/tacua-reviewer/assets/node_modules \
      /srv/tacua-reviewer/assets/node_modules/expo-router \
      /srv/tacua-reviewer/assets/node_modules/expo-router/assets \
      /srv/tacua-reviewer/assets/node_modules/expo-router/assets/react-navigation \
      /srv/tacua-reviewer/assets/node_modules/expo-router/assets/react-navigation/elements \
      /licenses \
      /licenses/tacua \
      /licenses/reviewer

COPY --chown=root:root --chmod=0555 services/reviewer-web/server.py /usr/local/bin/tacua-reviewer-web
COPY --chown=root:root --chmod=0444 apps/reviewer/dist/index.html apps/reviewer/dist/metadata.json /srv/tacua-reviewer/
COPY --chown=root:root --chmod=0444 apps/reviewer/dist/_expo/static/js/web/*.js /srv/tacua-reviewer/_expo/static/js/web/
COPY --chown=root:root --chmod=0444 apps/reviewer/dist/assets/node_modules/expo-router/assets/*.png /srv/tacua-reviewer/assets/node_modules/expo-router/assets/
COPY --chown=root:root --chmod=0444 apps/reviewer/dist/assets/node_modules/expo-router/assets/react-navigation/elements/*.png /srv/tacua-reviewer/assets/node_modules/expo-router/assets/react-navigation/elements/
COPY --chown=root:root --chmod=0444 LICENSE NOTICE /licenses/tacua/
COPY --chown=root:root --chmod=0444 apps/reviewer/NOTICE /licenses/reviewer/NOTICE
COPY --chown=root:root --chmod=0444 apps/reviewer/generated/THIRD_PARTY_NOTICES.txt /licenses/reviewer/THIRD_PARTY_NOTICES.txt

USER 10002:10002
EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8081/', timeout=2); assert r.status==200 and r.headers['Cache-Control']=='no-store' and r.headers['X-Content-Type-Options']=='nosniff'"]

ENTRYPOINT ["python", "-B", "/usr/local/bin/tacua-reviewer-web"]
