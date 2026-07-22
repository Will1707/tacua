# SPDX-License-Identifier: Apache-2.0

FROM python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91 AS runtime

# A fresh scratch stage deliberately inherits no environment, healthcheck,
# volume, entrypoint, user, or command metadata from the Python base image.
FROM scratch
COPY --from=runtime / /
COPY --chmod=0555 processor.py /opt/tacua-synthetic-processor.py
