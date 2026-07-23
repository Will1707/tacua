# SPDX-License-Identifier: Apache-2.0

ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

FROM ${DEBIAN_IMAGE} AS whisper-build
ARG WHISPER_CPP_REV=f24588a272ae8e23280d9c220536437164e6ed28
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates cmake g++ git make \
    && rm -rf /var/lib/apt/lists/*
RUN git init /src/whisper.cpp \
    && git -C /src/whisper.cpp remote add origin https://github.com/ggml-org/whisper.cpp.git \
    && git -C /src/whisper.cpp fetch --depth 1 origin "${WHISPER_CPP_REV}" \
    && test "$(git -C /src/whisper.cpp rev-parse FETCH_HEAD)" = "${WHISPER_CPP_REV}" \
    && git -C /src/whisper.cpp checkout --detach FETCH_HEAD
RUN cmake -S /src/whisper.cpp -B /src/whisper.cpp/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DWHISPER_BUILD_TESTS=OFF \
      -DWHISPER_BUILD_SERVER=OFF \
      -DWHISPER_CURL=OFF \
      -DBUILD_SHARED_LIBS=OFF \
      -DGGML_NATIVE=OFF \
      -DGGML_OPENMP=OFF \
    && cmake --build /src/whisper.cpp/build --config Release --target whisper-cli -j2

FROM ${DEBIAN_IMAGE} AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg python3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=whisper-build /src/whisper.cpp/build/bin/whisper-cli /usr/local/bin/whisper-cli
COPY --from=whisper-build /src/whisper.cpp/LICENSE /usr/share/doc/whisper.cpp/LICENSE
RUN install -d -m 0555 /usr/share/doc/tacua
COPY --chmod=0444 LICENSE /usr/share/doc/tacua/LICENSE
COPY --chmod=0444 NOTICE /usr/share/doc/tacua/NOTICE
COPY --chmod=0444 services/processor/THIRD_PARTY_NOTICES.md /usr/share/doc/tacua/THIRD_PARTY_NOTICES.md
COPY --chmod=0555 services/processor/processor.py /usr/local/bin/tacua-offline-processor

# Reset inherited image metadata. The trusted runner permits only locale/PATH
# environment metadata and rejects healthchecks, volumes, ports and authority.
FROM scratch
COPY --from=runtime / /
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
