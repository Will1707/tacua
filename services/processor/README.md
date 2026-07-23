# Offline marked-session processor

This optional Apache-2.0 processor turns explicit issue marks in a completed
Tacua iOS capture into conservative draft ticket candidates. It runs only
through Tacua's isolated private-pilot runner:

- Docker network mode is `none`.
- The model and admitted capture files are digest-verified, read-only payloads.
- FFmpeg extracts a real adaptively sized PNG at each issue mark and a bounded
  mono microphone window that may span adjacent media segments.
- a pinned `whisper.cpp` executable transcribes that window locally.
- first-party deterministic code creates a draft ticket, attached screenshot,
  and a blocking expected-behavior clarification.
- it never claims repository, backend, Sentry, or PostHog evidence that was not
  supplied.

The first four legacy pipeline stages are exact no-op checkpoints. The final
stage performs the media work once. This is intentionally a short pilot bridge;
the artifact pipeline must persist transcription before long 20–30 minute
captures are treated as release-proven.

## Build

Build from the repository root. The default Debian base is pinned to the reviewed
multi-platform digest used by this pilot:

```bash
node --test .github/scripts/validate-processor-image-inputs.test.mjs
node .github/scripts/validate-processor-image-inputs.mjs
PYTHONWARNINGS=error python3 -B -m unittest discover \
  -s services/processor/tests -v
TACUA_PROCESSOR_TEST_ID=local-verify \
TACUA_KEEP_VERIFIED_IMAGES=true \
  bash .github/scripts/verify-processor-container.sh
```

The image builds `whisper.cpp` v1.8.5 from exact source revision
`f24588a272ae8e23280d9c220536437164e6ed28`. The final scratch stage intentionally
inherits no entrypoint, command, healthcheck, volume, port, user, or credential
metadata.

The verifier refuses an existing candidate tag, builds through the closed
context, checks the final image has no entrypoint, command, port, volume,
healthcheck, user, or credential metadata, retains the Tacua and third-party
license notices, and runs a canonical checkpoint with no network or writeable
root. It deletes the image on every failure. With
`TACUA_KEEP_VERIFIED_IMAGES=true`, the exact successful
`tacua-offline-processor:local-verify` image is retained for digest-pinned
publication; do not rebuild it after verification.

For pilot or release promotion, perform that command from a fresh checkout of
the exact commit and first require an empty
`git status --porcelain --untracked-files=all`. Use a unique lowercase test ID
for every candidate. Record the image ID printed by the successful verifier,
tag that image ID—not a rebuild—to the authorized registry reference, push it
once, and record the resulting registry repository digest. Configure the
isolated runner with the immutable
`registry/repository@sha256:...` reference. A local image ID proves which
retained object was tested; a registry digest proves which pushed object will
be pulled. Neither may be substituted for the other.

## Model

The model is not baked into the image or repository. Download the operator's
chosen GGML model separately, store it in an owner-only directory, calculate
its SHA-256 digest, and put the exact path, model ID, and digest in the isolated
command document. `base.en` is the initial English pilot choice. The upstream
model is roughly 142 MB; Tacua reopens and hashes it before every run.

Do not use an unpinned mutable image tag or an unverified model. Do not add the
Docker socket, backend secret, provider credentials, network access, or an
always-on processing service.

## Behavior

Each `issue_mark` must fall inside an available media segment. The processor
extracts a frame at the mark and transcribes the microphone track from up to
15 seconds before through 20 seconds after it. The iOS writer creates stereo
app audio before mono microphone audio, so stream selection is based on the
one-channel track rather than an assumed numeric index.

Shared segment endpoints select the later segment, while narration is assembled
from every contiguous segment in the window. Known microphone gaps, missing
coverage, unsupported source media, silence, or issue marks closer than 12
seconds suppress automatic transcription; the screenshot still becomes a draft
candidate and the reviewer is asked to describe the expected result. A known
app-video gap at the exact mark fails closed and publishes nothing.

Whisper output is treated as low-confidence, unconfirmed derived text. Only
timestamped utterances near the mark are retained. Ticket evidence cites the
digest-bound retained QuickTime source clips—not an ephemeral transcript file—
and records the selected model ID plus pinned `whisper.cpp` revision as
uncertainty. The processor independently hashes models up to 1 GiB so the exact
model digest survives with that provenance. Human confirmation remains blocking.

One run accepts at most 12 issue marks, at most 2 MiB per screenshot, and at most
24 MiB of screenshot bytes in total. PNG extraction retries at narrower widths
before failing. The processor keeps a 135-second internal deadline inside the
runner's 150-second container limit.

`scripts/build_synthetic_runner_fixture.py` is a non-production verification
helper. It binds one operator-created 60-second synthetic MOV to Tacua's frozen
terminal-stage fixtures so the real isolated runner, model, image, keyframe,
and candidate envelope can be tested without a user recording.

## Third-party software

`whisper.cpp` and the OpenAI Whisper model weights are MIT licensed. FFmpeg is
installed from Debian and retains its packaged notices and license material in
the image. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
