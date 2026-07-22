# EXP-001 physical-device results

Status: physical candidate gates complete for foreground capture, interruption,
verified-partial choice, resume, scoped deletion, the 30-minute foreground
limit, lock recovery, and deterministic storage/writer/stop fault handling;
V1 app-audio release acceptance remains open because the observed drops were
not recorded as explicit gap entries

Date: 2026-07-21

Scope: local-only synthetic capture; no upload or external model egress

## Environment

- Physical iPhone 13 mini running iOS 18.4.1.
- Tacua Capture Lab development client, arm64, iOS 17 deployment target.
- Expo SDK 56 / React Native 0.85.3 / Xcode 26.4.1 toolchain.
- First-party `RPScreenRecorder.startCapture` module with microphone enabled.

No stable device identifier, signing credential, raw narration, or recording is
included in this document.

## Baseline foreground run

The operator completed a synthetic narrated foreground walkthrough and marked
two spoken issues. Tacua finalized four MOV segments and all four sidecar SHA-256
values matched their media files.

| Measurement | Observed |
| --- | ---: |
| Terminal state | `partial` |
| Verified segments | 4 |
| Total media bytes | 7,044,172 |
| Microphone samples | 1,765 |
| App-audio samples | 1,751 |
| Markers | 2 |
| Stable error codes | 0 |
| Continuity gaps | 8 |

Every segment contained H.264 video, stereo AAC app audio, and mono AAC
microphone audio at 44.1 kHz. The run therefore proves physical-device capture,
narration, app-audio delivery, segment finalization, sidecar integrity, marker
capture, and local recovery discovery.

## Finding F1: false discontinuities on static UI

The original spike classified any interval over 500 ms between video samples as
`video_pts_discontinuity`. ReplayKit legitimately uses variable video cadence and
can suppress unchanged frames, so long intervals were recorded even though
media time and monotonic host time advanced together.

The candidate fix now compares the media-clock delta with the host-clock delta.
A long interval is continuous when both clocks advance together; a regression
or material delta mismatch remains a gap. Platform-independent regression tests
cover static-screen continuity, uncorroborated media jumps, and media-clock
regression. A second physical foreground run exercised the candidate fix with a
mostly static screen. It completed with two finalized segments (10.1 and 7.3
seconds), 758 microphone samples, zero continuity gaps, and no stable errors. F1
is closed for the foreground proof. Background transitions, process
interruption, and the 30-minute limit remain separate gates.

## Finding F2: segment duration follows the last delivered video sample

The configured design segment was 10 seconds, but the baseline static interval allowed one
segment to reach about 20.17 seconds of audio while its delivered video track
ended near 6.80 seconds. Another segment contained about 10.46 seconds of audio
and 4.79 seconds of delivered video. Rotation was evaluated only when a video
sample arrived, while audio could continue during a static-screen interval.

The candidate fix rotates when any continuous media timestamp crosses the
segment boundary. When ReplayKit has suppressed unchanged video frames, Tacua
retimes a copy of the last observed frame to close the old segment and open the
new one. Each sidecar records `heldVideoSamples`, so this duration extension is
explicit evidence and cannot be mistaken for observed user interaction.

A mostly static 141.3-second physical run finalized fourteen 10.0-second
segments and one 1.3-second tail with zero gaps, no stable errors, 6,141
microphone samples, and 6,081 app-audio samples. All checksums matched. `ffprobe`
reported 10.033 seconds of video for every full segment, about 10 seconds on both
audio tracks, and 1.322 seconds of video in the tail. The manifest recorded 28
held frames across 15 segments. F2 is closed for foreground static capture; the
background/lock behavior remains a separate gate.

## 30-minute foreground resource run

An unattended physical-device run reached the persisted monotonic deadline and
stopped automatically. Tacua restored the host app's prior idle-timer setting
after the stop; the temporary override prevented auto-lock during capture.

| Measurement | Observed |
| --- | ---: |
| Stop reason | `maximum_duration` |
| Terminal state | `completed` |
| Finalized segments | 180 |
| Manifest media duration | 1,799.997 seconds |
| Start-to-terminal elapsed time | 1,800.409 seconds |
| Deadline overshoot | 0.409 seconds |
| Total media bytes | 33,888,910 |
| Microphone samples | 78,261 |
| App-audio samples | 77,402 |
| Held video frames | 359 |
| Continuity gaps | 0 |
| Stable errors | 0 |
| Dropped video samples | 0 |
| Dropped microphone samples | 0 |
| Dropped app-audio samples | 121 |

All 180 manifest SHA-256 values matched their media. Representative beginning,
middle, and final MOV segments each contained full-duration video and both audio
tracks. The 121 app-audio drops represent about 0.156% of 77,523 append attempts
and occurred without microphone or video loss. This remains acceptable evidence
for the experiment's foreground-duration gate. It does **not** pass the separate
V1 app-audio acceptance gate in
[ADR-018](../../docs/decisions/ADR-018-v1-app-audio-acceptance.md): the numeric
rate is below the accepted 0.2% ceiling, but none of the 121 dropped append
attempts was persisted as an explicit `app_audio_append_drop` gap.

The machine-readable historical artifact is intentionally negative:

```sh
python3 scripts/validate_app_audio_acceptance.py \
  fixtures/app-audio-acceptance/physical-2026-07-21-unaccounted.json
# UNACCOUNTED_APP_AUDIO_DROPS
```

Repository tests also exercise a clearly labeled synthetic conformance fixture
at exactly 0.2%. Synthetic conformance cannot close the physical gate. A new
30-minute physical run must remain in the gap-free `completed` state, record
every dropped append-attempt index exactly once in the acceptance artifact, and
pass the validator without `--conformance`. Schema-4 captures
now persist contiguous per-segment attempt ranges and each dropped index with a
closed cause. After the new run stops with zero stable errors, derive and
validate the canonical artifact directly from its private manifest:

```sh
python3 scripts/generate_app_audio_acceptance.py \
  /private/path/to/manifest.json \
  --run-id physical-audio-001 \
  --evidence-class physical_device \
  --output /private/path/to/app-audio-acceptance.json

python3 scripts/validate_app_audio_acceptance.py \
  /private/path/to/app-audio-acceptance.json \
  --source-manifest /private/path/to/manifest.json
```

The artifact binds the exact manifest bytes and capture/build identity. Its
mandatory `physical_device` label is the operator's evidence classification,
not hardware attestation. The generator refuses schema-3, `partial`, gapped,
interrupted/resumed, incomplete, errorful, or internally inconsistent runs. No new qualifying physical run has been executed
yet, so ADR-018's physical gate remains open.

## Lock-screen lifecycle run

The first lock test exposed a lifecycle bug in the held-frame implementation.
Tacua left the active writer open when the app backgrounded, then attempted to
rotate that writer after foreground media returned. AVAssetWriter rejected the
operation. Tacua preserved one checksum-valid segment and failed closed as
`partial`, but added avoidable `segment_rotation_failed`,
`video_tail_extension_failed`, and `segment_finalization_failed` gaps.

The fix finalizes the current segment as soon as the app enters the background,
suppresses held-frame rotation while the lifecycle gap is open, and starts a new
writer only when foreground video returns. It records audio callbacks received
while no writer is open in the nullable `droppedDuringBackground` manifest
field.

A physical lock/unlock retest completed manually with 10 checksum-valid
segments, one closed `app_backgrounded` gap, zero stable errors, and terminal
state `partial`. Eight segments were exactly 10 seconds; the pre-lock and final
tails were 8.061 and 8.945 seconds. The manifest recorded 14 microphone and 15
app-audio callbacks received during the closed lifecycle interval. No media was
invented across the lock gap, and capture resumed into new segment indexes after
unlock.

## Process-interruption recovery run

The operator started a narrated capture and Tacua Capture Lab was then
force-terminated and relaunched through the paired-device development bridge.
Before termination, the session finalized 10 segments containing 11,127
microphone samples and 11,026 app-audio samples. The recovery scan transitioned
the persisted manifest from `recording` to `recoverable_partial`, retained all
10 segments, added only `ERR_TACUA_CAPTURE_INTERRUPTED`, and reported zero
continuity gaps. Every manifest SHA-256 value matched its copied segment.

The harness now runs recovery discovery automatically on launch. The operator
explicitly selected `Keep partial`; the manifest transitioned to
`partial_ready_for_upload` while retaining all 10 verified segments, zero gaps,
and the stable interruption code. The operation did not upload or delete media.

The first choice attempt exposed a recovery-UI defect: sessions were presented
oldest-first and primarily identified by opaque IDs, so the operator selected an
older four-segment partial session. The harness now sorts newest-first and
highlights `Interrupted · action required` with its segment count. The second
attempt selected the intended 10-segment session. No data was lost during the
incorrect selection, but V1 must carry this disambiguation into its recovery UI.

A second interrupted session validated `Resume`. Tacua retained two pre-crash
segments, resumed at segment index 2, incremented `resumeCount` to 1, and closed
one explicit `process_resume` gap when new media arrived. Manual stop finalized
four segments with 2,309 microphone samples and 2,284 app-audio samples in
total. The terminal state remained `partial`, correctly preserving the original
interruption code and recovery gap as evidence. Explicit `Delete` validation
then removed only this newest four-segment synthetic session. The recovery count
dropped from five to four, and a direct lookup confirmed the exact session
manifest no longer existed. The harness now requires a destructive confirmation
that states how many verified segments and associated metadata will be removed.

## Deterministic fault-injection campaign

The dedicated QA variant at commit `ad1fc1e` exercised all seven plans in the
fault-injection runbook on the physical device. The variant required the
compile-time condition, exact harness bundle identifier, Info.plist opt-in, and
one exact launch environment value. A separately compiled ordinary pod binary
contained none of the plan names, QA stop reason, or environment key.

The two low-storage cases replaced only Tacua's capacity decision. They did not
fill the personal device or claim to reproduce an operating-system `ENOSPC`
failure. Writer and ReplayKit-stop cases exercised the real writer, recorder,
watchdogs, manifests, sidecars, and cleanup paths around the injected boundary.

| Plan | Physical outcome | Verified integrity |
| --- | --- | ---: |
| `low_storage_start` | Rejected with `ERR_TACUA_CAPTURE_STORAGE_LOW` before ReplayKit or session creation | No new session |
| `low_storage_writer_1` | `partial`; `ERR_TACUA_CAPTURE_STORAGE_LOW`; `segment_rotation_failed`; index 1 was never claimed | 1/1 segment |
| `writer_finish_failure_1` | `partial`; `ERR_TACUA_CAPTURE_WRITER_FINISH`; index 1 published no trusted artifact | 1/1 segment |
| `writer_finish_timeout_1` | `partial` after 45.9 seconds; `ERR_TACUA_CAPTURE_WRITER_TIMEOUT`; the real late callback left only an untrusted partial and could not publish index 1 | 1/1 segment |
| `stop_failure_once` | First callback failed; the serialized retry performed the live stop; `partial` with `ERR_TACUA_CAPTURE_STOP_FAILED` | 5/5 segments |
| `stop_timeout_once` | One 15-second watchdog elapsed, then the serialized live retry stopped ReplayKit; `partial` after 20.2 seconds | 3/3 segments |
| `stop_timeout_twice` | The operator observed the first Stop reach `stop_failed_capture_active`; the mandatory second Stop performed live cleanup; terminal `partial` after 36.8 seconds | 19/19 segments |

For every plan that produced media, each listed segment matched manifest byte
length, MOV SHA-256, and sidecar SHA-256. The stop plans ended with ReplayKit
inactive, no partial files, and only their expected stable error and gap
reasons. Segment counts vary with operator timing and are evidence counts, not
performance measurements.

One ordinary 10-second capture was started unintentionally between plans. It
was stopped manually, excluded from fault evidence, and deleted. Each planned
campaign session was also deleted through the harness's scoped confirmation UI
after private inspection. The final device check found zero campaign sessions;
older synthetic sessions were unchanged. All temporary media/metadata copies
and device-command JSON containing private identifiers were deleted from the
Mac before these aggregate results were written.

## Evidence handling

Raw media was copied to private temporary directories for `ffprobe` and checksum
inspection, then deleted immediately after aggregate measurements were recorded.
The eight older synthetic source sessions remain only in the app container
pending an explicit all-test-data cleanup decision. No fault-campaign session
or private Mac copy remains.
