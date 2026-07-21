# EXP-001 physical-device results

Status: foreground capture, interruption discovery, verified-partial choice,
resume, deletion, and the 30-minute foreground limit proven; background/lock
and fault-injection checks pending

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
and occurred without microphone or video loss. This is acceptable for closing
the experiment's foreground-duration gate, but production promotion must either
eliminate boundary reordering drops or define and enforce a measured threshold.

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

## Evidence handling

Raw media was copied to private temporary directories for `ffprobe` and checksum
inspection, then deleted immediately after aggregate measurements were recorded.
Remaining synthetic source sessions stay only in the app container until the
background/lock checks and final test-data cleanup.
