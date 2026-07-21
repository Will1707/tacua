# EXP-001 physical-device results

Status: foreground capture proven; interruption and long-run checks pending

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

The configured design segment was 10 seconds, but a static interval allowed one
segment to reach about 20.17 seconds of audio while its delivered video track
ended near 6.80 seconds. Another segment contained about 10.46 seconds of audio
and 4.79 seconds of delivered video. Rotation is currently evaluated when a
video sample arrives, while audio can continue during a static-screen interval.

This does not invalidate checksums or narration capture, but it means the
candidate cannot yet claim bounded segment duration or full-duration video
coverage under ReplayKit's variable frame cadence. The next implementation
experiment must evaluate safe last-frame extension and timer-driven rotation
without inventing user interaction or dropping narration.

## Evidence handling

Raw media was copied once to a private temporary directory for `ffprobe` and
checksum inspection, then deleted immediately after these aggregate measurements
were recorded. Synthetic source sessions remain only in the app container until
the planned recovery and deletion checks complete.
