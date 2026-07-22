# ADR-018: Bound and explicitly account for V1 app-audio append drops

- Status: accepted
- Date: 2026-07-22
- Scope: Tacua V1 physical capture acceptance

## Context

The 30-minute iPhone campaign observed 77,402 appended app-audio samples and
121 drops across 77,523 append attempts, about 0.156%. Video and microphone had
no drops. That was sufficient to study the foreground-duration design, but V1
had no accepted loss threshold and the manifest's zero continuity gaps did not
identify any of the app-audio loss. A percentage alone can therefore hide
unrepresented evidence discontinuity.

## Decision

A 30-minute physical V1 acceptance run passes app audio only when all rules are
true:

1. `dropped_app_audio_samples / app_audio_append_attempts <= 0.002` (0.2%),
   evaluated with integer arithmetic; and
2. every dropped append-attempt index appears exactly once in an explicit gap
   whose reason is `app_audio_append_drop`; and
3. its schema-4 source manifest is an accounting-complete, zero-resume,
   zero-error, gap-free `completed` capture. A `partial` run cannot close this
   physical gate.

The machine artifact is `tacua.app-audio-acceptance@1.0.0`. It binds the run and
evidence class, duration, total attempts, appended count, dropped count, and a
bounded set of unique gap IDs containing ordered exact dropped-attempt indexes.
It also binds the SHA-256 digest of the exact source-manifest bytes and the
manifest's application, build, build-number, session, and schema identity.
The validator also requires `appended + dropped == attempts`, rejects duplicate
accounting across gaps, caps attempts at 10,000,000 and exact drops at 2,048,
and bounds a physical campaign to 1,799,000 through 1,831,000 milliseconds. The
upper tolerance covers ReplayKit stop and writer-finalization watchdogs because
the terminal host-uptime timestamp is persisted after those callbacks settle.

Evidence class is mandatory. `physical_device` is an operator assertion backed
by the physical run record, not device attestation; `synthetic_conformance`
exercises contract behavior only. Passing physical validation also requires the
exact source manifest, and any byte or identity mismatch fails closed.

Synthetic conformance may test boundary arithmetic and schema behavior only
when explicitly requested. It cannot close the physical release gate. The
historical 2026-07-21 artifact is checked in as an intentional negative: its
0.156% rate satisfies the numeric ceiling, but its 121 drops have no gap
records, so validation returns `UNACCOUNTED_APP_AUDIO_DROPS`.

## Consequences

- A small, bounded drop rate is accepted only when downstream processing can
  identify exactly where capture evidence is discontinuous; reviewer-facing
  candidates may surface the resulting derived evidence.
- Zero-gap claims are impossible when any app-audio append was dropped.
- The numeric decision is closed, but physical release evidence remains open
  until a new 30-minute run records the accepted gap artifact and passes it
  without the synthetic-conformance option.
- Schema 4 carries exact append ranges, drop indexes, and closed causes in local
  segment sidecars, then admission persists their verified allowlisted
  projection in the sealed runtime completion manifest. That manifest remains
  available to the asynchronous processor after receipt-authorized local
  cleanup. The derived acceptance artifact independently preserves the same
  no-silent-drop invariant for the physical release gate.
- The SDK durably reserves app-audio indexes before issuing them. A crash seals
  the unused reservation as an explicit unknown range, never reuses those
  identities, and makes the run ineligible for this physical gate.

## Rejected alternatives

- **Require zero drops:** the documented boundary-reordering loss is small and
  isolated to app audio; an absolute zero criterion is not necessary for the
  V1 private pilot when every loss is explicit.
- **Accept a percentage without gaps:** aggregate loss can conceal when the
  evidence is discontinuous.
- **Count one aggregate gap without exact attempts:** it does not prove every
  drop was accounted once and only once.
- **Grandfather the historical run:** it predates the accounting requirement
  and cannot retroactively supply unknown drop indexes.
