# Active human-time logging protocol

Version: `1.0.0`

## Clock rule

Use monotonic offsets from session start in integer milliseconds. A logger
records `active_start` immediately before human attention begins and
`active_stop` immediately after it ends. Intervals may not overlap or remain
open. The deterministic summarizer adds paired intervals; it never estimates
missing markers.

Active work includes app review, narration, screenshot/note/ticket work,
candidate correction, answering clarification, and fix acceptance. Machine
upload, transcription, analysis, queue, build, and agent execution wait are
inactive.

## Event record

Each JSON Lines event conforms to `schemas/timing-event.schema.json` and has:

- `study_id`, anonymized `session_id`, `condition`, and `event_id`;
- monotonic `offset_ms` and one of `active_start`, `active_stop`,
  `interaction`, `correction`, `approval`, `note`;
- an activity/reason code with no raw recording or transcript content;
- optional `candidate_id`, `issue_id`, and safe notes.

Every `interaction` adds `interaction_kind`, `evidence_gap`, and
`prevented_error` (`yes`, `no`, or `unknown`). Every `correction` records a
correction class and active milliseconds are captured by surrounding active
markers.

## Audit

For each real run, manually stopwatch-audit at least one complete session (or
all sessions when fewer than five exist). Compare calculated active seconds to
the stopwatch value and report absolute/percentage difference. Do not repair a
bad log silently; append a correction event with author, timestamp, and reason.

`fixtures/timing/example-events.v1.0.0.jsonl` is synthetic and exists only to
exercise the format and summarizer.
