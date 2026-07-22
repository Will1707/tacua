// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  CandidateEvidenceViewValidationError,
  validateCandidateEvidenceView,
} from "./candidate-evidence-view.ts";

const digest = (character) => `sha256:${character.repeat(64)}`;

const binding = {
  candidateId: "candidate_example",
  candidateVersion: 3,
  candidateDigest: digest("a"),
  evidenceManifestDigest: digest("b"),
  evidenceIds: ["evidence_frame", "evidence_route", "evidence_sentry"],
};

function source(component, sourceId) {
  return {
    component,
    source_id: sourceId,
    snapshot_revision: "revision_1",
    captured_at: "2026-07-21T10:00:01Z",
  };
}

function event(eventId, sequence, elapsedMs, eventType, data, evidenceRefs = ["evidence_route"]) {
  return {
    event_id: eventId,
    sequence,
    elapsed_ms: elapsedMs,
    occurred_at: "2026-07-21T10:00:01Z",
    source: eventType === "capture_gap" ? "capture_extension" : "mobile_sdk",
    event_type: eventType,
    data,
    evidence_refs: evidenceRefs,
  };
}

function validView() {
  return {
    contract_version: "tacua.candidate-evidence-view@1.0.0",
    candidate_id: binding.candidateId,
    candidate_version: binding.candidateVersion,
    candidate_digest: binding.candidateDigest,
    evidence_manifest_digest: binding.evidenceManifestDigest,
    items: [
      {
        evidence_id: "evidence_frame",
        evidence_type: "media.keyframe",
        availability: "available",
        description: "Frame showing the reported button.",
        time_range: { start_ms: 100, end_ms: 200, clock: "session_monotonic" },
        source: source("mobile_sdk", "sdk_example"),
        reference: {
          content_type: "image/png",
          size_bytes: 1_024,
          content_digest: digest("c"),
        },
        unavailable: null,
        preview: {
          status: "available",
          content_type: "image/png",
          size_bytes: 1_024,
          content_digest: digest("c"),
        },
      },
      {
        evidence_id: "evidence_route",
        evidence_type: "sdk.route_transition",
        availability: "available",
        description: "Sanitized route transition metadata.",
        time_range: { start_ms: 0, end_ms: 1_000, clock: "session_monotonic" },
        source: source("mobile_sdk", "sdk_example"),
        reference: {
          content_type: "application/vnd.tacua.sdk-event+json",
          size_bytes: 512,
          content_digest: digest("d"),
        },
        unavailable: null,
        preview: {
          status: "not_applicable",
          content_type: null,
          size_bytes: null,
          content_digest: null,
        },
      },
      {
        evidence_id: "evidence_sentry",
        evidence_type: "observability.sentry_snapshot",
        availability: "unavailable",
        description: "Sentry was not configured.",
        time_range: null,
        source: source("sentry", "sentry_example"),
        reference: null,
        unavailable: {
          reason: "not_configured",
          detail: "The optional Sentry connector was not configured.",
        },
        preview: {
          status: "not_applicable",
          content_type: null,
          size_bytes: null,
          content_digest: null,
        },
      },
    ],
    diagnostic_events: [
      event("event_route", 10, 10, "route_transition", {
        from_route: null,
        to_route: "Settings",
        trigger: "user",
      }, []),
      event("event_interaction", 11, 20, "user_interaction", {
        action: "tap",
        target: "Save button",
        value_capture: "not_collected",
      }),
      event("event_error", 12, 30, "runtime_error", {
        error_class: "TypeError",
        sanitized_message: "A sanitized error message.",
        stack_trace_digest: digest("e"),
        handled: true,
      }),
      event("event_network", 13, 40, "network_request_completed", {
        request_id: "request_example",
        method: "POST",
        host: "api.example.test",
        path_template: "/v1/items/{id}",
        status_code: 409,
        duration_ms: 125,
        trace_id: "trace_example",
        outcome: "error",
        request_body_capture: "not_collected",
        response_body_capture: "not_collected",
      }),
      event("event_state", 14, 50, "app_state_changed", {
        from_state: "active",
        to_state: "background",
      }),
      event("event_issue", 15, 60, "issue_mark", {
        marker_id: "marker_example",
        kind: "spoken",
        narration_elapsed_ms: 60,
      }),
      event("event_gap", 16, 70, "capture_gap", {
        gap_id: "gap_example",
        affected_streams: ["app_video", "microphone"],
      }),
      event("event_custom", 17, 80, "custom_state", {
        provider_id: "provider_example",
        snapshot_digest: digest("f"),
        collection_status: "available",
      }),
    ],
  };
}

function rejectsView(view, expectedBinding = binding) {
  assert.throws(
    () => validateCandidateEvidenceView(view, expectedBinding),
    (error) => error instanceof CandidateEvidenceViewValidationError,
  );
}

test("accepts the exact evidence projection and every frozen diagnostic event variant", () => {
  assert.deepEqual(validateCandidateEvidenceView(validView(), binding), validView());
});

test("rejects candidate, manifest, membership, availability, source, reference, and preview substitution", () => {
  const mutations = [
    (view) => { view.extra = true; },
    (view) => { view.candidate_digest = digest("0"); },
    (view) => { view.items.pop(); },
    (view) => { view.items[1].evidence_id = "evidence_frame"; },
    (view) => { view.items[0].extra = true; },
    (view) => { view.items[1].evidence_type = "repository.commit_snapshot"; },
    (view) => { view.items[1].source.component = "backend"; },
    (view) => { view.items[1].description = "Cafe\u0301"; },
    (view) => { view.items[1].description = "Bearer abcdefghijklmnop"; },
    (view) => { view.items[1].time_range.start_ms = 1_001; },
    (view) => { view.items[1].reference.extra = true; },
    (view) => { view.items[1].reference.content_type = "image/jpeg"; },
    (view) => { view.items[2].unavailable.reason = "unknown"; },
    (view) => { view.items[2].reference = { ...view.items[1].reference }; },
    (view) => { view.items[1].preview.status = "available"; },
    (view) => { view.items[0].preview.content_digest = digest("9"); },
    (view) => { view.items[0].preview.status = "not_applicable"; },
    (view) => { view.items[0].preview.size_bytes = 2_097_153; },
    (view) => {
      for (const item of view.items) {
        item.availability = "unavailable";
        item.reference = null;
        item.unavailable = { reason: "not_configured", detail: "Unavailable." };
        if (item.evidence_type === "media.keyframe") {
          item.preview = { status: "unavailable", content_type: null, size_bytes: null, content_digest: null };
        }
      }
    },
  ];
  for (const mutate of mutations) {
    const view = validView();
    mutate(view);
    rejectsView(view);
  }
});

test("rejects malformed diagnostic variants, selection, references, identity, and deterministic order", () => {
  const mutations = [
    (view) => { view.diagnostic_events[0].extra = true; },
    (view) => { view.diagnostic_events[0].data.extra = true; },
    (view) => { view.diagnostic_events[1].data.extra = true; },
    (view) => { view.diagnostic_events[2].data.extra = true; },
    (view) => { view.diagnostic_events[3].data.extra = true; },
    (view) => { view.diagnostic_events[4].data.extra = true; },
    (view) => { view.diagnostic_events[5].data.extra = true; },
    (view) => { view.diagnostic_events[6].data.extra = true; },
    (view) => { view.diagnostic_events[7].data.extra = true; },
    (view) => { view.diagnostic_events[0].event_type = "unknown"; },
    (view) => { view.diagnostic_events[1].data.value_capture = "raw_value"; },
    (view) => { view.diagnostic_events[2].data.sanitized_message = "Cafe\u0301"; },
    (view) => { view.diagnostic_events[3].data.path_template = "/items?secret=value"; },
    (view) => { view.diagnostic_events[3].data.status_code = 99; },
    (view) => { view.diagnostic_events[5].data.narration_elapsed_ms = 1_800_001; },
    (view) => { view.diagnostic_events[6].data.affected_streams.push("app_video"); },
    (view) => { view.diagnostic_events[7].data.snapshot_digest = null; },
    (view) => { view.diagnostic_events[0].evidence_refs = ["evidence_unknown"]; },
    (view) => { view.diagnostic_events[1].evidence_refs.push("evidence_route"); },
    (view) => { view.diagnostic_events[1].event_id = "event_route"; },
    (view) => { view.diagnostic_events[0].elapsed_ms = 1_001; },
    (view) => { view.diagnostic_events[0].sequence = 9_007_199_254_740_992; },
    (view) => { view.diagnostic_events[0].occurred_at = "2026-02-30T10:00:01Z"; },
    (view) => { [view.diagnostic_events[0], view.diagnostic_events[1]] = [view.diagnostic_events[1], view.diagnostic_events[0]]; },
    (view) => { view.diagnostic_events = Array.from({ length: 513 }, (_, index) => ({ ...view.diagnostic_events[0], event_id: `event_${index}` })); },
  ];
  for (const mutate of mutations) {
    const view = validView();
    mutate(view);
    rejectsView(view);
  }
});

test("reports exact body-binding drift separately from malformed evidence", () => {
  const view = validView();
  view.candidate_version += 1;
  assert.throws(
    () => validateCandidateEvidenceView(view, binding),
    (error) => error instanceof CandidateEvidenceViewValidationError
      && error.code === "EVIDENCE_BINDING_MISMATCH",
  );
});
