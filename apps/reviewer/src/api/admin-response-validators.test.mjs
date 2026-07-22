// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AdminResponseValidationError,
  validateAuditEventPage,
  validateProcessingJobDetail,
  validateProcessingJobPage,
  validateSessionDetail,
} from "./admin-response-validators.ts";
import { canonicalJson } from "../approved-handoff/contract.ts";

const fixtureRoot = new URL("../../../../contracts/", import.meta.url);

async function fixture(relativePath) {
  return JSON.parse(await readFile(new URL(relativePath, fixtureRoot), "utf8"));
}

function clone(value) {
  return structuredClone(value);
}

async function digestBytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function reseal(value, field) {
  value[field] = await digestBytes(new TextEncoder().encode(canonicalJson(value, field)));
  return value;
}

async function completedSession() {
  const [build, scope, segmentReceipt, diagnosticReceipt, completionReceipt] = await Promise.all([
    fixture("sdk-backend-protocol/fixtures/positive/build-identity.json"),
    fixture("sdk-backend-protocol/fixtures/positive/capture-scope.json"),
    fixture("sdk-backend-protocol/fixtures/positive/segment-upload-receipt.json"),
    fixture("sdk-backend-protocol/fixtures/positive/diagnostic-upload-receipt.json"),
    fixture("sdk-backend-protocol/fixtures/positive/completion-receipt.json"),
  ]);
  const initialJob = completionReceipt.processing_job;
  return {
    application_id: scope.application_id,
    build_id: build.build_id,
    build_identity: build,
    build_identity_digest: build.build_identity_digest,
    completed_at: completionReceipt.accepted_at,
    completion_id: completionReceipt.completion_id,
    completion_receipt: completionReceipt,
    consent_contract: scope.consent.policy_version,
    created_at: "2026-07-21T10:00:00Z",
    credentials: [
      {
        credential_id: segmentReceipt.credential_id,
        ordinal: 0,
        issued_at: "2026-07-21T10:00:00Z",
        expires_at: "2026-08-20T10:00:00Z",
        revoked_at: "2026-07-21T10:01:00Z",
        issued_state: "active",
        current_state: "revoked",
        replay_completion_id: null,
      },
      {
        credential_id: completionReceipt.credential.credential_id,
        ordinal: 1,
        issued_at: "2026-07-21T10:01:00Z",
        expires_at: completionReceipt.credential.expires_at,
        revoked_at: null,
        issued_state: "active",
        current_state: "completion_replay_or_delete_only",
        replay_completion_id: completionReceipt.completion_id,
      },
    ],
    diagnostic_receipts: [diagnosticReceipt],
    diagnostics: [{
      envelope_id: diagnosticReceipt.envelope_id,
      size_bytes: diagnosticReceipt.size_bytes,
      content_digest: diagnosticReceipt.transport_digest,
      envelope_digest: diagnosticReceipt.envelope_digest,
      received_at: diagnosticReceipt.received_at,
    }],
    jobs: [{
      job_id: initialJob.job_id,
      job_type: "process_session",
      status: initialJob.status,
      requested_at: initialJob.requested_at,
      started_at: initialJob.started_at,
      completed_at: initialJob.completed_at,
      failure_code: null,
    }],
    manifest_digest: completionReceipt.local_cleanup.manifest_digest,
    organization_id: scope.organization_id,
    project_id: scope.project_id,
    retention: {
      policy_version: scope.retention.policy_version,
      raw_media_expires_at: "2026-08-20T10:00:00Z",
      derived_data_expires_at: "2026-08-20T10:00:00Z",
      deletion_status: "active",
    },
    scope,
    scope_digest: scope.scope_digest,
    segment_receipts: [segmentReceipt],
    segments: [segmentReceipt.runtime_receipt],
    session_id: completionReceipt.session_id,
    state: "completed",
  };
}

function rejectsAdmin(callback) {
  return assert.rejects(callback, (error) => error instanceof AdminResponseValidationError);
}

test("accepts the exact completed admin projection assembled from frozen backend protocol emitters", async () => {
  const session = await completedSession();
  const projected = await validateSessionDetail(session, session.session_id, digestBytes);
  assert.equal(projected.state, "completed");
  assert.equal(projected.segments.length, 1);
  assert.equal(projected.diagnostics.length, 1);
  assert.equal(projected.jobs.length, 1);
});

test("accepts a completed recovery rotation while binding the latest live credential", async () => {
  const session = await completedSession();
  const receiptCredential = session.credentials.at(-1);
  receiptCredential.revoked_at = "2026-07-21T10:03:00Z";
  receiptCredential.current_state = "revoked";
  session.credentials.push({
    credential_id: "credential_completed_recovery",
    ordinal: 2,
    issued_at: "2026-07-21T10:03:00Z",
    expires_at: "2026-08-20T10:03:00Z",
    revoked_at: null,
    issued_state: "completion_replay_or_delete_only",
    current_state: "completion_replay_or_delete_only",
    replay_completion_id: session.completion_id,
  });

  const projected = await validateSessionDetail(session, session.session_id, digestBytes);
  assert.equal(projected.state, "completed");

  const wrongCompletion = clone(session);
  wrongCompletion.credentials.at(-1).replay_completion_id = "completion_other";
  await rejectsAdmin(() => validateSessionDetail(wrongCompletion, session.session_id, digestBytes));

  const twoCurrent = clone(session);
  twoCurrent.credentials[1].revoked_at = null;
  twoCurrent.credentials[1].current_state = "completion_replay_or_delete_only";
  await rejectsAdmin(() => validateSessionDetail(twoCurrent, session.session_id, digestBytes));
});

test("accepts exact job summaries as a bounded page and full detail separately", async () => {
  const job = await fixture("runtime/fixtures/positive/job.json");
  const summary = {
    job_id: job.job_id,
    job_type: "process_session",
    status: job.status,
    requested_at: job.requested_at,
    started_at: job.started_at,
    completed_at: job.completed_at,
    failure_code: null,
  };
  const page = validateProcessingJobPage({ jobs: [summary], next_cursor: null });
  assert.deepEqual(page.jobs.map(({ job_id, status }) => ({ job_id, status })), [{
    job_id: job.job_id,
    status: "succeeded",
  }]);
  const projected = await validateProcessingJobDetail(job, job.job_id, digestBytes);
  assert.equal(projected.job_id, job.job_id);

  const tampered = clone(job);
  tampered.pipeline.pipeline_version = "tampered";
  await rejectsAdmin(() => validateProcessingJobDetail(tampered, job.job_id, digestBytes));
  await rejectsAdmin(() => validateProcessingJobDetail(job, "job_substituted", digestBytes));
});

test("full job detail enforces frozen version, output-disposition, and egress identity semantics", async () => {
  const source = await fixture("runtime/fixtures/positive/job.json");
  const mutations = [
    (job) => { job.job_version = 2; },
    (job) => { job.outputs.disposition = "no_issue_detected"; },
    (job) => {
      const destination = {
        destination_id: "destination_duplicate",
        provider_kind: "local",
        model_id: "local_model",
        content_categories: ["transcript"],
      };
      job.execution.egress = {
        policy: "default_deny",
        authorized: true,
        authorization_decision_id: "decision_synthetic",
        destinations: [destination, clone(destination)],
      };
    },
  ];
  for (const mutate of mutations) {
    const job = clone(source);
    mutate(job);
    await reseal(job, "job_digest");
    await rejectsAdmin(() => validateProcessingJobDetail(job, job.job_id, digestBytes));
  }
});

test("rejects oversized, malformed, and cursor-inconsistent admin pages", async () => {
  const job = await fixture("runtime/fixtures/positive/job.json");
  const summary = {
    job_id: job.job_id,
    job_type: "process_session",
    status: job.status,
    requested_at: job.requested_at,
    started_at: job.started_at,
    completed_at: job.completed_at,
    failure_code: null,
  };
  assert.throws(
    () => validateProcessingJobPage({ jobs: [summary], next_cursor: "cursor_jobs" }),
    AdminResponseValidationError,
  );
  assert.throws(
    () => validateProcessingJobPage({ jobs: Array.from({ length: 51 }, () => summary), next_cursor: null }),
    AdminResponseValidationError,
  );
  assert.throws(
    () => validateProcessingJobPage({ jobs: [{ ...summary, extra: true }], next_cursor: null }),
    AdminResponseValidationError,
  );
  assert.throws(
    () => validateProcessingJobPage({
      jobs: [{ ...summary, started_at: "2026-07-21T09:59:59Z" }],
      next_cursor: null,
    }),
    AdminResponseValidationError,
  );
});

test("accepts exact bounded audit-event pages and rejects duplicate events", () => {
  const event = {
    event_id: "audit_example",
    event_type: "session_completed",
    actor_kind: "sdk",
    organization_id: "organization_example",
    project_id: "project_example",
    session_id: "session_example",
    outcome: "succeeded",
    occurred_at: "2026-07-21T10:02:06Z",
  };
  assert.deepEqual(
    validateAuditEventPage({ events: [event], next_cursor: null }).events,
    [event],
  );
  assert.throws(
    () => validateAuditEventPage({ events: [event, event], next_cursor: null }),
    AdminResponseValidationError,
  );
});

test("uses the frozen 1 GiB transport maxima for media and diagnostic receipts", async () => {
  const session = await completedSession();
  const segment = session.segment_receipts[0];
  segment.runtime_receipt.size_bytes = 1_073_741_824;
  session.segments[0].size_bytes = 1_073_741_824;
  await reseal(segment.runtime_receipt, "receipt_digest");
  await reseal(segment, "segment_receipt_digest");

  const diagnostic = session.diagnostic_receipts[0];
  diagnostic.size_bytes = 1_073_741_824;
  session.diagnostics[0].size_bytes = 1_073_741_824;
  await reseal(diagnostic, "diagnostic_receipt_digest");

  session.completion_receipt.local_cleanup.segment_receipt_digests = [segment.segment_receipt_digest];
  session.completion_receipt.local_cleanup.diagnostic_receipt_digests = [diagnostic.diagnostic_receipt_digest];
  await reseal(session.completion_receipt, "completion_receipt_digest");
  await validateSessionDetail(session, session.session_id, digestBytes);
});

test("rejects malformed nested protocol records, digest substitution, bindings, and non-NFC text", async () => {
  const mutations = [
    (session) => { session.build_identity.expo.extra = true; },
    (session) => { session.build_identity.native_version = "2.0.0"; },
    (session) => { session.segment_receipts[0].scope_digest = `sha256:${"0".repeat(64)}`; },
    (session) => { session.segment_receipts[0].runtime_receipt.extra = true; },
    (session) => { session.completion_receipt.processing_job.pipeline.stages[0].extra = true; },
    (session) => { session.credentials[0].ordinal = 1; },
    (session) => { session.retention.policy_version = "Cafe\u0301"; },
  ];
  for (const mutate of mutations) {
    const session = await completedSession();
    mutate(session);
    await rejectsAdmin(() => validateSessionDetail(session, session.session_id, digestBytes));
  }
});

test("rejects protocol receipts that diverge from their concrete projections", async () => {
  const session = await completedSession();
  session.segments[0].object_id = "object_substituted";
  await reseal(session.segments[0], "receipt_digest");
  await rejectsAdmin(() => validateSessionDetail(session, session.session_id, digestBytes));
});
