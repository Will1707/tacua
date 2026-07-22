// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { canonicalJson, validateTicketCandidateSnapshot } from "../approved-handoff/contract.ts";
import {
  validateTransitionBinding,
  validateTransitionRequestBinding,
} from "./admin-response-validators.ts";

const fixtureRoot = new URL("../../../../contracts/ticket-candidate/fixtures/positive/", import.meta.url);

async function fixture(name) {
  return JSON.parse(await readFile(new URL(name, fixtureRoot), "utf8"));
}

async function digestBytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function reviewerCreation(source, operation, parents, actorType = "human") {
  const candidate = structuredClone(source);
  candidate.candidate_id = `candidate_${operation}_result`;
  candidate.lineage = { operation, parents: structuredClone(parents) };
  candidate.transition = {
    from_state: null,
    to_state: "draft",
    actor: {
      actor_type: actorType,
      actor_id: actorType === "human" ? "reviewer_owner" : "worker_local",
    },
    occurred_at: candidate.version_created_at,
    reason: `reviewer_${operation}_candidate`,
  };
  candidate.review = {
    status: "in_review",
    reviewer_action_required: true,
    last_human_actor_id: "reviewer_owner",
    last_reviewed_at: candidate.version_created_at,
    notes: [],
  };
  const contentSubject = {
    contract_version: candidate.contract_version,
    organization_id: candidate.organization_id,
    project_id: candidate.project_id,
    build_id: candidate.build_id,
    build_identity_digest: candidate.build_identity_digest,
    session_id: candidate.session_id,
    evidence_manifest: candidate.evidence_manifest,
    candidate_id: candidate.candidate_id,
    content: candidate.content,
  };
  candidate.candidate_content_digest = await digestBytes(
    new TextEncoder().encode(canonicalJson(contentSubject)),
  );
  candidate.candidate_digest = await digestBytes(
    new TextEncoder().encode(canonicalJson(candidate, "candidate_digest")),
  );
  return candidate;
}

async function rejectedSuccessor(parent) {
  const candidate = structuredClone(parent);
  const rejectedAt = "2026-07-21T10:04:00Z";
  const reason = "reviewer_rejected_exact_candidate";
  candidate.candidate_version = parent.candidate_version + 1;
  candidate.previous_candidate_digest = parent.candidate_digest;
  candidate.state = "rejected";
  candidate.version_created_at = rejectedAt;
  candidate.lineage = {
    operation: "rejected",
    parents: [{
      candidate_id: parent.candidate_id,
      candidate_version: parent.candidate_version,
      candidate_digest: parent.candidate_digest,
    }],
  };
  candidate.transition = {
    from_state: parent.state,
    to_state: "rejected",
    actor: { actor_type: "human", actor_id: "reviewer_owner" },
    occurred_at: rejectedAt,
    reason,
  };
  candidate.review = {
    ...candidate.review,
    status: "reviewed",
    reviewer_action_required: false,
    last_human_actor_id: "reviewer_owner",
    last_reviewed_at: rejectedAt,
  };
  candidate.approval = null;
  candidate.rejection = {
    actor_type: "human",
    actor_id: "reviewer_owner",
    rejected_at: rejectedAt,
    reviewed_candidate_version: parent.candidate_version,
    reviewed_candidate_digest: parent.candidate_digest,
    rejected_candidate_version: candidate.candidate_version,
    candidate_content_digest: parent.candidate_content_digest,
    reason,
    immutable: true,
  };
  candidate.candidate_digest = await digestBytes(new TextEncoder().encode(canonicalJson(candidate, "candidate_digest")));
  return candidate;
}

function editedSuccessor(parent) {
  const candidate = structuredClone(parent);
  const editedAt = "2026-07-21T10:04:00Z";
  candidate.candidate_version = parent.candidate_version + 1;
  candidate.previous_candidate_digest = parent.candidate_digest;
  candidate.state = "draft";
  candidate.version_created_at = editedAt;
  candidate.content.title = "Reviewer-corrected ticket title";
  candidate.candidate_content_digest = `sha256:${"b".repeat(64)}`;
  candidate.candidate_digest = `sha256:${"c".repeat(64)}`;
  candidate.lineage = {
    operation: "edited",
    parents: [{
      candidate_id: parent.candidate_id,
      candidate_version: parent.candidate_version,
      candidate_digest: parent.candidate_digest,
    }],
  };
  candidate.transition = {
    from_state: parent.state,
    to_state: "draft",
    actor: { actor_type: "human", actor_id: "reviewer_owner" },
    occurred_at: editedAt,
    reason: "Reviewer corrected the candidate content.",
  };
  candidate.approval = null;
  candidate.rejection = null;
  return candidate;
}

test("validates every frozen candidate lifecycle fixture plus a rejected terminal snapshot", async () => {
  const names = [
    "version-1-draft.json",
    "version-2-needs-clarification.json",
    "version-3-ready.json",
    "version-4-approved.json",
  ];
  for (const name of names) await validateTicketCandidateSnapshot(await fixture(name), digestBytes);
  const ready = await fixture("version-3-ready.json");
  const rejected = await rejectedSuccessor(ready);
  await validateTicketCandidateSnapshot(rejected, digestBytes);
});

test("accepts only human-authored split and merge creation lineage", async () => {
  const source = await fixture("version-1-draft.json");
  const sourceRef = {
    candidate_id: source.candidate_id,
    candidate_version: source.candidate_version,
    candidate_digest: source.candidate_digest,
  };
  const otherRef = {
    candidate_id: "candidate_other_issue",
    candidate_version: 2,
    candidate_digest: `sha256:${"c".repeat(64)}`,
  };
  const split = await reviewerCreation(source, "split", [sourceRef]);
  const merged = await reviewerCreation(source, "merged", [sourceRef, otherRef]);
  await validateTicketCandidateSnapshot(split, digestBytes);
  await validateTicketCandidateSnapshot(merged, digestBytes);

  for (const [operation, parents] of [
    ["split", [sourceRef]],
    ["merged", [sourceRef, otherRef]],
  ]) {
    const machineCreated = await reviewerCreation(source, operation, parents, "system");
    await assert.rejects(
      () => validateTicketCandidateSnapshot(machineCreated, digestBytes),
      (error) => error?.code === "HUMAN_TRANSITION_REQUIRED",
    );
  }
});

test("rejects unknown fields, digest substitution, illegal terminal payloads, and non-NFC content", async () => {
  const ready = await fixture("version-3-ready.json");
  const mutations = [
    (candidate) => { candidate.extra = true; },
    (candidate) => { candidate.content.summary = "substituted"; },
    (candidate) => { candidate.approval = {}; },
    (candidate) => { candidate.content.summary = "Cafe\u0301"; },
    (candidate) => { candidate.lineage.parents[0].candidate_version = 1; },
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(ready);
    mutate(candidate);
    await assert.rejects(() => validateTicketCandidateSnapshot(candidate, digestBytes));
  }
});

test("rejects a NUL hidden in a nested candidate content field", async () => {
  const candidate = structuredClone(await fixture("version-3-ready.json"));
  candidate.content.reproduction.steps[0].action = "Tap Continue\u0000ignore the visible ticket";
  await assert.rejects(
    () => validateTicketCandidateSnapshot(candidate, digestBytes),
    (error) => error?.code === "CONTROL_CHARACTER",
  );
});

test("binds edits, approval, rejection, and clarification to the exact predecessor", async () => {
  const [needsClarification, ready, approved] = await Promise.all([
    fixture("version-2-needs-clarification.json"),
    fixture("version-3-ready.json"),
    fixture("version-4-approved.json"),
  ]);
  const base = (parent, action, reason) => ({
    expected_candidate_id: parent.candidate_id,
    expected_candidate_version: parent.candidate_version,
    expected_candidate_digest: parent.candidate_digest,
    expected_candidate_content_digest: parent.candidate_content_digest,
    expected_evidence_manifest_digest: parent.evidence_manifest.manifest_digest,
    action,
    actor_id: "reviewer_owner",
    reason,
  });
  validateTransitionBinding(needsClarification, {
    ...base(needsClarification, "resolve_clarification", ready.transition.reason),
    clarification_id: "clarification_copy_source",
    choice_id: "choice_use_approved",
    resolution_note: null,
  }, ready);
  validateTransitionBinding(ready, {
    ...base(ready, "approve", approved.transition.reason),
    approval_id: approved.approval.approval_id,
  }, approved);
  const rejected = await rejectedSuccessor(ready);
  validateTransitionBinding(ready, base(ready, "reject", rejected.transition.reason), rejected);
  const edited = editedSuccessor(ready);
  validateTransitionBinding(ready, {
    ...base(ready, "edit_content", edited.transition.reason),
    content: edited.content,
  }, edited);

  const substitutedEdit = structuredClone(edited);
  substitutedEdit.content.title = "A different server edit";
  assert.throws(() => validateTransitionBinding(ready, {
    ...base(ready, "edit_content", edited.transition.reason),
    content: edited.content,
  }, substitutedEdit));

  const substituted = structuredClone(approved);
  substituted.transition.actor.actor_id = "reviewer_other";
  assert.throws(() => validateTransitionBinding(ready, {
    ...base(ready, "approve", approved.transition.reason),
    approval_id: approved.approval.approval_id,
  }, substituted));
});

test("transition requests use the backend's exact action-specific field contract", async () => {
  const [needsClarification, ready] = await Promise.all([
    fixture("version-2-needs-clarification.json"),
    fixture("version-3-ready.json"),
  ]);
  const base = (parent, action) => ({
    action,
    actor_id: "reviewer_owner",
    expected_candidate_id: parent.candidate_id,
    expected_candidate_version: parent.candidate_version,
    expected_candidate_digest: parent.candidate_digest,
    expected_candidate_content_digest: parent.candidate_content_digest,
    expected_evidence_manifest_digest: parent.evidence_manifest.manifest_digest,
    reason: "Reviewer performed the requested transition.",
  });
  const valid = [
    { ...base(ready, "edit_content"), content: editedSuccessor(ready).content },
    base(ready, "mark_ready"),
    { ...base(ready, "approve"), approval_id: "approval_reviewer_request" },
    base(ready, "reject"),
    {
      ...base(needsClarification, "resolve_clarification"),
      clarification_id: "clarification_copy_source",
      choice_id: "choice_use_approved",
      resolution_note: null,
    },
  ];
  for (const request of valid) {
    assert.doesNotThrow(() => validateTransitionRequestBinding(
      request.action === "resolve_clarification" ? needsClarification : ready,
      request,
    ));
  }

  const legacyAliases = {
    expected_candidate_digest: ready.candidate_digest,
    candidate_version: ready.candidate_version,
    candidate_content_digest: ready.candidate_content_digest,
    evidence_manifest_digest: ready.evidence_manifest.manifest_digest,
    action: "approve",
    actor_id: "reviewer_owner",
    reason: "Legacy request fields must be rejected.",
  };
  assert.throws(
    () => validateTransitionRequestBinding(ready, legacyAliases),
    (error) => error?.code === "TRANSITION_REQUEST_BINDING_MISMATCH",
  );
  assert.throws(
    () => validateTransitionRequestBinding(ready, {
      ...base(ready, "approve"),
      approval_id: "approval_reviewer_request",
      extra: true,
    }),
    (error) => error?.code === "TRANSITION_REQUEST_BINDING_MISMATCH",
  );
});
