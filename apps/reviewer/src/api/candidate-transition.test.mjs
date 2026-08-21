// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson } from "../approved-handoff/contract.ts";
import {
  createCandidateTransitionRequest,
  serializedCandidateTransitionRequest,
} from "./candidate-transition.ts";

const internalCommon = {
  expected_candidate_id: "candidate_profile_copy",
  expected_candidate_version: 3,
  expected_candidate_digest: `sha256:${"a".repeat(64)}`,
  expected_candidate_content_digest: `sha256:${"b".repeat(64)}`,
  expected_evidence_manifest_digest: `sha256:${"c".repeat(64)}`,
  actor_id: "reviewer_owner",
  reason: "Reviewer performed the requested transition.",
};

const publicCommon = {
  expected_candidate_digest: internalCommon.expected_candidate_digest,
  candidate_version: internalCommon.expected_candidate_version,
  candidate_content_digest: internalCommon.expected_candidate_content_digest,
  evidence_manifest_digest: internalCommon.expected_evidence_manifest_digest,
  actor_id: internalCommon.actor_id,
  reason: internalCommon.reason,
};

test("serializes every candidate action to CandidateStore's exact public wire shape", () => {
  const content = {
    title: "Reviewer-corrected candidate content",
    nested: { preserved: true },
  };
  const cases = [
    {
      internal: { ...internalCommon, action: "edit_content", content },
      expected: { ...publicCommon, action: "edit_content", content },
    },
    {
      internal: { ...internalCommon, action: "mark_ready" },
      expected: { ...publicCommon, action: "mark_ready" },
    },
    {
      internal: { ...internalCommon, action: "approve" },
      expected: { ...publicCommon, action: "approve" },
    },
    {
      internal: { ...internalCommon, action: "reject" },
      expected: { ...publicCommon, action: "reject" },
    },
    {
      internal: {
        ...internalCommon,
        action: "resolve_clarification",
        clarification_id: "clarification_copy_source",
        choice_id: "choice_use_approved",
        resolution_note: null,
      },
      expected: {
        ...publicCommon,
        action: "resolve_clarification",
        clarification_id: "clarification_copy_source",
        selected_choice_id: "choice_use_approved",
        resolution_note: null,
      },
    },
  ];

  for (const { internal, expected } of cases) {
    const request = createCandidateTransitionRequest(internal);
    assert.deepEqual(request, expected);
    assert.equal(serializedCandidateTransitionRequest(internal), canonicalJson(expected));
    assert.equal("expected_candidate_id" in request, false);
    assert.equal("expected_candidate_version" in request, false);
    assert.equal("expected_candidate_content_digest" in request, false);
    assert.equal("expected_evidence_manifest_digest" in request, false);
    assert.equal("approval_id" in request, false);
    assert.equal("choice_id" in request, false);
  }
});
