// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { canonicalJson, validateTicketCandidateSnapshot } from "../approved-handoff/contract.ts";
import { collectContentEvidenceRefs } from "../candidates/content-evidence-refs.ts";
import {
  CandidateReplacementValidationError,
  createCandidateReplacementRequest,
  exactCandidateBinding,
  seedMergeDraft,
  seedSplitDrafts,
  serializedReplacementRequest,
  validateCandidateReplacementResponse,
  validateCandidateSupersededErrorEnvelope,
  validateCandidateSupersessionResponse,
} from "./candidate-replacement.ts";

const fixtureUrl = new URL("../../../../contracts/ticket-candidate/fixtures/positive/version-1-draft.json", import.meta.url);
const occurredAt = "2026-07-21T10:08:00Z";

async function hash(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function seal(candidate) {
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
  candidate.candidate_content_digest = await hash(new TextEncoder().encode(canonicalJson(contentSubject)));
  candidate.candidate_digest = await hash(new TextEncoder().encode(canonicalJson(candidate, "candidate_digest")));
  return candidate;
}

async function sources() {
  const first = JSON.parse(await readFile(fixtureUrl, "utf8"));
  const second = structuredClone(first);
  second.candidate_id = "candidate_secondary_issue";
  second.content.title = "Profile helper text uses stale copy";
  second.content.summary.text = "The helper text does not match the approved profile wording.";
  second.evidence_manifest = {
    manifest_id: "manifest_secondary_002",
    manifest_digest: `sha256:${"b".repeat(64)}`,
    evidence_ids: [...first.evidence_manifest.evidence_ids, "evidence_secondary_002"],
  };
  await seal(second);
  await validateTicketCandidateSnapshot(second, hash);
  return [first, second];
}

async function resultCandidate(sourceCandidates, request, resultIndex, manifest) {
  const draft = request.results[resultIndex];
  const candidate = structuredClone(sourceCandidates[0]);
  candidate.candidate_id = draft.candidate_id;
  candidate.candidate_version = 1;
  candidate.previous_candidate_digest = null;
  candidate.state = "draft";
  candidate.candidate_created_at = occurredAt;
  candidate.version_created_at = occurredAt;
  candidate.evidence_manifest = structuredClone(manifest);
  candidate.lineage = {
    operation: request.operation === "merge" ? "merged" : "split",
    parents: request.sources.map(({ candidate_id, candidate_version, candidate_digest }) => ({
      candidate_id,
      candidate_version,
      candidate_digest,
    })),
  };
  candidate.transition = {
    from_state: null,
    to_state: "draft",
    actor: { actor_type: "human", actor_id: request.actor_id },
    occurred_at: occurredAt,
    reason: request.reason,
  };
  candidate.content = structuredClone(draft.content);
  candidate.review = {
    status: "in_review",
    reviewer_action_required: true,
    last_human_actor_id: request.actor_id,
    last_reviewed_at: occurredAt,
    notes: [],
  };
  candidate.approval = null;
  candidate.rejection = null;
  return seal(candidate);
}

function projection(request, candidates) {
  return {
    operation_id: `operation_${request.operation}_001`,
    operation: request.operation,
    actor_id: request.actor_id,
    occurred_at: occurredAt,
    sources: structuredClone(request.sources),
    results: candidates.map(exactCandidateBinding),
  };
}

test("seeds 2–16 distinct split drafts without changing the source", async () => {
  const [source] = await sources();
  const before = canonicalJson(source);
  const drafts = seedSplitDrafts(source, ["candidate_split_one", "candidate_split_two"]);
  assert.equal(drafts.length, 2);
  assert.notEqual(canonicalJson(drafts[0].content), canonicalJson(source.content));
  assert.notEqual(canonicalJson(drafts[0].content), canonicalJson(drafts[1].content));
  assert.equal(canonicalJson(source), before);
  const longSource = structuredClone(source);
  longSource.content.title = "x".repeat(256);
  const longDrafts = seedSplitDrafts(longSource, ["candidate_long_one", "candidate_long_two"]);
  assert.match(longDrafts[0].content.title, /Part 1$/u);
  assert.match(longDrafts[1].content.title, /Part 2$/u);
  assert.equal(Array.from(longDrafts[0].content.title).length, 256);

  const request = createCandidateReplacementRequest({
    operation: "split",
    actorId: "reviewer_owner",
    reason: "Reviewer separated two independently actionable findings.",
    sources: [source],
    results: drafts,
  });
  assert.deepEqual(Object.keys(request), ["operation", "actor_id", "reason", "sources", "results"]);
  assert.equal(serializedReplacementRequest(request), canonicalJson(request));
});

test("merge seed combines and remaps every source while staying inside the evidence union", async () => {
  const sourceCandidates = await sources();
  const first = seedMergeDraft(sourceCandidates, "candidate_combined_result");
  const second = seedMergeDraft(sourceCandidates, "candidate_combined_result");
  assert.equal(canonicalJson(first), canonicalJson(second));
  assert.match(first.content.summary.text, /\[Ticket 1\]/u);
  assert.match(first.content.summary.text, /\[Ticket 2\]/u);
  assert.equal(new Set(first.content.claims.map((claim) => claim.claim_id)).size, first.content.claims.length);
  const union = new Set(sourceCandidates.flatMap((source) => source.evidence_manifest.evidence_ids));
  assert.ok(collectContentEvidenceRefs(first.content).every((reference) => union.has(reference)));
  assert.ok(first.content.reproduction.steps.every((step) => step.claim_refs.every(
    (reference) => first.content.claims.some((claim) => claim.claim_id === reference),
  )));
});

test("merge preparation accepts 100 evidence items and rejects 101 before confirmation", async () => {
  const sourceCandidates = await sources();
  const withUnionSize = (size) => {
    const result = structuredClone(sourceCandidates);
    const required = [...new Set(result.flatMap((source) => source.evidence_manifest.evidence_ids))];
    assert.ok(required.length <= size);
    const additions = Array.from(
      { length: size - required.length },
      (_, index) => `evidence_boundary_${String(index + 1).padStart(3, "0")}`,
    );
    result[0].evidence_manifest.evidence_ids = [...required, ...additions];
    return result;
  };

  const boundarySources = withUnionSize(100);
  const boundaryDraft = seedMergeDraft(boundarySources, "candidate_boundary_result");
  assert.doesNotThrow(() => createCandidateReplacementRequest({
    operation: "merge",
    actorId: "reviewer_owner",
    reason: "Reviewer confirmed a bounded evidence union.",
    sources: boundarySources,
    results: [boundaryDraft],
  }));

  const oversizedSources = withUnionSize(101);
  assert.throws(
    () => seedMergeDraft(oversizedSources, "candidate_oversized_result"),
    (error) => error instanceof CandidateReplacementValidationError
      && error.code === "MERGE_EVIDENCE_UNION_TOO_LARGE",
  );
  assert.throws(
    () => createCandidateReplacementRequest({
      operation: "merge",
      actorId: "reviewer_owner",
      reason: "Reviewer attempted an oversized evidence union.",
      sources: oversizedSources,
      results: [boundaryDraft],
    }),
    (error) => error instanceof CandidateReplacementValidationError
      && error.code === "MERGE_EVIDENCE_UNION_TOO_LARGE",
  );
});

test("request builder fails closed on cardinality, duplicate content, scope, and evidence substitutions", async () => {
  const [source, second] = await sources();
  const drafts = seedSplitDrafts(source, ["candidate_split_one", "candidate_split_two"]);
  const cases = [
    { operation: "replace", sources: [source], results: drafts },
    { operation: "split", sources: [source], results: [drafts[0]] },
    { operation: "merge", sources: [source], results: [seedMergeDraft([source, second], "candidate_combined_result")] },
    { operation: "split", sources: [source], results: [drafts[0], { ...drafts[1], content: drafts[0].content }] },
    { operation: "merge", sources: [source, { ...second, build_id: "build_other" }], results: [seedMergeDraft([source, second], "candidate_combined_result")] },
    {
      operation: "split",
      sources: [source],
      results: [
        { ...drafts[0], content: { ...drafts[0].content, summary: { ...drafts[0].content.summary, evidence_refs: ["evidence_outside_union"] } } },
        drafts[1],
      ],
    },
    {
      operation: "split",
      sources: [source],
      results: [
        { ...drafts[0], content: { ...drafts[0].content, title: "Cafe\u0301 split" } },
        drafts[1],
      ],
    },
    {
      operation: "split",
      sources: [source],
      results: [
        { ...drafts[0], content: { ...drafts[0].content, title: "Bearer abcdefghijklmnopqrstuvwxyz" } },
        drafts[1],
      ],
    },
    {
      operation: "split",
      sources: [{ ...source, state: "approved" }],
      results: drafts,
    },
  ];
  for (const input of cases) {
    assert.throws(
      () => createCandidateReplacementRequest({
        ...input,
        actorId: "reviewer_owner",
        reason: "Reviewer confirmed the replacement.",
      }),
      CandidateReplacementValidationError,
    );
  }
});

test("strictly validates split and merge operation responses against exact sources, result content, lineage, and evidence", async () => {
  const sourceCandidates = await sources();
  const splitDrafts = seedSplitDrafts(sourceCandidates[0], ["candidate_split_one", "candidate_split_two"]);
  const splitRequest = createCandidateReplacementRequest({
    operation: "split",
    actorId: "reviewer_owner",
    reason: "Reviewer separated two findings.",
    sources: [sourceCandidates[0]],
    results: splitDrafts,
  });
  const splitCandidates = await Promise.all(splitDrafts.map((_, index) => resultCandidate(
    [sourceCandidates[0]],
    splitRequest,
    index,
    sourceCandidates[0].evidence_manifest,
  )));
  const splitResponse = { operation: projection(splitRequest, splitCandidates), candidates: splitCandidates };
  const validatedSplit = await validateCandidateReplacementResponse(splitResponse, splitRequest, [sourceCandidates[0]], hash);
  assert.equal(validatedSplit.candidates.length, 2);

  const responseWithUndisclosedResult = structuredClone(splitResponse);
  responseWithUndisclosedResult.operation.results.push({
    candidate_id: "candidate_undisclosed_result",
    candidate_version: 1,
    candidate_digest: `sha256:${"8".repeat(64)}`,
    candidate_content_digest: `sha256:${"9".repeat(64)}`,
    evidence_manifest_digest: sourceCandidates[0].evidence_manifest.manifest_digest,
  });
  await assert.rejects(
    () => validateCandidateReplacementResponse(
      responseWithUndisclosedResult,
      splitRequest,
      [sourceCandidates[0]],
      hash,
    ),
    (error) => error instanceof CandidateReplacementValidationError
      && error.code === "REPLACEMENT_RESPONSE_BINDING_MISMATCH",
  );

  const mergeDraft = seedMergeDraft(sourceCandidates, "candidate_combined_result");
  const mergeRequest = createCandidateReplacementRequest({
    operation: "merge",
    actorId: "reviewer_owner",
    reason: "Reviewer combined related findings.",
    sources: sourceCandidates,
    results: [mergeDraft],
  });
  const union = [...new Set(sourceCandidates.flatMap((source) => source.evidence_manifest.evidence_ids))].sort();
  const mergeManifest = {
    manifest_id: "manifest_merged_result",
    manifest_digest: `sha256:${"d".repeat(64)}`,
    evidence_ids: union,
  };
  const mergedCandidate = await resultCandidate(sourceCandidates, mergeRequest, 0, mergeManifest);
  const mergeResponse = { operation: projection(mergeRequest, [mergedCandidate]), candidates: [mergedCandidate] };
  const validatedMerge = await validateCandidateReplacementResponse(mergeResponse, mergeRequest, sourceCandidates, hash);
  assert.deepEqual(validatedMerge.candidates[0].evidence_manifest.evidence_ids, union);

  await assert.rejects(
    () => validateCandidateReplacementResponse(
      mergeResponse,
      mergeRequest,
      [...sourceCandidates].reverse(),
      hash,
    ),
    (error) => error instanceof CandidateReplacementValidationError
      && error.code === "REPLACEMENT_RESPONSE_BINDING_MISMATCH",
  );

  for (const mutate of [
    (value) => { value.operation.sources[0].candidate_digest = `sha256:${"f".repeat(64)}`; },
    (value) => { value.candidates[0].content.title = "Server-substituted result"; },
    (value) => { value.candidates[0].evidence_manifest.evidence_ids.pop(); },
    (value) => { value.operation.extra = true; },
  ]) {
    const substituted = structuredClone(mergeResponse);
    mutate(substituted);
    await assert.rejects(
      () => validateCandidateReplacementResponse(substituted, mergeRequest, sourceCandidates, hash),
      CandidateReplacementValidationError,
    );
  }
});

test("supersession projection and CANDIDATE_SUPERSEDED recovery details reject every substitution", async () => {
  const [source] = await sources();
  const replacement = {
    candidate_id: "candidate_split_one",
    candidate_version: 1,
    candidate_digest: `sha256:${"1".repeat(64)}`,
    candidate_content_digest: `sha256:${"2".repeat(64)}`,
    evidence_manifest_digest: source.evidence_manifest.manifest_digest,
  };
  const operation = {
    operation_id: "operation_split_001",
    operation: "split",
    actor_id: "reviewer_owner",
    occurred_at: occurredAt,
    sources: [exactCandidateBinding(source)],
    results: [replacement, { ...replacement, candidate_id: "candidate_split_two", candidate_digest: `sha256:${"3".repeat(64)}` }],
  };
  assert.equal(validateCandidateSupersessionResponse({ operation }, source).operation_id, operation.operation_id);
  for (const mutate of [
    (value) => { value.operation.results[0].candidate_version = 2; },
    (value) => { value.operation.results[0].evidence_manifest_digest = `sha256:${"f".repeat(64)}`; },
  ]) {
    const substituted = structuredClone({ operation });
    mutate(substituted);
    assert.throws(
      () => validateCandidateSupersessionResponse(substituted, source),
      CandidateReplacementValidationError,
    );
  }
  const envelope = {
    error: {
      code: "CANDIDATE_SUPERSEDED",
      message: "candidate was replaced by a reviewer operation",
      details: {
        operation_id: operation.operation_id,
        operation: "split",
        replacements: operation.results,
      },
    },
  };
  assert.equal(validateCandidateSupersededErrorEnvelope(envelope).details.replacements.length, 2);

  for (const mutate of [
    (value) => { value.error.extra = true; },
    (value) => { value.error.code = "CONFLICT"; },
    (value) => { value.error.details.replacements = [replacement]; },
    (value) => { value.error.details.replacements[0].candidate_version = 0; },
    (value) => { value.error.details.replacements[0].candidate_version = 2; },
  ]) {
    const substituted = structuredClone(envelope);
    mutate(substituted);
    assert.throws(() => validateCandidateSupersededErrorEnvelope(substituted), CandidateReplacementValidationError);
  }
});
