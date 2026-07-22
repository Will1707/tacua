// SPDX-License-Identifier: Apache-2.0

import type {
  CandidateExactBinding,
  CandidateReplacementDraft,
  CandidateReplacementOperation,
  CandidateReplacementOperationProjection,
  CandidateReplacementRequest,
  CandidateReplacementResponse,
  CandidateSupersededDetails,
  TicketCandidate,
} from "./types.ts";
import {
  ApprovedHandoffValidationError,
  canonicalJson,
  type DigestBytes,
  validateTicketCandidateContentDocument,
  validateTicketCandidateSnapshot,
} from "../approved-handoff/contract.ts";
import { collectContentEvidenceRefs } from "../candidates/content-evidence-refs.ts";

const bindingKeys = [
  "candidate_id",
  "candidate_version",
  "candidate_digest",
  "candidate_content_digest",
  "evidence_manifest_digest",
] as const;
const projectionKeys = ["operation_id", "operation", "actor_id", "occurred_at", "sources", "results"] as const;
const nonTerminalStates = new Set(["draft", "needs_clarification", "ready_for_review"]);
const maximumMergeEvidenceItems = 100;
const encoder = new TextEncoder();

export class CandidateReplacementValidationError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "CandidateReplacementValidationError";
  }
}

function fail(code: string): never {
  throw new CandidateReplacementValidationError(code);
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("INVALID_REPLACEMENT_RESPONSE");
  return value as Record<string, unknown>;
}

function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const result = record(value);
  const actual = Object.keys(result).sort();
  const expected = [...keys].sort();
  if (
    actual.some((key) => key.normalize("NFC") !== key)
    || actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) fail("INVALID_REPLACEMENT_RESPONSE");
  return result;
}

function identifier(value: unknown): string {
  if (typeof value !== "string" || value.normalize("NFC") !== value || !/^[a-z][a-z0-9_-]{2,63}$/.test(value)) {
    fail("INVALID_REPLACEMENT_RESPONSE");
  }
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value)) fail("INVALID_REPLACEMENT_RESPONSE");
  return value;
}

function timestamp(value: unknown): string {
  if (
    typeof value !== "string"
    || value.startsWith("0000-")
    || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(value)
  ) fail("INVALID_REPLACEMENT_RESPONSE");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== `${value.slice(0, -1)}.000Z`) {
    fail("INVALID_REPLACEMENT_RESPONSE");
  }
  return value;
}

function operation(value: unknown): CandidateReplacementOperation {
  if (value !== "split" && value !== "merge") fail("INVALID_REPLACEMENT_RESPONSE");
  return value;
}

function safeText(value: unknown, maximum: number): string {
  if (typeof value !== "string" || value.normalize("NFC") !== value) fail("INVALID_REPLACEMENT_REQUEST");
  const length = Array.from(value).length;
  if (length < 1 || length > maximum || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    fail("INVALID_REPLACEMENT_REQUEST");
  }
  return value;
}

function array(value: unknown, minimum: number, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) fail("INVALID_REPLACEMENT_RESPONSE");
  return value;
}

function binding(value: unknown): CandidateExactBinding {
  const source = exact(value, bindingKeys);
  if (!Number.isSafeInteger(source.candidate_version) || (source.candidate_version as number) < 1) {
    fail("INVALID_REPLACEMENT_RESPONSE");
  }
  return {
    candidate_id: identifier(source.candidate_id),
    candidate_version: source.candidate_version as number,
    candidate_digest: digest(source.candidate_digest),
    candidate_content_digest: digest(source.candidate_content_digest),
    evidence_manifest_digest: digest(source.evidence_manifest_digest),
  };
}

function sameBinding(left: CandidateExactBinding, right: CandidateExactBinding): boolean {
  return bindingKeys.every((key) => left[key] === right[key]);
}

function uniqueBindings(values: readonly CandidateExactBinding[]): void {
  if (new Set(values.map((value) => value.candidate_id)).size !== values.length) fail("INVALID_REPLACEMENT_RESPONSE");
}

export function exactCandidateBinding(candidate: TicketCandidate): CandidateExactBinding {
  return {
    candidate_id: candidate.candidate_id,
    candidate_version: candidate.candidate_version,
    candidate_digest: candidate.candidate_digest,
    candidate_content_digest: candidate.candidate_content_digest,
    evidence_manifest_digest: candidate.evidence_manifest.manifest_digest,
  };
}

function candidateBindingForRequest(candidate: TicketCandidate): CandidateExactBinding {
  const candidateId = identifierForRequest(candidate.candidate_id);
  [candidate.organization_id, candidate.project_id, candidate.session_id, candidate.build_id]
    .forEach(identifierForRequest);
  if (!Number.isSafeInteger(candidate.candidate_version) || candidate.candidate_version < 1) {
    fail("INVALID_REPLACEMENT_REQUEST");
  }
  for (const value of [
    candidate.candidate_digest,
    candidate.candidate_content_digest,
    candidate.evidence_manifest.manifest_digest,
    candidate.build_identity_digest,
  ]) {
    if (!/^sha256:[a-f0-9]{64}$/.test(value)) fail("INVALID_REPLACEMENT_REQUEST");
  }
  return {
    candidate_id: candidateId,
    candidate_version: candidate.candidate_version,
    candidate_digest: candidate.candidate_digest,
    candidate_content_digest: candidate.candidate_content_digest,
    evidence_manifest_digest: candidate.evidence_manifest.manifest_digest,
  };
}

function assertCardinality(
  selectedOperation: CandidateReplacementOperation,
  sourceCount: number,
  resultCount: number,
  code: string,
): void {
  if (
    (selectedOperation === "split" && (sourceCount !== 1 || resultCount < 2 || resultCount > 16))
    || (selectedOperation === "merge" && (sourceCount < 2 || sourceCount > 16 || resultCount !== 1))
  ) fail(code);
}

function commonScope(source: TicketCandidate, candidate: TicketCandidate): boolean {
  return source.organization_id === candidate.organization_id
    && source.project_id === candidate.project_id
    && source.session_id === candidate.session_id
    && source.build_id === candidate.build_id
    && source.build_identity_digest === candidate.build_identity_digest;
}

function evidenceUnion(sources: readonly TicketCandidate[]): readonly string[] {
  return [...new Set(sources.flatMap((source) => source.evidence_manifest.evidence_ids))].sort();
}

function assertDraftEvidence(
  content: TicketCandidate["content"],
  permittedEvidenceIds: readonly string[],
): void {
  const permitted = new Set(permittedEvidenceIds);
  if (collectContentEvidenceRefs(content).some((reference) => !permitted.has(reference))) {
    fail("RESULT_EVIDENCE_OUTSIDE_SOURCE_UNION");
  }
}

export function createCandidateReplacementRequest(input: {
  readonly operation: CandidateReplacementOperation;
  readonly actorId: string;
  readonly reason: string;
  readonly sources: readonly TicketCandidate[];
  readonly results: readonly CandidateReplacementDraft[];
}): CandidateReplacementRequest {
  if (input.operation !== "split" && input.operation !== "merge") {
    fail("INVALID_REPLACEMENT_REQUEST");
  }
  const actorId = identifierForRequest(input.actorId);
  const reason = safeText(input.reason, 256);
  assertCardinality(input.operation, input.sources.length, input.results.length, "INVALID_REPLACEMENT_REQUEST");
  const first = input.sources[0];
  if (!first) fail("INVALID_REPLACEMENT_REQUEST");
  input.sources.forEach(candidateBindingForRequest);
  if (
    new Set(input.sources.map((source) => source.candidate_id)).size !== input.sources.length
    || new Set(input.sources.map((source) => source.candidate_digest)).size !== input.sources.length
    || input.sources.some((source) => !nonTerminalStates.has(source.state) || !commonScope(first, source))
  ) fail("INVALID_REPLACEMENT_REQUEST");

  const resultIds = input.results.map((result) => identifierForRequest(result.candidate_id));
  if (
    new Set(resultIds).size !== resultIds.length
    || resultIds.some((candidateId) => input.sources.some((source) => source.candidate_id === candidateId))
  ) fail("INVALID_REPLACEMENT_REQUEST");
  const permittedEvidenceIds = evidenceUnion(input.sources);
  if (input.operation === "merge" && permittedEvidenceIds.length > maximumMergeEvidenceItems) {
    fail("MERGE_EVIDENCE_UNION_TOO_LARGE");
  }
  try {
    input.results.forEach((result) => {
      validateTicketCandidateContentDocument(result.content, permittedEvidenceIds);
      assertDraftEvidence(result.content, permittedEvidenceIds);
    });
  } catch (error) {
    if (error instanceof ApprovedHandoffValidationError) fail(error.code);
    throw error;
  }
  if (input.operation === "split") {
    const serialized = input.results.map((result) => canonicalJson(result.content));
    if (
      serialized.some((content) => content === canonicalJson(first.content))
      || new Set(serialized).size !== serialized.length
    ) fail("SPLIT_RESULTS_MUST_DIFFER");
  }

  const request = {
    operation: input.operation,
    actor_id: actorId,
    reason,
    sources: input.sources.map(candidateBindingForRequest),
    results: input.results.map((result) => ({ candidate_id: result.candidate_id, content: result.content })),
  };
  try {
    if (encoder.encode(`${canonicalJson(request)}\n`).byteLength > 16 * 1_024 * 1_024) fail("REPLACEMENT_REQUEST_TOO_LARGE");
  } catch (error) {
    if (error instanceof CandidateReplacementValidationError) throw error;
    if (error instanceof ApprovedHandoffValidationError) fail(error.code);
    throw error;
  }
  return request;
}

function identifierForRequest(value: unknown): string {
  if (typeof value !== "string" || value.normalize("NFC") !== value || !/^[a-z][a-z0-9_-]{2,63}$/.test(value)) {
    fail("INVALID_REPLACEMENT_REQUEST");
  }
  return value;
}

function validateProjection(
  value: unknown,
  expected?: Pick<CandidateReplacementRequest, "operation" | "actor_id" | "sources">,
): CandidateReplacementOperationProjection {
  const document = exact(value, projectionKeys);
  const selectedOperation = operation(document.operation);
  const sources = array(document.sources, selectedOperation === "split" ? 1 : 2, selectedOperation === "split" ? 1 : 16).map(binding);
  const results = array(document.results, selectedOperation === "split" ? 2 : 1, selectedOperation === "split" ? 16 : 1).map(binding);
  uniqueBindings(sources);
  uniqueBindings(results);
  if (
    new Set(sources.map((source) => source.candidate_digest)).size !== sources.length
    || results.some((result) => result.candidate_version !== 1)
    || sources.some((source) => results.some((result) => result.candidate_id === source.candidate_id))
    || (
      selectedOperation === "split"
      && results.some((result) => result.evidence_manifest_digest !== sources[0]!.evidence_manifest_digest)
    )
  ) {
    fail("INVALID_REPLACEMENT_RESPONSE");
  }
  const result = {
    operation_id: identifier(document.operation_id),
    operation: selectedOperation,
    actor_id: identifier(document.actor_id),
    occurred_at: timestamp(document.occurred_at),
    sources,
    results,
  };
  if (
    expected
    && (
      result.operation !== expected.operation
      || result.actor_id !== expected.actor_id
      || result.sources.length !== expected.sources.length
      || result.sources.some((source, index) => !sameBinding(source, expected.sources[index]!))
    )
  ) fail("REPLACEMENT_RESPONSE_BINDING_MISMATCH");
  return result;
}

export async function validateCandidateReplacementResponse(
  value: unknown,
  request: CandidateReplacementRequest,
  sourceCandidates: readonly TicketCandidate[],
  hash: DigestBytes,
): Promise<CandidateReplacementResponse> {
  const document = exact(value, ["operation", "candidates"]);
  const projection = validateProjection(document.operation, request);
  if (
    projection.results.length !== request.results.length
    || projection.results.some((result, index) => result.candidate_id !== request.results[index]?.candidate_id)
  ) fail("REPLACEMENT_RESPONSE_BINDING_MISMATCH");
  const rawCandidates = array(document.candidates, request.results.length, request.results.length);
  const candidates: TicketCandidate[] = [];
  for (const rawCandidate of rawCandidates) {
    try {
      candidates.push(await validateTicketCandidateSnapshot(rawCandidate, hash) as TicketCandidate);
    } catch (error) {
      if (error instanceof ApprovedHandoffValidationError) fail(error.code);
      throw error;
    }
  }
  const first = sourceCandidates[0];
  if (
    !first
    || sourceCandidates.length !== request.sources.length
    || sourceCandidates.some((source, index) => (
      !sameBinding(exactCandidateBinding(source), request.sources[index]!)
    ))
  ) fail("REPLACEMENT_RESPONSE_BINDING_MISMATCH");
  const expectedParents = request.sources.map(({ candidate_id, candidate_version, candidate_digest }) => ({
    candidate_id,
    candidate_version,
    candidate_digest,
  }));
  const expectedEvidence = evidenceUnion(sourceCandidates);

  candidates.forEach((candidate, index) => {
    const requested = request.results[index];
    const projected = projection.results[index];
    if (
      !requested
      || !projected
      || candidate.candidate_id !== requested.candidate_id
      || candidate.candidate_version !== 1
      || candidate.previous_candidate_digest !== null
      || candidate.state !== "draft"
      || candidate.lineage.operation !== (request.operation === "merge" ? "merged" : "split")
      || canonicalJson(candidate.lineage.parents) !== canonicalJson(expectedParents)
      || candidate.transition.actor.actor_type !== "human"
      || candidate.transition.actor.actor_id !== request.actor_id
      || candidate.transition.occurred_at !== projection.occurred_at
      || candidate.transition.reason !== request.reason
      || candidate.candidate_created_at !== projection.occurred_at
      || candidate.version_created_at !== projection.occurred_at
      || candidate.review.status !== "in_review"
      || candidate.review.reviewer_action_required !== true
      || candidate.review.last_human_actor_id !== request.actor_id
      || candidate.review.last_reviewed_at !== projection.occurred_at
      || !commonScope(first, candidate)
      || canonicalJson(candidate.content) !== canonicalJson(requested.content)
      || !sameBinding(exactCandidateBinding(candidate), projected)
    ) fail("REPLACEMENT_RESPONSE_BINDING_MISMATCH");

    if (request.operation === "split") {
      if (
        candidate.evidence_manifest.manifest_id !== first.evidence_manifest.manifest_id
        || candidate.evidence_manifest.manifest_digest !== first.evidence_manifest.manifest_digest
        || canonicalJson(candidate.evidence_manifest.evidence_ids) !== canonicalJson(first.evidence_manifest.evidence_ids)
      ) fail("REPLACEMENT_EVIDENCE_BINDING_MISMATCH");
    } else if (canonicalJson(candidate.evidence_manifest.evidence_ids) !== canonicalJson(expectedEvidence)) {
      fail("REPLACEMENT_EVIDENCE_BINDING_MISMATCH");
    }
    assertDraftEvidence(candidate.content, expectedEvidence);
  });
  return { operation: projection, candidates };
}

export function validateCandidateSupersessionResponse(
  value: unknown,
  sourceCandidate: TicketCandidate,
): CandidateReplacementOperationProjection {
  const document = exact(value, ["operation"]);
  const projection = validateProjection(document.operation);
  const expected = exactCandidateBinding(sourceCandidate);
  if (!projection.sources.some((source) => sameBinding(source, expected))) {
    fail("SUPERSESSION_SOURCE_BINDING_MISMATCH");
  }
  return projection;
}

export function validateCandidateSupersededErrorEnvelope(value: unknown): {
  readonly message: string;
  readonly details: CandidateSupersededDetails;
} {
  const envelope = exact(value, ["error"]);
  const error = exact(envelope.error, ["code", "message", "details"]);
  if (error.code !== "CANDIDATE_SUPERSEDED") fail("INVALID_SUPERSEDED_ERROR");
  const message = safeText(error.message, 512);
  const detailsDocument = exact(error.details, ["operation_id", "operation", "replacements"]);
  const selectedOperation = operation(detailsDocument.operation);
  const replacements = array(
    detailsDocument.replacements,
    selectedOperation === "split" ? 2 : 1,
    selectedOperation === "split" ? 16 : 1,
  ).map(binding);
  uniqueBindings(replacements);
  if (replacements.some((replacement) => replacement.candidate_version !== 1)) {
    fail("INVALID_SUPERSEDED_ERROR");
  }
  return {
    message,
    details: {
      operation_id: identifier(detailsDocument.operation_id),
      operation: selectedOperation,
      replacements,
    },
  };
}

function cloneContent(content: TicketCandidate["content"]): TicketCandidate["content"] {
  return JSON.parse(JSON.stringify(content)) as TicketCandidate["content"];
}

function boundedTitle(value: string): string {
  const points = Array.from(value.normalize("NFC"));
  return points.length <= 256 ? points.join("") : `${points.slice(0, 255).join("")}…`;
}

function splitTitle(sourceTitle: string, partNumber: number): string {
  const suffix = ` · Part ${partNumber}`;
  const suffixPoints = Array.from(suffix);
  const sourcePoints = Array.from(sourceTitle.normalize("NFC"));
  const allowance = 256 - suffixPoints.length;
  if (sourcePoints.length <= allowance) return `${sourcePoints.join("")}${suffix}`;
  return `${sourcePoints.slice(0, allowance - 1).join("")}…${suffix}`;
}

function combinedText(sources: readonly TicketCandidate[], select: (candidate: TicketCandidate) => string): string {
  const allowance = Math.max(32, Math.floor((4_096 - (sources.length - 1) * 2) / sources.length));
  return sources.map((source, index) => {
    const prefix = `[Ticket ${index + 1}] `;
    const available = Math.max(1, allowance - Array.from(prefix).length);
    const points = Array.from(select(source).normalize("NFC"));
    return `${prefix}${points.length <= available ? points.join("") : `${points.slice(0, available - 1).join("")}…`}`;
  }).join("\n\n");
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function requireMaximum(length: number, maximum: number): void {
  if (length > maximum) fail("MERGE_SEED_EXCEEDS_CONTRACT");
}

export function seedSplitDrafts(
  source: TicketCandidate,
  candidateIds: readonly string[],
): readonly CandidateReplacementDraft[] {
  if (candidateIds.length < 2 || candidateIds.length > 16 || new Set(candidateIds).size !== candidateIds.length) {
    fail("INVALID_REPLACEMENT_REQUEST");
  }
  return candidateIds.map((candidateId, index) => seedSplitDraft(source, candidateId, index + 1));
}

export function seedSplitDraft(
  source: TicketCandidate,
  candidateId: string,
  partNumber: number,
): CandidateReplacementDraft {
  identifierForRequest(candidateId);
  if (!Number.isSafeInteger(partNumber) || partNumber < 1) fail("INVALID_REPLACEMENT_REQUEST");
  const content = {
    ...cloneContent(source.content),
    title: splitTitle(source.content.title, partNumber),
  };
  return { candidate_id: candidateId, content };
}

export function seedMergeDraft(
  sources: readonly TicketCandidate[],
  candidateId: string,
): CandidateReplacementDraft {
  if (sources.length < 2 || sources.length > 16 || new Set(sources.map((source) => source.candidate_id)).size !== sources.length) {
    fail("INVALID_REPLACEMENT_REQUEST");
  }
  identifierForRequest(candidateId);
  const first = sources[0]!;
  if (sources.some((source) => !commonScope(first, source) || !nonTerminalStates.has(source.state))) {
    fail("INVALID_REPLACEMENT_REQUEST");
  }
  const permittedEvidence = evidenceUnion(sources);
  if (permittedEvidence.length > maximumMergeEvidenceItems) {
    fail("MERGE_EVIDENCE_UNION_TOO_LARGE");
  }
  const claimMaps = sources.map((source, sourceIndex) => new Map(
    source.content.claims.map((claim, claimIndex) => [claim.claim_id, `claim_merge_${sourceIndex + 1}_${claimIndex + 1}`]),
  ));
  const remapClaims = (refs: readonly string[], sourceIndex: number) => refs.map((ref) => {
    const mapped = claimMaps[sourceIndex]!.get(ref);
    if (!mapped) fail("MERGE_SEED_UNKNOWN_CLAIM");
    return mapped;
  });
  const allEvidence = (select: (source: TicketCandidate) => readonly string[]) => (
    [...new Set(sources.flatMap(select))].sort()
  );

  const summary = {
    text: combinedText(sources, (source) => source.content.summary.text),
    claim_refs: sources.flatMap((source, index) => remapClaims(source.content.summary.claim_refs, index)),
    evidence_refs: allEvidence((source) => source.content.summary.evidence_refs),
  };
  const actualBehavior = {
    text: combinedText(sources, (source) => source.content.actual_behavior.text),
    claim_refs: sources.flatMap((source, index) => remapClaims(source.content.actual_behavior.claim_refs, index)),
    evidence_refs: allEvidence((source) => source.content.actual_behavior.evidence_refs),
  };
  const expectedBehavior = {
    text: combinedText(sources, (source) => source.content.expected_behavior.text),
    claim_refs: sources.flatMap((source, index) => remapClaims(source.content.expected_behavior.claim_refs, index)),
    evidence_refs: allEvidence((source) => source.content.expected_behavior.evidence_refs),
  };
  const claims = sources.flatMap((source, sourceIndex) => source.content.claims.map((claim, claimIndex) => ({
    ...claim,
    claim_id: `claim_merge_${sourceIndex + 1}_${claimIndex + 1}`,
  })));
  const reproduction = {
    preconditions: sources.flatMap((source, sourceIndex) => source.content.reproduction.preconditions.map((item, itemIndex) => ({
      ...item,
      precondition_id: `precondition_merge_${sourceIndex + 1}_${itemIndex + 1}`,
      claim_refs: remapClaims(item.claim_refs, sourceIndex),
    }))),
    steps: sources.flatMap((source, sourceIndex) => source.content.reproduction.steps.map((item, itemIndex) => ({
      ...item,
      step_id: `step_merge_${sourceIndex + 1}_${itemIndex + 1}`,
      claim_refs: remapClaims(item.claim_refs, sourceIndex),
    }))),
    attempts: sources.reduce((sum, source) => sum + source.content.reproduction.attempts, 0),
    reproductions: sources.reduce((sum, source) => sum + source.content.reproduction.reproductions, 0),
  };
  const acceptanceCriteria = sources.flatMap((source, sourceIndex) => source.content.acceptance_criteria.map((item, itemIndex) => ({
    ...item,
    criterion_id: `criterion_merge_${sourceIndex + 1}_${itemIndex + 1}`,
    claim_refs: remapClaims(item.claim_refs, sourceIndex),
  })));
  const scope = {
    in_scope: uniqueStrings(sources.flatMap((source) => source.content.scope.in_scope)),
    out_of_scope: uniqueStrings(sources.flatMap((source) => source.content.scope.out_of_scope)),
  };
  const uncertainty: TicketCandidate["content"]["uncertainty"] = {
    overall_confidence: sources.some((source) => source.content.uncertainty.overall_confidence === "unknown")
      ? "unknown"
      : sources.some((source) => source.content.uncertainty.overall_confidence === "low")
        ? "low"
        : sources.some((source) => source.content.uncertainty.overall_confidence === "medium") ? "medium" : "high",
    items: sources.flatMap((source, sourceIndex) => source.content.uncertainty.items.map((item, itemIndex) => ({
      ...item,
      uncertainty_id: `uncertainty_merge_${sourceIndex + 1}_${itemIndex + 1}`,
    }))),
  };
  const clarifications = sources.flatMap((source, sourceIndex) => source.content.clarifications.map((item, itemIndex) => {
    const choiceIds = new Map(item.choices.map((choice, choiceIndex) => [
      choice.choice_id,
      `choice_merge_${sourceIndex + 1}_${itemIndex + 1}_${choiceIndex + 1}`,
    ]));
    return {
      ...item,
      clarification_id: `clarification_merge_${sourceIndex + 1}_${itemIndex + 1}`,
      choices: item.choices.map((choice) => ({ ...choice, choice_id: choiceIds.get(choice.choice_id)! })),
      selected_choice_id: item.selected_choice_id === null ? null : choiceIds.get(item.selected_choice_id) ?? null,
    };
  }));

  const content: TicketCandidate["content"] = {
    title: boundedTitle(`Combined: ${sources.map((source) => source.content.title).join(" / ")}`),
    priority: sources.map((source) => source.content.priority).sort()[0]!,
    summary,
    actual_behavior: actualBehavior,
    expected_behavior: expectedBehavior,
    claims,
    reproduction,
    scope,
    acceptance_criteria: acceptanceCriteria,
    uncertainty,
    clarifications,
  };

  [content.summary, content.actual_behavior, content.expected_behavior].forEach((grounded) => {
    requireMaximum(grounded.claim_refs.length, 128);
    requireMaximum(grounded.evidence_refs.length, 128);
  });
  requireMaximum(content.claims.length, 128);
  requireMaximum(content.reproduction.preconditions.length, 64);
  requireMaximum(content.reproduction.steps.length, 64);
  requireMaximum(content.acceptance_criteria.length, 64);
  requireMaximum(content.scope.in_scope.length, 64);
  requireMaximum(content.scope.out_of_scope.length, 64);
  requireMaximum(content.uncertainty.items.length, 64);
  requireMaximum(content.clarifications.length, 64);
  requireMaximum(content.reproduction.attempts, 1_000);
  requireMaximum(content.reproduction.reproductions, 1_000);
  assertDraftEvidence(content, permittedEvidence);
  return { candidate_id: candidateId, content };
}

export function serializedReplacementRequest(request: CandidateReplacementRequest): string {
  // The backend seals the canonical request digest. Sending the same canonical
  // bytes makes the idempotency key and the human-confirmed document stable.
  return canonicalJson(request);
}

export async function replacementRequestDigest(
  request: CandidateReplacementRequest,
  hash: DigestBytes,
): Promise<string> {
  return hash(encoder.encode(serializedReplacementRequest(request)));
}
