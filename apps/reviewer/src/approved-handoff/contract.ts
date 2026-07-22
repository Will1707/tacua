// SPDX-License-Identifier: Apache-2.0

/**
 * Dependency-free structural validator and deterministic renderer for the
 * approved-handoff v1.1 trust boundary. Cryptography is injected so this
 * module can run unchanged in Expo and Node fixture tests.
 */

export const approvedHandoffContractVersion = "tacua.approved-handoff@1.1.0";
export const approvedHandoffMediaType = "application/vnd.tacua.approved-handoff+json;version=1.1.0";
export const maximumJsonHandoffBytes = 1_048_576;
export const maximumMarkdownHandoffBytes = 2_097_152;

const maximumSafeInteger = 9_007_199_254_740_991;
const candidateContractVersion = "tacua.ticket-candidate@1.0.0";
const candidateMediaType = "application/vnd.tacua.ticket-candidate+json;version=1.0.0";
const encoder = new TextEncoder();
const idPattern = /^[a-z][a-z0-9_-]{2,63}$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const shaPattern = /^[a-f0-9]{40}$/;
const timestampPattern = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const forbiddenKeys = new Set([
  "access_token", "api_key", "client_secret", "cookie", "password", "private_key",
  "refresh_token", "secret", "session_cookie", "set_cookie",
]);
const secretPatterns = [
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}/i,
  /\b(?:gh[opusr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b/,
  /\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,})\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /(?:[?&](?:x-amz-signature|x-goog-signature|signature|sig|access_token|token)=)[^&#\s]{8,}/i,
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s/@:]+:[^\s/@]+@/i,
];

type JsonObject = Record<string, any>;
export type DigestBytes = (bytes: Uint8Array) => Promise<string>;

export class ApprovedHandoffValidationError extends Error {
  readonly code: string;
  readonly path: string;
  readonly detail: string;

  constructor(
    code: string,
    path: string,
    detail: string,
  ) {
    super(`${code} at ${path}: ${detail}`);
    this.name = "ApprovedHandoffValidationError";
    this.code = code;
    this.path = path;
    this.detail = detail;
  }
}

function fail(code: string, path: string, detail: string): never {
  throw new ApprovedHandoffValidationError(code, path, detail);
}

function requireValue(condition: unknown, code: string, path: string, detail: string): asserts condition {
  if (!condition) fail(code, path, detail);
}

function isRecord(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function codePointLength(value: string): number {
  return Array.from(value).length;
}

function compareUnicodeCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftPoints[index] ?? 0) - (rightPoints[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function validateScalarString(value: string, path: string): void {
  requireValue(value.normalize("NFC") === value, "NON_CANONICAL_UNICODE", path, "strings must use Unicode NFC");
  requireValue(!value.includes("\0"), "CONTROL_CHARACTER", path, "NUL is forbidden");
  requireValue(!/[\uD800-\uDFFF]/u.test(value), "INVALID_UNICODE_SCALAR", path, "unpaired UTF-16 surrogates are forbidden");
  for (const pattern of secretPatterns) {
    requireValue(!pattern.test(value), "SECRET_VALUE_DETECTED", path, "credential-like value is forbidden");
  }
}

function validateJsonValues(value: unknown, path = "$", depth = 0): void {
  requireValue(depth <= 128, "MAXIMUM_DEPTH", path, "JSON nesting exceeds the contract limit");
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    requireValue(Number.isSafeInteger(value), "INVALID_NUMBER", path, "only interoperable safe integers are permitted");
    requireValue(Math.abs(value) <= maximumSafeInteger, "INTEGER_OUT_OF_RANGE", path, "integer exceeds the safe range");
    return;
  }
  if (typeof value === "string") {
    validateScalarString(value, path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((child, index) => validateJsonValues(child, `${path}[${index}]`, depth + 1));
    return;
  }
  requireValue(isRecord(value), "INVALID_JSON_VALUE", path, "unsupported JSON value");
  for (const [key, child] of Object.entries(value)) {
    validateScalarString(key, `${path}.${key}`);
    requireValue(
      !forbiddenKeys.has(key.toLowerCase().replaceAll("-", "_")),
      "SECRET_FIELD_FORBIDDEN",
      `${path}.${key}`,
      "credential-bearing fields are forbidden",
    );
    validateJsonValues(child, `${path}.${key}`, depth + 1);
  }
}

export function canonicalJson(value: unknown, omittedRootKey?: string): string {
  function encode(child: unknown, depth: number, root: boolean): string {
    requireValue(depth <= 128, "MAXIMUM_DEPTH", "$", "JSON nesting exceeds the contract limit");
    if (child === null) return "null";
    if (typeof child === "boolean") return child ? "true" : "false";
    if (typeof child === "number") {
      requireValue(Number.isSafeInteger(child), "INVALID_NUMBER", "$", "only interoperable safe integers are permitted");
      return String(child);
    }
    if (typeof child === "string") {
      validateScalarString(child, "$");
      return JSON.stringify(child);
    }
    if (Array.isArray(child)) return `[${child.map((item) => encode(item, depth + 1, false)).join(",")}]`;
    requireValue(isRecord(child), "INVALID_JSON_VALUE", "$", "unsupported JSON value");
    const keys = Object.keys(child)
      .filter((key) => !(root && omittedRootKey !== undefined && key === omittedRootKey))
      .sort(compareUnicodeCodePoints);
    return `{${keys.map((key) => {
      validateScalarString(key, "$");
      return `${JSON.stringify(key)}:${encode(child[key], depth + 1, false)}`;
    }).join(",")}}`;
  }
  return encode(value, 0, true);
}

function parseCanonicalJson(serialized: string, artifact: boolean): JsonObject {
  const payload = artifact && serialized.endsWith("\n") ? serialized.slice(0, -1) : serialized;
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch {
    fail("INVALID_CANONICAL_JSON", "$", "JSON could not be parsed");
  }
  requireValue(isRecord(parsed), "INVALID_CANONICAL_JSON", "$", "root must be an object");
  validateJsonValues(parsed);
  const expected = `${canonicalJson(parsed)}${artifact ? "\n" : ""}`;
  requireValue(serialized === expected, "NON_CANONICAL_JSON", "$", "bytes do not equal Tacua Canonical JSON");
  return parsed;
}

/** Parse one response object encoded as exact Tacua Canonical JSON bytes. */
export function parseTacuaCanonicalJson(serialized: string): Record<string, unknown> {
  return parseCanonicalJson(serialized, false) as Record<string, unknown>;
}

function exactObject(value: unknown, path: string, keys: readonly string[]): JsonObject {
  requireValue(isRecord(value), "SCHEMA_TYPE", path, "expected object");
  const actual = Object.keys(value).sort(compareUnicodeCodePoints);
  const expected = [...keys].sort(compareUnicodeCodePoints);
  requireValue(
    actual.length === expected.length && actual.every((key, index) => key === expected[index]),
    "SCHEMA_PROPERTIES",
    path,
    "object is missing a required property or contains an unknown property",
  );
  return value;
}

function stringValue(value: unknown, path: string, minimum: number, maximum: number): string {
  requireValue(typeof value === "string", "SCHEMA_TYPE", path, "expected string");
  const length = codePointLength(value);
  requireValue(length >= minimum && length <= maximum, "SCHEMA_STRING_LENGTH", path, `expected ${minimum}..${maximum} code points`);
  return value;
}

function identifier(value: unknown, path: string): string {
  const result = stringValue(value, path, 3, 64);
  requireValue(idPattern.test(result), "SCHEMA_ID", path, "invalid Tacua identifier");
  return result;
}

function digestValue(value: unknown, path: string): string {
  requireValue(typeof value === "string" && digestPattern.test(value), "SCHEMA_DIGEST", path, "invalid SHA-256 digest");
  return value;
}

function nullableDigest(value: unknown, path: string): string | null {
  if (value === null) return null;
  return digestValue(value, path);
}

function integerValue(value: unknown, path: string, minimum: number, maximum: number): number {
  requireValue(Number.isSafeInteger(value), "SCHEMA_INTEGER", path, "expected a safe integer");
  requireValue((value as number) >= minimum && (value as number) <= maximum, "SCHEMA_INTEGER_RANGE", path, `expected ${minimum}..${maximum}`);
  return value as number;
}

function enumValue<T extends string>(value: unknown, path: string, allowed: readonly T[]): T {
  requireValue(typeof value === "string" && allowed.includes(value as T), "SCHEMA_ENUM", path, "value is outside the closed enum");
  return value as T;
}

function timestamp(value: unknown, path: string): string {
  requireValue(typeof value === "string" && timestampPattern.test(value), "INVALID_TIMESTAMP", path, "expected a UTC RFC 3339 second");
  requireValue(!value.startsWith("0000-"), "INVALID_TIMESTAMP", path, "year zero is invalid");
  const milliseconds = Date.parse(value);
  requireValue(Number.isFinite(milliseconds), "INVALID_TIMESTAMP", path, "timestamp is not a real calendar time");
  requireValue(new Date(milliseconds).toISOString() === `${value.slice(0, -1)}.000Z`, "INVALID_TIMESTAMP", path, "timestamp is not a real UTC second");
  return value;
}

function timestampMilliseconds(value: unknown, path: string): number {
  return Date.parse(timestamp(value, path));
}

function arrayValue(value: unknown, path: string, minimum: number, maximum: number): any[] {
  requireValue(Array.isArray(value), "SCHEMA_TYPE", path, "expected array");
  requireValue(value.length >= minimum && value.length <= maximum, "SCHEMA_ARRAY_LENGTH", path, `expected ${minimum}..${maximum} items`);
  return value;
}

function uniqueStrings(values: readonly string[], path: string): void {
  requireValue(new Set(values).size === values.length, "SCHEMA_UNIQUE_ITEMS", path, "items must be unique");
}

function idList(value: unknown, path: string, minimum: number, maximum: number): string[] {
  const result = arrayValue(value, path, minimum, maximum).map((item, index) => identifier(item, `${path}[${index}]`));
  uniqueStrings(result, path);
  return result;
}

function textList(value: unknown, path: string, minimum: number, maximum: number): string[] {
  return arrayValue(value, path, minimum, maximum).map((item, index) => stringValue(item, `${path}[${index}]`, 1, 4096));
}

function sameSet(left: Iterable<string>, right: Iterable<string>): boolean {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  return leftSet.size === rightSet.size && [...leftSet].every((item) => rightSet.has(item));
}

async function sha256Canonical(value: unknown, digest: DigestBytes, omittedRootKey?: string): Promise<string> {
  return digest(encoder.encode(canonicalJson(value, omittedRootKey)));
}

function validateCandidateClaim(value: unknown, path: string): JsonObject {
  const claim = exactObject(value, path, ["claim_id", "kind", "support", "confidence", "statement", "evidence_refs"]);
  identifier(claim.claim_id, `${path}.claim_id`);
  enumValue(claim.kind, `${path}.kind`, ["observed", "expected", "diagnosis", "hypothesis", "constraint"]);
  enumValue(claim.support, `${path}.support`, ["direct", "inferred", "unknown"]);
  enumValue(claim.confidence, `${path}.confidence`, ["high", "medium", "low", "unknown"]);
  stringValue(claim.statement, `${path}.statement`, 1, 4096);
  idList(claim.evidence_refs, `${path}.evidence_refs`, 0, 128);
  return claim;
}

function validateGroundedText(value: unknown, path: string): JsonObject {
  const grounded = exactObject(value, path, ["text", "claim_refs", "evidence_refs"]);
  stringValue(grounded.text, `${path}.text`, 1, 4096);
  idList(grounded.claim_refs, `${path}.claim_refs`, 1, 128);
  idList(grounded.evidence_refs, `${path}.evidence_refs`, 1, 128);
  return grounded;
}

function validateCandidateContent(value: unknown, path: string): JsonObject {
  const content = exactObject(value, path, [
    "title", "priority", "summary", "actual_behavior", "expected_behavior", "claims",
    "reproduction", "scope", "acceptance_criteria", "uncertainty", "clarifications",
  ]);
  stringValue(content.title, `${path}.title`, 1, 256);
  enumValue(content.priority, `${path}.priority`, ["P0", "P1", "P2", "P3"]);
  validateGroundedText(content.summary, `${path}.summary`);
  validateGroundedText(content.actual_behavior, `${path}.actual_behavior`);
  validateGroundedText(content.expected_behavior, `${path}.expected_behavior`);
  arrayValue(content.claims, `${path}.claims`, 1, 128).forEach((item, index) => validateCandidateClaim(item, `${path}.claims[${index}]`));

  const reproduction = exactObject(content.reproduction, `${path}.reproduction`, ["preconditions", "steps", "attempts", "reproductions"]);
  arrayValue(reproduction.preconditions, `${path}.reproduction.preconditions`, 0, 64).forEach((item, index) => {
    const precondition = exactObject(item, `${path}.reproduction.preconditions[${index}]`, ["precondition_id", "text", "claim_refs", "evidence_refs"]);
    identifier(precondition.precondition_id, `${path}.reproduction.preconditions[${index}].precondition_id`);
    stringValue(precondition.text, `${path}.reproduction.preconditions[${index}].text`, 1, 4096);
    idList(precondition.claim_refs, `${path}.reproduction.preconditions[${index}].claim_refs`, 0, 128);
    idList(precondition.evidence_refs, `${path}.reproduction.preconditions[${index}].evidence_refs`, 0, 128);
  });
  arrayValue(reproduction.steps, `${path}.reproduction.steps`, 1, 64).forEach((item, index) => {
    const stepPath = `${path}.reproduction.steps[${index}]`;
    const step = exactObject(item, stepPath, ["step_id", "action", "expected_result", "actual_result", "claim_refs", "evidence_refs", "confidence"]);
    identifier(step.step_id, `${stepPath}.step_id`);
    stringValue(step.action, `${stepPath}.action`, 1, 4096);
    if (step.expected_result !== null) stringValue(step.expected_result, `${stepPath}.expected_result`, 1, 4096);
    if (step.actual_result !== null) stringValue(step.actual_result, `${stepPath}.actual_result`, 1, 4096);
    idList(step.claim_refs, `${stepPath}.claim_refs`, 1, 128);
    idList(step.evidence_refs, `${stepPath}.evidence_refs`, 1, 128);
    enumValue(step.confidence, `${stepPath}.confidence`, ["high", "medium", "low", "unknown"]);
  });
  integerValue(reproduction.attempts, `${path}.reproduction.attempts`, 1, 1000);
  integerValue(reproduction.reproductions, `${path}.reproduction.reproductions`, 0, 1000);

  const scope = exactObject(content.scope, `${path}.scope`, ["in_scope", "out_of_scope"]);
  textList(scope.in_scope, `${path}.scope.in_scope`, 1, 64);
  textList(scope.out_of_scope, `${path}.scope.out_of_scope`, 0, 64);

  arrayValue(content.acceptance_criteria, `${path}.acceptance_criteria`, 1, 64).forEach((item, index) => {
    const criterionPath = `${path}.acceptance_criteria[${index}]`;
    const criterion = exactObject(item, criterionPath, ["criterion_id", "criterion", "verification", "claim_refs", "evidence_refs"]);
    identifier(criterion.criterion_id, `${criterionPath}.criterion_id`);
    stringValue(criterion.criterion, `${criterionPath}.criterion`, 1, 4096);
    stringValue(criterion.verification, `${criterionPath}.verification`, 1, 4096);
    idList(criterion.claim_refs, `${criterionPath}.claim_refs`, 1, 128);
    idList(criterion.evidence_refs, `${criterionPath}.evidence_refs`, 1, 128);
  });

  const uncertainty = exactObject(content.uncertainty, `${path}.uncertainty`, ["overall_confidence", "items"]);
  enumValue(uncertainty.overall_confidence, `${path}.uncertainty.overall_confidence`, ["high", "medium", "low", "unknown"]);
  arrayValue(uncertainty.items, `${path}.uncertainty.items`, 0, 64).forEach((item, index) => {
    const itemPath = `${path}.uncertainty.items[${index}]`;
    const uncertaintyItem = exactObject(item, itemPath, ["uncertainty_id", "statement", "impact", "evidence_refs"]);
    identifier(uncertaintyItem.uncertainty_id, `${itemPath}.uncertainty_id`);
    stringValue(uncertaintyItem.statement, `${itemPath}.statement`, 1, 4096);
    enumValue(uncertaintyItem.impact, `${itemPath}.impact`, ["blocking", "non_blocking"]);
    idList(uncertaintyItem.evidence_refs, `${itemPath}.evidence_refs`, 0, 128);
  });

  arrayValue(content.clarifications, `${path}.clarifications`, 0, 64).forEach((item, index) => {
    const clarificationPath = `${path}.clarifications[${index}]`;
    const clarification = exactObject(item, clarificationPath, [
      "clarification_id", "question", "target", "impact", "status", "choices", "selected_choice_id", "resolution_note",
    ]);
    identifier(clarification.clarification_id, `${clarificationPath}.clarification_id`);
    stringValue(clarification.question, `${clarificationPath}.question`, 1, 4096);
    stringValue(clarification.target, `${clarificationPath}.target`, 1, 256);
    enumValue(clarification.impact, `${clarificationPath}.impact`, ["blocking", "non_blocking"]);
    enumValue(clarification.status, `${clarificationPath}.status`, ["unresolved", "resolved"]);
    const choices = arrayValue(clarification.choices, `${clarificationPath}.choices`, 2, 5);
    choices.forEach((choiceValue, choiceIndex) => {
      const choicePath = `${clarificationPath}.choices[${choiceIndex}]`;
      const choice = exactObject(choiceValue, choicePath, ["choice_id", "label", "description", "consequence", "requires_note", "presentation", "evidence_refs"]);
      identifier(choice.choice_id, `${choicePath}.choice_id`);
      stringValue(choice.label, `${choicePath}.label`, 1, 256);
      stringValue(choice.description, `${choicePath}.description`, 1, 4096);
      stringValue(choice.consequence, `${choicePath}.consequence`, 1, 4096);
      requireValue(typeof choice.requires_note === "boolean", "SCHEMA_TYPE", `${choicePath}.requires_note`, "expected boolean");
      const presentation = exactObject(choice.presentation, `${choicePath}.presentation`, ["kind", "value", "evidence_ref"]);
      const kind = enumValue(presentation.kind, `${choicePath}.presentation.kind`, ["text", "evidence_thumbnail", "color_swatch", "sf_symbol"]);
      if (presentation.value !== null) stringValue(presentation.value, `${choicePath}.presentation.value`, 1, 4096);
      if (presentation.evidence_ref !== null) identifier(presentation.evidence_ref, `${choicePath}.presentation.evidence_ref`);
      const evidenceRefs = idList(choice.evidence_refs, `${choicePath}.evidence_refs`, 0, 128);
      if (kind === "text") requireValue(typeof presentation.value === "string" && presentation.evidence_ref === null, "INVALID_CHOICE_PRESENTATION", `${choicePath}.presentation`, "text presentation requires only value");
      if (kind === "evidence_thumbnail") requireValue(presentation.value === null && typeof presentation.evidence_ref === "string" && evidenceRefs.includes(presentation.evidence_ref), "INVALID_CHOICE_PRESENTATION", `${choicePath}.presentation`, "thumbnail requires cited evidence");
      if (kind === "color_swatch") requireValue(typeof presentation.value === "string" && /^#[0-9A-Fa-f]{6}$/.test(presentation.value) && presentation.evidence_ref === null, "INVALID_CHOICE_PRESENTATION", `${choicePath}.presentation`, "invalid color swatch");
      if (kind === "sf_symbol") requireValue(typeof presentation.value === "string" && /^[A-Za-z0-9.]{1,64}$/.test(presentation.value) && presentation.evidence_ref === null, "INVALID_CHOICE_PRESENTATION", `${choicePath}.presentation`, "invalid SF Symbol");
    });
    const choiceIds = choices.map((choice) => choice.choice_id as string);
    uniqueStrings(choiceIds, `${clarificationPath}.choices`);
    if (clarification.selected_choice_id !== null) identifier(clarification.selected_choice_id, `${clarificationPath}.selected_choice_id`);
    if (clarification.resolution_note !== null) stringValue(clarification.resolution_note, `${clarificationPath}.resolution_note`, 1, 4096);
    if (clarification.status === "unresolved") requireValue(clarification.selected_choice_id === null && clarification.resolution_note === null, "CLARIFICATION_STATE_MISMATCH", clarificationPath, "unresolved clarification cannot contain a resolution");
    if (clarification.status === "resolved") requireValue(choiceIds.includes(clarification.selected_choice_id), "UNKNOWN_CLARIFICATION_CHOICE", `${clarificationPath}.selected_choice_id`, "resolved choice is absent");
  });
  return content;
}

function collectEvidenceRefs(value: unknown, result = new Set<string>()): Set<string> {
  if (Array.isArray(value)) {
    value.forEach((child) => collectEvidenceRefs(child, result));
  } else if (isRecord(value)) {
    if (Array.isArray(value.evidence_refs)) value.evidence_refs.forEach((ref: unknown) => { if (typeof ref === "string") result.add(ref); });
    if (isRecord(value.presentation) && typeof value.presentation.evidence_ref === "string") result.add(value.presentation.evidence_ref);
    Object.values(value).forEach((child) => collectEvidenceRefs(child, result));
  }
  return result;
}

function collectClaimRefs(value: unknown, result: string[] = []): string[] {
  if (Array.isArray(value)) value.forEach((child) => collectClaimRefs(child, result));
  else if (isRecord(value)) {
    if (Array.isArray(value.claim_refs)) value.claim_refs.forEach((ref: unknown) => { if (typeof ref === "string") result.push(ref); });
    Object.values(value).forEach((child) => collectClaimRefs(child, result));
  }
  return result;
}

function uniqueField(items: readonly JsonObject[], field: string, path: string): void {
  const values = items.map((item) => item[field] as string);
  uniqueStrings(values, path);
}

function validateCandidateApproval(value: unknown, path: string): JsonObject {
  const approval = exactObject(value, path, [
    "approval_id", "actor_type", "actor_id", "approved_at", "reviewed_candidate_version", "reviewed_candidate_digest",
    "approved_candidate_version", "candidate_content_digest", "evidence_manifest_digest", "authorized_evidence_ids", "immutable",
  ]);
  identifier(approval.approval_id, `${path}.approval_id`);
  requireValue(approval.actor_type === "human", "SCHEMA_CONST", `${path}.actor_type`, "approval actor must be human");
  identifier(approval.actor_id, `${path}.actor_id`);
  timestamp(approval.approved_at, `${path}.approved_at`);
  integerValue(approval.reviewed_candidate_version, `${path}.reviewed_candidate_version`, 1, maximumSafeInteger);
  digestValue(approval.reviewed_candidate_digest, `${path}.reviewed_candidate_digest`);
  integerValue(approval.approved_candidate_version, `${path}.approved_candidate_version`, 2, maximumSafeInteger);
  digestValue(approval.candidate_content_digest, `${path}.candidate_content_digest`);
  digestValue(approval.evidence_manifest_digest, `${path}.evidence_manifest_digest`);
  idList(approval.authorized_evidence_ids, `${path}.authorized_evidence_ids`, 1, 128);
  requireValue(approval.immutable === true, "SCHEMA_CONST", `${path}.immutable`, "approval must be immutable");
  return approval;
}

function validateCandidateRejection(value: unknown, path: string): JsonObject {
  const rejection = exactObject(value, path, [
    "actor_type", "actor_id", "rejected_at", "reviewed_candidate_version", "reviewed_candidate_digest",
    "rejected_candidate_version", "candidate_content_digest", "reason", "immutable",
  ]);
  requireValue(rejection.actor_type === "human", "SCHEMA_CONST", `${path}.actor_type`, "rejection actor must be human");
  identifier(rejection.actor_id, `${path}.actor_id`);
  timestamp(rejection.rejected_at, `${path}.rejected_at`);
  integerValue(rejection.reviewed_candidate_version, `${path}.reviewed_candidate_version`, 1, maximumSafeInteger);
  digestValue(rejection.reviewed_candidate_digest, `${path}.reviewed_candidate_digest`);
  integerValue(rejection.rejected_candidate_version, `${path}.rejected_candidate_version`, 2, maximumSafeInteger);
  digestValue(rejection.candidate_content_digest, `${path}.candidate_content_digest`);
  stringValue(rejection.reason, `${path}.reason`, 1, 4096);
  requireValue(rejection.immutable === true, "SCHEMA_CONST", `${path}.immutable`, "rejection must be immutable");
  return rejection;
}

/**
 * Validate one immutable ticket-candidate snapshot in any lifecycle state.
 * This mirrors the frozen Python contract used by the backend and verifies
 * both content and complete-snapshot digests before the reviewer consumes it.
 */
export async function validateTicketCandidateSnapshot(
  value: unknown,
  digest: DigestBytes,
): Promise<Record<string, unknown>> {
  validateJsonValues(value);
  const candidate = exactObject(value, "$", [
    "contract_version", "media_type", "organization_id", "project_id", "build_id", "build_identity_digest",
    "session_id", "evidence_manifest", "candidate_id", "candidate_version", "previous_candidate_digest", "state",
    "candidate_created_at", "version_created_at", "lineage", "transition", "content", "review", "approval",
    "rejection", "candidate_content_digest", "candidate_digest",
  ]);
  requireValue(encoder.encode(`${canonicalJson(candidate)}\n`).byteLength <= 1_048_576, "ARTIFACT_TOO_LARGE", "$", "candidate exceeds 1 MiB");
  requireValue(candidate.contract_version === candidateContractVersion, "UNSUPPORTED_VERSION", "$.contract_version", "unsupported candidate contract");
  requireValue(candidate.media_type === candidateMediaType, "SCHEMA_CONST", "$.media_type", "unsupported candidate media type");
  ["organization_id", "project_id", "build_id", "session_id", "candidate_id"].forEach((field) => identifier(candidate[field], `$.${field}`));
  digestValue(candidate.build_identity_digest, "$.build_identity_digest");
  const version = integerValue(candidate.candidate_version, "$.candidate_version", 1, maximumSafeInteger);
  nullableDigest(candidate.previous_candidate_digest, "$.previous_candidate_digest");
  const state = enumValue(candidate.state, "$.state", ["draft", "needs_clarification", "ready_for_review", "approved", "rejected"] as const);
  const createdAt = timestampMilliseconds(candidate.candidate_created_at, "$.candidate_created_at");
  const versionCreatedAt = timestampMilliseconds(candidate.version_created_at, "$.version_created_at");
  digestValue(candidate.candidate_content_digest, "$.candidate_content_digest");
  digestValue(candidate.candidate_digest, "$.candidate_digest");

  const manifest = exactObject(candidate.evidence_manifest, "$.evidence_manifest", ["manifest_id", "manifest_digest", "evidence_ids"]);
  identifier(manifest.manifest_id, "$.evidence_manifest.manifest_id");
  digestValue(manifest.manifest_digest, "$.evidence_manifest.manifest_digest");
  const manifestIds = idList(manifest.evidence_ids, "$.evidence_manifest.evidence_ids", 1, 128);

  const lineage = exactObject(candidate.lineage, "$.lineage", ["operation", "parents"]);
  const operation = enumValue(lineage.operation, "$.lineage.operation", [
    "generated", "split", "merged", "edited", "clarification_answered", "reviewed", "approved", "rejected", "reopened",
  ] as const);
  const parents = arrayValue(lineage.parents, "$.lineage.parents", 0, 16).map((parentValue, index) => {
    const path = `$.lineage.parents[${index}]`;
    const parent = exactObject(parentValue, path, ["candidate_id", "candidate_version", "candidate_digest"]);
    identifier(parent.candidate_id, `${path}.candidate_id`);
    integerValue(parent.candidate_version, `${path}.candidate_version`, 1, maximumSafeInteger);
    digestValue(parent.candidate_digest, `${path}.candidate_digest`);
    return parent;
  });
  uniqueStrings(parents.map((parent) => canonicalJson(parent)), "$.lineage.parents");

  const transition = exactObject(candidate.transition, "$.transition", ["from_state", "to_state", "actor", "occurred_at", "reason"]);
  const fromState = transition.from_state === null
    ? null
    : enumValue(transition.from_state, "$.transition.from_state", ["draft", "needs_clarification", "ready_for_review", "approved", "rejected"] as const);
  const toState = enumValue(transition.to_state, "$.transition.to_state", ["draft", "needs_clarification", "ready_for_review", "approved", "rejected"] as const);
  const actor = exactObject(transition.actor, "$.transition.actor", ["actor_type", "actor_id"]);
  const actorType = enumValue(actor.actor_type, "$.transition.actor.actor_type", ["human", "system", "model"] as const);
  identifier(actor.actor_id, "$.transition.actor.actor_id");
  const transitionedAt = timestampMilliseconds(transition.occurred_at, "$.transition.occurred_at");
  stringValue(transition.reason, "$.transition.reason", 1, 256);
  requireValue(toState === state, "STATE_TRANSITION_MISMATCH", "$.transition.to_state", "transition differs from snapshot state");

  const content = validateCandidateContent(candidate.content, "$.content");
  const review = exactObject(candidate.review, "$.review", ["status", "reviewer_action_required", "last_human_actor_id", "last_reviewed_at", "notes"]);
  const reviewStatus = enumValue(review.status, "$.review.status", ["unreviewed", "in_review", "reviewed"] as const);
  requireValue(typeof review.reviewer_action_required === "boolean", "SCHEMA_TYPE", "$.review.reviewer_action_required", "expected boolean");
  if (review.last_human_actor_id !== null) identifier(review.last_human_actor_id, "$.review.last_human_actor_id");
  if (review.last_reviewed_at !== null) timestamp(review.last_reviewed_at, "$.review.last_reviewed_at");
  textList(review.notes, "$.review.notes", 0, 64);

  let approval: JsonObject | null = null;
  let rejection: JsonObject | null = null;
  if (state === "approved") {
    approval = validateCandidateApproval(candidate.approval, "$.approval");
    requireValue(candidate.rejection === null, "SCHEMA_CONST", "$.rejection", "approved candidate cannot be rejected");
  } else if (state === "rejected") {
    rejection = validateCandidateRejection(candidate.rejection, "$.rejection");
    requireValue(candidate.approval === null, "SCHEMA_CONST", "$.approval", "rejected candidate cannot be approved");
  } else {
    requireValue(candidate.approval === null && candidate.rejection === null, "SCHEMA_CONST", "$", "non-terminal candidate cannot contain approval or rejection");
  }

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
  requireValue(candidate.candidate_content_digest === await sha256Canonical(contentSubject, digest), "CONTENT_DIGEST_MISMATCH", "$.candidate_content_digest", "candidate content or bound scope changed");
  requireValue(candidate.candidate_digest === await sha256Canonical(candidate, digest, "candidate_digest"), "CANDIDATE_DIGEST_MISMATCH", "$.candidate_digest", "candidate snapshot changed");

  if (version === 1) {
    requireValue(candidate.previous_candidate_digest === null, "VERSION_CHAIN_MISMATCH", "$.previous_candidate_digest", "version one has no predecessor");
    requireValue(fromState === null && state === "draft", "FIRST_VERSION_MUST_BE_DRAFT", "$.state", "new candidates begin as drafts");
    requireValue(["generated", "split", "merged"].includes(operation), "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "invalid first-version operation");
    const parentRange = operation === "generated" ? [0, 0] : operation === "split" ? [1, 1] : [2, 16];
    requireValue(parents.length >= (parentRange[0] ?? 0) && parents.length <= (parentRange[1] ?? 0), "LINEAGE_PARENT_MISMATCH", "$.lineage.parents", "first-version parent count is invalid");
  } else {
    requireValue(candidate.previous_candidate_digest !== null, "VERSION_CHAIN_MISMATCH", "$.previous_candidate_digest", "later versions require a predecessor");
    requireValue(fromState !== null, "STATE_TRANSITION_MISMATCH", "$.transition.from_state", "later versions require a prior state");
    requireValue(!["generated", "split", "merged"].includes(operation), "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "creation operation used after version one");
    requireValue(parents.length === 1, "LINEAGE_PARENT_MISMATCH", "$.lineage.parents", "later versions require one predecessor");
    const parent = parents[0] as JsonObject;
    requireValue(parent.candidate_id === candidate.candidate_id, "LINEAGE_PARENT_MISMATCH", "$.lineage.parents[0].candidate_id", "predecessor has another candidate ID");
    requireValue(parent.candidate_version === version - 1, "LINEAGE_PARENT_MISMATCH", "$.lineage.parents[0].candidate_version", "predecessor version is not contiguous");
    requireValue(parent.candidate_digest === candidate.previous_candidate_digest, "LINEAGE_PARENT_MISMATCH", "$.lineage.parents[0].candidate_digest", "predecessor digest is inconsistent");
  }

  const allowedTransitions: Record<string, readonly string[]> = {
    null: ["draft"],
    draft: ["draft", "needs_clarification", "ready_for_review"],
    needs_clarification: ["draft", "needs_clarification", "ready_for_review", "rejected"],
    ready_for_review: ["draft", "needs_clarification", "ready_for_review", "approved", "rejected"],
    approved: ["draft"],
    rejected: ["draft"],
  };
  requireValue(allowedTransitions[fromState ?? "null"]?.includes(state), "ILLEGAL_STATE_TRANSITION", "$.transition", "candidate transition is not allowed");
  if (["split", "merged", "clarification_answered", "reviewed", "approved", "rejected", "reopened"].includes(operation)) {
    requireValue(actorType === "human", "HUMAN_TRANSITION_REQUIRED", "$.transition.actor", `${operation} requires a human`);
  }
  if (operation === "approved") requireValue(state === "approved", "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "approval operation must create approved state");
  if (operation === "rejected") requireValue(state === "rejected", "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "rejection operation must create rejected state");
  if (operation === "reopened") requireValue((fromState === "approved" || fromState === "rejected") && state === "draft", "LINEAGE_OPERATION_MISMATCH", "$.lineage.operation", "reopen must create a draft from a terminal state");

  const claims = content.claims as JsonObject[];
  const claimIds = claims.map((claim) => claim.claim_id as string);
  uniqueStrings(claimIds, "$.content.claims");
  uniqueField(content.reproduction.preconditions, "precondition_id", "$.content.reproduction.preconditions");
  uniqueField(content.reproduction.steps, "step_id", "$.content.reproduction.steps");
  uniqueField(content.acceptance_criteria, "criterion_id", "$.content.acceptance_criteria");
  uniqueField(content.uncertainty.items, "uncertainty_id", "$.content.uncertainty.items");
  uniqueField(content.clarifications, "clarification_id", "$.content.clarifications");
  claims.forEach((claim, index) => {
    if (claim.support === "direct" || claim.support === "inferred") {
      requireValue(claim.evidence_refs.length > 0, "SUPPORTED_CLAIM_REQUIRES_EVIDENCE", `$.content.claims[${index}].evidence_refs`, "supported claim requires evidence");
    }
  });
  for (const ref of collectClaimRefs(content)) requireValue(claimIds.includes(ref), "UNKNOWN_CLAIM_REFERENCE", "$.content", ref);
  const usedEvidence = collectEvidenceRefs(content);
  requireValue([...usedEvidence].every((ref) => manifestIds.includes(ref)), "UNKNOWN_EVIDENCE_REFERENCE", "$.content", "content cites evidence outside its manifest");

  const blocking = (content.clarifications as JsonObject[]).filter((clarification) => clarification.impact === "blocking" && clarification.status === "unresolved");
  for (const [index, clarification] of (content.clarifications as JsonObject[]).entries()) {
    if (clarification.status !== "resolved") continue;
    const selected = (clarification.choices as JsonObject[]).find((choice) => choice.choice_id === clarification.selected_choice_id);
    requireValue(selected, "UNKNOWN_CLARIFICATION_CHOICE", `$.content.clarifications[${index}].selected_choice_id`, "resolved choice is missing");
    if (selected.requires_note) requireValue(typeof clarification.resolution_note === "string", "CLARIFICATION_NOTE_REQUIRED", `$.content.clarifications[${index}].resolution_note`, "selected choice requires a note");
  }
  if (state === "ready_for_review" || state === "approved") requireValue(blocking.length === 0, "UNRESOLVED_BLOCKING_CLARIFICATION", "$.content.clarifications", "blocking questions must be resolved");
  if (state === "needs_clarification") requireValue(blocking.length > 0, "CLARIFICATION_STATE_MISMATCH", "$.state", "state requires an unresolved blocking question");

  if (reviewStatus === "unreviewed") {
    requireValue(review.last_human_actor_id === null && review.last_reviewed_at === null, "REVIEW_STATE_MISMATCH", "$.review", "unreviewed candidate cannot name a reviewer");
  } else {
    requireValue(review.last_human_actor_id !== null && review.last_reviewed_at !== null, "REVIEW_STATE_MISMATCH", "$.review", "review activity requires a human and time");
  }
  if (state === "needs_clarification" || state === "ready_for_review") requireValue(review.reviewer_action_required === true, "REVIEW_ACTION_MISMATCH", "$.review.reviewer_action_required", "reviewable state requires action");
  if (state === "approved" || state === "rejected") requireValue(review.reviewer_action_required === false, "REVIEW_ACTION_MISMATCH", "$.review.reviewer_action_required", "terminal state cannot require action");
  requireValue(createdAt <= versionCreatedAt, "INVALID_CHRONOLOGY", "$.version_created_at", "version predates candidate");
  requireValue(versionCreatedAt === transitionedAt, "TRANSITION_CHRONOLOGY_MISMATCH", "$.transition.occurred_at", "transition must create this version");
  if (review.last_reviewed_at !== null) {
    const reviewedAt = timestampMilliseconds(review.last_reviewed_at, "$.review.last_reviewed_at");
    requireValue(createdAt <= reviewedAt && reviewedAt <= versionCreatedAt, "INVALID_CHRONOLOGY", "$.review.last_reviewed_at", "review time is outside the snapshot");
  }

  if (state === "approved") {
    requireValue(approval !== null && operation === "approved" && fromState === "ready_for_review", "APPROVAL_TRANSITION_REQUIRED", "$.transition", "approval requires a ready candidate");
    requireValue(actorType === "human" && actor.actor_id === approval.actor_id, "APPROVAL_ACTOR_MISMATCH", "$.approval.actor_id", "approval actor differs from transition");
    requireValue(approval.approved_at === candidate.version_created_at, "APPROVAL_CHRONOLOGY_MISMATCH", "$.approval.approved_at", "approval time must create approved version");
    requireValue(approval.reviewed_candidate_version === version - 1 && approval.reviewed_candidate_digest === candidate.previous_candidate_digest, "APPROVAL_BINDING_MISMATCH", "$.approval", "approval did not bind the reviewed predecessor");
    requireValue(approval.approved_candidate_version === version && approval.candidate_content_digest === candidate.candidate_content_digest && approval.evidence_manifest_digest === manifest.manifest_digest, "APPROVAL_BINDING_MISMATCH", "$.approval", "approval does not bind this candidate and manifest");
    requireValue(sameSet(approval.authorized_evidence_ids, usedEvidence), "APPROVAL_EVIDENCE_BINDING_MISMATCH", "$.approval.authorized_evidence_ids", "approval must authorize exact referenced evidence");
    requireValue(reviewStatus === "reviewed", "REVIEW_REQUIRED", "$.review.status", "approved candidate requires completed review");
  }
  if (state === "rejected") {
    requireValue(rejection !== null && operation === "rejected" && (fromState === "needs_clarification" || fromState === "ready_for_review"), "REJECTION_TRANSITION_REQUIRED", "$.transition", "rejection requires a reviewable candidate");
    requireValue(actorType === "human" && actor.actor_id === rejection.actor_id, "REJECTION_ACTOR_MISMATCH", "$.rejection.actor_id", "rejection actor differs from transition");
    requireValue(rejection.rejected_at === candidate.version_created_at, "REJECTION_CHRONOLOGY_MISMATCH", "$.rejection.rejected_at", "rejection time must create rejected version");
    requireValue(rejection.reviewed_candidate_version === version - 1 && rejection.reviewed_candidate_digest === candidate.previous_candidate_digest, "REJECTION_BINDING_MISMATCH", "$.rejection", "rejection did not bind predecessor");
    requireValue(rejection.rejected_candidate_version === version && rejection.candidate_content_digest === candidate.candidate_content_digest, "REJECTION_BINDING_MISMATCH", "$.rejection", "rejection does not bind this candidate");
  }

  return candidate as Record<string, unknown>;
}

async function validateApprovedCandidate(candidate: JsonObject, digest: DigestBytes): Promise<void> {
  await validateTicketCandidateSnapshot(candidate, digest);
  exactObject(candidate, "$.source_candidate.canonical_json", [
    "contract_version", "media_type", "organization_id", "project_id", "build_id", "build_identity_digest",
    "session_id", "evidence_manifest", "candidate_id", "candidate_version", "previous_candidate_digest", "state",
    "candidate_created_at", "version_created_at", "lineage", "transition", "content", "review", "approval",
    "rejection", "candidate_content_digest", "candidate_digest",
  ]);
  requireValue(candidate.contract_version === candidateContractVersion, "SOURCE_CANDIDATE_INVALID", "$.source_candidate.canonical_json.contract_version", "unsupported candidate contract");
  requireValue(candidate.media_type === candidateMediaType, "SOURCE_CANDIDATE_INVALID", "$.source_candidate.canonical_json.media_type", "unsupported candidate media type");
  ["organization_id", "project_id", "build_id", "session_id", "candidate_id"].forEach((field) => identifier(candidate[field], `$.source_candidate.canonical_json.${field}`));
  digestValue(candidate.build_identity_digest, "$.source_candidate.canonical_json.build_identity_digest");
  const version = integerValue(candidate.candidate_version, "$.source_candidate.canonical_json.candidate_version", 1, maximumSafeInteger);
  nullableDigest(candidate.previous_candidate_digest, "$.source_candidate.canonical_json.previous_candidate_digest");
  requireValue(candidate.state === "approved", "SOURCE_CANDIDATE_NOT_APPROVED", "$.source_candidate.canonical_json.state", "candidate must be approved");
  const createdAt = timestampMilliseconds(candidate.candidate_created_at, "$.source_candidate.canonical_json.candidate_created_at");
  const versionAt = timestampMilliseconds(candidate.version_created_at, "$.source_candidate.canonical_json.version_created_at");
  digestValue(candidate.candidate_content_digest, "$.source_candidate.canonical_json.candidate_content_digest");
  digestValue(candidate.candidate_digest, "$.source_candidate.canonical_json.candidate_digest");

  const manifest = exactObject(candidate.evidence_manifest, "$.source_candidate.canonical_json.evidence_manifest", ["manifest_id", "manifest_digest", "evidence_ids"]);
  identifier(manifest.manifest_id, "$.source_candidate.canonical_json.evidence_manifest.manifest_id");
  digestValue(manifest.manifest_digest, "$.source_candidate.canonical_json.evidence_manifest.manifest_digest");
  const manifestIds = idList(manifest.evidence_ids, "$.source_candidate.canonical_json.evidence_manifest.evidence_ids", 1, 128);

  const lineage = exactObject(candidate.lineage, "$.source_candidate.canonical_json.lineage", ["operation", "parents"]);
  requireValue(lineage.operation === "approved", "APPROVAL_TRANSITION_REQUIRED", "$.source_candidate.canonical_json.lineage.operation", "approved candidate requires approval lineage");
  const parents = arrayValue(lineage.parents, "$.source_candidate.canonical_json.lineage.parents", 1, 1);
  const parent = exactObject(parents[0], "$.source_candidate.canonical_json.lineage.parents[0]", ["candidate_id", "candidate_version", "candidate_digest"]);
  identifier(parent.candidate_id, "$.source_candidate.canonical_json.lineage.parents[0].candidate_id");
  integerValue(parent.candidate_version, "$.source_candidate.canonical_json.lineage.parents[0].candidate_version", 1, maximumSafeInteger);
  digestValue(parent.candidate_digest, "$.source_candidate.canonical_json.lineage.parents[0].candidate_digest");

  const transition = exactObject(candidate.transition, "$.source_candidate.canonical_json.transition", ["from_state", "to_state", "actor", "occurred_at", "reason"]);
  requireValue(transition.from_state === "ready_for_review" && transition.to_state === "approved", "APPROVAL_TRANSITION_REQUIRED", "$.source_candidate.canonical_json.transition", "expected ready_for_review to approved");
  const actor = exactObject(transition.actor, "$.source_candidate.canonical_json.transition.actor", ["actor_type", "actor_id"]);
  requireValue(actor.actor_type === "human", "HUMAN_TRANSITION_REQUIRED", "$.source_candidate.canonical_json.transition.actor_type", "approval requires a human");
  identifier(actor.actor_id, "$.source_candidate.canonical_json.transition.actor_id");
  const transitionAt = timestampMilliseconds(transition.occurred_at, "$.source_candidate.canonical_json.transition.occurred_at");
  stringValue(transition.reason, "$.source_candidate.canonical_json.transition.reason", 1, 256);

  const content = validateCandidateContent(candidate.content, "$.source_candidate.canonical_json.content");
  const review = exactObject(candidate.review, "$.source_candidate.canonical_json.review", ["status", "reviewer_action_required", "last_human_actor_id", "last_reviewed_at", "notes"]);
  requireValue(review.status === "reviewed" && review.reviewer_action_required === false, "REVIEW_REQUIRED", "$.source_candidate.canonical_json.review", "approved candidate requires completed review");
  identifier(review.last_human_actor_id, "$.source_candidate.canonical_json.review.last_human_actor_id");
  const reviewedAt = timestampMilliseconds(review.last_reviewed_at, "$.source_candidate.canonical_json.review.last_reviewed_at");
  textList(review.notes, "$.source_candidate.canonical_json.review.notes", 0, 64);

  const approval = exactObject(candidate.approval, "$.source_candidate.canonical_json.approval", [
    "approval_id", "actor_type", "actor_id", "approved_at", "reviewed_candidate_version", "reviewed_candidate_digest",
    "approved_candidate_version", "candidate_content_digest", "evidence_manifest_digest", "authorized_evidence_ids", "immutable",
  ]);
  identifier(approval.approval_id, "$.source_candidate.canonical_json.approval.approval_id");
  requireValue(approval.actor_type === "human", "SCHEMA_CONST", "$.source_candidate.canonical_json.approval.actor_type", "expected human");
  identifier(approval.actor_id, "$.source_candidate.canonical_json.approval.actor_id");
  const approvedAt = timestampMilliseconds(approval.approved_at, "$.source_candidate.canonical_json.approval.approved_at");
  integerValue(approval.reviewed_candidate_version, "$.source_candidate.canonical_json.approval.reviewed_candidate_version", 1, maximumSafeInteger);
  digestValue(approval.reviewed_candidate_digest, "$.source_candidate.canonical_json.approval.reviewed_candidate_digest");
  integerValue(approval.approved_candidate_version, "$.source_candidate.canonical_json.approval.approved_candidate_version", 2, maximumSafeInteger);
  digestValue(approval.candidate_content_digest, "$.source_candidate.canonical_json.approval.candidate_content_digest");
  digestValue(approval.evidence_manifest_digest, "$.source_candidate.canonical_json.approval.evidence_manifest_digest");
  const authorizedEvidenceIds = idList(approval.authorized_evidence_ids, "$.source_candidate.canonical_json.approval.authorized_evidence_ids", 1, 128);
  requireValue(approval.immutable === true, "SCHEMA_CONST", "$.source_candidate.canonical_json.approval.immutable", "approval must be immutable");
  requireValue(candidate.rejection === null, "SCHEMA_CONST", "$.source_candidate.canonical_json.rejection", "approved candidate cannot be rejected");

  requireValue(version > 1 && candidate.previous_candidate_digest !== null, "VERSION_CHAIN_MISMATCH", "$.source_candidate.canonical_json.candidate_version", "approved candidate requires a predecessor");
  requireValue(parent.candidate_id === candidate.candidate_id && parent.candidate_version === version - 1 && parent.candidate_digest === candidate.previous_candidate_digest, "LINEAGE_PARENT_MISMATCH", "$.source_candidate.canonical_json.lineage.parents[0]", "lineage does not identify the exact predecessor");
  requireValue(actor.actor_id === approval.actor_id, "APPROVAL_ACTOR_MISMATCH", "$.source_candidate.canonical_json.approval.actor_id", "approval actor differs from transition");
  requireValue(createdAt <= reviewedAt && reviewedAt <= versionAt && versionAt === transitionAt && transitionAt === approvedAt, "APPROVAL_CHRONOLOGY_MISMATCH", "$.source_candidate.canonical_json.approval.approved_at", "candidate review/approval chronology is invalid");
  requireValue(approval.reviewed_candidate_version === version - 1 && approval.reviewed_candidate_digest === candidate.previous_candidate_digest, "APPROVAL_BINDING_MISMATCH", "$.source_candidate.canonical_json.approval", "approval does not bind the reviewed predecessor");
  requireValue(approval.approved_candidate_version === version && approval.candidate_content_digest === candidate.candidate_content_digest && approval.evidence_manifest_digest === manifest.manifest_digest, "APPROVAL_BINDING_MISMATCH", "$.source_candidate.canonical_json.approval", "approval does not bind this candidate and manifest");

  const claims = content.claims as JsonObject[];
  const claimIds = claims.map((claim) => claim.claim_id as string);
  uniqueStrings(claimIds, "$.source_candidate.canonical_json.content.claims");
  uniqueField(content.reproduction.preconditions, "precondition_id", "$.source_candidate.canonical_json.content.reproduction.preconditions");
  uniqueField(content.reproduction.steps, "step_id", "$.source_candidate.canonical_json.content.reproduction.steps");
  uniqueField(content.acceptance_criteria, "criterion_id", "$.source_candidate.canonical_json.content.acceptance_criteria");
  uniqueField(content.uncertainty.items, "uncertainty_id", "$.source_candidate.canonical_json.content.uncertainty.items");
  uniqueField(content.clarifications, "clarification_id", "$.source_candidate.canonical_json.content.clarifications");
  for (const [index, claim] of claims.entries()) {
    if (claim.support === "direct" || claim.support === "inferred") requireValue(claim.evidence_refs.length > 0, "SUPPORTED_CLAIM_REQUIRES_EVIDENCE", `$.source_candidate.canonical_json.content.claims[${index}].evidence_refs`, "supported claim requires evidence");
  }
  for (const ref of collectClaimRefs(content)) requireValue(claimIds.includes(ref), "UNKNOWN_CLAIM_REFERENCE", "$.source_candidate.canonical_json.content", ref);
  const usedEvidence = collectEvidenceRefs(content);
  requireValue([...usedEvidence].every((ref) => manifestIds.includes(ref)), "UNKNOWN_EVIDENCE_REFERENCE", "$.source_candidate.canonical_json.content", "content cites evidence outside its manifest");
  requireValue(sameSet(usedEvidence, authorizedEvidenceIds), "APPROVAL_EVIDENCE_BINDING_MISMATCH", "$.source_candidate.canonical_json.approval.authorized_evidence_ids", "approval must authorize the exact used evidence set");
  for (const [index, clarification] of (content.clarifications as JsonObject[]).entries()) {
    if (clarification.impact === "blocking") requireValue(clarification.status === "resolved", "UNRESOLVED_BLOCKING_CLARIFICATION", `$.source_candidate.canonical_json.content.clarifications[${index}]`, "blocking clarification is unresolved");
    if (clarification.status === "resolved") {
      const selected = (clarification.choices as JsonObject[]).find((choice) => choice.choice_id === clarification.selected_choice_id);
      requireValue(selected, "UNKNOWN_CLARIFICATION_CHOICE", `$.source_candidate.canonical_json.content.clarifications[${index}]`, "selected choice is absent");
      if (selected.requires_note) requireValue(typeof clarification.resolution_note === "string", "CLARIFICATION_NOTE_REQUIRED", `$.source_candidate.canonical_json.content.clarifications[${index}].resolution_note`, "selected choice requires a note");
    }
  }

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
  requireValue(candidate.candidate_content_digest === await sha256Canonical(contentSubject, digest), "CONTENT_DIGEST_MISMATCH", "$.source_candidate.canonical_json.candidate_content_digest", "candidate content digest mismatch");
  requireValue(candidate.candidate_digest === await sha256Canonical(candidate, digest, "candidate_digest"), "CANDIDATE_DIGEST_MISMATCH", "$.source_candidate.canonical_json.candidate_digest", "candidate digest mismatch");
}

function validateSourceSnapshot(value: unknown, path: string): JsonObject {
  const snapshot = exactObject(value, path, ["repository_id", "revision", "dirty"]);
  identifier(snapshot.repository_id, `${path}.repository_id`);
  requireValue(typeof snapshot.revision === "string" && shaPattern.test(snapshot.revision), "SCHEMA_SHA", `${path}.revision`, "expected a 40-character lowercase revision");
  requireValue(snapshot.dirty === false, "SCHEMA_CONST", `${path}.dirty`, "tested source must be clean");
  return snapshot;
}

function validateBuildIdentity(value: unknown): JsonObject {
  const path = "$.build_identity";
  const build = exactObject(value, path, [
    "contract_version", "media_type", "organization_id", "project_id", "build_id", "mobile", "backend", "sdk", "build_identity_digest",
  ]);
  requireValue(build.contract_version === "tacua.build-identity@1.0.0", "SCHEMA_CONST", `${path}.contract_version`, "unsupported build identity");
  requireValue(build.media_type === "application/vnd.tacua.build-identity+json;version=1.0.0", "SCHEMA_CONST", `${path}.media_type`, "unsupported build media type");
  ["organization_id", "project_id", "build_id"].forEach((field) => identifier(build[field], `${path}.${field}`));
  digestValue(build.build_identity_digest, `${path}.build_identity_digest`);

  const mobile = exactObject(build.mobile, `${path}.mobile`, ["platform", "application_id", "app_version", "build_number", "distribution", "source", "native_binary_digest"]);
  enumValue(mobile.platform, `${path}.mobile.platform`, ["ios", "android"]);
  requireValue(typeof mobile.application_id === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{2,254}$/.test(mobile.application_id), "SCHEMA_PATTERN", `${path}.mobile.application_id`, "invalid application ID");
  stringValue(mobile.app_version, `${path}.mobile.app_version`, 1, 64);
  stringValue(mobile.build_number, `${path}.mobile.build_number`, 1, 64);
  enumValue(mobile.distribution, `${path}.mobile.distribution`, ["local-development", "internal", "testflight", "app-store", "play-internal", "play-store"]);
  validateSourceSnapshot(mobile.source, `${path}.mobile.source`);
  digestValue(mobile.native_binary_digest, `${path}.mobile.native_binary_digest`);

  const backend = exactObject(build.backend, `${path}.backend`, ["availability", "environment", "deployment_id", "image_digest", "deployed_at", "sources", "unavailable_reason"]);
  const availability = enumValue(backend.availability, `${path}.backend.availability`, ["available", "unavailable"]);
  stringValue(backend.environment, `${path}.backend.environment`, 1, 64);
  if (availability === "available") {
    identifier(backend.deployment_id, `${path}.backend.deployment_id`);
    digestValue(backend.image_digest, `${path}.backend.image_digest`);
    timestamp(backend.deployed_at, `${path}.backend.deployed_at`);
    arrayValue(backend.sources, `${path}.backend.sources`, 1, 16).forEach((source, index) => validateSourceSnapshot(source, `${path}.backend.sources[${index}]`));
    requireValue(backend.unavailable_reason === null, "SCHEMA_CONST", `${path}.backend.unavailable_reason`, "available backend cannot have an unavailable reason");
  } else {
    requireValue(backend.deployment_id === null && backend.image_digest === null && backend.deployed_at === null, "SCHEMA_CONST", `${path}.backend`, "unavailable backend cannot identify a deployment");
    arrayValue(backend.sources, `${path}.backend.sources`, 0, 0);
    enumValue(backend.unavailable_reason, `${path}.backend.unavailable_reason`, ["not_applicable", "not_deployed", "deployment_identity_unavailable", "connector_unavailable", "redacted_by_policy"]);
  }

  const sdk = exactObject(build.sdk, `${path}.sdk`, ["package_name", "package_version", "source_revision", "capture_schema_version", "configuration_digest"]);
  requireValue(sdk.package_name === "@tacua/mobile-sdk", "SCHEMA_CONST", `${path}.sdk.package_name`, "unexpected SDK package");
  requireValue(typeof sdk.package_version === "string" && codePointLength(sdk.package_version) <= 64 && /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(sdk.package_version), "SCHEMA_PATTERN", `${path}.sdk.package_version`, "invalid SDK version");
  requireValue(typeof sdk.source_revision === "string" && shaPattern.test(sdk.source_revision), "SCHEMA_SHA", `${path}.sdk.source_revision`, "invalid SDK revision");
  stringValue(sdk.capture_schema_version, `${path}.sdk.capture_schema_version`, 1, 128);
  digestValue(sdk.configuration_digest, `${path}.sdk.configuration_digest`);
  return build;
}

const evidenceTypes = [
  "sdk.route_transition", "sdk.user_interaction", "sdk.runtime_error", "sdk.network_metadata", "sdk.trace_correlation",
  "sdk.app_state_provider", "sdk.capture_gap", "media.keyframe", "media.clip", "media.transcript_excerpt",
  "repository.commit_snapshot", "backend.deployment_snapshot", "backend.log_snapshot", "backend.trace_snapshot",
  "observability.sentry_snapshot", "observability.posthog_snapshot",
] as const;

function validateEvidenceItem(value: unknown, path: string): JsonObject {
  const item = exactObject(value, path, [
    "contract_version", "organization_id", "project_id", "session_id", "evidence_id", "evidence_type", "availability",
    "description", "time_range", "source", "reference", "authorization", "unavailable", "evidence_item_digest",
  ]);
  requireValue(item.contract_version === "tacua.evidence-item@1.0.0", "SCHEMA_CONST", `${path}.contract_version`, "unsupported evidence item");
  ["organization_id", "project_id", "session_id", "evidence_id"].forEach((field) => identifier(item[field], `${path}.${field}`));
  const evidenceType = enumValue(item.evidence_type, `${path}.evidence_type`, evidenceTypes);
  const availability = enumValue(item.availability, `${path}.availability`, ["available", "unavailable"]);
  stringValue(item.description, `${path}.description`, 1, 2048);
  if (item.time_range !== null) {
    const range = exactObject(item.time_range, `${path}.time_range`, ["start_ms", "end_ms", "clock"]);
    integerValue(range.start_ms, `${path}.time_range.start_ms`, 0, maximumSafeInteger);
    integerValue(range.end_ms, `${path}.time_range.end_ms`, 0, maximumSafeInteger);
    requireValue(range.clock === "session_monotonic", "SCHEMA_CONST", `${path}.time_range.clock`, "unexpected evidence clock");
    requireValue(range.start_ms <= range.end_ms, "REVERSED_TIME_RANGE", `${path}.time_range`, "start must not follow end");
  }
  const source = exactObject(item.source, `${path}.source`, ["component", "source_id", "snapshot_revision", "captured_at"]);
  const component = enumValue(source.component, `${path}.source.component`, ["mobile_sdk", "backend", "repository", "sentry", "posthog"]);
  identifier(source.source_id, `${path}.source.source_id`);
  stringValue(source.snapshot_revision, `${path}.source.snapshot_revision`, 1, 128);
  timestamp(source.captured_at, `${path}.source.captured_at`);
  const expectedComponent = evidenceType.startsWith("sdk.") || evidenceType.startsWith("media.") ? "mobile_sdk"
    : evidenceType.startsWith("repository.") ? "repository"
      : evidenceType.startsWith("backend.") ? "backend"
        : evidenceType.startsWith("observability.sentry_") ? "sentry" : "posthog";
  requireValue(component === expectedComponent, "SOURCE_TYPE_MISMATCH", `${path}.source.component`, `${evidenceType} requires ${expectedComponent}`);

  if (availability === "available") {
    const reference = exactObject(item.reference, `${path}.reference`, ["locator", "content_type", "size_bytes", "content_digest"]);
    const locator = exactObject(reference.locator, `${path}.reference.locator`, ["scheme", "organization_id", "project_id", "evidence_id", "revision_id"]);
    requireValue(locator.scheme === "tacua-evidence", "SCHEMA_CONST", `${path}.reference.locator.scheme`, "unexpected evidence scheme");
    ["organization_id", "project_id", "evidence_id", "revision_id"].forEach((field) => identifier(locator[field], `${path}.reference.locator.${field}`));
    enumValue(reference.content_type, `${path}.reference.content_type`, ["application/json", "text/plain", "image/png", "video/quicktime", "application/vnd.tacua.sdk-event+json", "application/vnd.tacua.connector-snapshot+json"]);
    integerValue(reference.size_bytes, `${path}.reference.size_bytes`, 0, 104_857_600);
    digestValue(reference.content_digest, `${path}.reference.content_digest`);
    const authorization = exactObject(item.authorization, `${path}.authorization`, ["authorized_for_handoff", "organization_id", "project_id", "evidence_id", "decision_id", "actor_id", "policy_version", "approved_at", "immutable"]);
    requireValue(authorization.authorized_for_handoff === true, "SCHEMA_CONST", `${path}.authorization.authorized_for_handoff`, "evidence is not authorized for handoff");
    ["organization_id", "project_id", "evidence_id", "decision_id", "actor_id"].forEach((field) => identifier(authorization[field], `${path}.authorization.${field}`));
    requireValue(authorization.policy_version === "tacua.egress@1.0.0" && authorization.immutable === true, "SCHEMA_CONST", `${path}.authorization`, "invalid immutable egress authorization");
    timestamp(authorization.approved_at, `${path}.authorization.approved_at`);
    requireValue(item.unavailable === null, "SCHEMA_CONST", `${path}.unavailable`, "available evidence cannot be unavailable");
  } else {
    requireValue(item.reference === null && item.authorization === null, "SCHEMA_CONST", path, "unavailable evidence cannot contain a reference or authorization");
    const unavailable = exactObject(item.unavailable, `${path}.unavailable`, ["reason", "detail"]);
    enumValue(unavailable.reason, `${path}.unavailable.reason`, ["capture_gap", "collection_disabled", "permission_denied", "provider_unavailable", "connector_revoked", "redacted_by_policy", "not_configured", "outside_retention", "correlation_missing"]);
    stringValue(unavailable.detail, `${path}.unavailable.detail`, 1, 512);
  }
  digestValue(item.evidence_item_digest, `${path}.evidence_item_digest`);
  return item;
}

function validateEvidenceManifest(value: unknown): JsonObject {
  const path = "$.evidence_manifest";
  const manifest = exactObject(value, path, ["contract_version", "media_type", "organization_id", "project_id", "session_id", "manifest_id", "items", "evidence_manifest_digest"]);
  requireValue(manifest.contract_version === "tacua.evidence-manifest@1.0.0", "SCHEMA_CONST", `${path}.contract_version`, "unsupported manifest");
  requireValue(manifest.media_type === "application/vnd.tacua.evidence-manifest+json;version=1.0.0", "SCHEMA_CONST", `${path}.media_type`, "unsupported manifest media type");
  ["organization_id", "project_id", "session_id", "manifest_id"].forEach((field) => identifier(manifest[field], `${path}.${field}`));
  const items = arrayValue(manifest.items, `${path}.items`, 1, 100);
  items.forEach((item, index) => validateEvidenceItem(item, `${path}.items[${index}]`));
  digestValue(manifest.evidence_manifest_digest, `${path}.evidence_manifest_digest`);
  return manifest;
}

function validateTicket(value: unknown): JsonObject {
  const path = "$.ticket";
  const ticket = exactObject(value, path, ["ticket_id", "ticket_version", "state", "title", "priority", "summary", "summary_claim_refs", "claims", "reproduction", "scope", "acceptance_criteria", "clarifications", "ticket_content_digest"]);
  identifier(ticket.ticket_id, `${path}.ticket_id`);
  integerValue(ticket.ticket_version, `${path}.ticket_version`, 1, maximumSafeInteger);
  requireValue(ticket.state === "approved", "SCHEMA_CONST", `${path}.state`, "handoff ticket must be approved");
  stringValue(ticket.title, `${path}.title`, 1, 256);
  enumValue(ticket.priority, `${path}.priority`, ["P0", "P1", "P2", "P3"]);
  stringValue(ticket.summary, `${path}.summary`, 1, 4096);
  idList(ticket.summary_claim_refs, `${path}.summary_claim_refs`, 1, 32);
  arrayValue(ticket.claims, `${path}.claims`, 1, 64).forEach((claim, index) => {
    const claimPath = `${path}.claims[${index}]`;
    const record = exactObject(claim, claimPath, ["claim_id", "kind", "support", "confidence", "statement", "evidence_refs"]);
    identifier(record.claim_id, `${claimPath}.claim_id`);
    enumValue(record.kind, `${claimPath}.kind`, ["observed", "expected", "diagnosis", "hypothesis", "constraint"]);
    enumValue(record.support, `${claimPath}.support`, ["direct", "inferred", "unknown"]);
    enumValue(record.confidence, `${claimPath}.confidence`, ["high", "medium", "low", "unknown"]);
    stringValue(record.statement, `${claimPath}.statement`, 1, 4096);
    idList(record.evidence_refs, `${claimPath}.evidence_refs`, 0, 32);
  });
  const reproduction = exactObject(ticket.reproduction, `${path}.reproduction`, ["preconditions", "steps", "observed_result", "expected_result", "observed_claim_refs", "expected_claim_refs", "attempts", "reproductions"]);
  textList(reproduction.preconditions, `${path}.reproduction.preconditions`, 0, 32);
  arrayValue(reproduction.steps, `${path}.reproduction.steps`, 1, 64).forEach((step, index) => {
    const stepPath = `${path}.reproduction.steps[${index}]`;
    const record = exactObject(step, stepPath, ["step_id", "action", "claim_refs", "evidence_refs"]);
    identifier(record.step_id, `${stepPath}.step_id`);
    stringValue(record.action, `${stepPath}.action`, 1, 4096);
    idList(record.claim_refs, `${stepPath}.claim_refs`, 1, 32);
    idList(record.evidence_refs, `${stepPath}.evidence_refs`, 1, 32);
  });
  stringValue(reproduction.observed_result, `${path}.reproduction.observed_result`, 1, 4096);
  stringValue(reproduction.expected_result, `${path}.reproduction.expected_result`, 1, 4096);
  idList(reproduction.observed_claim_refs, `${path}.reproduction.observed_claim_refs`, 1, 32);
  idList(reproduction.expected_claim_refs, `${path}.reproduction.expected_claim_refs`, 1, 32);
  integerValue(reproduction.attempts, `${path}.reproduction.attempts`, 1, 1000);
  integerValue(reproduction.reproductions, `${path}.reproduction.reproductions`, 0, 1000);
  const scope = exactObject(ticket.scope, `${path}.scope`, ["in_scope", "out_of_scope"]);
  textList(scope.in_scope, `${path}.scope.in_scope`, 1, 64);
  textList(scope.out_of_scope, `${path}.scope.out_of_scope`, 0, 64);
  arrayValue(ticket.acceptance_criteria, `${path}.acceptance_criteria`, 1, 64).forEach((criterion, index) => {
    const criterionPath = `${path}.acceptance_criteria[${index}]`;
    const record = exactObject(criterion, criterionPath, ["criterion_id", "criterion", "verification"]);
    identifier(record.criterion_id, `${criterionPath}.criterion_id`);
    stringValue(record.criterion, `${criterionPath}.criterion`, 1, 4096);
    stringValue(record.verification, `${criterionPath}.verification`, 1, 4096);
  });
  arrayValue(ticket.clarifications, `${path}.clarifications`, 0, 64).forEach((clarification, index) => {
    const clarificationPath = `${path}.clarifications[${index}]`;
    const record = exactObject(clarification, clarificationPath, ["clarification_id", "question", "impact", "status", "resolution"]);
    identifier(record.clarification_id, `${clarificationPath}.clarification_id`);
    stringValue(record.question, `${clarificationPath}.question`, 1, 4096);
    enumValue(record.impact, `${clarificationPath}.impact`, ["blocking", "non_blocking"]);
    enumValue(record.status, `${clarificationPath}.status`, ["resolved", "unresolved"]);
    if (record.status === "resolved") stringValue(record.resolution, `${clarificationPath}.resolution`, 1, 4096);
    else requireValue(record.resolution === null, "SCHEMA_CONST", `${clarificationPath}.resolution`, "unresolved clarification has no resolution");
  });
  digestValue(ticket.ticket_content_digest, `${path}.ticket_content_digest`);
  return ticket;
}

function validateHandoffOuterSchema(value: unknown): JsonObject {
  const handoff = exactObject(value, "$", ["contract_version", "media_type", "organization_id", "project_id", "source_candidate", "ticket", "build_identity", "evidence_manifest", "approval", "supersession", "authority", "handoff_digest"]);
  requireValue(handoff.contract_version === approvedHandoffContractVersion, "SCHEMA_CONST", "$.contract_version", "unsupported handoff contract");
  requireValue(handoff.media_type === approvedHandoffMediaType, "SCHEMA_CONST", "$.media_type", "unsupported handoff media type");
  identifier(handoff.organization_id, "$.organization_id");
  identifier(handoff.project_id, "$.project_id");
  const source = exactObject(handoff.source_candidate, "$.source_candidate", ["contract_version", "candidate_id", "candidate_version", "candidate_digest", "candidate_content_digest", "canonical_json"]);
  requireValue(source.contract_version === candidateContractVersion, "SCHEMA_CONST", "$.source_candidate.contract_version", "unsupported source candidate");
  identifier(source.candidate_id, "$.source_candidate.candidate_id");
  integerValue(source.candidate_version, "$.source_candidate.candidate_version", 1, maximumSafeInteger);
  digestValue(source.candidate_digest, "$.source_candidate.candidate_digest");
  digestValue(source.candidate_content_digest, "$.source_candidate.candidate_content_digest");
  stringValue(source.canonical_json, "$.source_candidate.canonical_json", 2, 1_048_575);
  validateTicket(handoff.ticket);
  validateBuildIdentity(handoff.build_identity);
  validateEvidenceManifest(handoff.evidence_manifest);
  const approval = exactObject(handoff.approval, "$.approval", ["state", "approval_id", "actor_id", "organization_id", "project_id", "ticket_id", "approved_at", "ticket_version", "ticket_content_digest", "immutable"]);
  requireValue(approval.state === "approved", "SCHEMA_CONST", "$.approval.state", "handoff approval must be approved");
  ["approval_id", "actor_id", "organization_id", "project_id", "ticket_id"].forEach((field) => identifier(approval[field], `$.approval.${field}`));
  timestamp(approval.approved_at, "$.approval.approved_at");
  integerValue(approval.ticket_version, "$.approval.ticket_version", 1, maximumSafeInteger);
  digestValue(approval.ticket_content_digest, "$.approval.ticket_content_digest");
  requireValue(approval.immutable === true, "SCHEMA_CONST", "$.approval.immutable", "approval must be immutable");
  const supersession = exactObject(handoff.supersession, "$.supersession", ["status", "supersedes_handoff_digest", "superseded_by_handoff_digest", "checked_at", "registry_revision"]);
  enumValue(supersession.status, "$.supersession.status", ["current", "superseded"]);
  nullableDigest(supersession.supersedes_handoff_digest, "$.supersession.supersedes_handoff_digest");
  nullableDigest(supersession.superseded_by_handoff_digest, "$.supersession.superseded_by_handoff_digest");
  timestamp(supersession.checked_at, "$.supersession.checked_at");
  identifier(supersession.registry_revision, "$.supersession.registry_revision");
  if (supersession.status === "current") requireValue(supersession.superseded_by_handoff_digest === null, "SCHEMA_CONST", "$.supersession.superseded_by_handoff_digest", "current handoff cannot be superseded");
  else requireValue(typeof supersession.superseded_by_handoff_digest === "string", "SCHEMA_CONST", "$.supersession.superseded_by_handoff_digest", "superseded handoff must name its successor");
  const authority = exactObject(handoff.authority, "$.authority", ["purpose", "allowed_repositories", "read_authorized_evidence", "modify_code", "run_tests", "external_writes", "merge", "deploy"]);
  requireValue(authority.purpose === "implement_approved_ticket", "SCHEMA_CONST", "$.authority.purpose", "unexpected authority purpose");
  idList(authority.allowed_repositories, "$.authority.allowed_repositories", 1, 16);
  requireValue(authority.read_authorized_evidence === true && authority.modify_code === true && authority.run_tests === true && authority.external_writes === false && authority.merge === false && authority.deploy === false, "AUTHORITY_MISMATCH", "$.authority", "authority constants do not match the approved V1 boundary");
  digestValue(handoff.handoff_digest, "$.handoff_digest");
  return handoff;
}

function resolvedSourceClarification(clarification: JsonObject): string | null {
  if (clarification.status !== "resolved") return null;
  if (clarification.resolution_note) return clarification.resolution_note;
  const selected = (clarification.choices as JsonObject[]).find((choice) => choice.choice_id === clarification.selected_choice_id);
  requireValue(selected, "SOURCE_CANDIDATE_CLARIFICATION_INVALID", "$.source_candidate.canonical_json", "resolved clarification has no selected choice");
  return selected.label;
}

function sourceStepAction(step: JsonObject): string {
  const parts = [step.action as string];
  if (step.expected_result !== null) parts.push(`Expected: ${step.expected_result}`);
  if (step.actual_result !== null) parts.push(`Observed: ${step.actual_result}`);
  return parts.join("\n");
}

export function projectApprovedCandidateTicket(candidate: JsonObject): JsonObject {
  const content = candidate.content as JsonObject;
  return {
    ticket_id: candidate.candidate_id,
    ticket_version: candidate.candidate_version,
    state: "approved",
    title: content.title,
    priority: content.priority,
    summary: content.summary.text,
    summary_claim_refs: content.summary.claim_refs,
    claims: content.claims,
    reproduction: {
      preconditions: content.reproduction.preconditions.map((item: JsonObject) => item.text),
      steps: content.reproduction.steps.map((item: JsonObject) => ({ step_id: item.step_id, action: sourceStepAction(item), claim_refs: item.claim_refs, evidence_refs: item.evidence_refs })),
      observed_result: content.actual_behavior.text,
      expected_result: content.expected_behavior.text,
      observed_claim_refs: content.actual_behavior.claim_refs,
      expected_claim_refs: content.expected_behavior.claim_refs,
      attempts: content.reproduction.attempts,
      reproductions: content.reproduction.reproductions,
    },
    scope: content.scope,
    acceptance_criteria: content.acceptance_criteria.map((item: JsonObject) => ({ criterion_id: item.criterion_id, criterion: item.criterion, verification: item.verification })),
    clarifications: content.clarifications.map((item: JsonObject) => ({ clarification_id: item.clarification_id, question: item.question, impact: item.impact, status: item.status, resolution: resolvedSourceClarification(item) })),
    ticket_content_digest: `sha256:${"0".repeat(64)}`,
  };
}

function approvalSubject(handoff: JsonObject): JsonObject {
  const ticket = { ...handoff.ticket };
  delete ticket.ticket_content_digest;
  return {
    contract_version: handoff.contract_version,
    organization_id: handoff.organization_id,
    project_id: handoff.project_id,
    source_candidate: handoff.source_candidate,
    ticket,
    build_identity_digest: handoff.build_identity.build_identity_digest,
    evidence_manifest_digest: handoff.evidence_manifest.evidence_manifest_digest,
    authority: handoff.authority,
  };
}

async function validateApprovedHandoff(
  handoffValue: unknown,
  displayedCandidateValue: unknown,
  expectedHandoffDigest: string,
  digest: DigestBytes,
): Promise<JsonObject> {
  validateJsonValues(handoffValue);
  const handoff = validateHandoffOuterSchema(handoffValue);
  requireValue(encoder.encode(`${canonicalJson(handoff)}\n`).byteLength <= maximumJsonHandoffBytes, "JSON_SIZE_LIMIT", "$", "handoff exceeds 1 MiB");
  requireValue(digestPattern.test(expectedHandoffDigest), "HANDOFF_BINDING_MISMATCH", "$.handoff_digest", "invalid expected digest");

  const source = handoff.source_candidate as JsonObject;
  const candidate = parseCanonicalJson(source.canonical_json, false);
  await validateApprovedCandidate(candidate, digest);
  for (const field of ["contract_version", "candidate_id", "candidate_version", "candidate_digest", "candidate_content_digest"]) {
    requireValue(source[field] === candidate[field], "SOURCE_CANDIDATE_METADATA_MISMATCH", `$.source_candidate.${field}`, "source metadata differs from embedded candidate");
  }
  requireValue(isRecord(displayedCandidateValue), "HANDOFF_SOURCE_CANDIDATE_MISMATCH", "$.source_candidate", "displayed candidate is invalid");
  validateJsonValues(displayedCandidateValue);
  requireValue(source.canonical_json === canonicalJson(displayedCandidateValue), "HANDOFF_SOURCE_CANDIDATE_MISMATCH", "$.source_candidate.canonical_json", "source candidate does not exactly equal the displayed candidate");

  const ticket = handoff.ticket as JsonObject;
  const build = handoff.build_identity as JsonObject;
  const manifest = handoff.evidence_manifest as JsonObject;
  const approval = handoff.approval as JsonObject;
  const candidateApproval = candidate.approval as JsonObject;

  for (const nested of [build, manifest]) {
    requireValue(nested.organization_id === handoff.organization_id && nested.project_id === handoff.project_id, "SCOPE_MISMATCH", "$", "nested artifact scope differs from handoff");
  }
  requireValue(candidate.organization_id === handoff.organization_id && candidate.project_id === handoff.project_id, "SOURCE_CANDIDATE_SCOPE_MISMATCH", "$.source_candidate.canonical_json", "candidate scope differs from handoff");
  requireValue(candidate.candidate_id === ticket.ticket_id && candidate.candidate_version === ticket.ticket_version, "SOURCE_CANDIDATE_TICKET_MISMATCH", "$.ticket", "ticket does not identify the embedded candidate");
  requireValue(candidate.build_id === build.build_id, "SOURCE_CANDIDATE_BUILD_MISMATCH", "$.build_identity.build_id", "build does not identify candidate build");
  requireValue(candidate.session_id === manifest.session_id && candidate.evidence_manifest.manifest_id === manifest.manifest_id, "SOURCE_CANDIDATE_EVIDENCE_MISMATCH", "$.evidence_manifest", "manifest does not identify candidate evidence");
  const handoffEvidenceIds = (manifest.items as JsonObject[]).map((item) => item.evidence_id as string);
  requireValue(sameSet(handoffEvidenceIds, candidateApproval.authorized_evidence_ids), "SOURCE_CANDIDATE_EVIDENCE_MISMATCH", "$.evidence_manifest.items", "handoff evidence differs from candidate approval");
  requireValue(handoffEvidenceIds.every((id) => candidate.evidence_manifest.evidence_ids.includes(id)), "SOURCE_CANDIDATE_EVIDENCE_MISMATCH", "$.evidence_manifest.items", "handoff evidence is absent from candidate manifest");
  for (const field of ["approval_id", "actor_id", "approved_at"]) requireValue(approval[field] === candidateApproval[field], "SOURCE_CANDIDATE_APPROVAL_MISMATCH", `$.approval.${field}`, "handoff approval differs from candidate approval");
  requireValue(approval.ticket_version === candidateApproval.approved_candidate_version, "SOURCE_CANDIDATE_APPROVAL_MISMATCH", "$.approval.ticket_version", "approval version differs from candidate approval");
  const projectedTicket = projectApprovedCandidateTicket(candidate);
  projectedTicket.ticket_content_digest = ticket.ticket_content_digest;
  requireValue(canonicalJson(ticket) === canonicalJson(projectedTicket), "SOURCE_CANDIDATE_TICKET_MISMATCH", "$.ticket", "ticket is not the deterministic candidate projection");

  requireValue(build.build_identity_digest === await sha256Canonical(build, digest, "build_identity_digest"), "DIGEST_MISMATCH", "$.build_identity.build_identity_digest", "build identity digest mismatch");
  const evidenceIds = new Set<string>();
  let hasAvailableEvidence = false;
  for (const [index, item] of (manifest.items as JsonObject[]).entries()) {
    const itemPath = `$.evidence_manifest.items[${index}]`;
    requireValue(!evidenceIds.has(item.evidence_id), "DUPLICATE_ID", `${itemPath}.evidence_id`, "evidence IDs must be unique");
    evidenceIds.add(item.evidence_id);
    requireValue(item.organization_id === manifest.organization_id && item.project_id === manifest.project_id && item.session_id === manifest.session_id, "SCOPE_MISMATCH", itemPath, "evidence scope differs from manifest");
    if (item.availability === "available") {
      hasAvailableEvidence = true;
      for (const field of ["organization_id", "project_id", "evidence_id"]) {
        requireValue(item.reference.locator[field] === item[field], "REFERENCE_SCOPE_MISMATCH", `${itemPath}.reference.locator.${field}`, "reference differs from evidence item");
        requireValue(item.authorization[field] === item[field], "AUTHORIZATION_SCOPE_MISMATCH", `${itemPath}.authorization.${field}`, "authorization differs from evidence item");
      }
      requireValue(timestampMilliseconds(item.source.captured_at, `${itemPath}.source.captured_at`) <= timestampMilliseconds(item.authorization.approved_at, `${itemPath}.authorization.approved_at`), "EVIDENCE_AUTHORIZATION_PRECEDES_CAPTURE", `${itemPath}.authorization.approved_at`, "evidence was authorized before capture");
    }
    requireValue(item.evidence_item_digest === await sha256Canonical(item, digest, "evidence_item_digest"), "DIGEST_MISMATCH", `${itemPath}.evidence_item_digest`, "evidence item digest mismatch");
  }
  requireValue(hasAvailableEvidence, "NO_AVAILABLE_EVIDENCE", "$.evidence_manifest.items", "at least one authorized evidence item is required");
  requireValue(manifest.evidence_manifest_digest === await sha256Canonical(manifest, digest, "evidence_manifest_digest"), "DIGEST_MISMATCH", "$.evidence_manifest.evidence_manifest_digest", "manifest digest mismatch");

  const expectedTicketDigest = await sha256Canonical(approvalSubject(handoff), digest);
  requireValue(ticket.ticket_content_digest === expectedTicketDigest, "DIGEST_MISMATCH", "$.ticket.ticket_content_digest", "approved ticket content digest mismatch");
  requireValue(approval.ticket_content_digest === ticket.ticket_content_digest, "APPROVAL_DIGEST_MISMATCH", "$.approval.ticket_content_digest", "approval does not bind ticket content");
  requireValue(approval.ticket_version === ticket.ticket_version && approval.organization_id === handoff.organization_id && approval.project_id === handoff.project_id && approval.ticket_id === ticket.ticket_id, "APPROVAL_SCOPE_MISMATCH", "$.approval", "approval does not bind this ticket and scope");

  const approvalTime = timestampMilliseconds(approval.approved_at, "$.approval.approved_at");
  if (build.backend.availability === "available") requireValue(timestampMilliseconds(build.backend.deployed_at, "$.build_identity.backend.deployed_at") <= approvalTime, "TICKET_APPROVAL_PRECEDES_BACKEND_DEPLOYMENT", "$.approval.approved_at", "approval predates backend deployment");
  for (const [index, item] of (manifest.items as JsonObject[]).entries()) {
    requireValue(timestampMilliseconds(item.source.captured_at, `$.evidence_manifest.items[${index}].source.captured_at`) <= approvalTime, "TICKET_APPROVAL_PRECEDES_EVIDENCE_CAPTURE", "$.approval.approved_at", "approval predates evidence capture");
    if (item.availability === "available") requireValue(timestampMilliseconds(item.authorization.approved_at, `$.evidence_manifest.items[${index}].authorization.approved_at`) <= approvalTime, "TICKET_APPROVAL_PRECEDES_EVIDENCE_AUTHORIZATION", "$.approval.approved_at", "approval predates evidence authorization");
  }

  const itemsById = new Map((manifest.items as JsonObject[]).map((item) => [item.evidence_id as string, item]));
  const claims = ticket.claims as JsonObject[];
  uniqueField(claims, "claim_id", "$.ticket.claims");
  uniqueField(ticket.reproduction.steps, "step_id", "$.ticket.reproduction.steps");
  uniqueField(ticket.acceptance_criteria, "criterion_id", "$.ticket.acceptance_criteria");
  uniqueField(ticket.clarifications, "clarification_id", "$.ticket.clarifications");
  const claimsById = new Map(claims.map((claim) => [claim.claim_id as string, claim]));
  for (const [index, claim] of claims.entries()) {
    const referenced = (claim.evidence_refs as string[]).map((id) => itemsById.get(id));
    requireValue(referenced.every(Boolean), "UNKNOWN_EVIDENCE_REFERENCE", `$.ticket.claims[${index}].evidence_refs`, "claim cites unknown evidence");
    const available = referenced.filter((item) => item?.availability === "available");
    if (claim.support === "direct") requireValue(available.length > 0, "DIRECT_CLAIM_UNGROUNDED", `$.ticket.claims[${index}].evidence_refs`, "direct claim requires available evidence");
    else if (claim.support === "inferred") requireValue(referenced.length > 0, "INFERRED_CLAIM_UNGROUNDED", `$.ticket.claims[${index}].evidence_refs`, "inference requires evidence");
    else requireValue(claim.confidence === "unknown", "UNKNOWN_SUPPORT_CONFIDENCE_MISMATCH", `$.ticket.claims[${index}].confidence`, "unknown support requires unknown confidence");
    if (claim.kind === "observed") requireValue(claim.support === "direct" && available.length > 0, "OBSERVED_CLAIM_UNGROUNDED", `$.ticket.claims[${index}]`, "observed claim requires direct available evidence");
  }
  const assertClaimRefs = (refs: string[], path: string, kinds?: Set<string>) => {
    requireValue(refs.every((ref) => claimsById.has(ref)), "UNKNOWN_CLAIM_REFERENCE", path, "reference names an unknown claim");
    if (kinds) requireValue(refs.some((ref) => kinds.has(claimsById.get(ref)?.kind)), "CLAIM_KIND_MISMATCH", path, "required claim kind is absent");
  };
  assertClaimRefs(ticket.summary_claim_refs, "$.ticket.summary_claim_refs");
  assertClaimRefs(ticket.reproduction.observed_claim_refs, "$.ticket.reproduction.observed_claim_refs", new Set(["observed"]));
  assertClaimRefs(ticket.reproduction.expected_claim_refs, "$.ticket.reproduction.expected_claim_refs", new Set(["expected", "constraint"]));
  for (const [index, step] of (ticket.reproduction.steps as JsonObject[]).entries()) {
    requireValue(step.evidence_refs.length > 0 && step.evidence_refs.every((ref: string) => itemsById.has(ref)), "REPRODUCTION_STEP_UNGROUNDED", `$.ticket.reproduction.steps[${index}].evidence_refs`, "step requires known evidence");
    assertClaimRefs(step.claim_refs, `$.ticket.reproduction.steps[${index}].claim_refs`);
  }
  requireValue(ticket.reproduction.reproductions <= ticket.reproduction.attempts, "INVALID_REPRO_COUNTS", "$.ticket.reproduction", "reproductions cannot exceed attempts");
  for (const [index, clarification] of (ticket.clarifications as JsonObject[]).entries()) if (clarification.impact === "blocking") requireValue(clarification.status === "resolved", "UNRESOLVED_BLOCKING_CLARIFICATION", `$.ticket.clarifications[${index}]`, "blocking clarification is unresolved");

  const testedSources = [build.mobile.source, ...(build.backend.availability === "available" ? build.backend.sources : [])] as JsonObject[];
  const testedRepositories = new Set(testedSources.map((source) => source.repository_id as string));
  requireValue([...testedRepositories].every((repository) => handoff.authority.allowed_repositories.includes(repository)), "REPOSITORY_AUTHORITY_MISMATCH", "$.authority.allowed_repositories", "authority omits a tested repository");
  const testedRevisions = new Map(testedSources.map((source) => [source.repository_id as string, source.revision as string]));
  for (const [index, item] of (manifest.items as JsonObject[]).entries()) {
    if (item.source.component === "repository") {
      requireValue(testedRevisions.has(item.source.source_id), "REPOSITORY_EVIDENCE_SOURCE_MISMATCH", `$.evidence_manifest.items[${index}].source.source_id`, "repository evidence is not a tested source");
      requireValue(testedRevisions.get(item.source.source_id) === item.source.snapshot_revision, "REPOSITORY_EVIDENCE_REVISION_MISMATCH", `$.evidence_manifest.items[${index}].source.snapshot_revision`, "repository evidence revision differs from tested source");
    }
  }
  requireValue(approvalTime <= timestampMilliseconds(handoff.supersession.checked_at, "$.supersession.checked_at"), "REGISTRY_CHECK_PRECEDES_APPROVAL", "$.supersession.checked_at", "registry observation predates approval");
  if (handoff.supersession.supersedes_handoff_digest !== null) requireValue(ticket.ticket_version > 1, "INVALID_SUPERSESSION_CHAIN", "$.ticket.ticket_version", "superseding handoff must use a later ticket version");
  requireValue(handoff.supersession.status === "current" && handoff.supersession.superseded_by_handoff_digest === null, "STALE_HANDOFF", "$.supersession", "reviewer only shares the current approved version");

  const computedHandoffDigest = await sha256Canonical(handoff, digest, "handoff_digest");
  requireValue(handoff.handoff_digest === computedHandoffDigest, "DIGEST_MISMATCH", "$.handoff_digest", "handoff digest mismatch");
  requireValue(handoff.handoff_digest === expectedHandoffDigest, "HANDOFF_BINDING_MISMATCH", "$.handoff_digest", "handoff differs from response binding");
  return handoff;
}

function escapeHtml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function escapeHtmlAttribute(value: string): string {
  return escapeHtml(value).replaceAll('"', "&quot;").replaceAll("'", "&#x27;");
}

function pre(value: unknown, field?: string): string {
  const attribute = field ? ` data-tacua-field="${escapeHtmlAttribute(field)}"` : "";
  const rendered = value === null ? "None" : String(value);
  return `<pre${attribute}>${escapeHtml(rendered)}</pre>`;
}

export function renderApprovedHandoffMarkdown(handoff: JsonObject): string {
  const ticket = handoff.ticket as JsonObject;
  const build = handoff.build_identity as JsonObject;
  const manifest = handoff.evidence_manifest as JsonObject;
  const source = handoff.source_candidate as JsonObject;
  const lines = [
    "<!-- SPDX-License-Identifier: Apache-2.0 -->",
    "# Tacua approved ticket",
    "",
    `- Contract: \`${handoff.contract_version}\``,
    `- Handoff digest: \`${handoff.handoff_digest}\``,
    `- Ticket/version: \`${ticket.ticket_id}\` / \`${ticket.ticket_version}\``,
    `- Approved content digest: \`${ticket.ticket_content_digest}\``,
    `- Build identity digest: \`${build.build_identity_digest}\``,
    `- Evidence manifest digest: \`${manifest.evidence_manifest_digest}\``,
    `- Supersession: \`${handoff.supersession.status}\``,
    "",
    "## Exact approved source candidate",
    "",
    `- Candidate/version: \`${source.candidate_id}\` / \`${source.candidate_version}\``,
    `- Candidate digest: \`${source.candidate_digest}\``,
    `- Candidate content digest: \`${source.candidate_content_digest}\``,
    "",
    "The JSON below is the exact canonical approved ticket-candidate source, without an artifact trailing newline.",
    "",
    pre(source.canonical_json, "source_candidate.canonical_json"),
    "",
    "## Title", "", pre(ticket.title, "ticket.title"), "",
    "## Summary", "", pre(ticket.summary, "ticket.summary"), "",
    `Claims: ${ticket.summary_claim_refs.map((reference: string) => `\`${reference}\``).join(", ")}`,
    "", "## Claims", "",
  ];
  for (const claim of ticket.claims as JsonObject[]) {
    lines.push(
      `### \`${claim.claim_id}\` — \`${claim.kind}\` / \`${claim.support}\` / \`${claim.confidence}\``, "",
      pre(claim.statement, `claim.${claim.claim_id}`), "",
      `Evidence: ${claim.evidence_refs.map((reference: string) => `\`${reference}\``).join(", ")}`, "",
    );
  }
  lines.push("## Reproduction", "", "### Preconditions", "");
  if (ticket.reproduction.preconditions.length) for (const value of ticket.reproduction.preconditions) lines.push(pre(value, "reproduction.precondition"), "");
  else lines.push("None.", "");
  lines.push("### Steps", "");
  (ticket.reproduction.steps as JsonObject[]).forEach((step, index) => {
    const refs = step.evidence_refs.map((reference: string) => `\`${reference}\``).join(", ") || "none";
    const claimRefs = step.claim_refs.map((reference: string) => `\`${reference}\``).join(", ");
    lines.push(`${index + 1}. \`${step.step_id}\` (claims: ${claimRefs}; evidence: ${refs})`, "", pre(step.action, `reproduction.${step.step_id}`), "");
  });
  lines.push(
    "### Observed result", "", pre(ticket.reproduction.observed_result, "reproduction.observed_result"), "",
    `Claims: ${ticket.reproduction.observed_claim_refs.map((reference: string) => `\`${reference}\``).join(", ")}`, "",
    "### Expected result", "", pre(ticket.reproduction.expected_result, "reproduction.expected_result"), "",
    `Claims: ${ticket.reproduction.expected_claim_refs.map((reference: string) => `\`${reference}\``).join(", ")}`, "",
    `Attempts/reproductions: \`${ticket.reproduction.attempts}\` / \`${ticket.reproduction.reproductions}\``, "",
    "## Scope", "", "### In scope", "",
  );
  for (const value of ticket.scope.in_scope) lines.push(pre(value, "scope.in_scope"), "");
  lines.push("### Out of scope", "");
  if (ticket.scope.out_of_scope.length) for (const value of ticket.scope.out_of_scope) lines.push(pre(value, "scope.out_of_scope"), "");
  else lines.push("None declared.", "");
  lines.push("## Acceptance criteria", "");
  for (const criterion of ticket.acceptance_criteria as JsonObject[]) {
    lines.push(`### \`${criterion.criterion_id}\``, "", pre(criterion.criterion, `acceptance.${criterion.criterion_id}.criterion`), "", "Verification:", "", pre(criterion.verification, `acceptance.${criterion.criterion_id}.verification`), "");
  }
  lines.push("## Clarifications and open questions", "");
  if (ticket.clarifications.length) for (const clarification of ticket.clarifications as JsonObject[]) {
    lines.push(`### \`${clarification.clarification_id}\` — \`${clarification.impact}\` / \`${clarification.status}\``, "", pre(clarification.question, `clarification.${clarification.clarification_id}.question`), "", pre(clarification.resolution, `clarification.${clarification.clarification_id}.resolution`), "");
  } else lines.push("None.", "");
  lines.push(
    "## Build snapshots", "",
    `- Mobile: \`${build.mobile.platform}\` / \`${build.mobile.application_id}\` / \`${build.mobile.app_version} (${build.mobile.build_number})\``,
    `- Mobile source: \`${build.mobile.source.repository_id}@${build.mobile.source.revision}\``,
  );
  if (build.backend.availability === "available") {
    lines.push(`- Backend: \`${build.backend.deployment_id}\` / \`${build.backend.image_digest}\``);
    for (const backendSource of build.backend.sources as JsonObject[]) lines.push(`- Backend source: \`${backendSource.repository_id}@${backendSource.revision}\``);
  } else lines.push(`- Backend unavailable: \`${build.backend.unavailable_reason}\``);
  lines.push("", "## Authorized evidence references", "");
  for (const item of manifest.items as JsonObject[]) {
    lines.push(`### \`${item.evidence_id}\` — \`${item.evidence_type}\` / \`${item.availability}\``, "", pre(item.description, `evidence.${item.evidence_id}.description`), "");
    if (item.availability === "available") lines.push(
      `- Revision: \`${item.reference.locator.revision_id}\``,
      `- Content: \`${item.reference.content_type}\` / \`${item.reference.size_bytes}\` bytes / \`${item.reference.content_digest}\``,
      `- Authorization: \`${item.authorization.decision_id}\` / \`${item.authorization.policy_version}\``, "",
    );
    else lines.push(`- Unavailable reason: \`${item.unavailable.reason}\``, "", pre(item.unavailable.detail, `evidence.${item.evidence_id}.unavailable`), "");
  }
  lines.push(
    "## Structural scope — not execution authority", "",
    "- This file is not execution authorization. Before acting, obtain and verify a current trusted registry assertion for this exact handoff digest.",
    "- Only after that independent authorization, the requested scope permits reading the authorized evidence references, modifying code in the listed repositories, and running tests.",
    "- This structural scope never permits external writes, merge, or deploy.",
    `- Repositories: ${handoff.authority.allowed_repositories.map((repository: string) => `\`${repository}\``).join(", ")}`,
    "", "## Canonical JSON", "",
    "The escaped canonical JSON below is the complete machine-equivalent representation.", "",
    `<pre><code class="language-json">${escapeHtml(canonicalJson(handoff))}</code></pre>`, "",
  );
  const rendered = lines.join("\n");
  requireValue(encoder.encode(rendered).byteLength <= maximumMarkdownHandoffBytes, "MARKDOWN_SIZE_LIMIT", "$", "rendered Markdown exceeds 2 MiB");
  return rendered;
}

const markdownCanonicalJsonStart = '<pre><code class="language-json">';
const markdownCanonicalJsonEnd = "</code></pre>";

function extractMarkdownCanonicalJson(markdown: string): string {
  const start = markdown.indexOf(markdownCanonicalJsonStart);
  requireValue(start >= 0 && markdown.indexOf(markdownCanonicalJsonStart, start + 1) < 0, "INVALID_HANDOFF_MARKDOWN", "$", "Markdown must contain exactly one canonical JSON block");
  const contentStart = start + markdownCanonicalJsonStart.length;
  const end = markdown.indexOf(markdownCanonicalJsonEnd, contentStart);
  requireValue(end >= 0 && markdown.indexOf(markdownCanonicalJsonEnd, end + 1) < 0, "INVALID_HANDOFF_MARKDOWN", "$", "canonical JSON block is incomplete");
  const escaped = markdown.slice(contentStart, end);
  const unescaped = escaped.replaceAll("&gt;", ">").replaceAll("&lt;", "<").replaceAll("&amp;", "&");
  requireValue(escapeHtml(unescaped) === escaped, "INVALID_HANDOFF_MARKDOWN", "$", "canonical JSON block uses invalid escaping");
  return unescaped;
}

export async function validateApprovedHandoffArtifact(input: {
  readonly format: "json" | "markdown";
  readonly text: string;
  readonly displayedCandidate: unknown;
  readonly expectedHandoffDigest: string;
  readonly digest: DigestBytes;
}): Promise<JsonObject> {
  const size = encoder.encode(input.text).byteLength;
  const maximum = input.format === "json" ? maximumJsonHandoffBytes : maximumMarkdownHandoffBytes;
  requireValue(size > 0 && size <= maximum, "ARTIFACT_SIZE_LIMIT", "$", "artifact is outside the accepted byte range");
  const document = input.format === "json"
    ? parseCanonicalJson(input.text, true)
    : parseCanonicalJson(extractMarkdownCanonicalJson(input.text), false);
  const validated = await validateApprovedHandoff(document, input.displayedCandidate, input.expectedHandoffDigest, input.digest);
  if (input.format === "markdown") {
    requireValue(input.text === renderApprovedHandoffMarkdown(validated), "MARKDOWN_EQUIVALENCE_MISMATCH", "$", "Markdown is not the exact deterministic approved-handoff rendering");
  }
  return validated;
}
