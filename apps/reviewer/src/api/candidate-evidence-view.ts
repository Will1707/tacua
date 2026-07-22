// SPDX-License-Identifier: Apache-2.0

import type {
  CandidateDiagnosticEvent,
  CandidateEvidenceItem,
  CandidateEvidenceView,
} from "./types.ts";

const maximumSafeInteger = 9_007_199_254_740_991;
const maximumSessionElapsedMilliseconds = 1_800_000;
const maximumReferenceBytes = 104_857_600;
const maximumPreviewBytes = 2_097_152;

const evidenceTypes = [
  "sdk.route_transition",
  "sdk.user_interaction",
  "sdk.runtime_error",
  "sdk.network_metadata",
  "sdk.trace_correlation",
  "sdk.app_state_provider",
  "sdk.capture_gap",
  "media.keyframe",
  "media.clip",
  "media.transcript_excerpt",
  "repository.commit_snapshot",
  "backend.deployment_snapshot",
  "backend.log_snapshot",
  "backend.trace_snapshot",
  "observability.sentry_snapshot",
  "observability.posthog_snapshot",
] as const;

const referenceContentTypes = [
  "application/json",
  "text/plain",
  "image/png",
  "video/quicktime",
  "application/vnd.tacua.sdk-event+json",
  "application/vnd.tacua.connector-snapshot+json",
] as const;

const unavailableReasons = [
  "capture_gap",
  "collection_disabled",
  "permission_denied",
  "provider_unavailable",
  "connector_revoked",
  "redacted_by_policy",
  "not_configured",
  "outside_retention",
  "correlation_missing",
] as const;

const secretPatterns = [
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}/iu,
  /\b(?:gh[opusr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b/u,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
] as const;

const forbiddenSecretKeys = new Set([
  "access_token",
  "api_key",
  "client_secret",
  "cookie",
  "password",
  "private_key",
  "refresh_token",
  "secret",
  "session_cookie",
  "set_cookie",
]);

export type CandidateEvidenceBinding = {
  readonly candidateId: string;
  readonly candidateVersion: number;
  readonly candidateDigest: string;
  readonly evidenceManifestDigest: string;
  readonly evidenceIds: readonly string[];
};

export class CandidateEvidenceViewValidationError extends Error {
  readonly code: "INVALID_EVIDENCE_VIEW" | "EVIDENCE_BINDING_MISMATCH";

  constructor(code: CandidateEvidenceViewValidationError["code"]) {
    super(code);
    this.code = code;
    this.name = "CandidateEvidenceViewValidationError";
  }
}

function fail(
  code: CandidateEvidenceViewValidationError["code"] = "INVALID_EVIDENCE_VIEW",
): never {
  throw new CandidateEvidenceViewValidationError(code);
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  return value as Record<string, unknown>;
}

function exact(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  const result = record(value);
  const actualKeys = Object.keys(result).sort();
  const expected = [...expectedKeys].sort();
  if (
    actualKeys.some((key) => key.normalize("NFC") !== key)
    || actualKeys.length !== expected.length
    || actualKeys.some((key, index) => key !== expected[index])
  ) fail();
  return result;
}

function array(value: unknown, minimum: number, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) fail();
  return value;
}

function text(value: unknown, minimum: number, maximum: number): string {
  if (typeof value !== "string" || value.normalize("NFC") !== value) fail();
  const length = Array.from(value).length;
  if (length < minimum || length > maximum) fail();
  return value;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T {
  const candidate = text(value, 1, 512);
  if (!allowed.includes(candidate as T)) fail();
  return candidate as T;
}

function identifier(value: unknown): string {
  const candidate = text(value, 3, 64);
  if (!/^[a-z][a-z0-9_-]{2,63}$/.test(candidate)) fail();
  return candidate;
}

function digest(value: unknown): string {
  const candidate = text(value, 71, 71);
  if (!/^sha256:[a-f0-9]{64}$/.test(candidate)) fail();
  return candidate;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) fail();
  return value as number;
}

function timestamp(value: unknown): string {
  const candidate = text(value, 20, 20);
  if (
    candidate.startsWith("0000-")
    || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(candidate)
  ) fail();
  const milliseconds = Date.parse(candidate);
  if (
    !Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString() !== `${candidate.slice(0, -1)}.000Z`
  ) fail();
  return candidate;
}

function unique(values: readonly string[]): void {
  if (new Set(values).size !== values.length) fail();
}

function assertNoSecretMaterial(value: unknown): void {
  if (typeof value === "string") {
    if (secretPatterns.some((pattern) => pattern.test(value))) fail();
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(assertNoSecretMaterial);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (forbiddenSecretKeys.has(key.toLocaleLowerCase("en-US").replaceAll("-", "_"))) fail();
    assertNoSecretMaterial(child);
  }
}

function evidenceSourceForType(evidenceType: string): string {
  if (evidenceType.startsWith("sdk.") || evidenceType.startsWith("media.")) return "mobile_sdk";
  if (evidenceType.startsWith("repository.")) return "repository";
  if (evidenceType.startsWith("backend.")) return "backend";
  if (evidenceType.startsWith("observability.sentry_")) return "sentry";
  if (evidenceType.startsWith("observability.posthog_")) return "posthog";
  fail();
}

function validateTimeRange(value: unknown): { readonly start_ms: number; readonly end_ms: number; readonly clock: "session_monotonic" } | null {
  if (value === null) return null;
  const range = exact(value, ["start_ms", "end_ms", "clock"]);
  const start = integer(range.start_ms, 0, maximumSafeInteger);
  const end = integer(range.end_ms, 0, maximumSafeInteger);
  if (start > end || range.clock !== "session_monotonic") fail();
  return { start_ms: start, end_ms: end, clock: "session_monotonic" };
}

function validateEvidenceItem(value: unknown): CandidateEvidenceItem {
  assertNoSecretMaterial(value);
  const item = exact(value, [
    "evidence_id",
    "evidence_type",
    "availability",
    "description",
    "time_range",
    "source",
    "reference",
    "unavailable",
    "preview",
  ]);
  identifier(item.evidence_id);
  const evidenceType = oneOf(item.evidence_type, evidenceTypes);
  const availability = oneOf(item.availability, ["available", "unavailable"] as const);
  text(item.description, 1, 2_048);
  validateTimeRange(item.time_range);

  const source = exact(item.source, ["component", "source_id", "snapshot_revision", "captured_at"]);
  const component = oneOf(source.component, ["mobile_sdk", "backend", "repository", "sentry", "posthog"] as const);
  if (component !== evidenceSourceForType(evidenceType)) fail();
  identifier(source.source_id);
  text(source.snapshot_revision, 1, 128);
  timestamp(source.captured_at);

  let reference: Record<string, unknown> | null = null;
  if (availability === "available") {
    reference = exact(item.reference, ["content_type", "size_bytes", "content_digest"]);
    oneOf(reference.content_type, referenceContentTypes);
    integer(reference.size_bytes, 0, maximumReferenceBytes);
    digest(reference.content_digest);
    if (item.unavailable !== null) fail();
  } else {
    if (item.reference !== null) fail();
    const unavailable = exact(item.unavailable, ["reason", "detail"]);
    oneOf(unavailable.reason, unavailableReasons);
    text(unavailable.detail, 1, 512);
  }

  const preview = exact(item.preview, ["status", "content_type", "size_bytes", "content_digest"]);
  const previewStatus = oneOf(preview.status, ["available", "unavailable", "not_applicable"] as const);
  if (evidenceType !== "media.keyframe") {
    if (
      previewStatus !== "not_applicable"
      || preview.content_type !== null
      || preview.size_bytes !== null
      || preview.content_digest !== null
    ) fail();
  } else if (previewStatus === "available") {
    if (availability !== "available" || reference === null) fail();
    const contentType = oneOf(preview.content_type, ["image/png", "image/jpeg", "image/webp"] as const);
    const size = integer(preview.size_bytes, 1, maximumPreviewBytes);
    const contentDigest = digest(preview.content_digest);
    if (
      reference.content_type !== contentType
      || reference.size_bytes !== size
      || reference.content_digest !== contentDigest
    ) fail();
  } else if (
    previewStatus !== "unavailable"
    || preview.content_type !== null
    || preview.size_bytes !== null
    || preview.content_digest !== null
  ) fail();

  return item as CandidateEvidenceItem;
}

function nullableShortText(value: unknown): string | null {
  return value === null ? null : text(value, 1, 512);
}

function nullableDigest(value: unknown): string | null {
  return value === null ? null : digest(value);
}

function nullableInteger(value: unknown): number | null {
  return value === null ? null : integer(value, 0, maximumSafeInteger);
}

function validateEventData(eventType: string, value: unknown): void {
  if (eventType === "route_transition") {
    const data = exact(value, ["from_route", "to_route", "trigger"]);
    nullableShortText(data.from_route);
    text(data.to_route, 1, 512);
    oneOf(data.trigger, ["user", "system", "deep_link", "unknown"] as const);
    return;
  }
  if (eventType === "user_interaction") {
    const data = exact(value, ["action", "target", "value_capture"]);
    oneOf(data.action, ["tap", "long_press", "text_input", "swipe", "submit", "other"] as const);
    text(data.target, 1, 512);
    if (data.value_capture !== "not_collected") fail();
    return;
  }
  if (eventType === "runtime_error") {
    const data = exact(value, ["error_class", "sanitized_message", "stack_trace_digest", "handled"]);
    text(data.error_class, 1, 512);
    text(data.sanitized_message, 1, 4_096);
    nullableDigest(data.stack_trace_digest);
    if (typeof data.handled !== "boolean") fail();
    return;
  }
  if (eventType === "network_request_completed") {
    const data = exact(value, [
      "request_id",
      "method",
      "host",
      "path_template",
      "status_code",
      "duration_ms",
      "trace_id",
      "outcome",
      "request_body_capture",
      "response_body_capture",
    ]);
    identifier(data.request_id);
    oneOf(data.method, ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const);
    const host = text(data.host, 1, 253);
    if (!/^[A-Za-z0-9.-]{1,253}$/.test(host)) fail();
    const pathTemplate = text(data.path_template, 1, 512);
    if (!pathTemplate.startsWith("/") || pathTemplate.includes("?") || pathTemplate.includes("#")) fail();
    if (data.status_code !== null) integer(data.status_code, 100, 599);
    nullableInteger(data.duration_ms);
    nullableShortText(data.trace_id);
    oneOf(data.outcome, ["success", "error", "cancelled", "unknown"] as const);
    if (data.request_body_capture !== "not_collected" || data.response_body_capture !== "not_collected") fail();
    return;
  }
  if (eventType === "app_state_changed") {
    const data = exact(value, ["from_state", "to_state"]);
    oneOf(data.from_state, ["active", "inactive", "background", "unknown"] as const);
    oneOf(data.to_state, ["active", "inactive", "background", "unknown"] as const);
    return;
  }
  if (eventType === "issue_mark") {
    const data = exact(value, ["marker_id", "kind", "narration_elapsed_ms"]);
    identifier(data.marker_id);
    oneOf(data.kind, ["spoken", "manual"] as const);
    integer(data.narration_elapsed_ms, 0, maximumSessionElapsedMilliseconds);
    return;
  }
  if (eventType === "capture_gap") {
    const data = exact(value, ["gap_id", "affected_streams"]);
    identifier(data.gap_id);
    const streams = array(data.affected_streams, 1, 4).map((stream) => oneOf(
      stream,
      ["app_video", "app_audio", "microphone", "diagnostics"] as const,
    ));
    unique(streams);
    return;
  }
  if (eventType === "custom_state") {
    const data = exact(value, ["provider_id", "snapshot_digest", "collection_status"]);
    identifier(data.provider_id);
    const snapshot = nullableDigest(data.snapshot_digest);
    const status = oneOf(data.collection_status, ["available", "unavailable"] as const);
    if ((status === "available") !== (snapshot !== null)) fail();
    return;
  }
  fail();
}

function validateDiagnosticEvent(value: unknown, evidenceIds: ReadonlySet<string>): CandidateDiagnosticEvent {
  const event = exact(value, [
    "event_id",
    "sequence",
    "elapsed_ms",
    "occurred_at",
    "source",
    "event_type",
    "data",
    "evidence_refs",
  ]);
  identifier(event.event_id);
  integer(event.sequence, 0, maximumSafeInteger);
  integer(event.elapsed_ms, 0, maximumSessionElapsedMilliseconds);
  timestamp(event.occurred_at);
  oneOf(event.source, ["mobile_sdk", "capture_extension"] as const);
  const eventType = oneOf(event.event_type, [
    "route_transition",
    "user_interaction",
    "runtime_error",
    "network_request_completed",
    "app_state_changed",
    "issue_mark",
    "capture_gap",
    "custom_state",
  ] as const);
  validateEventData(eventType, event.data);
  const references = array(event.evidence_refs, 0, 32).map(identifier);
  unique(references);
  if (references.some((reference) => !evidenceIds.has(reference))) fail();
  return event as CandidateDiagnosticEvent;
}

function eventSortKey(event: CandidateDiagnosticEvent): readonly [number, number, string] {
  return [event.elapsed_ms, event.sequence, event.event_id];
}

function isBeforeOrEqual(left: readonly [number, number, string], right: readonly [number, number, string]): boolean {
  if (left[0] !== right[0]) return left[0] < right[0];
  if (left[1] !== right[1]) return left[1] < right[1];
  return left[2] <= right[2];
}

export function validateCandidateEvidenceView(
  value: unknown,
  binding: CandidateEvidenceBinding,
): CandidateEvidenceView {
  const expectedIds = binding.evidenceIds.map(identifier);
  unique(expectedIds);
  identifier(binding.candidateId);
  integer(binding.candidateVersion, 1, maximumSafeInteger);
  digest(binding.candidateDigest);
  digest(binding.evidenceManifestDigest);

  const view = exact(value, [
    "contract_version",
    "candidate_id",
    "candidate_version",
    "candidate_digest",
    "evidence_manifest_digest",
    "items",
    "diagnostic_events",
  ]);
  if (
    view.contract_version !== "tacua.candidate-evidence-view@1.0.0"
    || view.candidate_id !== binding.candidateId
    || view.candidate_version !== binding.candidateVersion
    || view.candidate_digest !== binding.candidateDigest
    || view.evidence_manifest_digest !== binding.evidenceManifestDigest
  ) fail("EVIDENCE_BINDING_MISMATCH");

  const items = array(view.items, 1, 100).map(validateEvidenceItem);
  const returnedIds = items.map((item) => item.evidence_id);
  unique(returnedIds);
  if (!items.some((item) => item.availability === "available")) fail();
  const sortedReturnedIds = [...returnedIds].sort();
  const sortedExpectedIds = [...expectedIds].sort();
  if (
    sortedReturnedIds.length !== sortedExpectedIds.length
    || sortedReturnedIds.some((evidenceId, index) => evidenceId !== sortedExpectedIds[index])
  ) fail("EVIDENCE_BINDING_MISMATCH");

  const returnedIdSet = new Set(returnedIds);
  const events = array(view.diagnostic_events, 0, 512).map((event) => (
    validateDiagnosticEvent(event, returnedIdSet)
  ));
  unique(events.map((event) => event.event_id));
  const windows = items.flatMap((item) => item.time_range === null ? [] : [item.time_range]);
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (!event) fail();
    if (
      event.evidence_refs.length === 0
      && !windows.some((range) => range.start_ms <= event.elapsed_ms && event.elapsed_ms <= range.end_ms)
    ) fail();
    const previous = events[index - 1];
    if (previous && !isBeforeOrEqual(eventSortKey(previous), eventSortKey(event))) fail();
  }

  return view as CandidateEvidenceView;
}
