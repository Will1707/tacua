// SPDX-License-Identifier: Apache-2.0

import type {
  AuditEvent,
  AuditEventPage,
  CaptureSession,
  DiagnosticSummary,
  JobPage,
  ProcessingJob,
  TicketCandidate,
  UploadReceipt,
} from "./types";
import { canonicalJson, type DigestBytes } from "../approved-handoff/contract.ts";
import { isAdminPageCursor } from "./admin-page-cursor.ts";

const maximumSafeInteger = 9_007_199_254_740_991;
const maximumTransportBytes = 1_073_741_824;
const protocolVersion = "tacua.sdk-backend@1.0.0";
const stages = ["transcribe", "align", "correlate", "research", "generate_tickets"] as const;
const encoder = new TextEncoder();

export class AdminResponseValidationError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "AdminResponseValidationError";
  }
}

function fail(code: string): never {
  throw new AdminResponseValidationError(code);
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("INVALID_ADMIN_RESPONSE");
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
  ) fail("INVALID_ADMIN_RESPONSE");
  return result;
}

function identifier(value: unknown): string {
  if (typeof value !== "string" || value.normalize("NFC") !== value || !/^[a-z][a-z0-9_-]{2,63}$/.test(value)) fail("INVALID_ADMIN_RESPONSE");
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || value.normalize("NFC") !== value || !/^sha256:[a-f0-9]{64}$/.test(value)) fail("INVALID_ADMIN_RESPONSE");
  return value;
}

function timestamp(value: unknown): string {
  if (
    typeof value !== "string"
    || value.normalize("NFC") !== value
    || value.startsWith("0000-")
    || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(value)
  ) fail("INVALID_ADMIN_RESPONSE");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== `${value.slice(0, -1)}.000Z`) fail("INVALID_ADMIN_RESPONSE");
  return value;
}

function nullableTimestamp(value: unknown): string | null {
  return value === null ? null : timestamp(value);
}

function integer(value: unknown, minimum = 0, maximum = maximumSafeInteger): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) fail("INVALID_ADMIN_RESPONSE");
  return value as number;
}

function text(value: unknown, minimum: number, maximum: number): string {
  if (typeof value !== "string" || value.normalize("NFC") !== value) fail("INVALID_ADMIN_RESPONSE");
  const length = Array.from(value).length;
  if (length < minimum || length > maximum) fail("INVALID_ADMIN_RESPONSE");
  return value;
}

function array(value: unknown, maximum: number, minimum = 0): unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) fail("INVALID_ADMIN_RESPONSE");
  return value;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T {
  if (typeof value !== "string" || value.normalize("NFC") !== value || !allowed.includes(value as T)) fail("INVALID_ADMIN_RESPONSE");
  return value as T;
}

function unique(values: readonly string[]): void {
  if (new Set(values).size !== values.length) fail("INVALID_ADMIN_RESPONSE");
}

function pageCursor(value: unknown): string | null {
  if (!isAdminPageCursor(value)) fail("INVALID_ADMIN_RESPONSE");
  return value;
}

async function validateSealedDigest(
  value: Record<string, unknown>,
  digestField: string,
  hash: DigestBytes,
  mismatchCode: string,
): Promise<void> {
  const expected = digest(value[digestField]);
  let computed: string;
  try {
    computed = await hash(encoder.encode(canonicalJson(value, digestField)));
  } catch {
    fail("INVALID_ADMIN_RESPONSE");
  }
  if (computed !== expected) fail(mismatchCode);
}

async function uploadReceipt(value: unknown, hash: DigestBytes): Promise<UploadReceipt> {
  const receipt = exact(value, ["segment_id", "object_id", "size_bytes", "content_digest", "received_at", "receipt_digest"]);
  const result = {
    segment_id: identifier(receipt.segment_id),
    object_id: identifier(receipt.object_id),
    size_bytes: integer(receipt.size_bytes, 1, maximumTransportBytes),
    content_digest: digest(receipt.content_digest),
    received_at: timestamp(receipt.received_at),
    receipt_digest: digest(receipt.receipt_digest),
  };
  await validateSealedDigest(receipt, "receipt_digest", hash, "RUNTIME_RECEIPT_DIGEST_MISMATCH");
  return result;
}

function diagnosticSummary(value: unknown): DiagnosticSummary {
  const summary = exact(value, ["envelope_id", "size_bytes", "content_digest", "envelope_digest", "received_at"]);
  return {
    envelope_id: identifier(summary.envelope_id),
    size_bytes: integer(summary.size_bytes, 1, maximumTransportBytes),
    content_digest: digest(summary.content_digest),
    envelope_digest: digest(summary.envelope_digest),
    received_at: timestamp(summary.received_at),
  };
}

type BuildIdentityBinding = {
  readonly raw: Record<string, unknown>;
  readonly buildId: string;
  readonly buildIdentityDigest: string;
  readonly createdAt: string;
};

async function validateBuildIdentity(value: unknown, hash: DigestBytes): Promise<BuildIdentityBinding> {
  const build = exact(value, [
    "protocol_version", "message_type", "build_id", "platform", "bundle_identifier", "native_version", "native_build",
    "build_variant", "distribution", "react_native_version", "transport_configuration_digest", "expo", "source", "created_at",
    "build_identity_digest",
  ]);
  if (build.protocol_version !== protocolVersion || build.message_type !== "build_identity" || build.platform !== "ios") fail("INVALID_ADMIN_RESPONSE");
  const buildId = identifier(build.build_id);
  const bundleIdentifier = text(build.bundle_identifier, 3, 255);
  if (!/^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$/.test(bundleIdentifier)) fail("INVALID_ADMIN_RESPONSE");
  for (const field of ["native_version", "native_build", "react_native_version"] as const) {
    const version = text(build[field], 1, 128);
    if (!/^[A-Za-z0-9._+/-]+$/.test(version)) fail("INVALID_ADMIN_RESPONSE");
  }
  oneOf(build.build_variant, ["development", "preview"] as const);
  oneOf(build.distribution, ["local", "internal", "testflight"] as const);
  digest(build.transport_configuration_digest);
  if (build.expo !== null) {
    const expo = exact(build.expo, ["sdk_version", "runtime_version", "update_id", "update_channel"]);
    for (const field of ["sdk_version", "runtime_version"] as const) {
      const version = text(expo[field], 1, 128);
      if (!/^[A-Za-z0-9._+/-]+$/.test(version)) fail("INVALID_ADMIN_RESPONSE");
    }
    const updateId = expo.update_id === null ? null : text(expo.update_id, 1, 512);
    const updateChannel = expo.update_channel === null ? null : text(expo.update_channel, 1, 512);
    if ((updateId === null) !== (updateChannel === null)) fail("INVALID_ADMIN_RESPONSE");
  }
  const source = exact(build.source, ["git_revision", "working_tree_dirty"]);
  const revision = text(source.git_revision, 7, 64);
  if (!/^[a-f0-9]{7,64}$/.test(revision) || typeof source.working_tree_dirty !== "boolean") fail("INVALID_ADMIN_RESPONSE");
  const createdAt = timestamp(build.created_at);
  const buildIdentityDigest = digest(build.build_identity_digest);
  await validateSealedDigest(build, "build_identity_digest", hash, "BUILD_IDENTITY_DIGEST_MISMATCH");
  return { raw: build, buildId, buildIdentityDigest, createdAt };
}

type CaptureScopeBinding = {
  readonly raw: Record<string, unknown>;
  readonly organizationId: string;
  readonly projectId: string;
  readonly applicationId: string;
  readonly buildId: string;
  readonly buildIdentityDigest: string;
  readonly scopeDigest: string;
  readonly consentPolicyVersion: string;
  readonly consentGrantedAt: string;
  readonly retentionPolicyVersion: string;
  readonly rawMediaDays: number;
  readonly derivedDataDays: number;
};

async function validateCaptureScope(value: unknown, hash: DigestBytes): Promise<CaptureScopeBinding> {
  const scope = exact(value, [
    "protocol_version", "message_type", "organization_id", "project_id", "application_id", "build_id", "build_identity_digest",
    "capture_scope", "consent", "retention", "scope_digest",
  ]);
  if (scope.protocol_version !== protocolVersion || scope.message_type !== "capture_scope" || scope.capture_scope !== "app_only") fail("INVALID_ADMIN_RESPONSE");
  const consent = exact(scope.consent, ["policy_version", "screen_recording", "microphone", "diagnostics", "raw_media_upload", "granted_at"]);
  const consentPolicyVersion = text(consent.policy_version, 1, 128);
  if (!/^[A-Za-z0-9._+/-]+$/.test(consentPolicyVersion)) fail("INVALID_ADMIN_RESPONSE");
  for (const field of ["screen_recording", "microphone", "diagnostics", "raw_media_upload"] as const) {
    if (consent[field] !== "granted") fail("INVALID_ADMIN_RESPONSE");
  }
  const consentGrantedAt = timestamp(consent.granted_at);
  const retention = exact(scope.retention, ["policy_version", "raw_media_days", "derived_data_days"]);
  const retentionPolicyVersion = text(retention.policy_version, 1, 128);
  if (!/^[A-Za-z0-9._+/-]+$/.test(retentionPolicyVersion)) fail("INVALID_ADMIN_RESPONSE");
  const rawMediaDays = integer(retention.raw_media_days, 1, 30);
  const derivedDataDays = integer(retention.derived_data_days, 1, 365);
  const result = {
    raw: scope,
    organizationId: identifier(scope.organization_id),
    projectId: identifier(scope.project_id),
    applicationId: identifier(scope.application_id),
    buildId: identifier(scope.build_id),
    buildIdentityDigest: digest(scope.build_identity_digest),
    scopeDigest: digest(scope.scope_digest),
    consentPolicyVersion,
    consentGrantedAt,
    retentionPolicyVersion,
    rawMediaDays,
    derivedDataDays,
  };
  await validateSealedDigest(scope, "scope_digest", hash, "CAPTURE_SCOPE_DIGEST_MISMATCH");
  return result;
}

type SegmentReceiptBinding = {
  readonly raw: Record<string, unknown>;
  readonly uploadId: string;
  readonly credentialId: string;
  readonly sequence: number;
  readonly segmentReceiptDigest: string;
  readonly runtimeReceipt: UploadReceipt;
};

async function validateSegmentProtocolReceipt(value: unknown, hash: DigestBytes): Promise<SegmentReceiptBinding> {
  const receipt = exact(value, [
    "protocol_version", "message_type", "upload_id", "intent_digest", "session_id", "scope_digest", "credential_id", "sequence",
    "segment_id", "content_type", "sidecar_digest", "runtime_receipt", "transport_digest", "segment_receipt_digest",
  ]);
  if (receipt.protocol_version !== protocolVersion || receipt.message_type !== "segment_upload_receipt") fail("INVALID_ADMIN_RESPONSE");
  const runtimeReceipt = await uploadReceipt(receipt.runtime_receipt, hash);
  const segmentId = identifier(receipt.segment_id);
  const transportDigest = digest(receipt.transport_digest);
  if (
    segmentId !== runtimeReceipt.segment_id
    || transportDigest !== runtimeReceipt.content_digest
  ) fail("SESSION_BINDING_MISMATCH");
  oneOf(receipt.content_type, ["video/mp4", "video/quicktime"] as const);
  const result = {
    raw: receipt,
    uploadId: identifier(receipt.upload_id),
    credentialId: identifier(receipt.credential_id),
    sequence: integer(receipt.sequence, 0, 2047),
    segmentReceiptDigest: digest(receipt.segment_receipt_digest),
    runtimeReceipt,
  };
  identifier(receipt.session_id);
  digest(receipt.intent_digest);
  digest(receipt.scope_digest);
  digest(receipt.sidecar_digest);
  await validateSealedDigest(receipt, "segment_receipt_digest", hash, "SEGMENT_RECEIPT_DIGEST_MISMATCH");
  return result;
}

type DiagnosticReceiptBinding = {
  readonly raw: Record<string, unknown>;
  readonly receiptId: string;
  readonly uploadId: string;
  readonly credentialId: string;
  readonly diagnosticReceiptDigest: string;
  readonly summary: DiagnosticSummary;
};

async function validateDiagnosticProtocolReceipt(value: unknown, hash: DigestBytes): Promise<DiagnosticReceiptBinding> {
  const receipt = exact(value, [
    "protocol_version", "message_type", "receipt_id", "upload_id", "request_digest", "session_id", "scope_digest", "credential_id",
    "object_id", "size_bytes", "transport_digest", "envelope_id", "envelope_digest", "received_at", "diagnostic_receipt_digest",
  ]);
  if (receipt.protocol_version !== protocolVersion || receipt.message_type !== "diagnostic_upload_receipt") fail("INVALID_ADMIN_RESPONSE");
  const summary = diagnosticSummary({
    envelope_id: receipt.envelope_id,
    size_bytes: receipt.size_bytes,
    content_digest: receipt.transport_digest,
    envelope_digest: receipt.envelope_digest,
    received_at: receipt.received_at,
  });
  const result = {
    raw: receipt,
    receiptId: identifier(receipt.receipt_id),
    uploadId: identifier(receipt.upload_id),
    credentialId: identifier(receipt.credential_id),
    diagnosticReceiptDigest: digest(receipt.diagnostic_receipt_digest),
    summary,
  };
  identifier(receipt.session_id);
  identifier(receipt.object_id);
  digest(receipt.request_digest);
  digest(receipt.scope_digest);
  await validateSealedDigest(receipt, "diagnostic_receipt_digest", hash, "DIAGNOSTIC_RECEIPT_DIGEST_MISMATCH");
  return result;
}

function projectedJob(value: unknown): ProcessingJob {
  const job = exact(value, ["job_id", "job_type", "status", "requested_at", "started_at", "completed_at", "failure_code"]);
  const status = oneOf(job.status, ["queued", "running", "succeeded", "failed"] as const);
  const failureCode = job.failure_code === null
    ? null
    : text(job.failure_code, 3, 64);
  if (failureCode !== null && !/^[A-Z][A-Z0-9_]{2,63}$/.test(failureCode)) fail("INVALID_ADMIN_RESPONSE");
  if (job.job_type !== "process_session") fail("INVALID_ADMIN_RESPONSE");
  const result = {
    job_id: identifier(job.job_id),
    job_type: "process_session",
    status,
    requested_at: timestamp(job.requested_at),
    started_at: nullableTimestamp(job.started_at),
    completed_at: nullableTimestamp(job.completed_at),
    failure_code: failureCode,
  } as const;
  if (status === "queued" && (result.started_at !== null || result.completed_at !== null || result.failure_code !== null)) fail("INVALID_ADMIN_RESPONSE");
  if (status === "running" && (result.started_at === null || result.completed_at !== null || result.failure_code !== null)) fail("INVALID_ADMIN_RESPONSE");
  if (status === "succeeded" && (result.started_at === null || result.completed_at === null || result.failure_code !== null)) fail("INVALID_ADMIN_RESPONSE");
  if (status === "failed" && (result.started_at === null || result.completed_at === null || result.failure_code === null)) fail("INVALID_ADMIN_RESPONSE");
  if (result.started_at !== null && Date.parse(result.started_at) < Date.parse(result.requested_at)) fail("INVALID_ADMIN_RESPONSE");
  if (result.completed_at !== null && (result.started_at === null || Date.parse(result.completed_at) < Date.parse(result.started_at))) fail("INVALID_ADMIN_RESPONSE");
  return result;
}

type CompletionReceiptBinding = {
  readonly raw: Record<string, unknown>;
  readonly completionId: string;
  readonly sessionId: string;
  readonly scopeDigest: string;
  readonly acceptedAt: string;
  readonly requestDigest: string;
  readonly completionReceiptDigest: string;
  readonly credentialId: string;
  readonly credentialExpiresAt: string;
  readonly manifestDigest: string;
  readonly segmentReceiptDigests: readonly string[];
  readonly diagnosticReceiptDigests: readonly string[];
  readonly initialJob: ProcessingJob;
  readonly initialJobRaw: Record<string, unknown>;
};

async function validateCompletionProtocolReceipt(
  value: unknown,
  hash: DigestBytes,
): Promise<CompletionReceiptBinding> {
  const receipt = exact(value, [
    "protocol_version", "message_type", "completion_id", "request_digest", "session_id", "scope_digest", "accepted_at",
    "processing_job", "credential", "local_cleanup", "completion_receipt_digest",
  ]);
  if (receipt.protocol_version !== protocolVersion || receipt.message_type !== "completion_receipt") fail("INVALID_ADMIN_RESPONSE");
  const completionId = identifier(receipt.completion_id);
  const sessionId = identifier(receipt.session_id);
  const scopeDigest = digest(receipt.scope_digest);
  const acceptedAt = timestamp(receipt.accepted_at);
  const requestDigest = digest(receipt.request_digest);
  const credential = exact(receipt.credential, ["credential_id", "state", "replay_completion_id", "expires_at"]);
  if (credential.state !== "completion_replay_or_delete_only" || credential.replay_completion_id !== completionId) fail("SESSION_BINDING_MISMATCH");
  const credentialId = identifier(credential.credential_id);
  const credentialExpiresAt = timestamp(credential.expires_at);
  if (Date.parse(credentialExpiresAt) <= Date.parse(acceptedAt)) fail("INVALID_ADMIN_RESPONSE");
  const cleanup = exact(receipt.local_cleanup, ["state", "manifest_digest", "segment_receipt_digests", "diagnostic_receipt_digests"]);
  if (cleanup.state !== "authorized_after_durable_receipt") fail("INVALID_ADMIN_RESPONSE");
  const manifestDigest = digest(cleanup.manifest_digest);
  const segmentReceiptDigests = array(cleanup.segment_receipt_digests, 2048, 1).map(digest);
  const diagnosticReceiptDigests = array(cleanup.diagnostic_receipt_digests, 2048, 1).map(digest);
  unique(segmentReceiptDigests);
  unique(diagnosticReceiptDigests);
  const initialJobRaw = record(receipt.processing_job);
  const initialJob = await validateFullProcessingJob(initialJobRaw, hash);
  if (
    initialJob.status !== "queued"
    || initialJobRaw.session_id !== sessionId
    || initialJob.requested_at !== acceptedAt
    || record(initialJobRaw.inputs).capture_manifest_digest !== manifestDigest
  ) fail("SESSION_BINDING_MISMATCH");
  const completionReceiptDigest = digest(receipt.completion_receipt_digest);
  await validateSealedDigest(receipt, "completion_receipt_digest", hash, "COMPLETION_RECEIPT_DIGEST_MISMATCH");
  return {
    raw: receipt,
    completionId,
    sessionId,
    scopeDigest,
    acceptedAt,
    requestDigest,
    completionReceiptDigest,
    credentialId,
    credentialExpiresAt,
    manifestDigest,
    segmentReceiptDigests,
    diagnosticReceiptDigests,
    initialJob,
    initialJobRaw,
  };
}

function sameStringSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value) => right.includes(value));
}

function addUtcDays(timestampValue: string, days: number): string {
  return new Date(Date.parse(timestampValue) + days * 86_400_000).toISOString().replace(".000Z", "Z");
}

export async function validateSessionDetail(
  value: unknown,
  expectedSessionId: string,
  hash: DigestBytes,
): Promise<CaptureSession> {
  identifier(expectedSessionId);
  const session = exact(value, [
    "session_id", "organization_id", "project_id", "application_id", "build_id", "consent_contract", "state",
    "scope_digest", "build_identity_digest", "created_at", "completed_at", "completion_id", "manifest_digest", "retention",
    "build_identity", "scope", "credentials", "segment_receipts", "segments", "diagnostic_receipts", "diagnostics",
    "completion_receipt", "jobs",
  ]);
  if (session.session_id !== expectedSessionId) fail("SESSION_BINDING_MISMATCH");
  const organizationId = identifier(session.organization_id);
  const projectId = identifier(session.project_id);
  const applicationId = identifier(session.application_id);
  const buildId = identifier(session.build_id);
  const scopeDigest = digest(session.scope_digest);
  const buildIdentityDigest = digest(session.build_identity_digest);
  const consentContract = text(session.consent_contract, 1, 128);
  const state = oneOf(session.state, ["receiving", "completed"] as const);
  const createdAt = timestamp(session.created_at);
  const completedAt = nullableTimestamp(session.completed_at);
  const completionId = session.completion_id === null ? null : identifier(session.completion_id);
  const manifestDigest = session.manifest_digest === null ? null : digest(session.manifest_digest);
  const retention = exact(session.retention, ["policy_version", "raw_media_expires_at", "derived_data_expires_at", "deletion_status"]);
  const rawExpiresAt = timestamp(retention.raw_media_expires_at);
  const derivedExpiresAt = timestamp(retention.derived_data_expires_at);
  const retentionPolicyVersion = text(retention.policy_version, 1, 128);
  if (retention.deletion_status !== "active" || Date.parse(createdAt) >= Date.parse(rawExpiresAt) || Date.parse(createdAt) >= Date.parse(derivedExpiresAt)) fail("INVALID_ADMIN_RESPONSE");
  if (state === "receiving" && (completedAt !== null || completionId !== null || manifestDigest !== null)) fail("INVALID_ADMIN_RESPONSE");
  if (state === "completed" && (completedAt === null || completionId === null || manifestDigest === null || Date.parse(completedAt) < Date.parse(createdAt))) fail("INVALID_ADMIN_RESPONSE");

  const segments = await Promise.all(array(session.segments, 2048).map((receipt) => uploadReceipt(receipt, hash)));
  const diagnostics = array(session.diagnostics, 2048).map(diagnosticSummary);
  // V1's database enforces one processing job per session. Keeping this at
  // the storage cardinality is part of the 16 MiB session transport proof.
  const jobs = array(session.jobs, 1).map(projectedJob);
  unique(segments.map((item) => item.segment_id));
  unique(diagnostics.map((item) => item.envelope_id));
  unique(jobs.map((item) => item.job_id));

  const buildIdentity = await validateBuildIdentity(session.build_identity, hash);
  const scope = await validateCaptureScope(session.scope, hash);
  if (
    buildIdentity.buildId !== buildId
    || buildIdentity.buildIdentityDigest !== buildIdentityDigest
    || scope.organizationId !== organizationId
    || scope.projectId !== projectId
    || scope.applicationId !== applicationId
    || scope.buildId !== buildId
    || scope.scopeDigest !== scopeDigest
    || scope.buildIdentityDigest !== buildIdentityDigest
    || scope.consentPolicyVersion !== consentContract
    || scope.retentionPolicyVersion !== retentionPolicyVersion
    || addUtcDays(createdAt, scope.rawMediaDays) !== rawExpiresAt
    || addUtcDays(createdAt, scope.derivedDataDays) !== derivedExpiresAt
  ) fail("SESSION_BINDING_MISMATCH");

  const credentialIds: string[] = [];
  const credentials = array(session.credentials, 64, 1).map((credentialValue, index) => {
    const credential = exact(credentialValue, ["credential_id", "ordinal", "issued_at", "expires_at", "revoked_at", "issued_state", "current_state", "replay_completion_id"]);
    const credentialId = identifier(credential.credential_id);
    credentialIds.push(credentialId);
    const ordinal = integer(credential.ordinal, 0, 63);
    if (ordinal !== index) fail("INVALID_ADMIN_RESPONSE");
    const issuedAt = timestamp(credential.issued_at);
    const expiresAt = timestamp(credential.expires_at);
    const revokedAt = nullableTimestamp(credential.revoked_at);
    const issuedState = oneOf(credential.issued_state, ["active", "completion_replay_or_delete_only"] as const);
    const currentState = oneOf(credential.current_state, ["active", "completion_replay_or_delete_only", "revoked"] as const);
    const replayCompletionId = credential.replay_completion_id === null ? null : identifier(credential.replay_completion_id);
    if (
      Date.parse(expiresAt) <= Date.parse(issuedAt)
      || (revokedAt !== null && Date.parse(revokedAt) < Date.parse(issuedAt))
      || ((currentState === "revoked") !== (revokedAt !== null))
      || (issuedState === "completion_replay_or_delete_only" && replayCompletionId === null)
      || (currentState === "completion_replay_or_delete_only" && replayCompletionId === null)
    ) fail("INVALID_ADMIN_RESPONSE");
    return { credentialId, ordinal, issuedAt, expiresAt, revokedAt, issuedState, currentState, replayCompletionId };
  });
  unique(credentialIds);
  for (let index = 1; index < credentials.length; index += 1) {
    const previous = credentials[index - 1];
    const current = credentials[index];
    if (!previous || !current || Date.parse(current.issuedAt) < Date.parse(previous.issuedAt)) fail("INVALID_ADMIN_RESPONSE");
  }
  const unrevokedCredentials = credentials.filter((credential) => credential.currentState !== "revoked");
  const latestCredential = credentials.at(-1);
  if (
    unrevokedCredentials.length !== 1
    || latestCredential === undefined
    || unrevokedCredentials[0]?.credentialId !== latestCredential.credentialId
  ) fail("SESSION_BINDING_MISMATCH");

  const segmentReceipts = await Promise.all(array(session.segment_receipts, 2048).map((receipt) => validateSegmentProtocolReceipt(receipt, hash)));
  if (segmentReceipts.length !== segments.length) fail("SESSION_BINDING_MISMATCH");
  unique(segmentReceipts.map((item) => item.uploadId));
  unique(segmentReceipts.map((item) => item.runtimeReceipt.segment_id));
  unique(segmentReceipts.map((item) => String(item.sequence)));
  unique(segmentReceipts.map((item) => item.segmentReceiptDigest));
  segmentReceipts.forEach((receipt, index) => {
    if (
      receipt.raw.session_id !== expectedSessionId
      || receipt.raw.scope_digest !== scopeDigest
      || !credentialIds.includes(receipt.credentialId)
      || canonicalJson(receipt.runtimeReceipt) !== canonicalJson(segments[index])
      || (index > 0 && receipt.sequence <= (segmentReceipts[index - 1]?.sequence ?? -1))
      || Date.parse(receipt.runtimeReceipt.received_at) < Date.parse(createdAt)
    ) fail("SESSION_BINDING_MISMATCH");
  });
  const diagnosticReceipts = await Promise.all(array(session.diagnostic_receipts, 2048).map((receipt) => validateDiagnosticProtocolReceipt(receipt, hash)));
  if (diagnosticReceipts.length !== diagnostics.length) fail("SESSION_BINDING_MISMATCH");
  unique(diagnosticReceipts.map((item) => item.receiptId));
  unique(diagnosticReceipts.map((item) => item.uploadId));
  unique(diagnosticReceipts.map((item) => item.summary.envelope_id));
  unique(diagnosticReceipts.map((item) => item.diagnosticReceiptDigest));
  diagnosticReceipts.forEach((receipt, index) => {
    const summary = diagnostics[index];
    if (
      !summary
      || receipt.raw.session_id !== expectedSessionId
      || receipt.raw.scope_digest !== scopeDigest
      || !credentialIds.includes(receipt.credentialId)
      || canonicalJson(receipt.summary) !== canonicalJson(summary)
      || Date.parse(receipt.summary.received_at) < Date.parse(createdAt)
    ) fail("SESSION_BINDING_MISMATCH");
  });

  const completionReceipt = session.completion_receipt === null
    ? null
    : await validateCompletionProtocolReceipt(session.completion_receipt, hash);
  if (state === "receiving" && (completionReceipt !== null || jobs.length !== 0)) fail("SESSION_BINDING_MISMATCH");
  if (state === "completed") {
    if (
      completionReceipt === null
      || completionReceipt.sessionId !== expectedSessionId
      || completionReceipt.scopeDigest !== scopeDigest
      || completionReceipt.completionId !== completionId
      || completionReceipt.acceptedAt !== completedAt
      || completionReceipt.manifestDigest !== manifestDigest
      || !credentialIds.includes(completionReceipt.credentialId)
      || !sameStringSet(completionReceipt.segmentReceiptDigests, segmentReceipts.map((item) => item.segmentReceiptDigest))
      || !sameStringSet(completionReceipt.diagnosticReceiptDigests, diagnosticReceipts.map((item) => item.diagnosticReceiptDigest))
      || !sameStringSet(
        array(record(completionReceipt.initialJobRaw.inputs).diagnostic_envelope_digests, 2048, 1).map(digest),
        diagnosticReceipts.map((item) => item.summary.envelope_digest),
      )
      || completionReceipt.initialJobRaw.organization_id !== organizationId
      || completionReceipt.initialJobRaw.project_id !== projectId
      || completionReceipt.initialJobRaw.build_id !== buildId
      || completionReceipt.initialJobRaw.build_identity_digest !== buildIdentityDigest
      || !jobs.some((job) => job.job_id === completionReceipt.initialJob.job_id && job.requested_at === completionReceipt.initialJob.requested_at)
    ) fail("SESSION_BINDING_MISMATCH");
    const persistedCompletionCredential = credentials.find((credential) => credential.credentialId === completionReceipt.credentialId);
    const currentCompletionCredential = unrevokedCredentials[0];
    if (
      !persistedCompletionCredential
      || persistedCompletionCredential.replayCompletionId !== completionId
      || persistedCompletionCredential.expiresAt !== completionReceipt.credentialExpiresAt
      || Date.parse(persistedCompletionCredential.issuedAt) > Date.parse(completionReceipt.acceptedAt)
      || (
        persistedCompletionCredential.revokedAt !== null
        && Date.parse(persistedCompletionCredential.revokedAt) < Date.parse(completionReceipt.acceptedAt)
      )
      || !currentCompletionCredential
      || currentCompletionCredential.currentState !== "completion_replay_or_delete_only"
      || currentCompletionCredential.replayCompletionId !== completionId
    ) fail("SESSION_BINDING_MISMATCH");
  } else if (
    latestCredential.currentState !== "active"
    || latestCredential.replayCompletionId !== null
  ) {
    fail("SESSION_BINDING_MISMATCH");
  }
  if (completedAt !== null) {
    const latestReceipt = [...segments.map((item) => item.received_at), ...diagnostics.map((item) => item.received_at)]
      .reduce((latest, item) => Date.parse(item) > Date.parse(latest) ? item : latest, createdAt);
    if (Date.parse(completedAt) < Date.parse(latestReceipt)) fail("INVALID_ADMIN_RESPONSE");
  }

  return {
    session_id: expectedSessionId,
    organization_id: organizationId,
    project_id: projectId,
    application_id: applicationId,
    build_id: buildId,
    consent_contract: consentContract,
    state,
    scope_digest: scopeDigest,
    build_identity_digest: buildIdentityDigest,
    created_at: createdAt,
    completed_at: completedAt,
    completion_id: completionId,
    manifest_digest: manifestDigest,
    retention: {
      policy_version: retentionPolicyVersion,
      raw_media_expires_at: rawExpiresAt,
      derived_data_expires_at: derivedExpiresAt,
      deletion_status: "active",
    },
    segments,
    diagnostics,
    jobs,
  };
}

function validateContextSource(value: unknown): void {
  const source = exact(value, ["source_id", "kind", "access", "availability", "snapshot_digest", "unavailable"]);
  identifier(source.source_id);
  oneOf(source.kind, ["mobile_repository", "backend_repository", "sentry", "posthog", "other_observability"] as const);
  if (source.access !== "read_only") fail("INVALID_ADMIN_RESPONSE");
  const availability = oneOf(source.availability, ["available", "unavailable"] as const);
  if (availability === "available") {
    digest(source.snapshot_digest);
    if (source.unavailable !== null) fail("INVALID_ADMIN_RESPONSE");
  } else {
    if (source.snapshot_digest !== null) fail("INVALID_ADMIN_RESPONSE");
    const unavailable = exact(source.unavailable, ["reason", "detail"]);
    text(unavailable.reason, 1, 128);
    text(unavailable.detail, 1, 512);
  }
}

async function validateFullProcessingJob(value: unknown, hash: DigestBytes): Promise<ProcessingJob> {
  const job = exact(value, [
    "contract_version", "media_type", "organization_id", "project_id", "build_id", "build_identity_digest", "session_id",
    "job_id", "job_version", "previous_job_digest", "status", "requested_at", "started_at", "completed_at", "inputs",
    "pipeline", "execution", "outputs", "failure", "job_digest",
  ]);
  if (job.contract_version !== "tacua.processing-job@1.0.0" || job.media_type !== "application/vnd.tacua.processing-job+json;version=1.0.0") fail("INVALID_ADMIN_RESPONSE");
  ["organization_id", "project_id", "build_id", "session_id", "job_id"].forEach((field) => identifier(job[field]));
  digest(job.build_identity_digest);
  const jobVersion = integer(job.job_version, 1);
  const previousJobDigest = job.previous_job_digest === null
    ? null
    : digest(job.previous_job_digest);
  if ((jobVersion === 1) !== (previousJobDigest === null)) fail("INVALID_ADMIN_RESPONSE");
  const status = oneOf(job.status, ["queued", "running", "succeeded", "failed"] as const);
  const requestedAt = timestamp(job.requested_at);
  const startedAt = nullableTimestamp(job.started_at);
  const completedAt = nullableTimestamp(job.completed_at);

  const inputs = exact(job.inputs, ["capture_manifest_digest", "diagnostic_envelope_digests", "context_sources"]);
  digest(inputs.capture_manifest_digest);
  const diagnosticDigests = array(inputs.diagnostic_envelope_digests, 2048, 1).map(digest);
  unique(diagnosticDigests);
  array(inputs.context_sources, 32).forEach(validateContextSource);

  const pipeline = exact(job.pipeline, ["pipeline_version", "stages"]);
  text(pipeline.pipeline_version, 1, 128);
  const pipelineStages = array(pipeline.stages, 5, 5);
  pipelineStages.forEach((stageValue, index) => {
    const stage = exact(stageValue, ["name", "state", "attempt_count", "started_at", "completed_at", "detail"]);
    if (stage.name !== stages[index]) fail("INVALID_ADMIN_RESPONSE");
    oneOf(stage.state, ["pending", "running", "succeeded", "failed"] as const);
    integer(stage.attempt_count, 0, 1000);
    nullableTimestamp(stage.started_at);
    nullableTimestamp(stage.completed_at);
    if (stage.detail !== null) text(stage.detail, 1, 4096);
  });

  const execution = exact(job.execution, ["mode", "max_attempts", "egress"]);
  if (execution.mode !== "async") fail("INVALID_ADMIN_RESPONSE");
  integer(execution.max_attempts, 1, 100);
  const egress = exact(execution.egress, ["policy", "authorized", "authorization_decision_id", "destinations"]);
  if (egress.policy !== "default_deny" || typeof egress.authorized !== "boolean") fail("INVALID_ADMIN_RESPONSE");
  if (egress.authorization_decision_id !== null) identifier(egress.authorization_decision_id);
  const destinations = array(egress.destinations, 8);
  const destinationIds = destinations.map((destinationValue) => {
    const destination = exact(destinationValue, ["destination_id", "provider_kind", "model_id", "content_categories"]);
    const destinationId = identifier(destination.destination_id);
    oneOf(destination.provider_kind, ["local", "openai", "anthropic", "other_api"] as const);
    text(destination.model_id, 1, 128);
    const categories = array(destination.content_categories, 8, 1).map((category) => oneOf(category, ["transcript", "screenshots", "sdk_diagnostics", "repository_context", "observability_context"] as const));
    unique(categories);
    return destinationId;
  });
  unique(destinationIds);
  if (egress.authorized === false && (egress.authorization_decision_id !== null || destinations.length !== 0)) fail("INVALID_ADMIN_RESPONSE");
  if (egress.authorized === true && (egress.authorization_decision_id === null || destinations.length === 0)) fail("INVALID_ADMIN_RESPONSE");

  if (job.outputs !== null) {
    const outputs = exact(job.outputs, ["disposition", "candidate_refs", "derived_evidence_refs", "summary"]);
    const disposition = oneOf(outputs.disposition, ["candidates_created", "no_issue_detected"] as const);
    const candidateRefs = array(outputs.candidate_refs, 256);
    candidateRefs.forEach((candidateRefValue) => {
      const candidateRef = exact(candidateRefValue, ["candidate_id", "candidate_version"]);
      identifier(candidateRef.candidate_id);
      integer(candidateRef.candidate_version, 1);
    });
    if ((candidateRefs.length > 0) !== (disposition === "candidates_created")) fail("INVALID_ADMIN_RESPONSE");
    const evidenceRefs = array(outputs.derived_evidence_refs, 10_000).map(identifier);
    unique(evidenceRefs);
    text(outputs.summary, 1, 4096);
  }
  let failureCode: string | null = null;
  if (job.failure !== null) {
    const failure = exact(job.failure, ["code", "failed_stage", "retryable", "detail"]);
    failureCode = text(failure.code, 3, 64);
    if (!/^[A-Z][A-Z0-9_]{2,63}$/.test(failureCode) || typeof failure.retryable !== "boolean") fail("INVALID_ADMIN_RESPONSE");
    oneOf(failure.failed_stage, stages);
    text(failure.detail, 1, 256);
  }
  const jobDigest = digest(job.job_digest);
  const computedDigest = await hash(new TextEncoder().encode(canonicalJson(job, "job_digest")));
  if (jobDigest !== computedDigest) fail("PROCESSING_JOB_DIGEST_MISMATCH");

  if (status === "queued" && (startedAt !== null || completedAt !== null || job.outputs !== null || job.failure !== null)) fail("INVALID_ADMIN_RESPONSE");
  if (status === "running" && (startedAt === null || completedAt !== null || job.outputs !== null || job.failure !== null)) fail("INVALID_ADMIN_RESPONSE");
  if (status === "succeeded" && (startedAt === null || completedAt === null || job.outputs === null || job.failure !== null)) fail("INVALID_ADMIN_RESPONSE");
  if (status === "failed" && (startedAt === null || completedAt === null || job.outputs !== null || job.failure === null)) fail("INVALID_ADMIN_RESPONSE");
  if (startedAt !== null && Date.parse(startedAt) < Date.parse(requestedAt)) fail("INVALID_ADMIN_RESPONSE");
  if (completedAt !== null && (startedAt === null || Date.parse(completedAt) < Date.parse(startedAt))) fail("INVALID_ADMIN_RESPONSE");

  return {
    job_id: identifier(job.job_id),
    job_type: "process_session",
    status,
    requested_at: requestedAt,
    started_at: startedAt,
    completed_at: completedAt,
    failure_code: failureCode,
  };
}

export async function validateProcessingJobDetail(
  value: unknown,
  expectedJobId: string,
  hash: DigestBytes,
): Promise<ProcessingJob> {
  identifier(expectedJobId);
  const job = await validateFullProcessingJob(value, hash);
  if (job.job_id !== expectedJobId) fail("PROCESSING_JOB_BINDING_MISMATCH");
  return job;
}

export function validateProcessingJobPage(value: unknown): JobPage {
  const envelope = exact(value, ["jobs", "next_cursor"]);
  const jobs = array(envelope.jobs, 50).map(projectedJob);
  unique(jobs.map((job) => job.job_id));
  const nextCursor = pageCursor(envelope.next_cursor);
  if (nextCursor !== null && jobs.length !== 50) fail("INVALID_ADMIN_RESPONSE");
  return { jobs, next_cursor: nextCursor };
}

function auditEvent(value: unknown): AuditEvent {
  const event = exact(value, [
    "event_id", "event_type", "actor_kind", "organization_id", "project_id", "session_id", "outcome", "occurred_at",
  ]);
  const eventType = text(event.event_type, 3, 64);
  const actorKind = text(event.actor_kind, 3, 64);
  const outcome = text(event.outcome, 3, 64);
  if (
    !/^[a-z][a-z0-9_]{2,63}$/.test(eventType)
    || !/^[a-z][a-z0-9_]{2,63}$/.test(actorKind)
    || !/^[a-z][a-z0-9_]{2,63}$/.test(outcome)
  ) fail("INVALID_ADMIN_RESPONSE");
  return {
    event_id: identifier(event.event_id),
    event_type: eventType,
    actor_kind: actorKind,
    organization_id: identifier(event.organization_id),
    project_id: identifier(event.project_id),
    session_id: event.session_id === null ? null : identifier(event.session_id),
    outcome,
    occurred_at: timestamp(event.occurred_at),
  };
}

export function validateAuditEventPage(value: unknown): AuditEventPage {
  const envelope = exact(value, ["events", "next_cursor"]);
  const events = array(envelope.events, 50).map(auditEvent);
  unique(events.map((event) => event.event_id));
  const nextCursor = pageCursor(envelope.next_cursor);
  if (nextCursor !== null && events.length !== 50) fail("INVALID_ADMIN_RESPONSE");
  return { events, next_cursor: nextCursor };
}

type CandidateTransitionCommon = {
  readonly expected_candidate_id: string;
  readonly expected_candidate_version: number;
  readonly expected_candidate_digest: string;
  readonly expected_candidate_content_digest: string;
  readonly expected_evidence_manifest_digest: string;
  readonly actor_id: string;
  readonly reason: string;
};

export type CandidateTransitionBody = CandidateTransitionCommon & (
  | {
    readonly action: "edit_content";
    readonly content: TicketCandidate["content"];
  }
  | { readonly action: "mark_ready" }
  | {
    readonly action: "approve";
    readonly approval_id: string;
  }
  | { readonly action: "reject" }
  | {
    readonly action: "resolve_clarification";
    readonly clarification_id: string;
    readonly choice_id: string;
    readonly resolution_note: string | null;
  }
);

export function validateTransitionRequestBinding(
  parent: TicketCandidate,
  body: CandidateTransitionBody,
): void {
  try {
    const commonKeys = [
      "action",
      "actor_id",
      "expected_candidate_id",
      "expected_candidate_version",
      "expected_candidate_digest",
      "expected_candidate_content_digest",
      "expected_evidence_manifest_digest",
      "reason",
    ];
    const actionKeys: Record<CandidateTransitionBody["action"], readonly string[]> = {
      edit_content: ["content"],
      mark_ready: [],
      approve: ["approval_id"],
      reject: [],
      resolve_clarification: ["clarification_id", "choice_id", "resolution_note"],
    };
    oneOf(body.action, ["edit_content", "mark_ready", "approve", "reject", "resolve_clarification"] as const);
    exact(body, [...commonKeys, ...actionKeys[body.action]]);
    identifier(body.expected_candidate_id);
    integer(body.expected_candidate_version, 1);
    digest(body.expected_candidate_digest);
    digest(body.expected_candidate_content_digest);
    digest(body.expected_evidence_manifest_digest);
    identifier(body.actor_id);
    text(body.reason, 1, 256);
    if (body.action === "edit_content") {
      record(body.content);
    } else if (body.action === "approve") {
      identifier(body.approval_id);
    } else if (body.action === "resolve_clarification") {
      identifier(body.clarification_id);
      identifier(body.choice_id);
      if (body.resolution_note !== null) text(body.resolution_note, 1, 4096);
    }
    if (
      body.expected_candidate_id !== parent.candidate_id
      || body.expected_candidate_version !== parent.candidate_version
      || body.expected_candidate_digest !== parent.candidate_digest
      || body.expected_candidate_content_digest !== parent.candidate_content_digest
      || body.expected_evidence_manifest_digest !== parent.evidence_manifest.manifest_digest
    ) throw new Error("transition predecessor mismatch");
  } catch {
    fail("TRANSITION_REQUEST_BINDING_MISMATCH");
  }
}

export function validateTransitionBinding(
  parent: TicketCandidate,
  body: CandidateTransitionBody,
  candidate: TicketCandidate,
): void {
  validateTransitionRequestBinding(parent, body);
  const fixed = ["contract_version", "media_type", "organization_id", "project_id", "build_id", "build_identity_digest", "session_id", "evidence_manifest", "candidate_id", "candidate_created_at"] as const;
  if (fixed.some((field) => canonicalJson(candidate[field]) !== canonicalJson(parent[field]))) fail("TRANSITION_RESPONSE_BINDING_MISMATCH");
  if (
    candidate.candidate_version !== parent.candidate_version + 1
    || candidate.previous_candidate_digest !== parent.candidate_digest
    || candidate.transition.from_state !== parent.state
    || candidate.transition.actor.actor_type !== "human"
    || candidate.transition.actor.actor_id !== body.actor_id
    || candidate.transition.reason !== body.reason
    || candidate.lineage.parents.length !== 1
    || candidate.lineage.parents[0]?.candidate_id !== parent.candidate_id
    || candidate.lineage.parents[0]?.candidate_version !== parent.candidate_version
    || candidate.lineage.parents[0]?.candidate_digest !== parent.candidate_digest
    || Date.parse(candidate.version_created_at) <= Date.parse(parent.version_created_at)
  ) fail("TRANSITION_RESPONSE_BINDING_MISMATCH");

  let expectedContent = JSON.parse(canonicalJson(parent.content)) as TicketCandidate["content"];
  let expectedState: TicketCandidate["state"];
  let expectedOperation: TicketCandidate["lineage"]["operation"];
  if (body.action === "edit_content") {
    if (!body.content || canonicalJson(body.content) === canonicalJson(parent.content)) {
      fail("TRANSITION_REQUEST_BINDING_MISMATCH");
    }
    expectedContent = JSON.parse(canonicalJson(body.content)) as TicketCandidate["content"];
    expectedState = expectedContent.clarifications.some((item) => item.impact === "blocking" && item.status === "unresolved")
      ? "needs_clarification"
      : "draft";
    expectedOperation = "edited";
  } else if (body.action === "resolve_clarification") {
    const clarification = expectedContent.clarifications.find((item) => item.clarification_id === body.clarification_id);
    if (!clarification || clarification.status !== "unresolved" || !clarification.choices.some((choice) => choice.choice_id === body.choice_id)) fail("TRANSITION_REQUEST_BINDING_MISMATCH");
    (clarification as { status: string }).status = "resolved";
    (clarification as { selected_choice_id: string | null }).selected_choice_id = body.choice_id;
    (clarification as { resolution_note: string | null }).resolution_note = body.resolution_note;
    expectedState = expectedContent.clarifications.some((item) => item.impact === "blocking" && item.status === "unresolved")
      ? "needs_clarification"
      : "ready_for_review";
    expectedOperation = "clarification_answered";
  } else if (body.action === "mark_ready") {
    expectedState = "ready_for_review";
    expectedOperation = "reviewed";
  } else if (body.action === "approve") {
    expectedState = "approved";
    expectedOperation = "approved";
  } else {
    expectedState = "rejected";
    expectedOperation = "rejected";
  }
  if (
    candidate.state !== expectedState
    || candidate.transition.to_state !== expectedState
    || candidate.lineage.operation !== expectedOperation
    || canonicalJson(candidate.content) !== canonicalJson(expectedContent)
  ) fail("TRANSITION_RESPONSE_BINDING_MISMATCH");
  if (
    !["resolve_clarification", "edit_content"].includes(body.action)
    && candidate.candidate_content_digest !== parent.candidate_content_digest
  ) fail("TRANSITION_RESPONSE_BINDING_MISMATCH");
  if (
    body.action === "edit_content"
    && candidate.candidate_content_digest === parent.candidate_content_digest
  ) fail("TRANSITION_RESPONSE_BINDING_MISMATCH");
  if (
    body.action === "approve"
    && candidate.approval?.approval_id !== body.approval_id
  ) fail("TRANSITION_RESPONSE_BINDING_MISMATCH");
}
