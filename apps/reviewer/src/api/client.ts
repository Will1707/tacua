// SPDX-License-Identifier: Apache-2.0

import type { BackendConfig } from "@/config/backend-config";
import type {
  ApprovedHandoffArtifact,
  AuditEventPage,
  CandidatePage,
  CandidateEvidenceView,
  CandidateReplacementDraft,
  CandidateReplacementOperation,
  CandidateReplacementOperationProjection,
  CandidateReplacementResponse,
  CandidateSupersededDetails,
  CaptureSession,
  EvidencePreview,
  JobPage,
  ProcessingJob,
  RegisteredBuild,
  ResumeLaunchGrant,
  SessionPage,
  StartLaunchGrant,
  TicketCandidate,
} from "@/api/types";
import * as Crypto from "expo-crypto";
import { fetch, type FetchRequestInit } from "expo/fetch";

import {
  AdminResponseValidationError,
  type CandidateTransitionBody,
  validateAuditEventPage,
  validateProcessingJobDetail,
  validateProcessingJobPage,
  validateSessionDetail,
  validateTransitionBinding,
  validateTransitionRequestBinding,
} from "@/api/admin-response-validators";
import {
  CanonicalJsonResponseError,
  assertExpectedSuccessStatus,
  maximumGenericErrorBytes,
  readCanonicalJsonResponse,
  validateGenericErrorEnvelope,
} from "@/api/canonical-json-response";
import {
  ApprovedHandoffValidationError,
  approvedHandoffMediaType,
  maximumJsonHandoffBytes,
  maximumMarkdownHandoffBytes,
  validateApprovedHandoffArtifact,
  validateTicketCandidateSnapshot,
} from "@/approved-handoff/contract";
import {
  EvidencePreviewIntegrityError,
  verifyEvidencePreviewBytes,
} from "@/api/evidence-preview-integrity";
import {
  CandidateEvidenceViewValidationError,
  validateCandidateEvidenceView,
} from "@/api/candidate-evidence-view";
import {
  LaunchGrantValidationError,
  validateResumeLaunchGrant,
  validateStartLaunchGrant,
} from "@/api/launch-grant-validation";
import {
  AdminPageCursorError,
  adminPageHeaders,
  isAdminPageCursor,
} from "@/api/admin-page-cursor";
import { maximumSessionDetailResponseBytes } from "@/api/response-limits";
import {
  CandidateReplacementValidationError,
  createCandidateReplacementRequest,
  replacementRequestDigest,
  serializedReplacementRequest,
  validateCandidateReplacementResponse,
  validateCandidateSupersededErrorEnvelope,
  validateCandidateSupersessionResponse,
} from "@/api/candidate-replacement";

const maximumJsonResponseBytes = 2 * 1_024 * 1_024;
const maximumCandidateBytes = 1_048_576;
const maximumCandidateEvidenceViewBytes = 1_572_864;
const maximumCandidateReplacementBytes = 16 * 1_024 * 1_024;
const maximumEvidencePreviewBytes = 2 * 1_024 * 1_024;
const evidencePreviewContentTypes = new Set(["image/png", "image/jpeg", "image/webp"] as const);

type ExpectedJsonResponse = {
  readonly expectedStatuses: readonly number[];
  readonly maximumBytes?: number;
};

export class TacuaApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "TacuaApiError";
  }
}

export class CandidateSupersededApiError extends TacuaApiError {
  readonly details: CandidateSupersededDetails;

  constructor(status: number, message: string, details: CandidateSupersededDetails) {
    super(status, "CANDIDATE_SUPERSEDED", message);
    this.details = details;
    this.name = "CandidateSupersededApiError";
  }
}

// This fingerprint only keeps distinct human edits from accidentally reusing
// an idempotency key. The backend's canonical request digest remains the trust
// boundary, so a collision is a safe conflict rather than a wrong transition.
function operationFingerprint(value: string): string {
  const hash = (seed: number) => {
    let result = seed;
    for (let index = 0; index < value.length; index += 1) {
      result = Math.imul(result ^ value.charCodeAt(index), 0x01000193);
    }
    return (result >>> 0).toString(16).padStart(8, "0");
  };
  return `${hash(0x811c9dc5)}${hash(0x9e3779b1)}`;
}

function quotedEntityTag(digest: string): string {
  return `"${digest}"`;
}

function hasExactKeys(value: object, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return keys.length === sortedExpected.length
    && keys.every((key, index) => key === sortedExpected[index]);
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[a-z][a-z0-9_-]{2,63}$/.test(value);
}

function isDigest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

function isTimestamp(value: unknown): value is string {
  if (
    typeof value !== "string"
    || value.startsWith("0000-")
    || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(value)
  ) {
    return false;
  }
  const parsed = new Date(value);
  return !Number.isNaN(parsed.valueOf())
    && parsed.toISOString() === `${value.slice(0, -1)}.000Z`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function pageHeaders(cursor?: string): HeadersInit | undefined {
  try {
    return adminPageHeaders(cursor);
  } catch (error) {
    if (!(error instanceof AdminPageCursorError)) throw error;
    throw new TacuaApiError(0, "INVALID_PAGE_CURSOR", "The Tacua page cursor is invalid.");
  }
}

function isSessionSummary(value: unknown): value is CaptureSession {
  if (!isRecord(value) || !hasExactKeys(value, [
    "session_id", "organization_id", "project_id", "application_id", "build_id", "consent_contract", "state",
    "scope_digest", "build_identity_digest", "created_at", "completed_at", "completion_id", "manifest_digest", "retention",
  ])) return false;
  if (!isRecord(value.retention) || !hasExactKeys(value.retention, ["policy_version", "raw_media_expires_at", "derived_data_expires_at", "deletion_status"])) return false;
  const baseIsValid = isIdentifier(value.session_id)
    && isIdentifier(value.organization_id)
    && isIdentifier(value.project_id)
    && isIdentifier(value.application_id)
    && isIdentifier(value.build_id)
    && typeof value.consent_contract === "string"
    && value.consent_contract.length >= 1
    && value.consent_contract.length <= 128
    && ["receiving", "completed"].includes(value.state as string)
    && isDigest(value.scope_digest)
    && isDigest(value.build_identity_digest)
    && isTimestamp(value.created_at)
    && (value.completed_at === null || isTimestamp(value.completed_at))
    && (value.completion_id === null || isIdentifier(value.completion_id))
    && (value.manifest_digest === null || isDigest(value.manifest_digest))
    && typeof value.retention.policy_version === "string"
    && value.retention.policy_version.length >= 1
    && value.retention.policy_version.length <= 128
    && isTimestamp(value.retention.raw_media_expires_at)
    && isTimestamp(value.retention.derived_data_expires_at)
    && value.retention.deletion_status === "active";
  if (!baseIsValid) return false;
  const completionIsAbsent = value.completed_at === null && value.completion_id === null && value.manifest_digest === null;
  const completionIsPresent = value.completed_at !== null && value.completion_id !== null && value.manifest_digest !== null;
  const createdAt = Date.parse(value.created_at as string);
  const rawExpiresAt = Date.parse(value.retention.raw_media_expires_at as string);
  const derivedExpiresAt = Date.parse(value.retention.derived_data_expires_at as string);
  const retentionIsOrdered = createdAt < rawExpiresAt && rawExpiresAt <= derivedExpiresAt;
  return retentionIsOrdered && ((value.state === "receiving" && completionIsAbsent)
    || (
      value.state === "completed"
      && completionIsPresent
      && createdAt <= Date.parse(value.completed_at as string)
      && Date.parse(value.completed_at as string) <= rawExpiresAt
    ));
}

async function sha256Digest(bytes: Uint8Array): Promise<string> {
  const digestInput = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  digestInput.set(bytes);
  const digest = new Uint8Array(await Crypto.digest(Crypto.CryptoDigestAlgorithm.SHA256, digestInput));
  return `sha256:${Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

async function readBoundedBytes(
  response: Response,
  maximum: number,
  cancelSibling?: () => Promise<unknown>,
): Promise<Uint8Array> {
  if (!response.body) {
    throw new TacuaApiError(502, "RESPONSE_STREAM_REQUIRED", "The backend response could not be read within the reviewer limit.");
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > maximum) {
        await Promise.allSettled([
          reader.cancel(),
          ...(cancelSibling ? [cancelSibling()] : []),
        ]);
        throw new TacuaApiError(502, "RESPONSE_TOO_LARGE", "The backend response exceeded the reviewer limit.");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

type CloseableBlob = Blob & { readonly close?: () => void };

function createEvidencePreviewObject(blob: Blob): Pick<EvidencePreview, "uri" | "release"> {
  let uri: string;
  try {
    uri = URL.createObjectURL(blob);
  } catch (error) {
    (blob as CloseableBlob).close?.();
    throw error;
  }
  let released = false;
  return {
    uri,
    release: () => {
      if (released) return;
      released = true;
      try {
        URL.revokeObjectURL(uri);
      } finally {
        (blob as CloseableBlob).close?.();
      }
    },
  };
}

export class TacuaApiClient {
  constructor(private readonly config: BackendConfig) {}

  private async requestDocument<T>(
    path: string,
    init?: FetchRequestInit,
    options?: ExpectedJsonResponse,
  ): Promise<{ readonly body: T; readonly bytes: Uint8Array; readonly response: Response }> {
    if (!options) {
      throw new TacuaApiError(0, "EXPECTED_STATUS_REQUIRED", "The Tacua API call did not pin its success status.");
    }
    if (!path.startsWith("/") || path.startsWith("//")) {
      throw new TacuaApiError(0, "INVALID_REQUEST_PATH", "The Tacua request path is invalid.");
    }
    const endpoint = new URL(path, `${this.config.baseUrl}/`);
    if (endpoint.origin !== this.config.baseUrl) {
      throw new TacuaApiError(0, "INVALID_REQUEST_ORIGIN", "The Tacua request escaped the configured backend.");
    }

    const controller = new AbortController();
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 15_000);
    const headers = new Headers(init?.headers);
    headers.set("Accept", "application/json");
    headers.set("Authorization", `Bearer ${this.config.adminToken}`);
    headers.set("Cache-Control", "no-store");
    if (init?.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

    try {
      const response = await fetch(endpoint, {
        ...init,
        credentials: "omit",
        redirect: "error",
        headers,
        signal: controller.signal,
      });
      if (new URL(response.url).origin !== this.config.baseUrl || response.redirected) {
        throw new TacuaApiError(502, "UNEXPECTED_RESPONSE_ORIGIN", "The backend response came from another origin.");
      }

      if (!response.ok) {
        try {
          const { document } = await readCanonicalJsonResponse(response, maximumGenericErrorBytes);
          const errorCode = isRecord(document.error) ? document.error.code : null;
          if (errorCode === "CANDIDATE_SUPERSEDED") {
            const superseded = validateCandidateSupersededErrorEnvelope(document);
            throw new CandidateSupersededApiError(response.status, superseded.message, superseded.details);
          }
          const error = validateGenericErrorEnvelope(document);
          throw new TacuaApiError(response.status, error.code, error.message);
        } catch (error) {
          if (error instanceof TacuaApiError) throw error;
          if (error instanceof CandidateReplacementValidationError) {
            throw new TacuaApiError(502, error.code, "The Tacua backend returned an invalid supersession error envelope.");
          }
          throw new TacuaApiError(502, "INVALID_ERROR_RESPONSE", "The Tacua backend returned an invalid error envelope.");
        }
      }
      assertExpectedSuccessStatus(response.status, options.expectedStatuses);
      const parsed = await readCanonicalJsonResponse(response, options.maximumBytes ?? maximumJsonResponseBytes);
      return { body: parsed.document as T, bytes: parsed.bytes, response };
    } catch (error) {
      if (error instanceof TacuaApiError) throw error;
      if (error instanceof CanonicalJsonResponseError) {
        throw new TacuaApiError(502, error.code, "The Tacua backend response was not valid bounded canonical JSON.");
      }
      if (controller.signal.aborted && timedOut) {
        throw new TacuaApiError(408, "REQUEST_TIMEOUT", "The Tacua backend did not respond in time.");
      }
      throw new TacuaApiError(0, "NETWORK_ERROR", "Tacua could not reach the configured backend.");
    } finally {
      clearTimeout(timeout);
    }
  }

  private async request<T>(
    path: string,
    init?: FetchRequestInit,
    options?: ExpectedJsonResponse,
  ): Promise<T> {
    return (await this.requestDocument<T>(path, init, options)).body;
  }

  async listSessions(cursor?: string): Promise<SessionPage> {
    const response = await this.request<SessionPage>("/v1/admin/sessions", { headers: pageHeaders(cursor) }, { expectedStatuses: [200] });
    if (
      !isRecord(response)
      || !hasExactKeys(response, ["sessions", "next_cursor"])
      || !Array.isArray(response.sessions)
      || response.sessions.length > 50
      || response.sessions.some((session) => !isSessionSummary(session))
      || new Set(response.sessions.map((session) => session.session_id)).size !== response.sessions.length
      || (response.next_cursor !== null && response.sessions.length !== 50)
      || !isAdminPageCursor(response.next_cursor)
    ) {
      throw new TacuaApiError(502, "INVALID_SESSION_PAGE", "The backend returned an invalid session page.");
    }
    return response;
  }

  async listBuilds(): Promise<readonly RegisteredBuild[]> {
    const response = await this.request<{ readonly builds: readonly RegisteredBuild[] }>("/v1/admin/builds", undefined, { expectedStatuses: [200] });
    if (
      !response
      || typeof response !== "object"
      || !hasExactKeys(response, ["builds"])
      || !Array.isArray(response.builds)
      || response.builds.length > 100
      || response.builds.some((build) => (
        !build
        || typeof build !== "object"
        || !hasExactKeys(build, [
          "build_id",
          "application_id",
          "bundle_identifier",
          "native_version",
          "native_build",
          "distribution",
          "build_identity_digest",
        ])
        || !isIdentifier(build.build_id)
        || !isIdentifier(build.application_id)
        || typeof build.bundle_identifier !== "string"
        || build.bundle_identifier.length < 3
        || build.bundle_identifier.length > 255
        || !/^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$/.test(build.bundle_identifier)
        || typeof build.native_version !== "string"
        || build.native_version.length < 1
        || build.native_version.length > 128
        || !/^[A-Za-z0-9._+/-]+$/.test(build.native_version)
        || typeof build.native_build !== "string"
        || build.native_build.length < 1
        || build.native_build.length > 128
        || !/^[A-Za-z0-9._+/-]+$/.test(build.native_build)
        || !["local", "internal", "testflight"].includes(build.distribution)
        || !isDigest(build.build_identity_digest)
      ))
      || new Set(response.builds.map((build) => build.build_id)).size !== response.builds.length
      || new Set(response.builds.map((build) => build.build_identity_digest)).size !== response.builds.length
    ) {
      throw new TacuaApiError(502, "INVALID_BUILD_REGISTRY", "The backend returned an invalid build registry.");
    }
    return response.builds;
  }

  async createLaunchGrant(buildId: string): Promise<StartLaunchGrant> {
    if (!isIdentifier(buildId)) {
      throw new TacuaApiError(0, "INVALID_BUILD_ID", "The selected build identifier is invalid.");
    }
    const grant = await this.request<unknown>("/v1/admin/launch-codes", {
      method: "POST",
      body: JSON.stringify({ exchange_kind: "start_session", build_id: buildId }),
    }, { expectedStatuses: [201] });
    try {
      return validateStartLaunchGrant(grant);
    } catch (error) {
      if (!(error instanceof LaunchGrantValidationError)) throw error;
      throw new TacuaApiError(502, "INVALID_LAUNCH_GRANT", "The backend returned an invalid launch grant.");
    }
  }

  async createResumeGrant(sessionId: string): Promise<ResumeLaunchGrant> {
    if (!isIdentifier(sessionId)) {
      throw new TacuaApiError(0, "INVALID_SESSION_ID", "The session identifier is invalid.");
    }
    const grant = await this.request<unknown>("/v1/admin/launch-codes", {
      method: "POST",
      body: JSON.stringify({ exchange_kind: "resume_session", session_id: sessionId }),
    }, { expectedStatuses: [201] });
    try {
      return validateResumeLaunchGrant(grant, sessionId);
    } catch (error) {
      if (!(error instanceof LaunchGrantValidationError)) throw error;
      throw new TacuaApiError(
        502,
        error.code,
        "The backend returned a recovery grant that was not bound to this session.",
      );
    }
  }

  async getSession(sessionId: string): Promise<CaptureSession> {
    if (!isIdentifier(sessionId)) throw new TacuaApiError(0, "INVALID_SESSION_ID", "The session identifier is invalid.");
    const response = await this.request<unknown>(
      `/v1/admin/sessions/${encodeURIComponent(sessionId)}`,
      undefined,
      { expectedStatuses: [200], maximumBytes: maximumSessionDetailResponseBytes },
    );
    try {
      return await validateSessionDetail(response, sessionId, sha256Digest);
    } catch (error) {
      if (error instanceof AdminResponseValidationError) {
        throw new TacuaApiError(502, error.code, "The backend returned an invalid session detail response.");
      }
      throw error;
    }
  }

  async listJobs(cursor?: string): Promise<JobPage> {
    const response = await this.request<unknown>(
      "/v1/admin/jobs",
      { headers: pageHeaders(cursor) },
      { expectedStatuses: [200] },
    );
    try {
      return validateProcessingJobPage(response);
    } catch (error) {
      if (error instanceof AdminResponseValidationError) {
        throw new TacuaApiError(502, error.code, "The backend returned an invalid processing-job page.");
      }
      throw error;
    }
  }

  async getJob(jobId: string): Promise<ProcessingJob> {
    if (!isIdentifier(jobId)) throw new TacuaApiError(0, "INVALID_JOB_ID", "The processing-job identifier is invalid.");
    const response = await this.request<unknown>(
      `/v1/admin/jobs/${encodeURIComponent(jobId)}`,
      undefined,
      { expectedStatuses: [200] },
    );
    try {
      return await validateProcessingJobDetail(response, jobId, sha256Digest);
    } catch (error) {
      if (error instanceof AdminResponseValidationError) {
        throw new TacuaApiError(502, error.code, "The backend returned an invalid processing-job detail.");
      }
      throw error;
    }
  }

  async listAuditEvents(cursor?: string): Promise<AuditEventPage> {
    const response = await this.request<unknown>(
      "/v1/admin/audit-events",
      { headers: pageHeaders(cursor) },
      { expectedStatuses: [200] },
    );
    try {
      return validateAuditEventPage(response);
    } catch (error) {
      if (error instanceof AdminResponseValidationError) {
        throw new TacuaApiError(502, error.code, "The backend returned an invalid audit-event page.");
      }
      throw error;
    }
  }

  async listCandidates(sessionId: string, cursor?: string): Promise<CandidatePage> {
    if (!isIdentifier(sessionId)) throw new TacuaApiError(0, "INVALID_SESSION_ID", "The session identifier is invalid.");
    const response = await this.request<CandidatePage>(
      `/v1/admin/sessions/${encodeURIComponent(sessionId)}/candidates`,
      { headers: pageHeaders(cursor) },
      { expectedStatuses: [200] },
    );
    if (
      !isRecord(response)
      || !hasExactKeys(response, ["candidates", "next_cursor"])
      || !Array.isArray(response.candidates)
      || response.candidates.length > 50
      || !isAdminPageCursor(response.next_cursor)
      || (response.next_cursor !== null && response.candidates.length !== 50)
      || response.candidates.some((candidate) => (
        !isRecord(candidate)
        || !hasExactKeys(candidate, ["candidate_id", "candidate_version", "candidate_digest", "state", "priority", "title", "summary", "version_created_at"])
        || !isIdentifier(candidate.candidate_id)
        || !Number.isSafeInteger(candidate.candidate_version)
        || (candidate.candidate_version as number) < 1
        || !isDigest(candidate.candidate_digest)
        || !["draft", "needs_clarification", "ready_for_review", "rejected", "approved"].includes(candidate.state as string)
        || !["P0", "P1", "P2", "P3"].includes(candidate.priority as string)
        || typeof candidate.title !== "string"
        || Array.from(candidate.title).length < 1
        || Array.from(candidate.title).length > 256
        || typeof candidate.summary !== "string"
        || Array.from(candidate.summary).length < 1
        || Array.from(candidate.summary).length > 4096
        || !isTimestamp(candidate.version_created_at)
      ))
      || new Set(response.candidates.map((candidate) => candidate.candidate_id)).size !== response.candidates.length
    ) {
      throw new TacuaApiError(502, "INVALID_CANDIDATE_PAGE", "The backend returned an invalid candidate page.");
    }
    return response;
  }

  async getCandidate(candidateId: string): Promise<TicketCandidate> {
    if (!isIdentifier(candidateId)) throw new TacuaApiError(0, "INVALID_CANDIDATE_ID", "The candidate identifier is invalid.");
    const result = await this.requestDocument<unknown>(
      `/v1/admin/candidates/${encodeURIComponent(candidateId)}`,
      undefined,
      { maximumBytes: maximumCandidateBytes, expectedStatuses: [200] },
    );
    try {
      const candidate = await validateTicketCandidateSnapshot(result.body, sha256Digest) as TicketCandidate;
      if (
        candidate.candidate_id !== candidateId
        || result.response.headers.get("ETag") !== quotedEntityTag(candidate.candidate_digest)
      ) {
        throw new TacuaApiError(502, "CANDIDATE_BINDING_MISMATCH", "The candidate response was not bound to the requested ticket.");
      }
      return candidate;
    } catch (error) {
      if (error instanceof TacuaApiError) throw error;
      if (error instanceof ApprovedHandoffValidationError) {
        throw new TacuaApiError(502, error.code, `The candidate response failed validation (${error.path}).`);
      }
      throw error;
    }
  }

  async getCandidateSupersession(
    candidate: TicketCandidate,
  ): Promise<CandidateReplacementOperationProjection | null> {
    try {
      const response = await this.request<unknown>(
        `/v1/admin/candidates/${encodeURIComponent(candidate.candidate_id)}/supersession`,
        undefined,
        { expectedStatuses: [200], maximumBytes: maximumCandidateReplacementBytes },
      );
      return validateCandidateSupersessionResponse(response, candidate);
    } catch (error) {
      if (error instanceof TacuaApiError && error.status === 404 && error.code === "SUPERSESSION_NOT_FOUND") {
        return null;
      }
      if (error instanceof CandidateReplacementValidationError) {
        throw new TacuaApiError(502, error.code, "The supersession response was not bound to this exact ticket version.");
      }
      throw error;
    }
  }

  async getCandidateEvidence(candidate: TicketCandidate): Promise<CandidateEvidenceView> {
    const result = await this.requestDocument<unknown>(
      `/v1/admin/candidates/${encodeURIComponent(candidate.candidate_id)}/versions/${candidate.candidate_version}/evidence`,
      {
        headers: {
          "If-Match": quotedEntityTag(candidate.candidate_digest),
          "Tacua-Evidence-Manifest-Digest": candidate.evidence_manifest.manifest_digest,
        },
      },
      { expectedStatuses: [200], maximumBytes: maximumCandidateEvidenceViewBytes },
    );
    try {
      if (
        result.response.headers.get("ETag") !== quotedEntityTag(candidate.candidate_digest)
        || result.response.headers.get("Tacua-Evidence-Manifest-Digest") !== candidate.evidence_manifest.manifest_digest
      ) {
        throw new TacuaApiError(502, "EVIDENCE_BINDING_MISMATCH", "The evidence response was not bound to this ticket version.");
      }
      return validateCandidateEvidenceView(result.body, {
        candidateId: candidate.candidate_id,
        candidateVersion: candidate.candidate_version,
        candidateDigest: candidate.candidate_digest,
        evidenceManifestDigest: candidate.evidence_manifest.manifest_digest,
        evidenceIds: candidate.evidence_manifest.evidence_ids,
      });
    } catch (error) {
      if (error instanceof TacuaApiError) throw error;
      if (error instanceof CandidateEvidenceViewValidationError) {
        const message = error.code === "EVIDENCE_BINDING_MISMATCH"
          ? "The evidence response was not bound to this ticket version."
          : "The backend returned an invalid ticket evidence view.";
        throw new TacuaApiError(502, error.code, message);
      }
      throw error;
    }
  }

  async getEvidencePreview(
    candidate: TicketCandidate,
    evidenceId: string,
    expectedContentDigest: string,
    externalSignal?: AbortSignal,
  ): Promise<EvidencePreview> {
    const path = `/v1/admin/candidates/${encodeURIComponent(candidate.candidate_id)}/versions/${candidate.candidate_version}/evidence/${encodeURIComponent(evidenceId)}/preview`;
    if (!path.startsWith("/") || path.startsWith("//")) {
      throw new TacuaApiError(0, "INVALID_REQUEST_PATH", "The Tacua request path is invalid.");
    }
    const endpoint = new URL(path, `${this.config.baseUrl}/`);
    if (endpoint.origin !== this.config.baseUrl) {
      throw new TacuaApiError(0, "INVALID_REQUEST_ORIGIN", "The Tacua request escaped the configured backend.");
    }

    const controller = new AbortController();
    let previewResponse: Response | null = null;
    let timedOut = false;
    const abortFromCaller = () => controller.abort();
    if (externalSignal?.aborted) abortFromCaller();
    else externalSignal?.addEventListener("abort", abortFromCaller, { once: true });
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 15_000);
    try {
      const response = await fetch(endpoint, {
        method: "GET",
        credentials: "omit",
        redirect: "error",
        headers: {
          Accept: "image/png, image/jpeg, image/webp",
          Authorization: `Bearer ${this.config.adminToken}`,
          "Cache-Control": "no-store",
          "If-Match": quotedEntityTag(candidate.candidate_digest),
          "Tacua-Evidence-Manifest-Digest": candidate.evidence_manifest.manifest_digest,
        },
        signal: controller.signal,
      });
      if (new URL(response.url).origin !== this.config.baseUrl || response.redirected) {
        throw new TacuaApiError(502, "UNEXPECTED_RESPONSE_ORIGIN", "The backend response came from another origin.");
      }
      if (!response.ok) {
        throw new TacuaApiError(response.status, "EVIDENCE_PREVIEW_FAILED", "The evidence preview could not be loaded.");
      }
      if (response.status !== 200) {
        throw new TacuaApiError(502, "UNEXPECTED_RESPONSE_STATUS", "The evidence preview returned an unexpected success status.");
      }

      const contentType = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
      if (!contentType || !evidencePreviewContentTypes.has(contentType as "image/png" | "image/jpeg" | "image/webp")) {
        throw new TacuaApiError(502, "INVALID_PREVIEW_TYPE", "The backend returned an unsupported evidence preview.");
      }
      const declaredLength = response.headers.get("Content-Length");
      if (declaredLength === null || !/^\d+$/.test(declaredLength) || Number(declaredLength) < 1 || Number(declaredLength) > maximumEvidencePreviewBytes) {
        throw new TacuaApiError(502, "INVALID_PREVIEW_SIZE", "The backend returned an invalid evidence preview size.");
      }
      const contentDigest = response.headers.get("Tacua-Content-Digest");
      const candidateDigest = response.headers.get("Tacua-Candidate-Digest");
      const manifestDigest = response.headers.get("Tacua-Evidence-Manifest-Digest");
      if (
        contentDigest !== expectedContentDigest
        || candidateDigest !== candidate.candidate_digest
        || manifestDigest !== candidate.evidence_manifest.manifest_digest
      ) {
        throw new TacuaApiError(502, "EVIDENCE_BINDING_MISMATCH", "The preview was not bound to this ticket evidence.");
      }

      // Tee only this one active preview. The sibling is canceled together
      // with the integrity stream if the hard byte cap is crossed.
      previewResponse = response.clone();
      const bytes = await readBoundedBytes(
        response,
        maximumEvidencePreviewBytes,
        () => previewResponse?.body?.cancel() ?? Promise.resolve(),
      );
      try {
        await verifyEvidencePreviewBytes({
          bytes,
          declaredLength: Number(declaredLength),
          expectedDigest: contentDigest,
          digest: sha256Digest,
        });
      } catch (error) {
        if (error instanceof EvidencePreviewIntegrityError) {
          const message = error.code === "PREVIEW_DIGEST_MISMATCH"
            ? "The evidence preview bytes did not match their bound digest."
            : "The evidence preview length or digest declaration was invalid.";
          throw new TacuaApiError(502, error.code, message);
        }
        throw error;
      }
      const typedContentType = contentType as EvidencePreview["contentType"];
      let objectPreview: Pick<EvidencePreview, "uri" | "release">;
      try {
        const blob = await previewResponse.blob();
        previewResponse = null;
        if (
          blob.size !== bytes.byteLength
          || blob.type.split(";", 1)[0]?.trim().toLowerCase() !== typedContentType
        ) {
          (blob as CloseableBlob).close?.();
          throw new Error("The native preview object differed from the verified response.");
        }
        objectPreview = createEvidencePreviewObject(blob);
      } catch {
        throw new TacuaApiError(502, "PREVIEW_URI_FAILED", "The verified evidence preview could not be prepared for display.");
      }
      return {
        ...objectPreview,
        contentType: typedContentType,
        sizeBytes: bytes.byteLength,
        contentDigest,
      };
    } catch (error) {
      if (error instanceof TacuaApiError) throw error;
      if (controller.signal.aborted && timedOut) {
        throw new TacuaApiError(408, "REQUEST_TIMEOUT", "The evidence preview did not respond in time.");
      }
      if (controller.signal.aborted) {
        throw new TacuaApiError(499, "REQUEST_CANCELLED", "The evidence preview request was cancelled.");
      }
      throw new TacuaApiError(0, "NETWORK_ERROR", "Tacua could not load the evidence preview.");
    } finally {
      clearTimeout(timeout);
      externalSignal?.removeEventListener("abort", abortFromCaller);
      if (previewResponse && !previewResponse.bodyUsed) {
        void previewResponse.body?.cancel().catch(() => undefined);
      }
    }
  }

  async getCandidateHandoff(
    candidate: TicketCandidate,
    format: "json" | "markdown",
    externalSignal?: AbortSignal,
  ): Promise<ApprovedHandoffArtifact> {
    if (candidate.state !== "approved") {
      throw new TacuaApiError(0, "HANDOFF_NOT_APPROVED", "Only an approved ticket has an agent handoff.");
    }
    if (
      !isIdentifier(candidate.organization_id)
      || !isIdentifier(candidate.project_id)
      || !isIdentifier(candidate.candidate_id)
      || !Number.isSafeInteger(candidate.candidate_version)
      || candidate.candidate_version < 1
      || !isDigest(candidate.candidate_digest)
      || !isDigest(candidate.candidate_content_digest)
    ) {
      throw new TacuaApiError(0, "HANDOFF_CANDIDATE_INVALID", "The approved ticket binding was invalid.");
    }
    const extension = format === "markdown" ? "md" : "json";
    const path = `/v1/admin/candidates/${encodeURIComponent(candidate.candidate_id)}/versions/${candidate.candidate_version}/handoff.${extension}`;
    const endpoint = new URL(path, `${this.config.baseUrl}/`);
    if (!path.startsWith("/") || path.startsWith("//") || endpoint.origin !== this.config.baseUrl) {
      throw new TacuaApiError(0, "INVALID_REQUEST_ORIGIN", "The Tacua handoff request escaped the configured backend.");
    }

    const expectedContentType = format === "markdown"
      ? "text/markdown; charset=utf-8"
      : approvedHandoffMediaType;
    const maximumBytes = format === "markdown"
      ? maximumMarkdownHandoffBytes
      : maximumJsonHandoffBytes;
    const controller = new AbortController();
    let timedOut = false;
    const abortFromCaller = () => controller.abort();
    if (externalSignal?.aborted) controller.abort();
    else externalSignal?.addEventListener("abort", abortFromCaller, { once: true });
    const timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 15_000);
    const throwIfCancelled = () => {
      if (!controller.signal.aborted) return;
      if (timedOut && !externalSignal?.aborted) {
        throw new TacuaApiError(408, "REQUEST_TIMEOUT", "The approved handoff did not respond in time.");
      }
      throw new TacuaApiError(499, "HANDOFF_REQUEST_CANCELLED", "The approved handoff request was cancelled.");
    };
    try {
      const response = await fetch(endpoint, {
        method: "GET",
        credentials: "omit",
        redirect: "error",
        headers: {
          Accept: expectedContentType,
          Authorization: `Bearer ${this.config.adminToken}`,
          "Cache-Control": "no-store",
        },
        signal: controller.signal,
      });
      if (new URL(response.url).origin !== this.config.baseUrl || response.redirected) {
        throw new TacuaApiError(502, "UNEXPECTED_RESPONSE_ORIGIN", "The handoff response came from another origin.");
      }
      const declaredLength = response.headers.get("Content-Length");
      if (
        declaredLength === null
        || !/^\d+$/.test(declaredLength)
        || Number(declaredLength) < 1
        || Number(declaredLength) > maximumBytes
      ) {
        throw new TacuaApiError(502, "INVALID_HANDOFF_SIZE", "The backend returned an invalid handoff size.");
      }
      if (!response.ok) {
        throw new TacuaApiError(response.status, "HANDOFF_DOWNLOAD_FAILED", "The approved handoff could not be downloaded.");
      }
      if (response.status !== 200) {
        throw new TacuaApiError(502, "UNEXPECTED_RESPONSE_STATUS", "The approved handoff returned an unexpected success status.");
      }
      if (response.headers.get("Content-Type")?.toLowerCase() !== expectedContentType) {
        throw new TacuaApiError(502, "INVALID_HANDOFF_TYPE", "The backend returned an unexpected handoff representation.");
      }

      const bodyDigest = response.headers.get("Tacua-Body-Digest");
      const handoffDigest = response.headers.get("Tacua-Handoff-Digest");
      const candidateDigest = response.headers.get("Tacua-Candidate-Digest");
      const candidateVersion = response.headers.get("Tacua-Candidate-Version");
      if (
        !isDigest(bodyDigest)
        || !isDigest(handoffDigest)
        || candidateDigest !== candidate.candidate_digest
        || candidateVersion !== String(candidate.candidate_version)
        || response.headers.get("ETag") !== quotedEntityTag(bodyDigest)
      ) {
        throw new TacuaApiError(502, "HANDOFF_BINDING_MISMATCH", "The handoff was not bound to this exact approved ticket.");
      }

      const bytes = await readBoundedBytes(response, maximumBytes);
      if (bytes.byteLength !== Number(declaredLength)) {
        throw new TacuaApiError(502, "HANDOFF_LENGTH_MISMATCH", "The handoff length did not match its declaration.");
      }
      const computedBodyDigest = await sha256Digest(bytes);
      throwIfCancelled();
      if (computedBodyDigest !== bodyDigest) {
        throw new TacuaApiError(502, "HANDOFF_BODY_DIGEST_MISMATCH", "The handoff bytes did not match their declared digest.");
      }
      let body: string;
      try {
        body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        throw new TacuaApiError(502, "INVALID_HANDOFF_ENCODING", "The handoff was not valid UTF-8.");
      }
      try {
        await validateApprovedHandoffArtifact({
          format,
          text: body,
          displayedCandidate: candidate,
          expectedHandoffDigest: handoffDigest,
          digest: sha256Digest,
        });
      } catch (error) {
        if (error instanceof ApprovedHandoffValidationError) {
          throw new TacuaApiError(502, error.code, `The approved handoff failed validation (${error.path}).`);
        }
        throw error;
      }
      throwIfCancelled();
      return {
        format,
        bytes,
        bodyDigest,
        handoffDigest,
        candidateDigest,
        candidateVersion: candidate.candidate_version,
      };
    } catch (error) {
      if (error instanceof TacuaApiError) throw error;
      if (controller.signal.aborted && externalSignal?.aborted) {
        throw new TacuaApiError(499, "HANDOFF_REQUEST_CANCELLED", "The approved handoff request was cancelled.");
      }
      if (controller.signal.aborted && timedOut) {
        throw new TacuaApiError(408, "REQUEST_TIMEOUT", "The approved handoff did not respond in time.");
      }
      throw new TacuaApiError(0, "NETWORK_ERROR", "Tacua could not load the approved handoff.");
    } finally {
      clearTimeout(timeout);
      externalSignal?.removeEventListener("abort", abortFromCaller);
    }
  }

  async transitionCandidate(
    parent: TicketCandidate,
    body: CandidateTransitionBody,
  ): Promise<TicketCandidate> {
    const candidateId = parent.candidate_id;
    if (!isIdentifier(candidateId)) throw new TacuaApiError(0, "INVALID_CANDIDATE_ID", "The candidate identifier is invalid.");
    try {
      validateTransitionRequestBinding(parent, body);
    } catch (error) {
      if (error instanceof AdminResponseValidationError) {
        throw new TacuaApiError(0, error.code, "The transition request was not bound to the displayed candidate.");
      }
      throw error;
    }
    const idempotencyKey = `candidate:${candidateId}:${body.expected_candidate_version}:${body.action}:${operationFingerprint(JSON.stringify(body))}`;
    const result = await this.requestDocument<unknown>(`/v1/admin/candidates/${encodeURIComponent(candidateId)}/transitions`, {
      method: "POST",
      headers: {
        "If-Match": quotedEntityTag(body.expected_candidate_digest),
        "Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify(body),
    }, { maximumBytes: maximumCandidateBytes, expectedStatuses: [200, 201] });
    try {
      const candidate = await validateTicketCandidateSnapshot(result.body, sha256Digest) as TicketCandidate;
      validateTransitionBinding(parent, body, candidate);
      const bodyDigest = await sha256Digest(result.bytes);
      if (
        result.response.headers.get("ETag") !== quotedEntityTag(candidate.candidate_digest)
        || result.response.headers.get("Tacua-Body-Digest") !== bodyDigest
      ) {
        throw new TacuaApiError(502, "TRANSITION_RESPONSE_BINDING_MISMATCH", "The transition response headers did not bind its candidate bytes.");
      }
      return candidate;
    } catch (error) {
      if (error instanceof TacuaApiError) throw error;
      if (error instanceof ApprovedHandoffValidationError || error instanceof AdminResponseValidationError) {
        const code = error.code;
        throw new TacuaApiError(502, code, "The transition response failed its candidate and predecessor binding checks.");
      }
      throw error;
    }
  }

  async replaceCandidates(input: {
    readonly operation: CandidateReplacementOperation;
    readonly actorId: string;
    readonly reason: string;
    readonly sources: readonly TicketCandidate[];
    readonly results: readonly CandidateReplacementDraft[];
  }): Promise<CandidateReplacementResponse> {
    let request;
    try {
      request = createCandidateReplacementRequest(input);
    } catch (error) {
      if (error instanceof CandidateReplacementValidationError) {
        throw new TacuaApiError(0, error.code, "The candidate replacement request was invalid or not bound to one exact capture and build.");
      }
      throw error;
    }
    const requestDigest = await replacementRequestDigest(request, sha256Digest);
    const result = await this.requestDocument<unknown>("/v1/admin/candidate-replacements", {
      method: "POST",
      headers: {
        "Idempotency-Key": `replacement:${request.operation}:${requestDigest.slice("sha256:".length)}`,
      },
      body: serializedReplacementRequest(request),
    }, { maximumBytes: maximumCandidateReplacementBytes, expectedStatuses: [201] });
    try {
      const response = await validateCandidateReplacementResponse(result.body, request, input.sources, sha256Digest);
      const bodyDigest = await sha256Digest(result.bytes);
      if (result.response.headers.get("Tacua-Body-Digest") !== bodyDigest) {
        throw new TacuaApiError(502, "REPLACEMENT_RESPONSE_DIGEST_MISMATCH", "The replacement response bytes did not match their declared digest.");
      }
      return response;
    } catch (error) {
      if (error instanceof TacuaApiError) throw error;
      if (error instanceof CandidateReplacementValidationError) {
        throw new TacuaApiError(502, error.code, "The replacement response failed its exact source, result, lineage, or evidence binding checks.");
      }
      throw error;
    }
  }
}
