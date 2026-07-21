// SPDX-License-Identifier: Apache-2.0

import type { BackendConfig } from "@/config/backend-config";
import type {
  ApprovedHandoffArtifact,
  CandidatePage,
  CandidateEvidenceView,
  CaptureSession,
  EvidencePreview,
  LaunchGrant,
  ProcessingJob,
  RegisteredBuild,
  SessionPage,
  TicketCandidate,
} from "@/api/types";
import * as Crypto from "expo-crypto";
import { fetch, type FetchRequestInit } from "expo/fetch";

import {
  ApprovedHandoffValidationError,
  approvedHandoffMediaType,
  maximumJsonHandoffBytes,
  maximumMarkdownHandoffBytes,
  validateApprovedHandoffArtifact,
} from "@/approved-handoff/contract";

const maximumResponseCharacters = 2_000_000;
const maximumEvidencePreviewBytes = 2 * 1_024 * 1_024;
const evidencePreviewContentTypes = new Set(["image/png", "image/jpeg", "image/webp"] as const);

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

type ErrorResponse = { readonly error?: { readonly code?: unknown; readonly message?: unknown } };

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

function validatePageCursor(value: unknown): value is string | null {
  return value === null || (
    typeof value === "string"
    && value.length >= 1
    && value.length <= 512
    && value.length % 4 !== 1
    && /^[A-Za-z0-9_-]+$/.test(value)
  );
}

function pageHeaders(cursor?: string): HeadersInit | undefined {
  if (cursor === undefined) return undefined;
  if (!validatePageCursor(cursor) || cursor === null) {
    throw new TacuaApiError(0, "INVALID_PAGE_CURSOR", "The Tacua page cursor is invalid.");
  }
  return { "Tacua-Page-Cursor": cursor };
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
  const retentionIsOrdered = createdAt <= rawExpiresAt && rawExpiresAt <= derivedExpiresAt;
  return retentionIsOrdered && ((value.state === "receiving" && completionIsAbsent)
    || (
      value.state === "completed"
      && completionIsPresent
      && createdAt <= Date.parse(value.completed_at as string)
      && Date.parse(value.completed_at as string) <= rawExpiresAt
    ));
}

function bytesToBase64(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const chunks: string[] = [];
  let chunk = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1] ?? 0;
    const third = bytes[index + 2] ?? 0;
    const packed = (first << 16) | (second << 8) | third;
    chunk += alphabet[(packed >>> 18) & 63];
    chunk += alphabet[(packed >>> 12) & 63];
    chunk += index + 1 < bytes.length ? alphabet[(packed >>> 6) & 63] : "=";
    chunk += index + 2 < bytes.length ? alphabet[packed & 63] : "=";
    if (chunk.length >= 16_384) {
      chunks.push(chunk);
      chunk = "";
    }
  }
  if (chunk) chunks.push(chunk);
  return chunks.join("");
}

async function sha256Digest(bytes: Uint8Array): Promise<string> {
  const digestInput = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  digestInput.set(bytes);
  const digest = new Uint8Array(await Crypto.digest(Crypto.CryptoDigestAlgorithm.SHA256, digestInput));
  return `sha256:${Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("")}`;
}

async function readBoundedBytes(response: Response, maximum: number): Promise<Uint8Array> {
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
        await reader.cancel();
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

export class TacuaApiClient {
  constructor(private readonly config: BackendConfig) {}

  private async request<T>(path: string, init?: FetchRequestInit): Promise<T> {
    if (!path.startsWith("/") || path.startsWith("//")) {
      throw new TacuaApiError(0, "INVALID_REQUEST_PATH", "The Tacua request path is invalid.");
    }
    const endpoint = new URL(path, `${this.config.baseUrl}/`);
    if (endpoint.origin !== this.config.baseUrl) {
      throw new TacuaApiError(0, "INVALID_REQUEST_ORIGIN", "The Tacua request escaped the configured backend.");
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
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

      const declaredLength = response.headers.get("Content-Length");
      if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumResponseCharacters * 4)) {
        throw new TacuaApiError(502, "RESPONSE_TOO_LARGE", "The Tacua backend response exceeded the reviewer limit.");
      }
      const contentType = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
      const rawBody = await response.text();
      if (rawBody.length > maximumResponseCharacters) {
        throw new TacuaApiError(502, "RESPONSE_TOO_LARGE", "The Tacua backend response exceeded the reviewer limit.");
      }
      let body: T | ErrorResponse | null = null;
      if (contentType === "application/json") {
        try {
          body = JSON.parse(rawBody) as T | ErrorResponse;
        } catch {
          body = null;
        }
      }
      if (!response.ok) {
        const error = body && typeof body === "object" && "error" in body
          ? (body as ErrorResponse).error
          : undefined;
        throw new TacuaApiError(
          response.status,
          typeof error?.code === "string" ? error.code : "HTTP_ERROR",
          typeof error?.message === "string" ? error.message : "The Tacua backend request failed.",
        );
      }
      if (body === null) {
        throw new TacuaApiError(502, "INVALID_RESPONSE", "The Tacua backend returned invalid JSON.");
      }
      return body as T;
    } catch (error) {
      if (error instanceof TacuaApiError) throw error;
      if (error instanceof Error && error.name === "AbortError") {
        throw new TacuaApiError(408, "REQUEST_TIMEOUT", "The Tacua backend did not respond in time.");
      }
      throw new TacuaApiError(0, "NETWORK_ERROR", "Tacua could not reach the configured backend.");
    } finally {
      clearTimeout(timeout);
    }
  }

  async listSessions(cursor?: string): Promise<SessionPage> {
    const response = await this.request<SessionPage>("/v1/admin/sessions", { headers: pageHeaders(cursor) });
    if (
      !isRecord(response)
      || !hasExactKeys(response, ["sessions", "next_cursor"])
      || !Array.isArray(response.sessions)
      || response.sessions.length > 50
      || response.sessions.some((session) => !isSessionSummary(session))
      || new Set(response.sessions.map((session) => session.session_id)).size !== response.sessions.length
      || (response.next_cursor !== null && response.sessions.length !== 50)
      || !validatePageCursor(response.next_cursor)
    ) {
      throw new TacuaApiError(502, "INVALID_SESSION_PAGE", "The backend returned an invalid session page.");
    }
    return response;
  }

  async listBuilds(): Promise<readonly RegisteredBuild[]> {
    const response = await this.request<{ readonly builds: readonly RegisteredBuild[] }>("/v1/admin/builds");
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
        || build.native_version.length > 64
        || typeof build.native_build !== "string"
        || build.native_build.length < 1
        || build.native_build.length > 64
        || !["local", "internal", "testflight"].includes(build.distribution)
        || !isDigest(build.build_identity_digest)
      ))
    ) {
      throw new TacuaApiError(502, "INVALID_BUILD_REGISTRY", "The backend returned an invalid build registry.");
    }
    return response.builds;
  }

  async createLaunchGrant(buildId: string): Promise<LaunchGrant> {
    if (!isIdentifier(buildId)) {
      throw new TacuaApiError(0, "INVALID_BUILD_ID", "The selected build identifier is invalid.");
    }
    const grant = await this.request<LaunchGrant>("/v1/admin/launch-codes", {
      method: "POST",
      body: JSON.stringify({ exchange_kind: "start_session", build_id: buildId }),
    });
    if (
      !grant
      || typeof grant !== "object"
      || !hasExactKeys(grant, [
        "launch_id",
        "launch_code",
        "exchange_kind",
        "session_id",
        "build_identity_digest",
        "scope_policy_digest",
        "expires_at",
      ])
      || !isIdentifier(grant.launch_id)
      || typeof grant.launch_code !== "string"
      || !/^[A-Za-z0-9_-]{32,512}$/.test(grant.launch_code)
      || grant.exchange_kind !== "start_session"
      || grant.session_id !== null
      || !isDigest(grant.build_identity_digest)
      || !isDigest(grant.scope_policy_digest)
      || !isTimestamp(grant.expires_at)
    ) {
      throw new TacuaApiError(502, "INVALID_LAUNCH_GRANT", "The backend returned an invalid launch grant.");
    }
    return grant;
  }

  getSession(sessionId: string): Promise<CaptureSession> {
    return this.request(`/v1/admin/sessions/${encodeURIComponent(sessionId)}`);
  }

  async listJobs(): Promise<readonly ProcessingJob[]> {
    const response = await this.request<{ readonly jobs: readonly ProcessingJob[] }>("/v1/admin/jobs");
    return response.jobs;
  }

  async listCandidates(sessionId: string, cursor?: string): Promise<CandidatePage> {
    if (!isIdentifier(sessionId)) throw new TacuaApiError(0, "INVALID_SESSION_ID", "The session identifier is invalid.");
    const response = await this.request<CandidatePage>(
      `/v1/admin/sessions/${encodeURIComponent(sessionId)}/candidates`,
      { headers: pageHeaders(cursor) },
    );
    if (
      !isRecord(response)
      || !hasExactKeys(response, ["candidates", "next_cursor"])
      || !Array.isArray(response.candidates)
      || response.candidates.length > 50
      || !validatePageCursor(response.next_cursor)
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

  getCandidate(candidateId: string): Promise<TicketCandidate> {
    return this.request(`/v1/admin/candidates/${encodeURIComponent(candidateId)}`);
  }

  async getCandidateEvidence(candidate: TicketCandidate): Promise<CandidateEvidenceView> {
    const view = await this.request<CandidateEvidenceView>(
      `/v1/admin/candidates/${encodeURIComponent(candidate.candidate_id)}/versions/${candidate.candidate_version}/evidence`,
      {
        headers: {
          "If-Match": quotedEntityTag(candidate.candidate_digest),
          "Tacua-Evidence-Manifest-Digest": candidate.evidence_manifest.manifest_digest,
        },
      },
    );
    if (
      !view
      || typeof view !== "object"
      || view.contract_version !== "tacua.candidate-evidence-view@1.0.0"
      || view.candidate_id !== candidate.candidate_id
      || view.candidate_version !== candidate.candidate_version
      || view.candidate_digest !== candidate.candidate_digest
      || view.evidence_manifest_digest !== candidate.evidence_manifest.manifest_digest
      || !Array.isArray(view.items)
      || !Array.isArray(view.diagnostic_events)
      || view.items.length > 100
      || view.diagnostic_events.length > 512
    ) {
      throw new TacuaApiError(502, "EVIDENCE_BINDING_MISMATCH", "The evidence response was not bound to this ticket version.");
    }
    const expectedIds = [...candidate.evidence_manifest.evidence_ids].sort();
    const returnedIds = view.items.map((item) => item.evidence_id).sort();
    if (
      returnedIds.length !== expectedIds.length
      || new Set(returnedIds).size !== returnedIds.length
      || returnedIds.some((evidenceId, index) => evidenceId !== expectedIds[index])
      || view.diagnostic_events.some((event) => (
        !Array.isArray(event.evidence_refs)
        || event.evidence_refs.some((evidenceId: unknown) => (
          typeof evidenceId !== "string" || !expectedIds.includes(evidenceId)
        ))
      ))
      || view.items.some((item) => {
        const preview = item.preview;
        if (!preview || preview.status !== "available") return false;
        return item.evidence_type !== "media.keyframe"
          || item.availability !== "available"
          || preview.content_type === null
          || !evidencePreviewContentTypes.has(preview.content_type)
          || preview.size_bytes === null
          || !Number.isSafeInteger(preview.size_bytes)
          || preview.size_bytes < 1
          || preview.size_bytes > maximumEvidencePreviewBytes
          || preview.content_digest === null
          || !/^sha256:[a-f0-9]{64}$/.test(preview.content_digest);
      })
    ) {
      throw new TacuaApiError(502, "INVALID_EVIDENCE_VIEW", "The backend returned an invalid ticket evidence view.");
    }
    return view;
  }

  async getEvidencePreview(
    candidate: TicketCandidate,
    evidenceId: string,
    expectedContentDigest: string,
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
    const timeout = setTimeout(() => controller.abort(), 15_000);
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

      const bytes = await readBoundedBytes(response, maximumEvidencePreviewBytes);
      if (bytes.byteLength !== Number(declaredLength)) {
        throw new TacuaApiError(502, "PREVIEW_LENGTH_MISMATCH", "The evidence preview length did not match its declaration.");
      }
      return {
        uri: `data:${contentType};base64,${bytesToBase64(bytes)}`,
        contentType: contentType as EvidencePreview["contentType"],
        sizeBytes: bytes.byteLength,
        contentDigest,
      };
    } catch (error) {
      if (error instanceof TacuaApiError) throw error;
      if (error instanceof Error && error.name === "AbortError") {
        throw new TacuaApiError(408, "REQUEST_TIMEOUT", "The evidence preview did not respond in time.");
      }
      throw new TacuaApiError(0, "NETWORK_ERROR", "Tacua could not load the evidence preview.");
    } finally {
      clearTimeout(timeout);
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

  transitionCandidate(
    candidateId: string,
    body: {
      readonly expected_candidate_digest: string;
      readonly candidate_version: number;
      readonly candidate_content_digest: string;
      readonly evidence_manifest_digest: string;
      readonly action: "mark_ready" | "approve" | "reject" | "resolve_clarification";
      readonly actor_id: string;
      readonly reason: string;
      readonly clarification_id?: string;
      readonly selected_choice_id?: string;
      readonly resolution_note?: string;
    },
  ): Promise<TicketCandidate> {
    const idempotencyKey = `candidate:${candidateId}:${body.candidate_version}:${body.action}:${operationFingerprint(JSON.stringify(body))}`;
    return this.request(`/v1/admin/candidates/${encodeURIComponent(candidateId)}/transitions`, {
      method: "POST",
      headers: {
        "If-Match": quotedEntityTag(body.expected_candidate_digest),
        "Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify(body),
    });
  }
}
