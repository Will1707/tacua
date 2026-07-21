// SPDX-License-Identifier: Apache-2.0

import type { BackendConfig } from "@/config/backend-config";
import type {
  CandidateEvidenceView,
  CaptureSession,
  EvidencePreview,
  ProcessingJob,
  TicketCandidate,
} from "@/api/types";
import { fetch, type FetchRequestInit } from "expo/fetch";

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

async function readBoundedBytes(response: Response, maximum: number): Promise<Uint8Array> {
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maximum) {
      throw new TacuaApiError(502, "RESPONSE_TOO_LARGE", "The evidence preview exceeded the reviewer limit.");
    }
    return bytes;
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
        throw new TacuaApiError(502, "RESPONSE_TOO_LARGE", "The evidence preview exceeded the reviewer limit.");
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

  async listSessions(): Promise<readonly CaptureSession[]> {
    const response = await this.request<{ readonly sessions: readonly CaptureSession[] }>("/v1/admin/sessions");
    return response.sessions;
  }

  getSession(sessionId: string): Promise<CaptureSession> {
    return this.request(`/v1/admin/sessions/${encodeURIComponent(sessionId)}`);
  }

  async listJobs(): Promise<readonly ProcessingJob[]> {
    const response = await this.request<{ readonly jobs: readonly ProcessingJob[] }>("/v1/admin/jobs");
    return response.jobs;
  }

  async listCandidates(sessionId: string): Promise<readonly TicketCandidate[]> {
    const response = await this.request<{ readonly candidates: readonly TicketCandidate[] }>(
      `/v1/admin/sessions/${encodeURIComponent(sessionId)}/candidates`,
    );
    return response.candidates;
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
