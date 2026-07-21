// SPDX-License-Identifier: Apache-2.0

import type { BackendConfig } from "@/config/backend-config";
import type { CaptureSession, ProcessingJob, TicketCandidate } from "@/api/types";
import { fetch, type FetchRequestInit } from "expo/fetch";

const maximumResponseCharacters = 2_000_000;

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
        "If-Match": `"${body.expected_candidate_digest}"`,
        "Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify(body),
    });
  }
}
