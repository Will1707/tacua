// SPDX-License-Identifier: Apache-2.0

import type { BackendConfig } from "@/config/backend-config";
import type { CaptureSession, ProcessingJob, TicketCandidate } from "@/api/types";

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

export class TacuaApiClient {
  constructor(private readonly config: BackendConfig) {}

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      const response = await fetch(`${this.config.baseUrl}${path}`, {
        ...init,
        cache: "no-store",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${this.config.adminToken}`,
          ...(init?.body ? { "Content-Type": "application/json" } : {}),
          ...init?.headers,
        },
        signal: controller.signal,
      });
      const body = (await response.json().catch(() => null)) as T | ErrorResponse | null;
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
      if (body === null) throw new TacuaApiError(502, "INVALID_RESPONSE", "The Tacua backend returned invalid JSON.");
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
    const idempotencyKey = [
      "candidate",
      candidateId,
      String(body.candidate_version),
      body.action,
      body.clarification_id ?? "none",
      body.selected_choice_id ?? "none",
    ].join(":");
    return this.request(`/v1/admin/candidates/${encodeURIComponent(candidateId)}/transitions`, {
      method: "POST",
      headers: {
        "If-Match": body.expected_candidate_digest,
        "Idempotency-Key": idempotencyKey,
      },
      body: JSON.stringify(body),
    });
  }
}
