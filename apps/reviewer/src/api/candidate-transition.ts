// SPDX-License-Identifier: Apache-2.0

import type { CandidateTransitionBody } from "./admin-response-validators.ts";
import type { TicketCandidate } from "./types.ts";
import { canonicalJson } from "../approved-handoff/contract.ts";

type CandidateTransitionRequestCommon = {
  readonly expected_candidate_digest: string;
  readonly candidate_version: number;
  readonly candidate_content_digest: string;
  readonly evidence_manifest_digest: string;
  readonly actor_id: string;
  readonly reason: string;
};

export type CandidateTransitionRequest = CandidateTransitionRequestCommon & (
  | {
    readonly action: "edit_content";
    readonly content: TicketCandidate["content"];
  }
  | { readonly action: "mark_ready" }
  | { readonly action: "approve" }
  | { readonly action: "reject" }
  | {
    readonly action: "resolve_clarification";
    readonly clarification_id: string;
    readonly selected_choice_id: string;
    readonly resolution_note: string | null;
  }
);

/**
 * Project the reviewer's exact predecessor binding into CandidateStore's
 * public transition contract. The route owns the candidate ID, and the
 * backend owns approval IDs, so neither belongs in the public request body.
 */
export function createCandidateTransitionRequest(
  body: CandidateTransitionBody,
): CandidateTransitionRequest {
  const common: CandidateTransitionRequestCommon = {
    expected_candidate_digest: body.expected_candidate_digest,
    candidate_version: body.expected_candidate_version,
    candidate_content_digest: body.expected_candidate_content_digest,
    evidence_manifest_digest: body.expected_evidence_manifest_digest,
    actor_id: body.actor_id,
    reason: body.reason,
  };
  switch (body.action) {
    case "edit_content":
      return { ...common, action: body.action, content: body.content };
    case "mark_ready":
    case "approve":
    case "reject":
      return { ...common, action: body.action };
    case "resolve_clarification":
      return {
        ...common,
        action: body.action,
        clarification_id: body.clarification_id,
        selected_choice_id: body.choice_id,
        resolution_note: body.resolution_note,
      };
  }
}

export function serializedCandidateTransitionRequest(
  body: CandidateTransitionBody,
): string {
  // CandidateStore seals the canonical request data for idempotent replay.
  return canonicalJson(createCandidateTransitionRequest(body));
}
