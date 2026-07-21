// SPDX-License-Identifier: Apache-2.0

export type RetentionSummary = {
  readonly policy_version: string;
  readonly raw_media_expires_at: string;
  readonly deletion_status: "active" | "deletion_requested" | "deleted";
};

export type UploadReceipt = {
  readonly segment_id: string;
  readonly object_id: string;
  readonly size_bytes: number;
  readonly content_digest: string;
  readonly received_at: string;
  readonly receipt_digest: string;
};

export type DiagnosticSummary = {
  readonly envelope_id: string;
  readonly size_bytes: number;
  readonly content_digest: string;
  readonly envelope_digest?: string;
  readonly received_at: string;
};

export type ProcessingJob = {
  readonly job_id: string;
  readonly job_type?: string;
  readonly status: "queued" | "running" | "waiting_for_clarification" | "succeeded" | "failed" | "cancelled";
  readonly requested_at: string;
  readonly started_at: string | null;
  readonly completed_at: string | null;
  readonly failure_code?: string | null;
};

export type CaptureSession = {
  readonly session_id: string;
  readonly organization_id: string;
  readonly project_id: string;
  readonly application_id: string;
  readonly build_id: string;
  readonly consent_contract: string;
  readonly state: string;
  readonly created_at: string;
  readonly completed_at: string | null;
  readonly retention: RetentionSummary;
  readonly manifest_digest: string | null;
  readonly segments?: readonly UploadReceipt[];
  readonly diagnostics?: readonly DiagnosticSummary[];
  readonly jobs?: readonly ProcessingJob[];
};

export type ClarificationChoice = {
  readonly choice_id: string;
  readonly label: string;
  readonly consequence: string;
};

export type Clarification = {
  readonly clarification_id: string;
  readonly question: string;
  readonly impact: "blocking" | "non_blocking";
  readonly status: "unresolved" | "resolved";
  readonly choices: readonly ClarificationChoice[];
  readonly selected_choice_id: string | null;
};

export type TicketCandidate = {
  readonly candidate_id: string;
  readonly candidate_version: number;
  readonly candidate_content_digest: string;
  readonly candidate_digest: string;
  readonly session_id: string;
  readonly state: "draft" | "needs_clarification" | "ready_for_review" | "rejected" | "approved";
  readonly updated_at: string;
  readonly source: {
    readonly job_id: string;
    readonly job_digest: string;
    readonly evidence_manifest_digest: string;
  };
  readonly content: {
    readonly title: string;
    readonly priority: "P0" | "P1" | "P2" | "P3";
    readonly summary: string;
    readonly actual_behavior: { readonly text: string; readonly evidence_refs: readonly string[] };
    readonly expected_behavior: { readonly text: string; readonly evidence_refs: readonly string[] };
    readonly reproduction_steps: readonly {
      readonly step_id: string;
      readonly action: string;
      readonly expected_result: string | null;
      readonly actual_result: string | null;
      readonly confidence: "high" | "medium" | "low" | "unknown";
      readonly evidence_refs: readonly string[];
    }[];
    readonly acceptance_criteria: readonly {
      readonly criterion_id: string;
      readonly criterion: string;
      readonly verification: string;
    }[];
    readonly uncertainty: {
      readonly overall_confidence: "high" | "medium" | "low" | "unknown";
      readonly items: readonly { readonly uncertainty_id: string; readonly statement: string; readonly impact: "blocking" | "non_blocking" }[];
    };
    readonly clarifications: readonly Clarification[];
  };
};
