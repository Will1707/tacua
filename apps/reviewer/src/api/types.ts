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
  readonly description: string;
  readonly consequence: string;
  readonly evidence_refs: readonly string[];
  readonly requires_note: boolean;
  readonly presentation: {
    readonly kind: "text" | "evidence_thumbnail" | "color_swatch" | "sf_symbol";
    readonly value: string | null;
    readonly evidence_ref: string | null;
  };
};

export type Clarification = {
  readonly clarification_id: string;
  readonly question: string;
  readonly impact: "blocking" | "non_blocking";
  readonly status: "unresolved" | "resolved";
  readonly target: string;
  readonly choices: readonly ClarificationChoice[];
  readonly selected_choice_id: string | null;
  readonly resolution_note: string | null;
};

export type EvidenceBoundText = {
  readonly text: string;
  readonly claim_refs: readonly string[];
  readonly evidence_refs: readonly string[];
};

export type CandidateActor = {
  readonly actor_type: "human" | "system" | "model";
  readonly actor_id: string;
};

export type CandidateState = "draft" | "needs_clarification" | "ready_for_review" | "rejected" | "approved";

export type TicketCandidate = {
  readonly contract_version: "tacua.ticket-candidate@1.0.0";
  readonly media_type: "application/vnd.tacua.ticket-candidate+json;version=1.0.0";
  readonly organization_id: string;
  readonly project_id: string;
  readonly build_id: string;
  readonly build_identity_digest: string;
  readonly candidate_id: string;
  readonly candidate_version: number;
  readonly candidate_content_digest: string;
  readonly candidate_digest: string;
  readonly previous_candidate_digest: string | null;
  readonly session_id: string;
  readonly state: CandidateState;
  readonly candidate_created_at: string;
  readonly version_created_at: string;
  readonly evidence_manifest: {
    readonly manifest_id: string;
    readonly manifest_digest: string;
    readonly evidence_ids: readonly string[];
  };
  readonly lineage: {
    readonly operation: "generated" | "split" | "merged" | "edited" | "clarification_answered" | "reviewed" | "approved" | "rejected" | "reopened";
    readonly parents: readonly {
      readonly candidate_id: string;
      readonly candidate_version: number;
      readonly candidate_digest: string;
    }[];
  };
  readonly transition: {
    readonly from_state: CandidateState | null;
    readonly to_state: CandidateState;
    readonly actor: CandidateActor;
    readonly occurred_at: string;
    readonly reason: string;
  };
  readonly content: {
    readonly title: string;
    readonly priority: "P0" | "P1" | "P2" | "P3";
    readonly summary: EvidenceBoundText;
    readonly actual_behavior: EvidenceBoundText;
    readonly expected_behavior: EvidenceBoundText;
    readonly claims: readonly {
      readonly claim_id: string;
      readonly kind: "observed" | "expected" | "diagnosis" | "hypothesis" | "constraint";
      readonly support: "direct" | "inferred" | "unknown";
      readonly confidence: "high" | "medium" | "low" | "unknown";
      readonly statement: string;
      readonly evidence_refs: readonly string[];
    }[];
    readonly reproduction: {
      readonly preconditions: readonly {
        readonly precondition_id: string;
        readonly text: string;
        readonly claim_refs: readonly string[];
        readonly evidence_refs: readonly string[];
      }[];
      readonly steps: readonly {
        readonly step_id: string;
        readonly action: string;
        readonly expected_result: string | null;
        readonly actual_result: string | null;
        readonly confidence: "high" | "medium" | "low" | "unknown";
        readonly claim_refs: readonly string[];
        readonly evidence_refs: readonly string[];
      }[];
      readonly attempts: number;
      readonly reproductions: number;
    };
    readonly acceptance_criteria: readonly {
      readonly criterion_id: string;
      readonly criterion: string;
      readonly verification: string;
      readonly claim_refs: readonly string[];
      readonly evidence_refs: readonly string[];
    }[];
    readonly scope: {
      readonly in_scope: readonly string[];
      readonly out_of_scope: readonly string[];
    };
    readonly uncertainty: {
      readonly overall_confidence: "high" | "medium" | "low" | "unknown";
      readonly items: readonly {
        readonly uncertainty_id: string;
        readonly statement: string;
        readonly impact: "blocking" | "non_blocking";
        readonly evidence_refs: readonly string[];
      }[];
    };
    readonly clarifications: readonly Clarification[];
  };
  readonly review: {
    readonly status: "unreviewed" | "in_review" | "reviewed";
    readonly reviewer_action_required: boolean;
    readonly last_human_actor_id: string | null;
    readonly last_reviewed_at: string | null;
    readonly notes: readonly string[];
  };
  readonly approval: null | {
    readonly actor_type: "human";
    readonly actor_id: string;
    readonly approved_at: string;
    readonly reviewed_candidate_version: number;
    readonly reviewed_candidate_digest: string;
    readonly approved_candidate_version: number;
    readonly candidate_content_digest: string;
    readonly evidence_manifest_digest: string;
    readonly authorized_evidence_ids: readonly string[];
    readonly immutable: true;
  };
  readonly rejection: null | {
    readonly actor_type: "human";
    readonly actor_id: string;
    readonly rejected_at: string;
    readonly reviewed_candidate_version: number;
    readonly reviewed_candidate_digest: string;
    readonly rejected_candidate_version: number;
    readonly candidate_content_digest: string;
    readonly reason: string;
    readonly immutable: true;
  };
};
