// SPDX-License-Identifier: Apache-2.0

export type RetentionSummary = {
  readonly policy_version: string;
  readonly raw_media_expires_at: string;
  readonly derived_data_expires_at: string;
  readonly deletion_status: "active" | "deleting" | "deleted";
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
  readonly envelope_digest: string;
  readonly received_at: string;
};

export type ProcessingJob = {
  readonly job_id: string;
  readonly job_type: "process_session";
  readonly status: "queued" | "running" | "succeeded" | "failed";
  readonly requested_at: string;
  readonly started_at: string | null;
  readonly completed_at: string | null;
  readonly failure_code: string | null;
};

export type JobPage = {
  readonly jobs: readonly ProcessingJob[];
  readonly next_cursor: string | null;
};

export type AuditEvent = {
  readonly event_id: string;
  readonly event_type: string;
  readonly actor_kind: string;
  readonly organization_id: string;
  readonly project_id: string;
  readonly session_id: string | null;
  readonly outcome: string;
  readonly occurred_at: string;
};

export type AuditEventPage = {
  readonly events: readonly AuditEvent[];
  readonly next_cursor: string | null;
};

export type CaptureSession = {
  readonly session_id: string;
  readonly organization_id: string;
  readonly project_id: string;
  readonly application_id: string;
  readonly build_id: string;
  readonly consent_contract: string;
  readonly state: string;
  readonly scope_digest: string;
  readonly build_identity_digest: string;
  readonly created_at: string;
  readonly completed_at: string | null;
  readonly completion_id: string | null;
  readonly retention: RetentionSummary;
  readonly manifest_digest: string | null;
  readonly segments?: readonly UploadReceipt[];
  readonly diagnostics?: readonly DiagnosticSummary[];
  readonly jobs?: readonly ProcessingJob[];
};

export type SessionPage = {
  readonly sessions: readonly CaptureSession[];
  readonly next_cursor: string | null;
};

export type TicketCandidateSummary = {
  readonly candidate_id: string;
  readonly candidate_version: number;
  readonly candidate_digest: string;
  readonly state: CandidateState;
  readonly priority: "P0" | "P1" | "P2" | "P3";
  readonly title: string;
  readonly summary: string;
  readonly version_created_at: string;
};

export type CandidatePage = {
  readonly candidates: readonly TicketCandidateSummary[];
  readonly next_cursor: string | null;
};

export type CandidateReplacementOperation = "split" | "merge";

export type CandidateExactBinding = {
  readonly candidate_id: string;
  readonly candidate_version: number;
  readonly candidate_digest: string;
  readonly candidate_content_digest: string;
  readonly evidence_manifest_digest: string;
};

export type CandidateReplacementDraft = {
  readonly candidate_id: string;
  readonly content: TicketCandidate["content"];
};

export type CandidateReplacementRequest = {
  readonly operation: CandidateReplacementOperation;
  readonly actor_id: string;
  readonly reason: string;
  readonly sources: readonly CandidateExactBinding[];
  readonly results: readonly CandidateReplacementDraft[];
};

export type CandidateReplacementOperationProjection = {
  readonly operation_id: string;
  readonly operation: CandidateReplacementOperation;
  readonly actor_id: string;
  readonly occurred_at: string;
  readonly sources: readonly CandidateExactBinding[];
  readonly results: readonly CandidateExactBinding[];
};

export type CandidateReplacementResponse = {
  readonly operation: CandidateReplacementOperationProjection;
  readonly candidates: readonly TicketCandidate[];
};

export type CandidateSupersededDetails = {
  readonly operation_id: string;
  readonly operation: CandidateReplacementOperation;
  readonly replacements: readonly CandidateExactBinding[];
};

export type RegisteredBuild = {
  readonly build_id: string;
  readonly application_id: string;
  readonly bundle_identifier: string;
  readonly native_version: string;
  readonly native_build: string;
  readonly distribution: "local" | "internal" | "testflight";
  readonly build_identity_digest: string;
};

type LaunchGrantBase = {
  readonly launch_id: string;
  readonly launch_code: string;
  readonly build_identity_digest: string;
  readonly expires_at: string;
};

export type StartLaunchGrant = LaunchGrantBase & {
  readonly exchange_kind: "start_session";
  readonly session_id: null;
  readonly scope_policy_digest: string;
};

export type ResumeLaunchGrant = LaunchGrantBase & {
  readonly exchange_kind: "resume_session";
  readonly session_id: string;
  readonly scope_digest: string;
};

export type LaunchGrant = StartLaunchGrant | ResumeLaunchGrant;

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
    readonly approval_id: string;
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

export type EvidenceTimeRange = {
  readonly start_ms: number;
  readonly end_ms: number;
  readonly clock: "session_monotonic";
};

export type CandidateEvidenceItem = {
  readonly evidence_id: string;
  readonly evidence_type:
    | "sdk.route_transition"
    | "sdk.user_interaction"
    | "sdk.runtime_error"
    | "sdk.network_metadata"
    | "sdk.trace_correlation"
    | "sdk.app_state_provider"
    | "sdk.capture_gap"
    | "media.keyframe"
    | "media.clip"
    | "media.transcript_excerpt"
    | "repository.commit_snapshot"
    | "backend.deployment_snapshot"
    | "backend.log_snapshot"
    | "backend.trace_snapshot"
    | "observability.sentry_snapshot"
    | "observability.posthog_snapshot";
  readonly availability: "available" | "unavailable";
  readonly description: string;
  readonly time_range: EvidenceTimeRange | null;
  readonly source: {
    readonly component: "mobile_sdk" | "backend" | "repository" | "sentry" | "posthog";
    readonly source_id: string;
    readonly snapshot_revision: string;
    readonly captured_at: string;
  };
  readonly reference: null | {
    readonly content_type: string;
    readonly size_bytes: number;
    readonly content_digest: string;
  };
  readonly unavailable: null | {
    readonly reason: string;
    readonly detail: string;
  };
  readonly preview: {
    readonly status: "available" | "unavailable" | "not_applicable";
    readonly content_type: "image/png" | "image/jpeg" | "image/webp" | null;
    readonly size_bytes: number | null;
    readonly content_digest: string | null;
  };
};

type DiagnosticEventBase = {
  readonly event_id: string;
  readonly sequence: number;
  readonly elapsed_ms: number;
  readonly occurred_at: string;
  readonly source: "mobile_sdk" | "capture_extension";
  readonly evidence_refs: readonly string[];
};

export type CandidateDiagnosticEvent = DiagnosticEventBase & (
  | {
    readonly event_type: "route_transition";
    readonly data: { readonly from_route: string | null; readonly to_route: string; readonly trigger: "user" | "system" | "deep_link" | "unknown" };
  }
  | {
    readonly event_type: "user_interaction";
    readonly data: { readonly action: "tap" | "long_press" | "text_input" | "swipe" | "submit" | "other"; readonly target: string; readonly value_capture: "not_collected" };
  }
  | {
    readonly event_type: "runtime_error";
    readonly data: { readonly error_class: string; readonly sanitized_message: string; readonly stack_trace_digest: string | null; readonly handled: boolean };
  }
  | {
    readonly event_type: "network_request_completed";
    readonly data: {
      readonly request_id: string;
      readonly method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
      readonly host: string;
      readonly path_template: string;
      readonly status_code: number | null;
      readonly duration_ms: number | null;
      readonly trace_id: string | null;
      readonly outcome: "success" | "error" | "cancelled" | "unknown";
      readonly request_body_capture: "not_collected";
      readonly response_body_capture: "not_collected";
    };
  }
  | {
    readonly event_type: "app_state_changed";
    readonly data: { readonly from_state: "active" | "inactive" | "background" | "unknown"; readonly to_state: "active" | "inactive" | "background" | "unknown" };
  }
  | {
    readonly event_type: "issue_mark";
    readonly data: { readonly marker_id: string; readonly kind: "spoken" | "manual"; readonly narration_elapsed_ms: number };
  }
  | {
    readonly event_type: "capture_gap";
    readonly data: { readonly gap_id: string; readonly affected_streams: readonly ("app_video" | "app_audio" | "microphone" | "diagnostics")[] };
  }
  | {
    readonly event_type: "custom_state";
    readonly data: { readonly provider_id: string; readonly snapshot_digest: string | null; readonly collection_status: "available" | "unavailable" };
  }
);

/**
 * Authenticated reviewer projection. This is deliberately not an approved
 * handoff evidence manifest: viewing evidence during review does not grant an
 * implementation agent permission to read or export it.
 */
export type CandidateEvidenceView = {
  readonly contract_version: "tacua.candidate-evidence-view@1.0.0";
  readonly candidate_id: string;
  readonly candidate_version: number;
  readonly candidate_digest: string;
  readonly evidence_manifest_digest: string;
  readonly items: readonly CandidateEvidenceItem[];
  readonly diagnostic_events: readonly CandidateDiagnosticEvent[];
};

export type EvidencePreview = {
  readonly uri: string;
  readonly contentType: "image/png" | "image/jpeg" | "image/webp";
  readonly sizeBytes: number;
  readonly contentDigest: string;
  /** Releases the native object backing `uri`. Safe to call more than once. */
  readonly release: () => void;
};

export type ApprovedHandoffArtifact = {
  readonly format: "json" | "markdown";
  readonly bytes: Uint8Array;
  readonly bodyDigest: string;
  readonly handoffDigest: string;
  readonly candidateDigest: string;
  readonly candidateVersion: number;
};
