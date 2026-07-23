// SPDX-License-Identifier: Apache-2.0

import { Link, useLocalSearchParams } from "expo-router";
import * as Crypto from "expo-crypto";
import { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, Pressable, RefreshControl, ScrollView, Text, TextInput, View } from "react-native";

import { CandidateSupersededApiError, TacuaApiError } from "@/api/client";
import type {
  CandidateEvidenceView,
  CandidateReplacementDraft,
  CandidateReplacementOperationProjection,
  Clarification,
  ClarificationChoice,
  TicketCandidate,
} from "@/api/types";
import {
  exportApprovedHandoff,
  prepareApprovedHandoffExport,
} from "@/approved-handoff/handoff-export";
import type { KeyframePreviewState, KeyframePreviewStates } from "@/candidates/keyframe-gallery-state";
import { ActionButton } from "@/components/action-button";
import { CandidateEvidencePanel } from "@/components/candidate-evidence-panel";
import { CandidateEditCard } from "@/components/candidate-edit-card";
import { CandidateSplitCard } from "@/components/candidate-split-card";
import { MessageState } from "@/components/message-state";
import { SectionCard } from "@/components/section-card";
import { StatusPill } from "@/components/status-pill";
import { useBackend } from "@/hooks/use-backend";
import { useCandidateKeyframePreviews } from "@/hooks/use-candidate-keyframe-previews";
import { useAppDialog } from "@/providers/app-dialog";
import { colors } from "@/theme/colors";

const handoffShareTypes = {
  markdown: {
    extension: "md",
    mimeType: "text/markdown",
    UTI: "net.daringfireball.markdown",
  },
  json: {
    extension: "json",
    mimeType: "application/vnd.tacua.approved-handoff+json;version=1.1.0",
    UTI: "public.json",
  },
} as const;

export default function CandidateRoute() {
  const { "candidate-id": candidateId } = useLocalSearchParams<{ "candidate-id": string }>();
  const { client, config } = useBackend();
  const showDialog = useAppDialog();
  const [candidate, setCandidate] = useState<TicketCandidate | null>(null);
  const [supersession, setSupersession] = useState<CandidateReplacementOperationProjection | null>(null);
  const [supersessionChecked, setSupersessionChecked] = useState(false);
  const [evidence, setEvidence] = useState<CandidateEvidenceView | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [candidateStale, setCandidateStale] = useState(true);
  const [action, setAction] = useState<string | null>(null);
  const [handoffAction, setHandoffAction] = useState<"json" | "markdown" | null>(null);
  const [handoffVerification, setHandoffVerification] = useState<{
    readonly format: "json" | "markdown";
    readonly handoffDigest: string;
    readonly bodyDigest: string;
  } | null>(null);
  const [handoffError, setHandoffError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [clarificationDraft, setClarificationDraft] = useState<{
    readonly clarificationId: string;
    readonly choiceId: string;
    readonly note: string;
  } | null>(null);
  const mountedRef = useRef(false);
  const loadingRef = useRef(true);
  const actionRef = useRef<string | null>(null);
  const loadRequestSequence = useRef(0);
  const handoffRequestSequence = useRef(0);
  const handoffRequestRef = useRef<{
    readonly requestId: number;
    readonly candidateBinding: string;
    readonly controller: AbortController;
  } | null>(null);
  const candidateBinding = candidate
    ? `${candidateId ?? "missing-route"}:${candidate.candidate_id}:${candidate.candidate_version}:${candidate.candidate_digest}`
    : null;
  const currentContextRef = useRef({ candidate, candidateId, candidateStale, client, supersession, supersessionChecked });
  currentContextRef.current = { candidate, candidateId, candidateStale, client, supersession, supersessionChecked };
  const {
    activeIndex: activeKeyframeIndex,
    activePreviewState,
    inspectionReady: evidenceInspectionReady,
    inspectedCount: inspectedKeyframeCount,
    keyframes,
    moveNext: showNextKeyframe,
    movePrevious: showPreviousKeyframe,
    previewStates,
    retryActivePreview,
    setKeyframeDecoded,
  } = useCandidateKeyframePreviews({ candidate, client, evidence });

  function isCurrentDisplayedCandidate(
    requestClient: typeof client,
    snapshot: TicketCandidate,
    routeId: typeof candidateId,
  ): boolean {
    const current = currentContextRef.current;
    return mountedRef.current
      && !current.candidateStale
      && current.supersessionChecked
      && current.supersession === null
      && current.client === requestClient
      && current.candidateId === routeId
      && current.candidate?.candidate_id === snapshot.candidate_id
      && current.candidate.candidate_version === snapshot.candidate_version
      && current.candidate.candidate_digest === snapshot.candidate_digest;
  }

  const load = useCallback(async (): Promise<{ readonly ok: true } | { readonly ok: false; readonly message: string }> => {
    const requestId = loadRequestSequence.current + 1;
    loadRequestSequence.current = requestId;
    if (!client || !candidateId) {
      const message = "A backend connection and candidate identifier are required.";
      loadingRef.current = false;
      setLoading(false);
      setCandidateStale(true);
      setError(message);
      return { ok: false, message };
    }
    loadingRef.current = true;
    setLoading(true);
    setCandidateStale(true);
    setSupersessionChecked(false);
    setError(null);
    try {
      const loaded = await client.getCandidate(candidateId);
      const loadedSupersession = await client.getCandidateSupersession(loaded);
      if (loadRequestSequence.current !== requestId) {
        return { ok: false, message: "A newer ticket refresh replaced this request." };
      }
      setCandidate(loaded);
      setSupersession(loadedSupersession);
      setSupersessionChecked(true);
      setCandidateStale(false);
      setError(null);
      return { ok: true };
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "Tacua could not load this candidate.";
      if (loadRequestSequence.current === requestId) {
        setCandidateStale(true);
        setSupersessionChecked(false);
        setError(message);
      }
      return { ok: false, message };
    } finally {
      if (loadRequestSequence.current === requestId) {
        loadingRef.current = false;
        setLoading(false);
      }
    }
  }, [candidateId, client]);

  useEffect(() => {
    void load();
    return () => { loadRequestSequence.current += 1; };
  }, [load]);

  useEffect(() => {
    mountedRef.current = true;
    try {
      prepareApprovedHandoffExport();
    } catch {
      // A later share will retry cleanup and fail closed if the bound cannot be enforced.
    }
    return () => {
      mountedRef.current = false;
      loadRequestSequence.current += 1;
      handoffRequestRef.current?.controller.abort();
      handoffRequestRef.current = null;
    };
  }, []);

  useEffect(() => {
    handoffRequestRef.current?.controller.abort();
    handoffRequestRef.current = null;
    setHandoffAction(null);
    setHandoffVerification(null);
    setHandoffError(null);
  }, [candidateBinding, client]);

  useEffect(() => {
    // In-flight transitions belong to the client and route that created them.
    // Releasing the local lock makes the new binding usable while stale
    // completions are ignored by the per-operation checks below.
    actionRef.current = null;
    setAction(null);
  }, [candidateId, client]);

  useEffect(() => {
    let active = true;
    if (!client || !candidate) {
      setEvidence(null);
      setEvidenceLoading(false);
      return () => { active = false; };
    }
    setEvidence(null);
    setEvidenceError(null);
    setEvidenceLoading(true);
    void client.getCandidateEvidence(candidate)
      .then((loaded) => { if (active) setEvidence(loaded); })
      .catch((caught) => {
        if (active) setEvidenceError(caught instanceof Error ? caught.message : "Tacua could not load the bound evidence.");
      })
      .finally(() => { if (active) setEvidenceLoading(false); });
    return () => { active = false; };
  }, [candidate, client]);

  async function handleTransitionError(title: string, caught: unknown, shouldReport: () => boolean) {
    if (caught instanceof TacuaApiError && (caught.status === 409 || caught.status === 412)) {
      const refresh = await load();
      if (!shouldReport()) return;
      if (refresh.ok) {
        showDialog(
          caught instanceof CandidateSupersededApiError ? "Ticket was replaced" : "Ticket refreshed",
          caught instanceof CandidateSupersededApiError
            ? "CANDIDATE_SUPERSEDED: this source left the active queue. Tacua loaded its immutable history and replacement links."
            : "This ticket changed while you were reviewing it. Tacua loaded the current version; please check it before trying again.",
        );
      } else {
        showDialog("Refresh failed", `${refresh.message}\n\nActions remain locked until Tacua successfully refreshes this ticket.`);
      }
      return;
    }
    if (!shouldReport()) return;
    const message = caught instanceof Error ? caught.message : "The backend rejected the transition.";
    setCandidateStale(true);
    setError("Tacua could not confirm the current ticket version. Refresh it before taking another action.");
    showDialog(title, `${message}\n\nActions are locked until this ticket is refreshed.`);
  }

  async function transition(nextAction: "mark_ready" | "approve" | "reject", reason: string) {
    if (
      !client
      || !config
      || !candidate
      || candidateStale
      || loadingRef.current
      || actionRef.current !== null
      || !isCurrentDisplayedCandidate(client, candidate, candidateId)
    ) return;
    const parent = candidate;
    const requestClient = client;
    const requestRouteId = candidateId;
    actionRef.current = nextAction;
    setAction(nextAction);
    const isCurrentContext = () => {
      const current = currentContextRef.current;
      return mountedRef.current
        && actionRef.current === nextAction
        && current.client === requestClient
        && current.candidateId === requestRouteId;
    };
    const isCurrentOperation = () => {
      const current = currentContextRef.current;
      return isCurrentContext()
        && current.candidate?.candidate_id === parent.candidate_id
        && current.candidate.candidate_version === parent.candidate_version
        && current.candidate.candidate_digest === parent.candidate_digest;
    };
    try {
      const binding = {
        expected_candidate_id: parent.candidate_id,
        expected_candidate_version: parent.candidate_version,
        expected_candidate_digest: parent.candidate_digest,
        expected_candidate_content_digest: parent.candidate_content_digest,
        expected_evidence_manifest_digest: parent.evidence_manifest.manifest_digest,
        actor_id: config.reviewerId,
        reason,
      };
      const request = nextAction === "approve"
        ? {
          ...binding,
          action: "approve" as const,
          approval_id: `approval_${Crypto.randomUUID().replaceAll("-", "")}`,
        }
        : nextAction === "mark_ready"
          ? { ...binding, action: "mark_ready" as const }
          : { ...binding, action: "reject" as const };
      const transitioned = await requestClient.transitionCandidate(parent, request);
      if (!isCurrentOperation()) return;
      setCandidate(transitioned);
      setCandidateStale(false);
      setError(null);
    } catch (caught) {
      if (!isCurrentOperation()) return;
      await handleTransitionError("Candidate was not changed", caught, isCurrentContext);
    } finally {
      if (actionRef.current === nextAction) {
        actionRef.current = null;
        setAction(null);
      }
    }
  }

  async function editContent(content: TicketCandidate["content"]): Promise<boolean> {
    const operation = "edit_content";
    if (
      !client
      || !config
      || !candidate
      || candidateStale
      || loadingRef.current
      || actionRef.current !== null
      || !isCurrentDisplayedCandidate(client, candidate, candidateId)
    ) return false;
    const parent = candidate;
    const requestClient = client;
    const requestRouteId = candidateId;
    actionRef.current = operation;
    setAction(operation);
    const isCurrentContext = () => {
      const current = currentContextRef.current;
      return mountedRef.current
        && actionRef.current === operation
        && current.client === requestClient
        && current.candidateId === requestRouteId;
    };
    const isCurrentOperation = () => {
      const current = currentContextRef.current;
      return isCurrentContext()
        && current.candidate?.candidate_id === parent.candidate_id
        && current.candidate.candidate_version === parent.candidate_version
        && current.candidate.candidate_digest === parent.candidate_digest;
    };
    try {
      const transitioned = await requestClient.transitionCandidate(parent, {
        expected_candidate_id: parent.candidate_id,
        expected_candidate_version: parent.candidate_version,
        expected_candidate_digest: parent.candidate_digest,
        expected_candidate_content_digest: parent.candidate_content_digest,
        expected_evidence_manifest_digest: parent.evidence_manifest.manifest_digest,
        action: "edit_content",
        actor_id: config.reviewerId,
        reason: "Reviewer corrected the candidate content.",
        content,
      });
      if (!isCurrentOperation()) return false;
      setCandidate(transitioned);
      setCandidateStale(false);
      setError(null);
      return true;
    } catch (caught) {
      if (!isCurrentOperation()) return false;
      await handleTransitionError("Candidate edits were not saved", caught, isCurrentContext);
      return false;
    } finally {
      if (actionRef.current === operation) {
        actionRef.current = null;
        setAction(null);
      }
    }
  }

  async function splitCandidate(drafts: readonly CandidateReplacementDraft[]): Promise<boolean> {
    const operation = "split";
    if (
      !client
      || !config
      || !candidate
      || candidateStale
      || !supersessionChecked
      || supersession !== null
      || loadingRef.current
      || actionRef.current !== null
      || !isCurrentDisplayedCandidate(client, candidate, candidateId)
    ) return false;
    const parent = candidate;
    const requestClient = client;
    const requestRouteId = candidateId;
    actionRef.current = operation;
    setAction(operation);
    const isCurrentContext = () => {
      const current = currentContextRef.current;
      return mountedRef.current
        && actionRef.current === operation
        && current.client === requestClient
        && current.candidateId === requestRouteId;
    };
    const isCurrentOperation = () => {
      const current = currentContextRef.current;
      return isCurrentContext()
        && current.candidate?.candidate_id === parent.candidate_id
        && current.candidate.candidate_version === parent.candidate_version
        && current.candidate.candidate_digest === parent.candidate_digest;
    };
    try {
      const response = await requestClient.replaceCandidates({
        operation: "split",
        actorId: config.reviewerId,
        reason: "Reviewer split one candidate finding into distinct result drafts.",
        sources: [parent],
        results: drafts,
      });
      if (!isCurrentOperation()) return false;
      setSupersession(response.operation);
      setSupersessionChecked(true);
      setCandidateStale(false);
      setError(null);
      showDialog(
        "Split drafts created",
        `${response.candidates.length} unapproved drafts are now active. This source remains available below as non-actionable history.`,
      );
      return true;
    } catch (caught) {
      if (!isCurrentOperation()) return false;
      await handleTransitionError("Ticket was not split", caught, isCurrentContext);
      return false;
    } finally {
      if (actionRef.current === operation) {
        actionRef.current = null;
        setAction(null);
      }
    }
  }

  async function resolveClarification(clarificationId: string, choiceId: string, resolutionNote?: string) {
    const operation = `clarification:${clarificationId}`;
    if (
      !client
      || !config
      || !candidate
      || candidateStale
      || loadingRef.current
      || actionRef.current !== null
      || !isCurrentDisplayedCandidate(client, candidate, candidateId)
    ) return;
    const parent = candidate;
    const requestClient = client;
    const requestRouteId = candidateId;
    actionRef.current = operation;
    setAction(operation);
    const isCurrentContext = () => {
      const current = currentContextRef.current;
      return mountedRef.current
        && actionRef.current === operation
        && current.client === requestClient
        && current.candidateId === requestRouteId;
    };
    const isCurrentOperation = () => {
      const current = currentContextRef.current;
      return isCurrentContext()
        && current.candidate?.candidate_id === parent.candidate_id
        && current.candidate.candidate_version === parent.candidate_version
        && current.candidate.candidate_digest === parent.candidate_digest;
    };
    try {
      const transitioned = await requestClient.transitionCandidate(parent, {
        expected_candidate_id: parent.candidate_id,
        expected_candidate_version: parent.candidate_version,
        expected_candidate_digest: parent.candidate_digest,
        expected_candidate_content_digest: parent.candidate_content_digest,
        expected_evidence_manifest_digest: parent.evidence_manifest.manifest_digest,
        action: "resolve_clarification",
        actor_id: config.reviewerId,
        reason: "Reviewer selected one bounded clarification choice.",
        clarification_id: clarificationId,
        choice_id: choiceId,
        resolution_note: resolutionNote ?? null,
      });
      if (!isCurrentOperation()) return;
      setCandidate(transitioned);
      setCandidateStale(false);
      setError(null);
      setClarificationDraft(null);
    } catch (caught) {
      if (!isCurrentOperation()) return;
      await handleTransitionError("Clarification was not saved", caught, isCurrentContext);
    } finally {
      if (actionRef.current === operation) {
        actionRef.current = null;
        setAction(null);
      }
    }
  }

  function confirmImmediateChoice(clarification: Clarification, choice: ClarificationChoice) {
    showDialog(
      `Choose “${choice.label}”?`,
      `${choice.description}\n\nConsequence: ${choice.consequence}`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Choose",
          onPress: () => void resolveClarification(clarification.clarification_id, choice.choice_id),
        },
      ],
    );
  }

  async function shareHandoff(format: "json" | "markdown") {
    if (
      !client
      || !candidate
      || candidateStale
      || loadingRef.current
      || handoffRequestRef.current !== null
      || candidate.state !== "approved"
      || candidate.candidate_id !== candidateId
      || !isCurrentDisplayedCandidate(client, candidate, candidateId)
    ) return;
    const candidateSnapshot = candidate;
    const requestBinding = `${candidateId}:${candidate.candidate_id}:${candidate.candidate_version}:${candidate.candidate_digest}`;
    const requestId = handoffRequestSequence.current + 1;
    handoffRequestSequence.current = requestId;
    const controller = new AbortController();
    handoffRequestRef.current = { requestId, candidateBinding: requestBinding, controller };
    const isCurrentRequest = () => (
      mountedRef.current
      && !controller.signal.aborted
      && handoffRequestRef.current?.requestId === requestId
      && handoffRequestRef.current.candidateBinding === requestBinding
      && currentContextRef.current.client === client
      && currentContextRef.current.candidateId === candidateId
      && currentContextRef.current.candidate?.candidate_digest === candidateSnapshot.candidate_digest
    );
    setHandoffAction(format);
    setHandoffError(null);
    try {
      const artifact = await client.getCandidateHandoff(candidateSnapshot, format, controller.signal);
      if (!isCurrentRequest()) return;
      setHandoffVerification({
        format,
        handoffDigest: artifact.handoffDigest,
        bodyDigest: artifact.bodyDigest,
      });
      const shareType = handoffShareTypes[format];
      await exportApprovedHandoff({
        title: candidateSnapshot.content.title,
        candidateId: candidateSnapshot.candidate_id,
        candidateVersion: candidateSnapshot.candidate_version,
        extension: shareType.extension,
        bytes: artifact.bytes,
        mimeType: shareType.mimeType,
        uti: shareType.UTI,
      });
    } catch (caught) {
      if (!isCurrentRequest()) return;
      const message = caught instanceof Error ? caught.message : "Tacua could not export the approved handoff.";
      setHandoffError(message);
      showDialog("Handoff unavailable", message);
    } finally {
      if (handoffRequestRef.current?.requestId === requestId) {
        handoffRequestRef.current = null;
        if (mountedRef.current) setHandoffAction(null);
      }
    }
  }

  if (loading && !candidate) return <View accessible accessibilityLabel="Loading ticket candidate" accessibilityRole="progressbar" style={{ flex: 1, justifyContent: "center" }}><ActivityIndicator /></View>;
  if (!candidate || !client) return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" contentContainerStyle={{ padding: 16, gap: 12 }}>
      <MessageState title="Candidate unavailable" detail={error ?? "The candidate was not found."} />
      {client && candidateId ? <ActionButton label="Retry candidate" loading={loading} onPress={() => void load()} /> : null}
    </ScrollView>
  );
  const unresolved = candidate.content.clarifications.filter((item) => item.status === "unresolved");
  const resolved = candidate.content.clarifications.filter((item) => item.status === "resolved");
  const actionsDisabled = candidateStale
    || !supersessionChecked
    || supersession !== null
    || loading
    || action !== null;

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      refreshControl={<RefreshControl refreshing={loading} onRefresh={() => { if (actionRef.current === null) void load(); }} />}
      contentContainerStyle={{ padding: 16, gap: 14 }}
    >
      <View style={{ gap: 8 }}>
        <View style={{ flexDirection: "row", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
          <Text selectable style={{ color: colors.label, fontSize: 24, lineHeight: 29, fontWeight: "800", flex: 1 }}>{candidate.content.title}</Text>
          <StatusPill value={candidate.state} />
        </View>
        <Text selectable style={{ color: colors.secondaryLabel, fontSize: 16, lineHeight: 22 }}>{candidate.content.summary.text}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel }}>Version {candidate.candidate_version} · {candidate.content.priority} · confidence {candidate.content.uncertainty.overall_confidence}</Text>
      </View>

      {candidateStale || error ? (
        <SectionCard title={loading ? "Checking current version" : "Current version not verified"}>
          <Text selectable style={{ color: colors.orange, fontWeight: "700", lineHeight: 20 }}>
            {loading
              ? "Review actions are temporarily locked while Tacua refreshes this ticket."
              : "Review actions are locked because Tacua could not verify that this is the current ticket version."}
          </Text>
          {error ? <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>{error}</Text> : null}
          <ActionButton
            label="Refresh ticket"
            disabled={loading || action !== null}
            loading={loading}
            onPress={() => { void load(); }}
          />
        </SectionCard>
      ) : null}

      {supersession ? (
        <SectionCard title="Replaced ticket history">
          <Text selectable accessibilityRole="alert" style={{ color: colors.orange, fontWeight: "800", lineHeight: 20 }}>
            CANDIDATE_SUPERSEDED
          </Text>
          <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
            This source left the active queue in a reviewer-confirmed {supersession.operation}. It remains readable, but cannot be edited, approved, rejected, split, merged, or exported.
          </Text>
          <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>Operation {supersession.operation_id} · {supersession.occurred_at}</Text>
          <Text selectable style={{ color: colors.label, fontWeight: "700" }}>Exact source tickets</Text>
          {supersession.sources.map((source, index) => (
            <Link
              key={`${source.candidate_id}:${source.candidate_version}:${source.candidate_digest}`}
              href={{ pathname: "/candidates/[candidate-id]", params: { "candidate-id": source.candidate_id } }}
              asChild
            >
              <Pressable
                accessibilityLabel={`Open exact source ${index + 1}, ${source.candidate_id}, version ${source.candidate_version}`}
                accessibilityRole="link"
                style={{ minHeight: 44, justifyContent: "center", borderTopColor: colors.separator, borderTopWidth: 1, paddingVertical: 8, gap: 2 }}
              >
                <Text selectable style={{ color: colors.primary, fontWeight: "800" }}>Open source {index + 1}</Text>
                <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{source.candidate_id} · version {source.candidate_version}</Text>
                <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{source.candidate_digest}</Text>
              </Pressable>
            </Link>
          ))}
          <Text selectable style={{ color: colors.label, fontWeight: "700" }}>Replacement drafts</Text>
          {supersession.results.map((replacement, index) => (
            <Link
              key={replacement.candidate_id}
              href={{ pathname: "/candidates/[candidate-id]", params: { "candidate-id": replacement.candidate_id } }}
              asChild
            >
              <Pressable
                accessibilityRole="link"
                style={{ minHeight: 44, justifyContent: "center", borderTopColor: colors.separator, borderTopWidth: 1, paddingVertical: 8 }}
              >
                <Text selectable style={{ color: colors.primary, fontWeight: "800" }}>Open replacement {index + 1}</Text>
                <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{replacement.candidate_id} · version {replacement.candidate_version}</Text>
              </Pressable>
            </Link>
          ))}
        </SectionCard>
      ) : null}

      {["split", "merged"].includes(candidate.lineage.operation) && candidate.lineage.parents.length ? (
        <SectionCard title="Source history">
          <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
            This {candidate.lineage.operation === "merged" ? "combined" : candidate.lineage.operation} candidate was created from these exact historical versions.
          </Text>
          {candidate.lineage.parents.map((parent, index) => (
            <Link
              key={`${parent.candidate_id}:${parent.candidate_version}:${parent.candidate_digest}`}
              href={{ pathname: "/candidates/[candidate-id]", params: { "candidate-id": parent.candidate_id } }}
              asChild
            >
              <Pressable
                accessibilityRole="link"
                style={{ minHeight: 44, justifyContent: "center", borderTopColor: colors.separator, borderTopWidth: 1, paddingVertical: 8 }}
              >
                <Text selectable style={{ color: colors.primary, fontWeight: "800" }}>Open source {index + 1}</Text>
                <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{parent.candidate_id} · version {parent.candidate_version}</Text>
              </Pressable>
            </Link>
          ))}
        </SectionCard>
      ) : null}

      {supersession === null ? (
        <>
          <CandidateEditCard
            candidate={candidate}
            disabled={actionsDisabled}
            saving={action === "edit_content"}
            onSave={editContent}
          />

          <CandidateSplitCard
            actorId={config?.reviewerId ?? ""}
            candidate={candidate}
            disabled={actionsDisabled}
            saving={action === "split"}
            onSubmit={splitCandidate}
          />
        </>
      ) : null}

      <CandidateEvidencePanel
        activeKeyframeIndex={activeKeyframeIndex}
        activePreviewState={activePreviewState}
        evidence={evidence}
        error={evidenceError}
        inspectedKeyframeCount={inspectedKeyframeCount}
        keyframes={keyframes}
        loading={evidenceLoading || loading}
        retryDisabled={loading || evidenceLoading}
        onRetry={() => { if (actionRef.current === null && !loadingRef.current && !evidenceLoading) void load(); }}
        onRetryActivePreview={retryActivePreview}
        onShowNextKeyframe={showNextKeyframe}
        onShowPreviousKeyframe={showPreviousKeyframe}
        onKeyframeDecodeStateChange={setKeyframeDecoded}
      />

      <SectionCard title="Observed">
        <Text selectable style={{ color: colors.label, fontSize: 16, lineHeight: 23 }}>{candidate.content.actual_behavior.text}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>Evidence: {candidate.content.actual_behavior.evidence_refs.join(", ")}</Text>
      </SectionCard>
      <SectionCard title="Expected">
        <Text selectable style={{ color: colors.label, fontSize: 16, lineHeight: 23 }}>{candidate.content.expected_behavior.text}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>Evidence: {candidate.content.expected_behavior.evidence_refs.join(", ")}</Text>
      </SectionCard>
      <SectionCard title="Reproduction">
        {candidate.content.reproduction.preconditions.length ? (
          <View style={{ gap: 6 }}>
            <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 13, fontWeight: "700", textTransform: "uppercase" }}>Before you start</Text>
            {candidate.content.reproduction.preconditions.map((precondition) => (
              <Text selectable key={precondition.precondition_id} style={{ color: colors.secondaryLabel }}>• {precondition.text}</Text>
            ))}
          </View>
        ) : null}
        {candidate.content.reproduction.steps.map((step, index) => (
          <View key={step.step_id} style={{ flexDirection: "row", gap: 12 }}>
            <Text selectable style={{ color: colors.primary, fontWeight: "800", fontVariant: ["tabular-nums"] }}>{index + 1}</Text>
            <View style={{ flex: 1, gap: 4 }}>
              <Text selectable style={{ color: colors.label, lineHeight: 21 }}>{step.action}</Text>
              {step.actual_result ? <Text selectable style={{ color: colors.secondaryLabel }}>Actual: {step.actual_result}</Text> : null}
              {step.expected_result ? <Text selectable style={{ color: colors.secondaryLabel }}>Expected: {step.expected_result}</Text> : null}
            </View>
          </View>
        ))}
      </SectionCard>
      <SectionCard title="Grounding">
        {candidate.content.claims.map((claim) => (
          <View key={claim.claim_id} style={{ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 10, gap: 4 }}>
            <Text selectable style={{ color: colors.label, lineHeight: 21 }}>{claim.statement}</Text>
            <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12, textTransform: "capitalize" }}>{claim.kind} · {claim.support} · {claim.confidence}</Text>
            <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>Evidence: {claim.evidence_refs.join(", ") || "none"}</Text>
          </View>
        ))}
      </SectionCard>
      <SectionCard title="Acceptance criteria">
        {candidate.content.acceptance_criteria.map((criterion) => (
          <View key={criterion.criterion_id} style={{ gap: 4 }}>
            <Text selectable style={{ color: colors.label, fontWeight: "600" }}>✓ {criterion.criterion}</Text>
            <Text selectable style={{ color: colors.secondaryLabel }}>{criterion.verification}</Text>
          </View>
        ))}
      </SectionCard>
      {candidate.content.uncertainty.items.length ? (
        <SectionCard title="Uncertainty">
          {candidate.content.uncertainty.items.map((item) => <Text selectable key={item.uncertainty_id} style={{ color: item.impact === "blocking" ? colors.orange : colors.secondaryLabel }}>• {item.statement}</Text>)}
        </SectionCard>
      ) : null}
      <SectionCard title="Scope">
        {candidate.content.scope.in_scope.map((item) => <Text selectable key={`in:${item}`} style={{ color: colors.label }}>✓ {item}</Text>)}
        {candidate.content.scope.out_of_scope.map((item) => <Text selectable key={`out:${item}`} style={{ color: colors.secondaryLabel }}>Not included: {item}</Text>)}
      </SectionCard>
      {unresolved.map((clarification) => {
        const draft = clarificationDraft?.clarificationId === clarification.clarification_id
          ? clarificationDraft
          : null;
        const selectedChoice = draft
          ? clarification.choices.find((choice) => choice.choice_id === draft.choiceId)
          : undefined;
        return (
          <SectionCard key={clarification.clarification_id} title={clarification.impact === "blocking" ? "Decision required" : "Clarification"}>
            <Text selectable style={{ color: colors.label, fontSize: 16 }}>{clarification.question}</Text>
            <View accessibilityRole="radiogroup" style={{ gap: 12 }}>
              {clarification.choices.map((choice) => (
                <Pressable
                  key={choice.choice_id}
                  accessibilityLabel={clarificationChoiceAccessibilityLabel(choice)}
                  accessibilityRole="radio"
                  accessibilityHint={choice.requires_note ? "Requires a short explanation before saving." : undefined}
                  accessibilityState={{ checked: draft?.choiceId === choice.choice_id, busy: action === `clarification:${clarification.clarification_id}`, disabled: actionsDisabled }}
                  disabled={actionsDisabled}
                  onPress={() => {
                    if (choice.requires_note) {
                      setClarificationDraft({ clarificationId: clarification.clarification_id, choiceId: choice.choice_id, note: "" });
                    } else {
                      setClarificationDraft(null);
                      confirmImmediateChoice(clarification, choice);
                    }
                  }}
                  style={({ pressed }) => ({
                    borderColor: draft?.choiceId === choice.choice_id ? colors.primary : colors.separator,
                    borderWidth: draft?.choiceId === choice.choice_id ? 2 : 1,
                    borderRadius: 12,
                    borderCurve: "continuous",
                    padding: 12,
                    gap: 4,
                    opacity: actionsDisabled ? 0.5 : pressed ? 0.65 : 1,
                  })}
                >
                  <ChoicePreview choice={choice} previewStates={previewStates} />
                  <Text selectable style={{ color: colors.label, fontWeight: "700" }}>{choice.label}</Text>
                  <Text selectable style={{ color: colors.secondaryLabel }}>{choice.description}</Text>
                  <Text selectable style={{ color: colors.secondaryLabel }}>{choice.consequence}</Text>
                  {choice.requires_note ? <Text selectable style={{ color: colors.orange, fontSize: 13, fontWeight: "700" }}>Explanation required</Text> : null}
                </Pressable>
              ))}
            </View>
            {draft && selectedChoice?.requires_note ? (
              <View style={{ gap: 8 }}>
                <Text nativeID={`clarification-note-${clarification.clarification_id}`} style={{ color: colors.label, fontWeight: "700" }}>
                  Why choose “{selectedChoice.label}”?
                </Text>
                <TextInput
                  accessibilityLabel={`Why choose ${selectedChoice.label}?`}
                  accessibilityLabelledBy={`clarification-note-${clarification.clarification_id}`}
                  multiline
                  maxLength={2048}
                  placeholder="Add the context the implementation agent will need"
                  placeholderTextColor={colors.tertiaryLabel}
                  value={draft.note}
                  onChangeText={(note) => setClarificationDraft({ ...draft, note })}
                  style={{
                    minHeight: 96,
                    borderColor: colors.separator,
                    borderWidth: 1,
                    borderRadius: 12,
                    borderCurve: "continuous",
                    backgroundColor: colors.groupedBackground,
                    color: colors.label,
                    fontSize: 16,
                    lineHeight: 22,
                    padding: 12,
                    textAlignVertical: "top",
                  }}
                />
                <ActionButton
                  label="Save choice and explanation"
                  disabled={!draft.note.trim() || actionsDisabled}
                  loading={action === `clarification:${clarification.clarification_id}`}
                  onPress={() => void resolveClarification(clarification.clarification_id, draft.choiceId, draft.note.trim())}
                />
              </View>
            ) : null}
          </SectionCard>
        );
      })}

      {resolved.length ? (
        <SectionCard title="Decisions made">
          {resolved.map((clarification) => {
            const selectedChoice = clarification.choices.find(
              (choice) => choice.choice_id === clarification.selected_choice_id,
            );
            return (
              <View key={clarification.clarification_id} style={{ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 10, gap: 7 }}>
                <Text selectable style={{ color: colors.label, fontSize: 16, lineHeight: 22 }}>{clarification.question}</Text>
                {selectedChoice ? (
                  <>
                    <ChoicePreview choice={selectedChoice} previewStates={previewStates} />
                    <Text selectable style={{ color: colors.primary, fontWeight: "800" }}>{selectedChoice.label}</Text>
                    <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>{selectedChoice.consequence}</Text>
                  </>
                ) : (
                  <Text selectable style={{ color: colors.orange }}>The selected choice is unavailable in this ticket version.</Text>
                )}
                {clarification.resolution_note ? (
                  <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>Reviewer note: {clarification.resolution_note}</Text>
                ) : null}
              </View>
            );
          })}
        </SectionCard>
      ) : null}

      {candidate.state === "ready_for_review" && supersession === null ? (
        <SectionCard title="Exact version to approve">
          <Text selectable style={{ color: colors.label, fontVariant: ["tabular-nums"] }}>Candidate version {candidate.candidate_version}</Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 12 }}>{candidate.candidate_content_digest}</Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 12 }}>Evidence {candidate.evidence_manifest.manifest_digest}</Text>
          <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{candidate.evidence_manifest.evidence_ids.length} evidence items are bound to this version.</Text>
          {!evidenceInspectionReady ? (
            <Text selectable style={{ color: colors.orange, fontSize: 13, fontWeight: "700" }}>
              Approval unlocks after every content-referenced available screenshot passes its digest check and decodes in the gallery ({keyframes.length} found).
            </Text>
          ) : null}
        </SectionCard>
      ) : null}

      {candidate.state === "approved" ? (
        <SectionCard title="Agent handoff">
          <Text selectable style={{ color: colors.label, lineHeight: 21 }}>
            This exact approved version has immutable Markdown and JSON handoffs ready to pass to an implementation agent.
          </Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13, lineHeight: 18 }}>
            The files are structural artifacts. Before changing code, a launcher must also validate current registry trust, a short-lived exact-scope execution assertion, and the registry-current signed revocation list.
          </Text>
          {handoffVerification ? (
            <View style={{ gap: 4 }}>
              <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>Handoff: {handoffVerification.handoffDigest}</Text>
              <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>
                {handoffVerification.format === "markdown" ? "Markdown" : "JSON"} file: {handoffVerification.bodyDigest}
              </Text>
            </View>
          ) : null}
          {handoffError ? <Text selectable style={{ color: colors.red, fontSize: 13 }}>{handoffError}</Text> : null}
          <ActionButton
            label="Export Markdown handoff"
            loading={handoffAction === "markdown"}
            disabled={handoffAction !== null || candidateStale || loading}
            onPress={() => void shareHandoff("markdown")}
          />
          <ActionButton
            label="Export JSON handoff"
            loading={handoffAction === "json"}
            disabled={handoffAction !== null || candidateStale || loading}
            onPress={() => void shareHandoff("json")}
          />
        </SectionCard>
      ) : null}

      {supersession === null ? (
        <View style={{ gap: 10, paddingTop: 4 }}>
          {candidate.state === "draft" || candidate.state === "needs_clarification" ? <ActionButton label="Mark ready for review" disabled={actionsDisabled || unresolved.some((item) => item.impact === "blocking")} loading={action === "mark_ready"} onPress={() => void transition("mark_ready", "Reviewer completed candidate preparation.")} /> : null}
          {candidate.state === "ready_for_review" ? <ActionButton label="Approve exact version" disabled={actionsDisabled || !evidenceInspectionReady || evidenceLoading || evidenceError !== null} loading={action === "approve"} onPress={() => showDialog("Approve this ticket?", "Approval binds this exact candidate and evidence and atomically creates its immutable handoff. The handoff is not authenticated execution trust by itself.", [{ text: "Cancel", style: "cancel" }, { text: "Approve", onPress: () => void transition("approve", "Reviewer approved the exact candidate version.") }])} /> : null}
          {candidate.state === "needs_clarification" || candidate.state === "ready_for_review" ? <ActionButton destructive label="Reject candidate" disabled={actionsDisabled} loading={action === "reject"} onPress={() => showDialog("Reject this candidate?", undefined, [{ text: "Cancel", style: "cancel" }, { text: "Reject", style: "destructive", onPress: () => void transition("reject", "Reviewer rejected the candidate.") }])} /> : null}
        </View>
      ) : null}
    </ScrollView>
  );
}

function ChoicePreview({
  choice,
  previewStates,
}: {
  readonly choice: ClarificationChoice;
  readonly previewStates: KeyframePreviewStates;
}) {
  const presentation = choice.presentation;
  if (presentation.kind === "color_swatch" && presentation.value) {
    return <View accessibilityElementsHidden importantForAccessibility="no" style={{ width: 42, height: 42, borderRadius: 10, borderCurve: "continuous", borderColor: colors.separator, borderWidth: 1, backgroundColor: presentation.value }} />;
  }
  if (presentation.kind === "evidence_thumbnail" && presentation.evidence_ref) {
    const previewState: KeyframePreviewState | undefined = previewStates[presentation.evidence_ref];
    const status = previewState?.status === "ready"
      ? "This digest-verified screenshot is open in the evidence gallery"
      : previewState?.status === "loading"
        ? "Loading this screenshot in the evidence gallery"
        : previewState?.status === "error"
          ? "Evidence screenshot unavailable"
          : "View this screenshot in the evidence gallery";
    return (
      <View style={{ minHeight: 58, borderRadius: 10, borderCurve: "continuous", borderColor: colors.separator, borderWidth: 1, backgroundColor: colors.groupedBackground, padding: 10, justifyContent: "center" }}>
        <Text selectable style={{ color: previewState?.status === "error" ? colors.orange : colors.primary, fontWeight: "700" }}>
          {status}
        </Text>
        {previewState?.status === "error" ? <Text selectable style={{ color: colors.secondaryLabel, fontSize: 12 }}>{previewState.message}</Text> : null}
        <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{presentation.evidence_ref}</Text>
      </View>
    );
  }
  if (presentation.value) {
    return <Text selectable style={{ color: colors.primary, fontSize: presentation.kind === "text" ? 20 : 16, fontWeight: "800" }}>{presentation.value}</Text>;
  }
  return null;
}

function clarificationChoiceAccessibilityLabel(choice: ClarificationChoice): string {
  const presentation = choice.presentation;
  const presentationDetail = presentation.value
    ? presentation.kind === "color_swatch"
      ? ` Colour ${presentation.value}.`
      : ` Preview value ${presentation.value}.`
    : presentation.evidence_ref
      ? ` Evidence ${presentation.evidence_ref}.`
      : "";
  return `${choice.label}. ${choice.description}. Consequence: ${choice.consequence}.${presentationDetail}`;
}
