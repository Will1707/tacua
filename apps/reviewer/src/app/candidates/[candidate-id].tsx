// SPDX-License-Identifier: Apache-2.0

import { useLocalSearchParams } from "expo-router";
import type { File } from "expo-file-system";
import * as Sharing from "expo-sharing";
import { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, Alert, Pressable, ScrollView, Text, TextInput, View } from "react-native";

import { TacuaApiError } from "@/api/client";
import type { CandidateEvidenceView, TicketCandidate } from "@/api/types";
import { cleanupApprovedHandoffShareCache, createApprovedHandoffShareFile } from "@/approved-handoff/share-cache";
import { ActionButton } from "@/components/action-button";
import { CandidateEvidencePanel } from "@/components/candidate-evidence-panel";
import { MessageState } from "@/components/message-state";
import { SectionCard } from "@/components/section-card";
import { StatusPill } from "@/components/status-pill";
import { useBackend } from "@/hooks/use-backend";
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
  const [candidate, setCandidate] = useState<TicketCandidate | null>(null);
  const [evidence, setEvidence] = useState<CandidateEvidenceView | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [evidenceInspectionReady, setEvidenceInspectionReady] = useState(false);
  const [loading, setLoading] = useState(true);
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
  const handoffRequestSequence = useRef(0);
  const handoffRequestRef = useRef<{
    readonly requestId: number;
    readonly candidateBinding: string;
    readonly controller: AbortController;
  } | null>(null);
  const candidateBinding = candidate
    ? `${candidateId ?? "missing-route"}:${candidate.candidate_id}:${candidate.candidate_version}:${candidate.candidate_digest}`
    : null;

  const load = useCallback(async () => {
    if (!client || !candidateId) return;
    setLoading(true);
    setError(null);
    try { setCandidate(await client.getCandidate(candidateId)); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Tacua could not load this candidate."); }
    finally { setLoading(false); }
  }, [candidateId, client]);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    mountedRef.current = true;
    try {
      cleanupApprovedHandoffShareCache();
    } catch {
      // A later share will retry cleanup and fail closed if the bound cannot be enforced.
    }
    return () => {
      mountedRef.current = false;
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
    let active = true;
    if (!client || !candidate) {
      setEvidence(null);
      setEvidenceLoading(false);
      setEvidenceInspectionReady(false);
      return () => { active = false; };
    }
    setEvidence(null);
    setEvidenceError(null);
    setEvidenceLoading(true);
    setEvidenceInspectionReady(false);
    void client.getCandidateEvidence(candidate)
      .then((loaded) => { if (active) setEvidence(loaded); })
      .catch((caught) => {
        if (active) setEvidenceError(caught instanceof Error ? caught.message : "Tacua could not load the bound evidence.");
      })
      .finally(() => { if (active) setEvidenceLoading(false); });
    return () => { active = false; };
  }, [candidate, client]);

  async function handleTransitionError(title: string, caught: unknown) {
    if (caught instanceof TacuaApiError && (caught.status === 409 || caught.status === 412)) {
      await load();
      Alert.alert("Ticket refreshed", "This ticket changed while you were reviewing it. Tacua loaded the current version; please check it before trying again.");
      return;
    }
    Alert.alert(title, caught instanceof Error ? caught.message : "The backend rejected the transition.");
  }

  async function transition(nextAction: "mark_ready" | "approve" | "reject", reason: string) {
    if (!client || !config || !candidate) return;
    setAction(nextAction);
    try {
      setCandidate(await client.transitionCandidate(candidate.candidate_id, {
        expected_candidate_digest: candidate.candidate_digest,
        candidate_version: candidate.candidate_version,
        candidate_content_digest: candidate.candidate_content_digest,
        evidence_manifest_digest: candidate.evidence_manifest.manifest_digest,
        action: nextAction,
        actor_id: config.reviewerId,
        reason,
      }));
    } catch (caught) {
      await handleTransitionError("Candidate was not changed", caught);
    } finally { setAction(null); }
  }

  async function resolveClarification(clarificationId: string, choiceId: string, resolutionNote?: string) {
    if (!client || !config || !candidate) return;
    setAction(`clarification:${clarificationId}`);
    try {
      setCandidate(await client.transitionCandidate(candidate.candidate_id, {
        expected_candidate_digest: candidate.candidate_digest,
        candidate_version: candidate.candidate_version,
        candidate_content_digest: candidate.candidate_content_digest,
        evidence_manifest_digest: candidate.evidence_manifest.manifest_digest,
        action: "resolve_clarification",
        actor_id: config.reviewerId,
        reason: "Reviewer selected one bounded clarification choice.",
        clarification_id: clarificationId,
        selected_choice_id: choiceId,
        ...(resolutionNote ? { resolution_note: resolutionNote } : {}),
      }));
      setClarificationDraft(null);
    } catch (caught) {
      await handleTransitionError("Clarification was not saved", caught);
    } finally { setAction(null); }
  }

  async function shareHandoff(format: "json" | "markdown") {
    if (!client || !candidate || candidate.state !== "approved" || candidate.candidate_id !== candidateId) return;
    const candidateSnapshot = candidate;
    const requestBinding = `${candidateId}:${candidate.candidate_id}:${candidate.candidate_version}:${candidate.candidate_digest}`;
    const requestId = handoffRequestSequence.current + 1;
    handoffRequestSequence.current = requestId;
    handoffRequestRef.current?.controller.abort();
    const controller = new AbortController();
    handoffRequestRef.current = { requestId, candidateBinding: requestBinding, controller };
    const isCurrentRequest = () => (
      mountedRef.current
      && !controller.signal.aborted
      && handoffRequestRef.current?.requestId === requestId
      && handoffRequestRef.current.candidateBinding === requestBinding
    );
    setHandoffAction(format);
    setHandoffError(null);
    try {
      if (!await Sharing.isAvailableAsync()) {
        throw new Error("File sharing is unavailable on this device.");
      }
      const artifact = await client.getCandidateHandoff(candidateSnapshot, format, controller.signal);
      if (!isCurrentRequest()) return;
      setHandoffVerification({
        format,
        handoffDigest: artifact.handoffDigest,
        bodyDigest: artifact.bodyDigest,
      });
      const shareType = handoffShareTypes[format];
      const sharedFile: File = createApprovedHandoffShareFile({
        candidateId: candidateSnapshot.candidate_id,
        candidateVersion: candidateSnapshot.candidate_version,
        extension: shareType.extension,
        bytes: artifact.bytes,
      });
      if (!isCurrentRequest()) return;
      await Sharing.shareAsync(sharedFile.uri, {
        dialogTitle: `${candidateSnapshot.content.title} · Tacua handoff`,
        mimeType: shareType.mimeType,
        UTI: shareType.UTI,
      });
    } catch (caught) {
      if (!isCurrentRequest()) return;
      const message = caught instanceof Error ? caught.message : "Tacua could not share the approved handoff.";
      setHandoffError(message);
      Alert.alert("Handoff unavailable", message);
    } finally {
      if (handoffRequestRef.current?.requestId === requestId) {
        handoffRequestRef.current = null;
        if (mountedRef.current) setHandoffAction(null);
      }
    }
  }

  if (loading && !candidate) return <View style={{ flex: 1, justifyContent: "center" }}><ActivityIndicator /></View>;
  if (!candidate || !client) return <ScrollView contentInsetAdjustmentBehavior="automatic"><MessageState title="Candidate unavailable" detail={error ?? "The candidate was not found."} /></ScrollView>;
  const unresolved = candidate.content.clarifications.filter((item) => item.status === "unresolved");

  return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" contentContainerStyle={{ padding: 16, gap: 14 }}>
      <View style={{ gap: 8 }}>
        <View style={{ flexDirection: "row", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
          <Text selectable style={{ color: colors.label, fontSize: 24, lineHeight: 29, fontWeight: "800", flex: 1 }}>{candidate.content.title}</Text>
          <StatusPill value={candidate.state} />
        </View>
        <Text selectable style={{ color: colors.secondaryLabel, fontSize: 16, lineHeight: 22 }}>{candidate.content.summary.text}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel }}>Version {candidate.candidate_version} · {candidate.content.priority} · confidence {candidate.content.uncertainty.overall_confidence}</Text>
      </View>

      <CandidateEvidencePanel
        candidate={candidate}
        client={client}
        evidence={evidence}
        error={evidenceError}
        loading={evidenceLoading}
        onInspectionStateChange={setEvidenceInspectionReady}
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
            {clarification.choices.map((choice) => (
              <Pressable
                key={choice.choice_id}
                accessibilityRole="radio"
                accessibilityHint={choice.requires_note ? "Requires a short explanation before saving." : undefined}
                accessibilityState={{ checked: draft?.choiceId === choice.choice_id, busy: action === `clarification:${clarification.clarification_id}` }}
                disabled={action !== null}
                onPress={() => {
                  if (choice.requires_note) {
                    setClarificationDraft({ clarificationId: clarification.clarification_id, choiceId: choice.choice_id, note: "" });
                  } else {
                    setClarificationDraft(null);
                    void resolveClarification(clarification.clarification_id, choice.choice_id);
                  }
                }}
                style={({ pressed }) => ({
                  borderColor: draft?.choiceId === choice.choice_id ? colors.primary : colors.separator,
                  borderWidth: draft?.choiceId === choice.choice_id ? 2 : 1,
                  borderRadius: 12,
                  borderCurve: "continuous",
                  padding: 12,
                  gap: 4,
                  opacity: action !== null ? 0.5 : pressed ? 0.65 : 1,
                })}
              >
                <ChoicePreview choice={choice} />
                <Text selectable style={{ color: colors.label, fontWeight: "700" }}>{choice.label}</Text>
                <Text selectable style={{ color: colors.secondaryLabel }}>{choice.description}</Text>
                <Text selectable style={{ color: colors.secondaryLabel }}>{choice.consequence}</Text>
                {choice.requires_note ? <Text selectable style={{ color: colors.orange, fontSize: 13, fontWeight: "700" }}>Explanation required</Text> : null}
              </Pressable>
            ))}
            {draft && selectedChoice?.requires_note ? (
              <View style={{ gap: 8 }}>
                <Text nativeID={`clarification-note-${clarification.clarification_id}`} style={{ color: colors.label, fontWeight: "700" }}>
                  Why choose “{selectedChoice.label}”?
                </Text>
                <TextInput
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
                  disabled={!draft.note.trim()}
                  loading={action === `clarification:${clarification.clarification_id}`}
                  onPress={() => void resolveClarification(clarification.clarification_id, draft.choiceId, draft.note.trim())}
                />
              </View>
            ) : null}
          </SectionCard>
        );
      })}

      {candidate.state === "ready_for_review" ? (
        <SectionCard title="Exact version to approve">
          <Text selectable style={{ color: colors.label, fontVariant: ["tabular-nums"] }}>Candidate version {candidate.candidate_version}</Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 12 }}>{candidate.candidate_content_digest}</Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 12 }}>Evidence {candidate.evidence_manifest.manifest_digest}</Text>
          <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{candidate.evidence_manifest.evidence_ids.length} evidence items are bound to this version.</Text>
          {!evidenceInspectionReady ? (
            <Text selectable style={{ color: colors.orange, fontSize: 13, fontWeight: "700" }}>
              Approval unlocks after the bound screenshot has loaded and passed its integrity checks.
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
            The files are structural artifacts. An agent must still validate execution authority against a separately trusted registry before changing code.
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
            label="Share Markdown handoff"
            loading={handoffAction === "markdown"}
            disabled={handoffAction !== null}
            onPress={() => void shareHandoff("markdown")}
          />
          <ActionButton
            label="Share JSON handoff"
            loading={handoffAction === "json"}
            disabled={handoffAction !== null}
            onPress={() => void shareHandoff("json")}
          />
        </SectionCard>
      ) : null}

      <View style={{ gap: 10, paddingTop: 4 }}>
        {candidate.state === "draft" || candidate.state === "needs_clarification" ? <ActionButton label="Mark ready for review" disabled={unresolved.some((item) => item.impact === "blocking")} loading={action === "mark_ready"} onPress={() => void transition("mark_ready", "Reviewer completed candidate preparation.")} /> : null}
        {candidate.state === "ready_for_review" ? <ActionButton label="Approve exact version" disabled={!evidenceInspectionReady || evidenceLoading || evidenceError !== null} loading={action === "approve"} onPress={() => Alert.alert("Approve this ticket?", "Approval binds this exact candidate and evidence and atomically creates its immutable handoff. The handoff is not authenticated execution trust by itself.", [{ text: "Cancel", style: "cancel" }, { text: "Approve", onPress: () => void transition("approve", "Reviewer approved the exact candidate version.") }])} /> : null}
        {candidate.state === "needs_clarification" || candidate.state === "ready_for_review" ? <ActionButton destructive label="Reject candidate" loading={action === "reject"} onPress={() => Alert.alert("Reject this candidate?", undefined, [{ text: "Cancel", style: "cancel" }, { text: "Reject", style: "destructive", onPress: () => void transition("reject", "Reviewer rejected the candidate.") }])} /> : null}
      </View>
    </ScrollView>
  );
}

function ChoicePreview({ choice }: { readonly choice: TicketCandidate["content"]["clarifications"][number]["choices"][number] }) {
  const presentation = choice.presentation;
  if (presentation.kind === "color_swatch" && presentation.value) {
    return <View accessibilityLabel={`Colour ${presentation.value}`} style={{ width: 42, height: 42, borderRadius: 10, borderCurve: "continuous", borderColor: colors.separator, borderWidth: 1, backgroundColor: presentation.value }} />;
  }
  if (presentation.kind === "evidence_thumbnail" && presentation.evidence_ref) {
    return (
      <View style={{ minHeight: 58, borderRadius: 10, borderCurve: "continuous", borderColor: colors.separator, borderWidth: 1, backgroundColor: colors.groupedBackground, padding: 10, justifyContent: "center" }}>
        <Text selectable style={{ color: colors.primary, fontWeight: "700" }}>Evidence preview</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{presentation.evidence_ref}</Text>
      </View>
    );
  }
  if (presentation.value) {
    return <Text selectable style={{ color: colors.primary, fontSize: presentation.kind === "text" ? 20 : 16, fontWeight: "800" }}>{presentation.value}</Text>;
  }
  return null;
}
