// SPDX-License-Identifier: Apache-2.0

import { useLocalSearchParams } from "expo-router";
import { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Alert, Pressable, ScrollView, Text, View } from "react-native";

import type { TicketCandidate } from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { MessageState } from "@/components/message-state";
import { SectionCard } from "@/components/section-card";
import { StatusPill } from "@/components/status-pill";
import { useBackend } from "@/hooks/use-backend";
import { colors } from "@/theme/colors";

export default function CandidateRoute() {
  const { "candidate-id": candidateId } = useLocalSearchParams<{ "candidate-id": string }>();
  const { client, config } = useBackend();
  const [candidate, setCandidate] = useState<TicketCandidate | null>(null);
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!client || !candidateId) return;
    setLoading(true);
    setError(null);
    try { setCandidate(await client.getCandidate(candidateId)); }
    catch (caught) { setError(caught instanceof Error ? caught.message : "Tacua could not load this candidate."); }
    finally { setLoading(false); }
  }, [candidateId, client]);

  useEffect(() => { void load(); }, [load]);

  async function transition(nextAction: "mark_ready" | "approve" | "reject", reason: string) {
    if (!client || !config || !candidate) return;
    setAction(nextAction);
    try {
      setCandidate(await client.transitionCandidate(candidate.candidate_id, {
        expected_candidate_digest: candidate.candidate_digest,
        candidate_version: candidate.candidate_version,
        candidate_content_digest: candidate.candidate_content_digest,
        evidence_manifest_digest: candidate.source.evidence_manifest_digest,
        action: nextAction,
        actor_id: config.reviewerId,
        reason,
      }));
    } catch (caught) {
      Alert.alert("Candidate was not changed", caught instanceof Error ? caught.message : "The backend rejected the transition.");
    } finally { setAction(null); }
  }

  async function resolveClarification(clarificationId: string, choiceId: string) {
    if (!client || !config || !candidate) return;
    setAction(`clarification:${clarificationId}`);
    try {
      setCandidate(await client.transitionCandidate(candidate.candidate_id, {
        expected_candidate_digest: candidate.candidate_digest,
        candidate_version: candidate.candidate_version,
        candidate_content_digest: candidate.candidate_content_digest,
        evidence_manifest_digest: candidate.source.evidence_manifest_digest,
        action: "resolve_clarification",
        actor_id: config.reviewerId,
        reason: "Reviewer selected one bounded clarification choice.",
        clarification_id: clarificationId,
        selected_choice_id: choiceId,
      }));
    } catch (caught) {
      Alert.alert("Clarification was not saved", caught instanceof Error ? caught.message : "The backend rejected the choice.");
    } finally { setAction(null); }
  }

  if (loading && !candidate) return <View style={{ flex: 1, justifyContent: "center" }}><ActivityIndicator /></View>;
  if (!candidate) return <ScrollView contentInsetAdjustmentBehavior="automatic"><MessageState title="Candidate unavailable" detail={error ?? "The candidate was not found."} /></ScrollView>;
  const unresolved = candidate.content.clarifications.filter((item) => item.status === "unresolved");

  return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" contentContainerStyle={{ padding: 16, gap: 14 }}>
      <View style={{ gap: 8 }}>
        <View style={{ flexDirection: "row", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
          <Text selectable style={{ color: colors.label, fontSize: 24, lineHeight: 29, fontWeight: "800", flex: 1 }}>{candidate.content.title}</Text>
          <StatusPill value={candidate.state} />
        </View>
        <Text selectable style={{ color: colors.secondaryLabel, fontSize: 16, lineHeight: 22 }}>{candidate.content.summary}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel }}>Version {candidate.candidate_version} · {candidate.content.priority} · confidence {candidate.content.uncertainty.overall_confidence}</Text>
      </View>

      <SectionCard title="Observed">
        <Text selectable style={{ color: colors.label, fontSize: 16, lineHeight: 23 }}>{candidate.content.actual_behavior.text}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>Evidence: {candidate.content.actual_behavior.evidence_refs.join(", ")}</Text>
      </SectionCard>
      <SectionCard title="Expected">
        <Text selectable style={{ color: colors.label, fontSize: 16, lineHeight: 23 }}>{candidate.content.expected_behavior.text}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>Evidence: {candidate.content.expected_behavior.evidence_refs.join(", ")}</Text>
      </SectionCard>
      <SectionCard title="Reproduction">
        {candidate.content.reproduction_steps.map((step, index) => (
          <View key={step.step_id} style={{ flexDirection: "row", gap: 12 }}>
            <Text selectable style={{ color: colors.blue, fontWeight: "800", fontVariant: ["tabular-nums"] }}>{index + 1}</Text>
            <View style={{ flex: 1, gap: 4 }}>
              <Text selectable style={{ color: colors.label, lineHeight: 21 }}>{step.action}</Text>
              {step.actual_result ? <Text selectable style={{ color: colors.secondaryLabel }}>Actual: {step.actual_result}</Text> : null}
              {step.expected_result ? <Text selectable style={{ color: colors.secondaryLabel }}>Expected: {step.expected_result}</Text> : null}
            </View>
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
      {unresolved.map((clarification) => (
        <SectionCard key={clarification.clarification_id} title={clarification.impact === "blocking" ? "Decision required" : "Clarification"}>
          <Text selectable style={{ color: colors.label, fontSize: 16 }}>{clarification.question}</Text>
          {clarification.choices.map((choice) => (
            <Pressable
              key={choice.choice_id}
              accessibilityRole="radio"
              accessibilityState={{ checked: false, busy: action === `clarification:${clarification.clarification_id}` }}
              disabled={action !== null}
              onPress={() => void resolveClarification(clarification.clarification_id, choice.choice_id)}
              style={({ pressed }) => ({ borderColor: colors.separator, borderWidth: 1, borderRadius: 12, borderCurve: "continuous", padding: 12, gap: 4, opacity: action !== null ? 0.5 : pressed ? 0.65 : 1 })}
            >
              <Text selectable style={{ color: colors.label, fontWeight: "700" }}>{choice.label}</Text>
              <Text selectable style={{ color: colors.secondaryLabel }}>{choice.consequence}</Text>
            </Pressable>
          ))}
        </SectionCard>
      ))}

      {candidate.state === "ready_for_review" ? (
        <SectionCard title="Exact version to approve">
          <Text selectable style={{ color: colors.label, fontVariant: ["tabular-nums"] }}>Candidate version {candidate.candidate_version}</Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 12 }}>{candidate.candidate_content_digest}</Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 12 }}>Evidence {candidate.source.evidence_manifest_digest}</Text>
        </SectionCard>
      ) : null}

      <View style={{ gap: 10, paddingTop: 4 }}>
        {candidate.state === "draft" || candidate.state === "needs_clarification" ? <ActionButton label="Mark ready for review" disabled={unresolved.some((item) => item.impact === "blocking")} loading={action === "mark_ready"} onPress={() => void transition("mark_ready", "Reviewer completed candidate preparation.")} /> : null}
        {candidate.state === "ready_for_review" ? <ActionButton label="Approve exact version" loading={action === "approve"} onPress={() => Alert.alert("Approve this ticket?", "Approval binds this exact candidate digest. It does not authorize a coding agent until an approved handoff is exported.", [{ text: "Cancel", style: "cancel" }, { text: "Approve", onPress: () => void transition("approve", "Reviewer approved the exact candidate version.") }])} /> : null}
        {candidate.state !== "approved" && candidate.state !== "rejected" ? <ActionButton destructive label="Reject candidate" loading={action === "reject"} onPress={() => Alert.alert("Reject this candidate?", undefined, [{ text: "Cancel", style: "cancel" }, { text: "Reject", style: "destructive", onPress: () => void transition("reject", "Reviewer rejected the candidate.") }])} /> : null}
      </View>
    </ScrollView>
  );
}
