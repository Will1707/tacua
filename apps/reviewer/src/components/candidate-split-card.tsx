// SPDX-License-Identifier: Apache-2.0

import * as Crypto from "expo-crypto";
import { Pressable, Text, View } from "react-native";
import { useEffect, useRef, useState } from "react";

import { createCandidateReplacementRequest, seedSplitDraft, seedSplitDrafts } from "@/api/candidate-replacement";
import type { CandidateReplacementDraft, TicketCandidate } from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { CandidateReplacementDraftFields } from "@/components/candidate-replacement-draft-fields";
import { SectionCard } from "@/components/section-card";
import { useAppDialog } from "@/providers/app-dialog";
import { colors } from "@/theme/colors";

type Props = {
  readonly actorId: string;
  readonly candidate: TicketCandidate;
  readonly disabled: boolean;
  readonly saving: boolean;
  readonly onSubmit: (drafts: readonly CandidateReplacementDraft[]) => Promise<boolean>;
};

function newCandidateId(): string {
  return `candidate_${Crypto.randomUUID().replaceAll("-", "")}`;
}

export function CandidateSplitCard({ actorId, candidate, disabled, saving, onSubmit }: Props) {
  const showDialog = useAppDialog();
  const [drafts, setDrafts] = useState<readonly CandidateReplacementDraft[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expandedDraftId, setExpandedDraftId] = useState<string | null>(null);
  const [reviewedDraftIds, setReviewedDraftIds] = useState<ReadonlySet<string>>(() => new Set());
  const nextPartNumber = useRef(3);
  const binding = `${candidate.candidate_id}:${candidate.candidate_version}:${candidate.candidate_digest}`;

  useEffect(() => {
    setDrafts(null);
    setError(null);
    setExpandedDraftId(null);
    setReviewedDraftIds(new Set());
    nextPartNumber.current = 3;
  }, [binding]);

  if (!["draft", "needs_clarification", "ready_for_review"].includes(candidate.state)) return null;

  const begin = () => {
    try {
      const seeded = seedSplitDrafts(candidate, [newCandidateId(), newCandidateId()]);
      setDrafts(seeded);
      setExpandedDraftId(seeded[0]?.candidate_id ?? null);
      setReviewedDraftIds(new Set(seeded[0] ? [seeded[0].candidate_id] : []));
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Tacua could not prepare split drafts.");
    }
  };
  const update = (index: number, draft: CandidateReplacementDraft) => {
    setDrafts((current) => current?.map((item, itemIndex) => itemIndex === index ? draft : item) ?? null);
  };
  const remove = (index: number) => {
    if (!drafts || drafts.length <= 2) return;
    const removed = drafts[index];
    if (!removed) return;
    const next = drafts.filter((_, itemIndex) => itemIndex !== index);
    setDrafts(next);
    setReviewedDraftIds((reviewed) => {
      const updated = new Set(reviewed);
      updated.delete(removed.candidate_id);
      return updated;
    });
    if (expandedDraftId === removed.candidate_id) {
      const replacement = next[Math.min(index, next.length - 1)];
      setExpandedDraftId(replacement?.candidate_id ?? null);
      if (replacement) setReviewedDraftIds((reviewed) => new Set([...reviewed, replacement.candidate_id]));
    }
  };
  const add = () => {
    if (!drafts || drafts.length >= 16) return;
    const next = seedSplitDraft(candidate, newCandidateId(), nextPartNumber.current);
    nextPartNumber.current += 1;
    setDrafts([...drafts, next]);
    setExpandedDraftId(next.candidate_id);
    setReviewedDraftIds((reviewed) => new Set([...reviewed, next.candidate_id]));
  };
  const toggleExpanded = (candidateId: string) => {
    if (disabled || saving) return;
    setExpandedDraftId((current) => current === candidateId ? null : candidateId);
    setReviewedDraftIds((reviewed) => new Set([...reviewed, candidateId]));
  };
  const confirm = () => {
    if (!drafts) return;
    const unreviewed = drafts.filter((draft) => !reviewedDraftIds.has(draft.candidate_id));
    if (unreviewed.length) {
      setError(`Open and review every complete result before continuing (${unreviewed.length} remaining).`);
      return;
    }
    try {
      createCandidateReplacementRequest({
        operation: "split",
        actorId,
        reason: "Reviewer split one candidate finding into distinct result drafts.",
        sources: [candidate],
        results: drafts,
      });
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error
        ? `Review the result fields before continuing (${caught.message}).`
        : "Review the result fields before continuing.");
      return;
    }
    showDialog(
      `Replace 1 active ticket with ${drafts.length} drafts?`,
      `“${candidate.content.title}” will leave the active queue. It remains visible in history and links to every replacement. None of the new drafts will be approved automatically.`,
      [
        { text: "Cancel", style: "cancel" },
        {
          text: `Create ${drafts.length} drafts`,
          onPress: () => {
            setError(null);
            void onSubmit(drafts).then((ok) => { if (ok) setDrafts(null); });
          },
        },
      ],
    );
  };

  if (!drafts) {
    return (
      <SectionCard title="Split ticket">
        <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
          Prepare 2–16 independent drafts from this exact ticket and evidence. Tacua only submits after you edit and confirm the result set.
        </Text>
        {error ? <Text selectable accessibilityRole="alert" style={{ color: colors.red }}>{error}</Text> : null}
        <ActionButton label="Prepare split drafts" disabled={disabled} onPress={begin} />
      </SectionCard>
    );
  }

  return (
    <SectionCard title="Split ticket">
      <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
        These are editable suggestions seeded from the source. Each result must remain different from the source and every sibling.
      </Text>
      {drafts.map((draft, index) => {
        const expanded = expandedDraftId === draft.candidate_id;
        const reviewed = reviewedDraftIds.has(draft.candidate_id);
        return (
          <View key={draft.candidate_id} style={{ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 10, gap: 8 }}>
            <Pressable
              accessibilityLabel={`${expanded ? "Collapse" : "Open"} complete result draft ${index + 1}`}
              accessibilityRole="button"
              accessibilityState={{ disabled: disabled || saving, expanded }}
              disabled={disabled || saving}
              onPress={() => toggleExpanded(draft.candidate_id)}
              style={({ pressed }) => ({
                minHeight: 52,
                borderRadius: 12,
                borderCurve: "continuous",
                backgroundColor: colors.groupedBackground,
                padding: 12,
                gap: 4,
                opacity: pressed ? 0.65 : 1,
              })}
            >
              <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
                <Text selectable style={{ color: colors.label, fontWeight: "800", flex: 1 }}>Result draft {index + 1}</Text>
                <Text style={{ color: reviewed ? colors.primary : colors.orange, fontSize: 12, fontWeight: "800" }}>
                  {reviewed ? "REVIEWED" : "OPEN TO REVIEW"}
                </Text>
                <Text accessibilityElementsHidden style={{ color: colors.primary, fontSize: 18, fontWeight: "900" }}>{expanded ? "−" : "+"}</Text>
              </View>
              <Text selectable numberOfLines={2} style={{ color: colors.secondaryLabel }}>{draft.content.title}</Text>
              <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{draft.candidate_id}</Text>
            </Pressable>
            {expanded ? (
              <CandidateReplacementDraftFields
                canRemove={drafts.length > 2}
                disabled={disabled || saving}
                draft={draft}
                index={index}
                onChange={(next) => update(index, next)}
                onRemove={() => remove(index)}
              />
            ) : null}
          </View>
        );
      })}
      {drafts.length < 16 ? (
        <Pressable
          accessibilityRole="button"
          disabled={disabled || saving}
          onPress={add}
          style={{ minHeight: 44, justifyContent: "center", alignItems: "center" }}
        >
          <Text style={{ color: colors.primary, fontWeight: "800" }}>Add another result draft</Text>
        </Pressable>
      ) : null}
      {error ? <Text selectable accessibilityRole="alert" style={{ color: colors.red }}>{error}</Text> : null}
      <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 13, fontVariant: ["tabular-nums"] }}>
        {drafts.filter((draft) => reviewedDraftIds.has(draft.candidate_id)).length} of {drafts.length} complete results opened for review
      </Text>
      <ActionButton
        label={`Review and create ${drafts.length} drafts`}
        disabled={disabled || drafts.some((draft) => !reviewedDraftIds.has(draft.candidate_id))}
        loading={saving}
        onPress={confirm}
      />
      <Pressable
        accessibilityRole="button"
        disabled={saving}
        onPress={() => { setDrafts(null); setExpandedDraftId(null); setReviewedDraftIds(new Set()); setError(null); }}
        style={{ minHeight: 44, justifyContent: "center", alignItems: "center" }}
      >
        <Text style={{ color: colors.primary, fontWeight: "800" }}>Cancel split</Text>
      </Pressable>
    </SectionCard>
  );
}
