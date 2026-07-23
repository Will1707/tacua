// SPDX-License-Identifier: Apache-2.0

import * as Crypto from "expo-crypto";
import { useEffect, useMemo, useRef, useState } from "react";
import { Pressable, Text, View } from "react-native";

import { createCandidateReplacementRequest, seedMergeDraft } from "@/api/candidate-replacement";
import { CandidateSupersededApiError, TacuaApiError } from "@/api/client";
import type { TacuaApiClient } from "@/api/client";
import type { CandidateReplacementDraft, TicketCandidate, TicketCandidateSummary } from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { CandidateReplacementDraftFields } from "@/components/candidate-replacement-draft-fields";
import { SectionCard } from "@/components/section-card";
import { useAppDialog } from "@/providers/app-dialog";
import { colors } from "@/theme/colors";

type Props = {
  readonly candidates: readonly TicketCandidateSummary[];
  readonly client: TacuaApiClient;
  readonly disabled: boolean;
  readonly reviewerId: string;
  readonly onCompleted: () => Promise<void>;
};

type PreparedMerge = {
  readonly sources: readonly TicketCandidate[];
  readonly draft: CandidateReplacementDraft;
};

function candidateId(): string {
  return `candidate_${Crypto.randomUUID().replaceAll("-", "")}`;
}

export function CandidateMergeCard({ candidates, client, disabled, reviewerId, onCompleted }: Props) {
  const showDialog = useAppDialog();
  const eligible = useMemo(
    () => candidates.filter((candidate) => ["draft", "needs_clarification", "ready_for_review"].includes(candidate.state)),
    [candidates],
  );
  const [selected, setSelected] = useState<readonly string[]>([]);
  const [prepared, setPrepared] = useState<PreparedMerge | null>(null);
  const [preparing, setPreparing] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestGeneration = useRef(0);
  const mountedRef = useRef(false);
  const candidateFingerprint = eligible.map((candidate) => (
    `${candidate.candidate_id}:${candidate.candidate_version}:${candidate.candidate_digest}`
  )).join("|");
  const currentContextRef = useRef({ candidateFingerprint, client, onCompleted });
  currentContextRef.current = { candidateFingerprint, client, onCompleted };

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      requestGeneration.current += 1;
    };
  }, []);

  useEffect(() => {
    requestGeneration.current += 1;
    setSelected([]);
    setPrepared(null);
    setPreparing(false);
    setSubmitting(false);
    setError(null);
  }, [candidateFingerprint, client]);

  if (eligible.length < 2) return null;

  const toggle = (id: string) => {
    if (disabled || preparing || submitting || prepared) return;
    setSelected((current) => current.includes(id)
      ? current.filter((candidate) => candidate !== id)
      : current.length < 16 ? [...current, id] : current);
  };

  const prepare = async () => {
    if (disabled || selected.length < 2 || selected.length > 16 || preparing || submitting) return;
    const generation = requestGeneration.current + 1;
    requestGeneration.current = generation;
    setPreparing(true);
    setError(null);
    try {
      const summaries = selected.map((id) => eligible.find((candidate) => candidate.candidate_id === id));
      if (summaries.some((summary) => !summary)) throw new Error("One selected ticket left the active queue. Refresh and select again.");
      const sources = await Promise.all(summaries.map(async (summary) => {
        const loaded = await client.getCandidate(summary!.candidate_id);
        if (
          loaded.candidate_version !== summary!.candidate_version
          || loaded.candidate_digest !== summary!.candidate_digest
          || !["draft", "needs_clarification", "ready_for_review"].includes(loaded.state)
        ) throw new Error("A selected ticket changed. Refresh and review the current versions before merging.");
        const supersession = await client.getCandidateSupersession(loaded);
        if (supersession !== null) throw new Error("A selected ticket was already replaced. Refresh the active queue before merging.");
        return loaded;
      }));
      if (requestGeneration.current !== generation) return;
      setPrepared({ sources, draft: seedMergeDraft(sources, candidateId()) });
    } catch (caught) {
      if (requestGeneration.current === generation) {
        setError(caught instanceof Error ? caught.message : "Tacua could not prepare the combined draft.");
      }
    } finally {
      if (requestGeneration.current === generation) setPreparing(false);
    }
  };

  const submit = async () => {
    if (!prepared || disabled || submitting) return;
    const generation = requestGeneration.current;
    const requestClient = client;
    const requestFingerprint = candidateFingerprint;
    const completion = onCompleted;
    const preparedRequest = prepared;
    const isCurrent = () => {
      const current = currentContextRef.current;
      return mountedRef.current
        && requestGeneration.current === generation
        && current.client === requestClient
        && current.candidateFingerprint === requestFingerprint
        && current.onCompleted === completion;
    };
    setSubmitting(true);
    setError(null);
    try {
      const response = await requestClient.replaceCandidates({
        operation: "merge",
        actorId: reviewerId,
        reason: "Reviewer combined related candidate findings into one draft.",
        sources: preparedRequest.sources,
        results: [preparedRequest.draft],
      });
      if (!isCurrent()) return;
      setPrepared(null);
      setSelected([]);
      showDialog(
        "Combined draft created",
        `${response.operation.sources.length} source tickets remain in history and the new draft is now in the active queue. It is not approved.`,
      );
      if (isCurrent()) await completion();
    } catch (caught) {
      if (!isCurrent()) return;
      const stale = caught instanceof CandidateSupersededApiError
        || (caught instanceof TacuaApiError && (caught.status === 409 || caught.status === 412));
      setError(stale
        ? "The active queue changed before confirmation. Refresh and review the current source tickets before trying again."
        : caught instanceof Error ? caught.message : "Tacua could not create the combined draft.");
      if (stale) {
        setPrepared(null);
        setSelected([]);
        if (isCurrent()) await completion();
      }
    } finally {
      if (isCurrent()) setSubmitting(false);
    }
  };

  const confirm = () => {
    if (!prepared) return;
    try {
      createCandidateReplacementRequest({
        operation: "merge",
        actorId: reviewerId,
        reason: "Reviewer combined related candidate findings into one draft.",
        sources: prepared.sources,
        results: [prepared.draft],
      });
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error
        ? `Review the combined result fields before continuing (${caught.message}).`
        : "Review the combined result fields before continuing.");
      return;
    }
    const sourceList = prepared.sources.map((source) => `• ${source.content.title}`).join("\n");
    showDialog(
      `Replace ${prepared.sources.length} active tickets with 1 draft?`,
      `These sources will leave the active queue:\n${sourceList}\n\nThey remain visible in history and link to the combined result. The result will be an unapproved draft.`,
      [
        { text: "Cancel", style: "cancel" },
        { text: "Create combined draft", onPress: () => void submit() },
      ],
    );
  };

  return (
    <SectionCard title="Merge related tickets">
      {!prepared ? (
        <>
          <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
            Select 2–16 active tickets from this capture. Tacua verifies their exact current versions and combines only their canonical evidence union.
          </Text>
          <View style={{ gap: 8 }}>
            {eligible.map((candidate) => {
              const checked = selected.includes(candidate.candidate_id);
              const selectionDisabled = disabled || preparing || submitting || (!checked && selected.length >= 16);
              return (
                <Pressable
                  key={candidate.candidate_id}
                  accessibilityLabel={`${checked ? "Selected" : "Select"} ${candidate.title} for merge`}
                  accessibilityRole="checkbox"
                  accessibilityState={{ checked, disabled: selectionDisabled }}
                  disabled={selectionDisabled}
                  onPress={() => toggle(candidate.candidate_id)}
                  style={({ pressed }) => ({
                    minHeight: 44,
                    borderColor: checked ? colors.primary : colors.separator,
                    borderWidth: checked ? 2 : 1,
                    borderRadius: 12,
                    borderCurve: "continuous",
                    padding: 11,
                    flexDirection: "row",
                    alignItems: "center",
                    gap: 10,
                    opacity: selectionDisabled ? 0.5 : pressed ? 0.65 : 1,
                  })}
                >
                  <Text accessibilityElementsHidden style={{ color: checked ? colors.primary : colors.tertiaryLabel, fontSize: 18, fontWeight: "900" }}>{checked ? "✓" : "○"}</Text>
                  <Text selectable style={{ color: colors.label, fontWeight: "700", flex: 1 }}>{candidate.title}</Text>
                </Pressable>
              );
            })}
          </View>
          <Text selectable style={{ color: colors.tertiaryLabel, fontVariant: ["tabular-nums"] }}>{selected.length} of 16 selected</Text>
          <ActionButton
            label="Prepare combined draft"
            disabled={disabled || selected.length < 2}
            loading={preparing}
            onPress={() => void prepare()}
          />
        </>
      ) : (
        <>
          <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
            This editable suggestion combines {prepared.sources.length} exact source tickets. Review every field before the separate confirmation.
          </Text>
          <CandidateReplacementDraftFields
            canRemove={false}
            disabled={disabled || submitting}
            draft={prepared.draft}
            index={0}
            onChange={(draft) => setPrepared({ ...prepared, draft })}
            onRemove={() => undefined}
          />
          <ActionButton label="Review and create combined draft" disabled={disabled} loading={submitting} onPress={confirm} />
          <Pressable
            accessibilityRole="button"
            disabled={submitting}
            onPress={() => { setPrepared(null); setError(null); }}
            style={{ minHeight: 44, justifyContent: "center", alignItems: "center" }}
          >
            <Text style={{ color: colors.primary, fontWeight: "800" }}>Cancel merge</Text>
          </Pressable>
        </>
      )}
      {error ? <Text selectable accessibilityRole="alert" style={{ color: colors.red, lineHeight: 20 }}>{error}</Text> : null}
    </SectionCard>
  );
}
