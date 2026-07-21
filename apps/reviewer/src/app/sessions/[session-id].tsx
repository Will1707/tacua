// SPDX-License-Identifier: Apache-2.0

import { Link, useLocalSearchParams } from "expo-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, Pressable, RefreshControl, ScrollView, Text, View } from "react-native";

import type { CaptureSession, TicketCandidateSummary } from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { MessageState } from "@/components/message-state";
import { SectionCard } from "@/components/section-card";
import { StatusPill } from "@/components/status-pill";
import { useBackend } from "@/hooks/use-backend";
import { colors } from "@/theme/colors";
import { formatBytes, formatDate } from "@/utils/format";

export default function SessionRoute() {
  const { "session-id": sessionId } = useLocalSearchParams<{ "session-id": string }>();
  const { client } = useBackend();
  const [session, setSession] = useState<CaptureSession | null>(null);
  const [candidates, setCandidates] = useState<readonly TicketCandidateSummary[]>([]);
  const [nextCandidateCursor, setNextCandidateCursor] = useState<string | null>(null);
  const [candidateError, setCandidateError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMoreCandidates, setLoadingMoreCandidates] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const refreshGeneration = useRef(0);
  const pageRequestGeneration = useRef(0);
  const loadingMoreRef = useRef(false);

  const refresh = useCallback(async () => {
    if (!client || !sessionId) return;
    const generation = ++refreshGeneration.current;
    ++pageRequestGeneration.current;
    loadingMoreRef.current = false;
    setLoading(true);
    setLoadingMoreCandidates(false);
    setError(null);
    try {
      const loaded = await client.getSession(sessionId);
      if (generation !== refreshGeneration.current) return;
      setSession(loaded);
      setCandidateError(null);
      try {
        const page = await client.listCandidates(sessionId);
        if (generation !== refreshGeneration.current) return;
        setCandidates(page.candidates);
        setNextCandidateCursor(page.next_cursor);
      } catch (caught) {
        if (generation !== refreshGeneration.current) return;
        setCandidates([]);
        setNextCandidateCursor(null);
        setCandidateError(caught instanceof Error ? caught.message : "Ticket candidates could not be loaded.");
      }
    } catch (caught) {
      if (generation !== refreshGeneration.current) return;
      setError(caught instanceof Error ? caught.message : "Tacua could not load this session.");
    } finally {
      if (generation === refreshGeneration.current) setLoading(false);
    }
  }, [client, sessionId]);

  const loadMoreCandidates = useCallback(async () => {
    if (!client || !sessionId || !nextCandidateCursor || loading || loadingMoreRef.current) return;
    const refreshAtStart = refreshGeneration.current;
    const requestGeneration = ++pageRequestGeneration.current;
    loadingMoreRef.current = true;
    setLoadingMoreCandidates(true);
    setCandidateError(null);
    try {
      const page = await client.listCandidates(sessionId, nextCandidateCursor);
      if (
        refreshAtStart !== refreshGeneration.current
        || requestGeneration !== pageRequestGeneration.current
      ) return;
      setCandidates((current) => {
        const known = new Set(current.map((candidate) => candidate.candidate_id));
        return [...current, ...page.candidates.filter((candidate) => !known.has(candidate.candidate_id))];
      });
      setNextCandidateCursor(page.next_cursor);
    } catch (caught) {
      if (
        refreshAtStart === refreshGeneration.current
        && requestGeneration === pageRequestGeneration.current
      ) {
        setCandidateError(caught instanceof Error ? caught.message : "More ticket candidates could not be loaded.");
      }
    } finally {
      if (requestGeneration === pageRequestGeneration.current) {
        loadingMoreRef.current = false;
        setLoadingMoreCandidates(false);
      }
    }
  }, [client, loading, nextCandidateCursor, sessionId]);

  useEffect(() => { void refresh(); }, [refresh]);
  if (!session && loading) return <View style={{ flex: 1, justifyContent: "center" }}><ActivityIndicator /></View>;
  if (!session) return <ScrollView contentInsetAdjustmentBehavior="automatic"><MessageState title="Session unavailable" detail={error ?? "The session was not found."} /></ScrollView>;

  return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" refreshControl={<RefreshControl refreshing={loading} onRefresh={() => void refresh()} />} contentContainerStyle={{ padding: 16, gap: 14 }}>
      <SectionCard title={session.build_id} trailing={<StatusPill value={session.state} />}>
        <Text selectable style={{ color: colors.secondaryLabel }}>{session.application_id}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontVariant: ["tabular-nums"] }}>Started {formatDate(session.created_at)}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontVariant: ["tabular-nums"] }}>Raw media expires {formatDate(session.retention.raw_media_expires_at)}</Text>
      </SectionCard>

      <SectionCard title="Captured evidence">
        <Text selectable style={{ color: colors.label }}>{session.segments?.length ?? 0} verified media segments</Text>
        <Text selectable style={{ color: colors.label }}>{session.diagnostics?.length ?? 0} diagnostic envelopes</Text>
        {(session.segments ?? []).map((receipt) => (
          <View key={receipt.segment_id} style={{ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 10, gap: 2 }}>
            <Text selectable style={{ color: colors.label, fontWeight: "600" }}>{receipt.segment_id}</Text>
            <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13 }}>{formatBytes(receipt.size_bytes)} · {receipt.content_digest.slice(0, 22)}…</Text>
          </View>
        ))}
      </SectionCard>

      <SectionCard title="Processing">
        {(session.jobs ?? []).length === 0 ? <Text selectable style={{ color: colors.secondaryLabel }}>No processing job has been queued.</Text> : null}
        {(session.jobs ?? []).map((job) => (
          <View key={job.job_id} style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <View style={{ flex: 1, gap: 2 }}>
              <Text selectable style={{ color: colors.label, fontWeight: "600" }}>{job.job_type ?? "process session"}</Text>
              <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 13 }}>{formatDate(job.requested_at)}</Text>
            </View>
            <StatusPill value={job.status} />
          </View>
        ))}
      </SectionCard>

      <SectionCard title="Ticket candidates" trailing={<Text selectable style={{ color: colors.secondaryLabel, fontVariant: ["tabular-nums"] }}>{candidates.length}{nextCandidateCursor ? "+" : ""}</Text>}>
        {candidateError ? <Text selectable style={{ color: colors.red }}>Candidate state is unavailable: {candidateError}</Text> : null}
        {!candidateError && candidates.length === 0 ? <Text selectable style={{ color: colors.secondaryLabel }}>Candidates will appear after processing. Approval always requires a human action.</Text> : null}
        {candidates.map((candidate) => (
          <Link key={candidate.candidate_id} href={{ pathname: "/candidates/[candidate-id]", params: { "candidate-id": candidate.candidate_id } }} asChild>
            <Link.Trigger>
              <Pressable style={({ pressed }) => ({ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 12, opacity: pressed ? 0.65 : 1, gap: 7 })}>
                <View style={{ flexDirection: "row", alignItems: "flex-start", gap: 10 }}>
                  <Text selectable style={{ color: colors.label, fontWeight: "700", flex: 1 }}>{candidate.title}</Text>
                  <StatusPill value={candidate.state} />
                </View>
                <Text selectable numberOfLines={2} style={{ color: colors.secondaryLabel }}>{candidate.summary}</Text>
              </Pressable>
            </Link.Trigger>
            <Link.Preview />
          </Link>
        ))}
        {nextCandidateCursor ? <ActionButton label="Load 50 more candidates" onPress={() => void loadMoreCandidates()} loading={loadingMoreCandidates} disabled={loading} /> : null}
      </SectionCard>
    </ScrollView>
  );
}
