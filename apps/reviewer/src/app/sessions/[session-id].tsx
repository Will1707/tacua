// SPDX-License-Identifier: Apache-2.0

import { Link, useLocalSearchParams } from "expo-router";
import { useCallback, useEffect, useState } from "react";
import { ActivityIndicator, Pressable, RefreshControl, ScrollView, Text, View } from "react-native";

import type { CaptureSession, TicketCandidate } from "@/api/types";
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
  const [candidates, setCandidates] = useState<readonly TicketCandidate[]>([]);
  const [candidateError, setCandidateError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!client || !sessionId) return;
    setLoading(true);
    setError(null);
    try {
      const loaded = await client.getSession(sessionId);
      setSession(loaded);
      setCandidateError(null);
      try {
        setCandidates(await client.listCandidates(sessionId));
      } catch (caught) {
        setCandidates([]);
        setCandidateError(caught instanceof Error ? caught.message : "Ticket candidates could not be loaded.");
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Tacua could not load this session.");
    } finally {
      setLoading(false);
    }
  }, [client, sessionId]);

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

      <SectionCard title="Ticket candidates" trailing={<Text selectable style={{ color: colors.secondaryLabel, fontVariant: ["tabular-nums"] }}>{candidates.length}</Text>}>
        {candidateError ? <Text selectable style={{ color: colors.red }}>Candidate state is unavailable: {candidateError}</Text> : null}
        {!candidateError && candidates.length === 0 ? <Text selectable style={{ color: colors.secondaryLabel }}>Candidates will appear after processing. Approval always requires a human action.</Text> : null}
        {candidates.map((candidate) => (
          <Link key={candidate.candidate_id} href={{ pathname: "/candidates/[candidate-id]", params: { "candidate-id": candidate.candidate_id } }} asChild>
            <Link.Trigger>
              <Pressable style={({ pressed }) => ({ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 12, opacity: pressed ? 0.65 : 1, gap: 7 })}>
                <View style={{ flexDirection: "row", alignItems: "flex-start", gap: 10 }}>
                  <Text selectable style={{ color: colors.label, fontWeight: "700", flex: 1 }}>{candidate.content.title}</Text>
                  <StatusPill value={candidate.state} />
                </View>
                <Text selectable numberOfLines={2} style={{ color: colors.secondaryLabel }}>{candidate.content.summary}</Text>
              </Pressable>
            </Link.Trigger>
            <Link.Preview />
          </Link>
        ))}
      </SectionCard>
    </ScrollView>
  );
}
