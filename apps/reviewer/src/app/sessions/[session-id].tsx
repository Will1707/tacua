// SPDX-License-Identifier: Apache-2.0

import { Link, useLocalSearchParams } from "expo-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, Pressable, RefreshControl, ScrollView, Text, View } from "react-native";

import type { TacuaApiClient } from "@/api/client";
import type { CaptureSession, ReviewerBootstrap, TicketCandidateSummary } from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { CandidateMergeCard } from "@/components/candidate-merge-card";
import { MessageState } from "@/components/message-state";
import { ResumeSessionCard } from "@/components/resume-session-card";
import { SectionCard } from "@/components/section-card";
import { StatusPill } from "@/components/status-pill";
import { useBackend } from "@/hooks/use-backend";
import { colors } from "@/theme/colors";
import { formatBytes, formatDate } from "@/utils/format";

export default function SessionRoute() {
  const { "session-id": sessionId } = useLocalSearchParams<{ "session-id": string }>();
  const { bootstrap, client } = useBackend();
  const [storedSession, setSession] = useState<CaptureSession | null>(null);
  const [storedCandidates, setCandidates] = useState<readonly TicketCandidateSummary[]>([]);
  const [storedNextCandidateCursor, setNextCandidateCursor] = useState<string | null>(null);
  const [storedCandidateError, setCandidateError] = useState<string | null>(null);
  const [requestLoading, setLoading] = useState(false);
  const [loadingMoreCandidates, setLoadingMoreCandidates] = useState(false);
  const [storedError, setError] = useState<string | null>(null);
  const [loadedClient, setLoadedClient] = useState<TacuaApiClient | null>(null);
  const [loadedBootstrap, setLoadedBootstrap] = useState<ReviewerBootstrap | null>(null);
  const [loadedSessionId, setLoadedSessionId] = useState<string | null>(null);
  const refreshGeneration = useRef(0);
  const pageRequestGeneration = useRef(0);
  const loadingMoreRef = useRef(false);
  const currentContextRef = useRef({ bootstrap, client, sessionId });
  currentContextRef.current = { bootstrap, client, sessionId };
  const dataIsCurrent = client !== null
    && bootstrap !== null
    && typeof sessionId === "string"
    && loadedClient === client
    && loadedBootstrap === bootstrap
    && loadedSessionId === sessionId;
  const session = dataIsCurrent ? storedSession : null;
  const candidates = dataIsCurrent ? storedCandidates : [];
  const nextCandidateCursor = dataIsCurrent ? storedNextCandidateCursor : null;
  const candidateError = dataIsCurrent ? storedCandidateError : null;
  const error = dataIsCurrent ? storedError : null;
  const loading = requestLoading || (client !== null && typeof sessionId === "string" && !dataIsCurrent);

  const refresh = useCallback(async () => {
    if (!client || !bootstrap || !sessionId) return;
    if (
      currentContextRef.current.client !== client
      || currentContextRef.current.bootstrap !== bootstrap
      || currentContextRef.current.sessionId !== sessionId
    ) return;
    const requestClient = client;
    const requestBootstrap = bootstrap;
    const requestSessionId = sessionId;
    const generation = ++refreshGeneration.current;
    const isCurrent = () => generation === refreshGeneration.current
      && currentContextRef.current.client === requestClient
      && currentContextRef.current.bootstrap === requestBootstrap
      && currentContextRef.current.sessionId === requestSessionId;
    ++pageRequestGeneration.current;
    loadingMoreRef.current = false;
    setLoadedClient(requestClient);
    setLoadedBootstrap(requestBootstrap);
    setLoadedSessionId(requestSessionId);
    setLoading(true);
    setLoadingMoreCandidates(false);
    setError(null);
    try {
      const loaded = await requestClient.getSession(requestSessionId);
      if (!isCurrent()) return;
      setSession(loaded);
      setCandidateError(null);
      try {
        const page = await requestClient.listCandidates(requestSessionId);
        if (!isCurrent()) return;
        setCandidates(page.candidates);
        setNextCandidateCursor(page.next_cursor);
      } catch (caught) {
        if (!isCurrent()) return;
        setCandidates([]);
        setNextCandidateCursor(null);
        setCandidateError(caught instanceof Error ? caught.message : "Ticket candidates could not be loaded.");
      }
    } catch (caught) {
      if (!isCurrent()) return;
      setError(caught instanceof Error ? caught.message : "Tacua could not load this session.");
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [bootstrap, client, sessionId]);

  const loadMoreCandidates = useCallback(async () => {
    if (
      !client
      || !bootstrap
      || !sessionId
      || loadedClient !== client
      || loadedBootstrap !== bootstrap
      || loadedSessionId !== sessionId
      || !storedNextCandidateCursor
      || requestLoading
      || loadingMoreRef.current
    ) return;
    if (
      currentContextRef.current.client !== client
      || currentContextRef.current.bootstrap !== bootstrap
      || currentContextRef.current.sessionId !== sessionId
    ) return;
    const requestClient = client;
    const requestBootstrap = bootstrap;
    const requestSessionId = sessionId;
    const refreshAtStart = refreshGeneration.current;
    const requestGeneration = ++pageRequestGeneration.current;
    const isCurrent = () => refreshAtStart === refreshGeneration.current
      && requestGeneration === pageRequestGeneration.current
      && currentContextRef.current.client === requestClient
      && currentContextRef.current.bootstrap === requestBootstrap
      && currentContextRef.current.sessionId === requestSessionId;
    loadingMoreRef.current = true;
    setLoadingMoreCandidates(true);
    setCandidateError(null);
    try {
      const page = await requestClient.listCandidates(requestSessionId, storedNextCandidateCursor);
      if (!isCurrent()) return;
      setCandidates((current) => {
        const known = new Set(current.map((candidate) => candidate.candidate_id));
        return [...current, ...page.candidates.filter((candidate) => !known.has(candidate.candidate_id))];
      });
      setNextCandidateCursor(page.next_cursor);
    } catch (caught) {
      if (isCurrent()) {
        setCandidateError(caught instanceof Error ? caught.message : "More ticket candidates could not be loaded.");
      }
    } finally {
      if (isCurrent()) {
        loadingMoreRef.current = false;
        setLoadingMoreCandidates(false);
      }
    }
  }, [bootstrap, client, loadedBootstrap, loadedClient, loadedSessionId, requestLoading, sessionId, storedNextCandidateCursor]);

  useEffect(() => {
    // A session projection and its candidate page belong to exactly one
    // authenticated client and route binding. Do not retain them through auth
    // loss or a backend/client replacement.
    ++refreshGeneration.current;
    ++pageRequestGeneration.current;
    loadingMoreRef.current = false;
    setLoadedClient(null);
    setLoadedBootstrap(null);
    setLoadedSessionId(null);
    setSession(null);
    setCandidates([]);
    setNextCandidateCursor(null);
    setCandidateError(null);
    setError(null);
    setLoading(false);
    setLoadingMoreCandidates(false);
    if (client && bootstrap && sessionId) void refresh();
    return () => {
      ++refreshGeneration.current;
      ++pageRequestGeneration.current;
      loadingMoreRef.current = false;
    };
  }, [bootstrap, client, refresh, sessionId]);
  if (!session && loading) return <View accessible accessibilityLabel="Loading review session" accessibilityRole="progressbar" style={{ flex: 1, justifyContent: "center" }}><ActivityIndicator /></View>;
  if (!session) return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" contentContainerStyle={{ padding: 16, gap: 12 }}>
      <MessageState title="Session unavailable" detail={error ?? (client ? "The session was not found." : "A verified backend connection is required.")} />
      {client && sessionId ? <ActionButton label="Retry session" loading={loading} onPress={() => void refresh()} /> : null}
    </ScrollView>
  );

  return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" refreshControl={<RefreshControl refreshing={loading} onRefresh={() => void refresh()} />} contentContainerStyle={{ padding: 16, gap: 14 }}>
      <SectionCard title={session.build_id} trailing={<StatusPill value={session.state} />}>
        <Text selectable style={{ color: colors.secondaryLabel }}>{session.application_id}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontVariant: ["tabular-nums"] }}>Started {formatDate(session.created_at)}</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontVariant: ["tabular-nums"] }}>Raw media expires {formatDate(session.retention.raw_media_expires_at)}</Text>
      </SectionCard>

      {error ? (
        <SectionCard title="Current session not verified">
          <Text selectable accessibilityRole="alert" style={{ color: colors.red, lineHeight: 20 }}>
            {error} Previously loaded details remain visible, but recovery is locked until refresh succeeds.
          </Text>
          <ActionButton label="Retry session refresh" loading={loading} onPress={() => void refresh()} />
        </SectionCard>
      ) : null}

      {client && bootstrap ? (
        <ResumeSessionCard bootstrap={bootstrap} client={client} disabled={loading || error !== null} session={session} />
      ) : null}

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
        {candidateError ? <Text selectable accessibilityRole="alert" style={{ color: colors.red }}>Candidate state is unavailable: {candidateError}</Text> : null}
        {!candidateError && candidates.length === 0 ? <Text selectable style={{ color: colors.secondaryLabel }}>Candidates will appear after processing. Approval always requires a human action.</Text> : null}
        {candidates.map((candidate) => (
          <Link key={candidate.candidate_id} href={{ pathname: "/candidates/[candidate-id]", params: { "candidate-id": candidate.candidate_id } }} asChild>
            <Link.Trigger>
              <Pressable style={({ pressed }) => ({ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 12, opacity: pressed ? 0.65 : 1, gap: 7 })}>
                <View style={{ flexDirection: "row", alignItems: "flex-start", gap: 10 }}>
                  <Text selectable style={{ color: colors.label, fontWeight: "700", flex: 1 }}>{candidate.title}</Text>
                  <StatusPill value={candidate.state} />
                </View>
                <Text selectable style={{ color: colors.secondaryLabel }}>{candidate.summary}</Text>
              </Pressable>
            </Link.Trigger>
            <Link.Preview />
          </Link>
        ))}
        {nextCandidateCursor ? <ActionButton label="Load 50 more candidates" onPress={() => void loadMoreCandidates()} loading={loadingMoreCandidates} disabled={loading || error !== null} /> : null}
      </SectionCard>

      {client && bootstrap && !nextCandidateCursor ? (
        <CandidateMergeCard
          candidates={candidates}
          client={client}
          disabled={loading || error !== null || candidateError !== null}
          reviewerId={bootstrap.reviewer_id}
          onCompleted={refresh}
        />
      ) : null}
      {nextCandidateCursor ? (
        <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 13, lineHeight: 18 }}>
          Load the complete active queue before choosing tickets to merge.
        </Text>
      ) : null}
    </ScrollView>
  );
}
