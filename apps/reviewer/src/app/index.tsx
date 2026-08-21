// SPDX-License-Identifier: Apache-2.0

import { Link } from "expo-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, Pressable, RefreshControl, ScrollView, Text, View } from "react-native";

import type { TacuaApiClient } from "@/api/client";
import type { CaptureSession, ReviewerBootstrap } from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { LaunchReviewCard } from "@/components/launch-review-card";
import { MessageState } from "@/components/message-state";
import { StatusPill } from "@/components/status-pill";
import { useBackend } from "@/hooks/use-backend";
import { colors } from "@/theme/colors";
import { formatDate } from "@/utils/format";

export default function ReviewsRoute() {
  const {
    client,
    config,
    session,
    bootstrap,
    status,
    pairing,
    error: backendError,
    migrationRequired,
    reload: reloadBackend,
    beginPairing,
    cancelPairing,
  } = useBackend();
  const [sessions, setSessions] = useState<readonly CaptureSession[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [loadedClient, setLoadedClient] = useState<TacuaApiClient | null>(null);
  const [loadedBootstrap, setLoadedBootstrap] = useState<ReviewerBootstrap | null>(null);
  const refreshGeneration = useRef(0);
  const pageRequestGeneration = useRef(0);
  const loadingMoreRef = useRef(false);
  const currentConnectionRef = useRef({ bootstrap, client, status });
  currentConnectionRef.current = { bootstrap, client, status };

  const refresh = useCallback(async () => {
    if (status !== "connected" || !client || !bootstrap) return;
    const requestClient = client;
    const requestBootstrap = bootstrap;
    const generation = ++refreshGeneration.current;
    const isCurrent = () => generation === refreshGeneration.current
      && currentConnectionRef.current.status === "connected"
      && currentConnectionRef.current.client === requestClient
      && currentConnectionRef.current.bootstrap === requestBootstrap;
    ++pageRequestGeneration.current;
    loadingMoreRef.current = false;
    setLoadedClient(requestClient);
    setLoadedBootstrap(requestBootstrap);
    setLoading(true);
    setLoadingMore(false);
    setError(null);
    setPageError(null);
    try {
      const page = await requestClient.listSessions();
      if (!isCurrent()) return;
      setSessions(page.sessions);
      setNextCursor(page.next_cursor);
    } catch (caught) {
      if (!isCurrent()) return;
      setError(caught instanceof Error ? caught.message : "Tacua could not load review sessions.");
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [bootstrap, client, status]);

  const loadMore = useCallback(async () => {
    if (
      status !== "connected"
      || !client
      || !bootstrap
      || loadedClient !== client
      || loadedBootstrap !== bootstrap
      || !nextCursor
      || loading
      || loadingMoreRef.current
    ) return;
    const requestClient = client;
    const requestBootstrap = bootstrap;
    const refreshAtStart = refreshGeneration.current;
    const requestGeneration = ++pageRequestGeneration.current;
    const isCurrent = () => refreshAtStart === refreshGeneration.current
      && requestGeneration === pageRequestGeneration.current
      && currentConnectionRef.current.status === "connected"
      && currentConnectionRef.current.client === requestClient
      && currentConnectionRef.current.bootstrap === requestBootstrap;
    loadingMoreRef.current = true;
    setLoadingMore(true);
    setPageError(null);
    try {
      const page = await requestClient.listSessions(nextCursor);
      if (!isCurrent()) return;
      setSessions((current) => {
        const known = new Set(current.map((session) => session.session_id));
        return [...current, ...page.sessions.filter((session) => !known.has(session.session_id))];
      });
      setNextCursor(page.next_cursor);
    } catch (caught) {
      if (isCurrent()) {
        setPageError(caught instanceof Error ? caught.message : "Tacua could not load more review sessions.");
      }
    } finally {
      if (isCurrent()) {
        loadingMoreRef.current = false;
        setLoadingMore(false);
      }
    }
  }, [bootstrap, client, loadedBootstrap, loadedClient, loading, nextCursor, status]);

  useEffect(() => {
    // Route-local records are confidential to one authenticated client
    // generation. Clear them when auth disappears or the provider activates a
    // replacement backend before starting that generation's first load.
    ++refreshGeneration.current;
    ++pageRequestGeneration.current;
    loadingMoreRef.current = false;
    setLoadedClient(null);
    setLoadedBootstrap(null);
    setSessions([]);
    setNextCursor(null);
    setLoading(false);
    setLoadingMore(false);
    setError(null);
    setPageError(null);
    if (status === "connected" && client && bootstrap) void refresh();
    return () => {
      ++refreshGeneration.current;
      ++pageRequestGeneration.current;
      loadingMoreRef.current = false;
    };
  }, [bootstrap, client, refresh, status]);

  const dataIsCurrent = status === "connected"
    && client !== null
    && bootstrap !== null
    && loadedClient === client
    && loadedBootstrap === bootstrap;
  const visibleSessions = dataIsCurrent ? sessions : [];
  const visibleNextCursor = dataIsCurrent ? nextCursor : null;
  const visibleError = dataIsCurrent ? error : null;
  const visiblePageError = dataIsCurrent ? pageError : null;
  const visibleLoading = loading || (status === "connected" && !dataIsCurrent);

  if (status === "loading") return <View accessible accessibilityLabel="Verifying reviewer access" accessibilityRole="progressbar" style={{ flex: 1, justifyContent: "center" }}><ActivityIndicator /></View>;
  if (status !== "connected" || !config || !client || !session || !bootstrap) {
    const title = status === "endpoint_required"
      ? "Choose your Tacua backend"
      : status === "pairing_pending"
        ? "Approve reviewer pairing"
        : migrationRequired
          ? "Server update required"
          : status === "error"
            ? "Could not connect to Tacua"
            : "Pair this reviewer";
    const detail = backendError ?? (status === "endpoint_required"
      ? "Enter the HTTPS endpoint once. Tacua will discover the reviewer identity and QA launch scheme from the backend."
      : status === "pairing_pending" && pairing !== null
        ? `Approve code ${pairing.human_code} on the backend host. Tacua will connect automatically when approval succeeds.`
        : "Use a Tailscale app capability for automatic access, or request a short-lived pairing code. No administrator token is entered in Tacua.");
    return (
      <ScrollView contentInsetAdjustmentBehavior="automatic" contentContainerStyle={{ padding: 20, gap: 12 }}>
        <MessageState title={title} detail={detail} />
        {status === "pairing_required" && !migrationRequired ? (
          <ActionButton label="Request pairing code" onPress={() => void beginPairing()} />
        ) : null}
        {status === "pairing_pending" ? (
          <ActionButton destructive label="Cancel pairing" onPress={cancelPairing} />
        ) : null}
        {status === "error" ? <ActionButton label="Try again" onPress={() => void reloadBackend()} /> : null}
        <Link href="/settings" asChild>
          <Pressable accessibilityRole="link" style={{ backgroundColor: colors.primary, minHeight: 44, borderRadius: 12, borderCurve: "continuous", alignItems: "center", justifyContent: "center", paddingHorizontal: 16, paddingVertical: 10 }}>
            <Text style={{ color: colors.onPrimary, fontWeight: "700", fontSize: 16, textAlign: "center" }}>
              {status === "endpoint_required" ? "Set backend endpoint" : "Connection settings"}
            </Text>
          </Pressable>
        </Link>
      </ScrollView>
    );
  }

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      refreshControl={<RefreshControl refreshing={visibleLoading} onRefresh={() => void reloadBackend()} />}
      contentContainerStyle={{ padding: 16, gap: 12 }}
    >
      <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "flex-start", gap: 8, paddingBottom: 4 }}>
        <Text selectable style={{ color: colors.secondaryLabel, flex: 1 }}>{config.baseUrl}</Text>
        <Link href="/settings" asChild>
          <Pressable accessibilityRole="link" hitSlop={4} style={{ minHeight: 44, minWidth: 44, justifyContent: "center", alignItems: "flex-end", paddingHorizontal: 4 }}>
            <Text style={{ color: colors.primary, fontWeight: "700" }}>Settings</Text>
          </Pressable>
        </Link>
      </View>
      <LaunchReviewCard client={client} bootstrap={bootstrap} />
      {visibleError ? (
        <MessageState
          title={visibleSessions.length ? "Could not refresh sessions" : "Could not load sessions"}
          detail={visibleSessions.length
            ? `${visibleError} Previously loaded sessions remain below; pull down to verify them again.`
            : visibleError}
        />
      ) : null}
      {!visibleError && !visibleLoading && visibleSessions.length === 0 ? <MessageState title="No review sessions yet" detail="A session will appear here after the QA build exchanges a launch code with this backend." /> : null}
      {visibleSessions.map((session) => (
        <Link key={session.session_id} href={{ pathname: "/sessions/[session-id]", params: { "session-id": session.session_id } }} asChild>
          <Link.Trigger>
            <Pressable style={({ pressed }) => ({ backgroundColor: colors.secondaryBackground, borderColor: colors.separator, borderWidth: 1, borderRadius: 16, borderCurve: "continuous", padding: 16, gap: 10, opacity: pressed ? 0.7 : 1 })}>
              <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                <View style={{ flex: 1, gap: 3 }}>
                  <Text selectable style={{ color: colors.label, fontSize: 17, fontWeight: "700" }}>{session.build_id}</Text>
                  <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13 }}>{session.application_id}</Text>
                </View>
                <StatusPill value={session.state} />
              </View>
              <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 13, fontVariant: ["tabular-nums"] }}>{formatDate(session.created_at)}</Text>
            </Pressable>
          </Link.Trigger>
          <Link.Preview />
        </Link>
      ))}
      {visiblePageError ? <MessageState title="Could not load more sessions" detail={visiblePageError} /> : null}
      {visibleNextCursor ? <ActionButton label="Load 50 more sessions" onPress={() => void loadMore()} loading={loadingMore} disabled={visibleLoading} /> : null}
    </ScrollView>
  );
}
