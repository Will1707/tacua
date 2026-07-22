// SPDX-License-Identifier: Apache-2.0

import { Link } from "expo-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, AppState, Pressable, RefreshControl, ScrollView, Text, View } from "react-native";

import type { CaptureSession } from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { LaunchReviewCard } from "@/components/launch-review-card";
import { MessageState } from "@/components/message-state";
import { StatusPill } from "@/components/status-pill";
import { useBackend } from "@/hooks/use-backend";
import { colors } from "@/theme/colors";
import { formatDate } from "@/utils/format";

export default function ReviewsRoute() {
  const { client, config, error: backendError, loading: configLoading } = useBackend();
  const [sessions, setSessions] = useState<readonly CaptureSession[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const refreshGeneration = useRef(0);
  const pageRequestGeneration = useRef(0);
  const loadingMoreRef = useRef(false);

  const refresh = useCallback(async () => {
    if (!client) return;
    const generation = ++refreshGeneration.current;
    ++pageRequestGeneration.current;
    loadingMoreRef.current = false;
    setLoading(true);
    setLoadingMore(false);
    setError(null);
    setPageError(null);
    try {
      const page = await client.listSessions();
      if (generation !== refreshGeneration.current) return;
      setSessions(page.sessions);
      setNextCursor(page.next_cursor);
    } catch (caught) {
      if (generation !== refreshGeneration.current) return;
      setError(caught instanceof Error ? caught.message : "Tacua could not load review sessions.");
    } finally {
      if (generation === refreshGeneration.current) setLoading(false);
    }
  }, [client]);

  const loadMore = useCallback(async () => {
    if (!client || !nextCursor || loading || loadingMoreRef.current) return;
    const refreshAtStart = refreshGeneration.current;
    const requestGeneration = ++pageRequestGeneration.current;
    loadingMoreRef.current = true;
    setLoadingMore(true);
    setPageError(null);
    try {
      const page = await client.listSessions(nextCursor);
      if (
        refreshAtStart !== refreshGeneration.current
        || requestGeneration !== pageRequestGeneration.current
      ) return;
      setSessions((current) => {
        const known = new Set(current.map((session) => session.session_id));
        return [...current, ...page.sessions.filter((session) => !known.has(session.session_id))];
      });
      setNextCursor(page.next_cursor);
    } catch (caught) {
      if (
        refreshAtStart === refreshGeneration.current
        && requestGeneration === pageRequestGeneration.current
      ) {
        setPageError(caught instanceof Error ? caught.message : "Tacua could not load more review sessions.");
      }
    } finally {
      if (requestGeneration === pageRequestGeneration.current) {
        loadingMoreRef.current = false;
        setLoadingMore(false);
      }
    }
  }, [client, loading, nextCursor]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const appState = useRef(AppState.currentState);
  useEffect(() => {
    const subscription = AppState.addEventListener("change", (nextState) => {
      const returnedToTacua = appState.current !== "active" && nextState === "active";
      appState.current = nextState;
      if (returnedToTacua) void refresh();
    });
    return () => subscription.remove();
  }, [refresh]);

  if (configLoading) return <View accessible accessibilityLabel="Loading secure backend configuration" accessibilityRole="progressbar" style={{ flex: 1, justifyContent: "center" }}><ActivityIndicator /></View>;
  if (!config || !client) {
    return (
      <ScrollView contentInsetAdjustmentBehavior="automatic" contentContainerStyle={{ padding: 20, gap: 12 }}>
        <MessageState
          title={backendError ? "Secure configuration unavailable" : "Connect your Tacua backend"}
          detail={backendError ?? "Configure the HTTPS endpoint and mounted administrator credential for this single-organization deployment."}
        />
        <Link href="/settings" asChild>
          <Pressable accessibilityRole="link" style={{ backgroundColor: colors.primary, minHeight: 44, borderRadius: 12, borderCurve: "continuous", alignItems: "center", justifyContent: "center", paddingHorizontal: 16, paddingVertical: 10 }}>
            <Text style={{ color: colors.onPrimary, fontWeight: "700", fontSize: 16, textAlign: "center" }}>Configure backend</Text>
          </Pressable>
        </Link>
      </ScrollView>
    );
  }

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      refreshControl={<RefreshControl refreshing={loading} onRefresh={() => void refresh()} />}
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
      <LaunchReviewCard client={client} targetScheme={config.targetScheme} />
      {error ? (
        <MessageState
          title={sessions.length ? "Could not refresh sessions" : "Could not load sessions"}
          detail={sessions.length
            ? `${error} Previously loaded sessions remain below; pull down to verify them again.`
            : error}
        />
      ) : null}
      {!error && !loading && sessions.length === 0 ? <MessageState title="No review sessions yet" detail="A session will appear here after the QA build exchanges a launch code with this backend." /> : null}
      {sessions.map((session) => (
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
      {pageError ? <MessageState title="Could not load more sessions" detail={pageError} /> : null}
      {nextCursor ? <ActionButton label="Load 50 more sessions" onPress={() => void loadMore()} loading={loadingMore} disabled={loading} /> : null}
    </ScrollView>
  );
}
