// SPDX-License-Identifier: Apache-2.0

import { Link } from "expo-router";
import { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, AppState, Pressable, RefreshControl, ScrollView, Text, View } from "react-native";

import type { CaptureSession } from "@/api/types";
import { LaunchReviewCard } from "@/components/launch-review-card";
import { MessageState } from "@/components/message-state";
import { StatusPill } from "@/components/status-pill";
import { useBackend } from "@/hooks/use-backend";
import { colors } from "@/theme/colors";
import { formatDate } from "@/utils/format";

export default function ReviewsRoute() {
  const { client, config, loading: configLoading } = useBackend();
  const [sessions, setSessions] = useState<readonly CaptureSession[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!client) return;
    setLoading(true);
    setError(null);
    try {
      setSessions(await client.listSessions());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Tacua could not load review sessions.");
    } finally {
      setLoading(false);
    }
  }, [client]);

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

  if (configLoading) return <View style={{ flex: 1, justifyContent: "center" }}><ActivityIndicator /></View>;
  if (!config || !client) {
    return (
      <ScrollView contentInsetAdjustmentBehavior="automatic" contentContainerStyle={{ padding: 20 }}>
        <MessageState title="Connect your Tacua backend" detail="Configure the HTTPS endpoint and mounted administrator credential for this single-organization deployment." />
        <Link href="/settings" asChild><Pressable style={{ backgroundColor: colors.primary, minHeight: 44, borderRadius: 12, borderCurve: "continuous", alignItems: "center", justifyContent: "center" }}><Text style={{ color: colors.onPrimary, fontWeight: "700", fontSize: 16 }}>Configure backend</Text></Pressable></Link>
      </ScrollView>
    );
  }

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      refreshControl={<RefreshControl refreshing={loading} onRefresh={() => void refresh()} />}
      contentContainerStyle={{ padding: 16, gap: 12 }}
    >
      <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", paddingBottom: 4 }}>
        <Text selectable style={{ color: colors.secondaryLabel, flex: 1 }} numberOfLines={1}>{config.baseUrl}</Text>
        <Link href="/settings" style={{ color: colors.primary, fontWeight: "700" }}>Settings</Link>
      </View>
      <LaunchReviewCard client={client} targetScheme={config.targetScheme} />
      {error ? <MessageState title="Could not load sessions" detail={error} /> : null}
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
    </ScrollView>
  );
}
