// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useState } from "react";
import { Linking, Pressable, Text, View } from "react-native";

import { TacuaApiError, type TacuaApiClient } from "@/api/client";
import type { LaunchGrant, RegisteredBuild } from "@/api/types";
import { SectionCard } from "@/components/section-card";
import { colors } from "@/theme/colors";
import { formatDate } from "@/utils/format";

type Props = {
  readonly client: TacuaApiClient;
  readonly targetScheme: string;
};

export function LaunchReviewCard({ client, targetScheme }: Props) {
  const [builds, setBuilds] = useState<readonly RegisteredBuild[]>([]);
  const [loading, setLoading] = useState(true);
  const [launchingBuildId, setLaunchingBuildId] = useState<string | null>(null);
  const [grant, setGrant] = useState<LaunchGrant | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadBuilds = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setBuilds(await client.listBuilds());
    } catch (caught) {
      setBuilds([]);
      setError(caught instanceof Error ? caught.message : "Tacua could not load the registered QA build.");
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => { void loadBuilds(); }, [loadBuilds]);
  useEffect(() => {
    if (!grant) return;
    const remaining = Date.parse(grant.expires_at) - Date.now();
    // The backend enforces expiry. A skewed reviewer wall clock must not stop
    // an otherwise-valid code from being opened immediately.
    if (remaining <= 0) return;
    const timer = setTimeout(() => setGrant(null), Math.min(remaining, 2_147_483_647));
    return () => clearTimeout(timer);
  }, [grant]);

  const openGrant = useCallback(async (nextGrant: LaunchGrant) => {
    const launchUrl = `${targetScheme}://tacua/start?launch_code=${encodeURIComponent(nextGrant.launch_code)}`;
    try {
      await Linking.openURL(launchUrl);
    } catch {
      throw new TacuaApiError(0, "QA_BUILD_UNAVAILABLE", "The registered QA app could not be opened on this device.");
    }
  }, [targetScheme]);

  async function start(build: RegisteredBuild) {
    setLaunchingBuildId(build.build_id);
    setGrant(null);
    setError(null);
    try {
      const nextGrant = await client.createLaunchGrant(build.build_id);
      if (nextGrant.build_identity_digest !== build.build_identity_digest) {
        throw new TacuaApiError(502, "BUILD_BINDING_MISMATCH", "The launch grant was issued for another build.");
      }
      setGrant(nextGrant);
      await openGrant(nextGrant);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Tacua could not start this review.");
    } finally {
      setLaunchingBuildId(null);
    }
  }

  return (
    <SectionCard title="Start a review">
      <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
        Tacua opens the registered QA build. That app shows the exact consent screen before app-only recording or upload begins, and capture stops after 30 minutes.
      </Text>
      {loading ? <Text selectable style={{ color: colors.tertiaryLabel }}>Loading registered builds…</Text> : null}
      {!loading && builds.length === 0 && !error ? (
        <Text selectable style={{ color: colors.orange }}>This deployment has no registered iOS QA build.</Text>
      ) : null}
      {builds.map((build) => {
        const launching = launchingBuildId === build.build_id;
        return (
          <Pressable
            key={build.build_id}
            accessibilityRole="button"
            accessibilityState={{ busy: launching, disabled: launchingBuildId !== null }}
            disabled={launchingBuildId !== null}
            onPress={() => void start(build)}
            style={({ pressed }) => ({
              borderColor: colors.separator,
              borderWidth: 1,
              borderRadius: 14,
              borderCurve: "continuous",
              padding: 13,
              gap: 5,
              opacity: launchingBuildId !== null ? 0.55 : pressed ? 0.7 : 1,
            })}
          >
            <View style={{ flexDirection: "row", alignItems: "flex-start", gap: 10 }}>
              <View style={{ flex: 1, gap: 3 }}>
                <Text selectable style={{ color: colors.label, fontWeight: "800", fontSize: 16 }}>{build.application_id}</Text>
                <Text selectable style={{ color: colors.secondaryLabel }}>
                  {build.native_version} ({build.native_build}) · {build.distribution}
                </Text>
                <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{build.bundle_identifier}</Text>
              </View>
              <Text style={{ color: colors.primary, fontWeight: "800" }}>{launching ? "Opening…" : "Open"}</Text>
            </View>
          </Pressable>
        );
      })}
      {grant ? (
        <View style={{ backgroundColor: colors.groupedBackground, borderRadius: 12, borderCurve: "continuous", padding: 12, gap: 7 }}>
          <Text selectable style={{ color: colors.label, fontWeight: "700" }}>One-time launch ready</Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13 }}>Expires {formatDate(grant.expires_at)}. The link contains only the short-lived launch code.</Text>
          <Pressable accessibilityRole="button" onPress={() => void openGrant(grant).catch((caught) => setError(caught instanceof Error ? caught.message : "The QA app could not be opened."))}>
            <Text style={{ color: colors.primary, fontWeight: "800" }}>Try opening the QA build again</Text>
          </Pressable>
        </View>
      ) : null}
      {error ? (
        <View style={{ gap: 7 }}>
          <Text selectable style={{ color: colors.orange, lineHeight: 20 }}>{error}</Text>
          {!grant ? (
            <Pressable accessibilityRole="button" disabled={loading} onPress={() => void loadBuilds()}>
              <Text style={{ color: colors.primary, fontWeight: "800" }}>Reload registered builds</Text>
            </Pressable>
          ) : null}
        </View>
      ) : null}
    </SectionCard>
  );
}
