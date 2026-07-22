// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from "react";
import { Linking, Pressable, Text, View } from "react-native";

import { TacuaApiError, type TacuaApiClient } from "@/api/client";
import { launchCodeRetentionMilliseconds } from "@/api/launch-code-retention";
import { buildLaunchURL } from "@/api/launch-grant-validation";
import type { RegisteredBuild, StartLaunchGrant } from "@/api/types";
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
  const [grant, setGrant] = useState<StartLaunchGrant | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const loadRequestSequence = useRef(0);
  const launchRequestSequence = useRef(0);
  const launchInFlightRef = useRef(false);
  const bindingRef = useRef({ client, targetScheme });
  bindingRef.current = { client, targetScheme };

  const loadBuilds = useCallback(async () => {
    const requestId = loadRequestSequence.current + 1;
    loadRequestSequence.current = requestId;
    setLoading(true);
    setLoadError(null);
    try {
      const loaded = await client.listBuilds();
      if (requestId !== loadRequestSequence.current || bindingRef.current.client !== client) return;
      setBuilds(loaded);
    } catch (caught) {
      if (requestId !== loadRequestSequence.current || bindingRef.current.client !== client) return;
      setBuilds([]);
      setLoadError(caught instanceof Error ? caught.message : "Tacua could not load the registered QA build.");
    } finally {
      if (requestId === loadRequestSequence.current && bindingRef.current.client === client) setLoading(false);
    }
  }, [client]);

  useEffect(() => {
    // A live code is bound to both the issuing backend client and the target
    // application scheme. Never carry it across either configuration change.
    launchRequestSequence.current += 1;
    launchInFlightRef.current = false;
    setLaunchingBuildId(null);
    setGrant(null);
    setLaunchError(null);
  }, [client, targetScheme]);
  useEffect(() => () => {
    loadRequestSequence.current += 1;
    launchRequestSequence.current += 1;
    launchInFlightRef.current = false;
  }, []);
  useEffect(() => { void loadBuilds(); }, [loadBuilds]);
  useEffect(() => {
    if (!grant) return;
    // Creating the state never delays the immediate open attempt below. This
    // timer only bounds how long the retry affordance retains the live code.
    const timer = setTimeout(
      () => setGrant(null),
      launchCodeRetentionMilliseconds(grant.expires_at),
    );
    return () => clearTimeout(timer);
  }, [grant]);

  const openGrant = useCallback(async (nextGrant: StartLaunchGrant) => {
    const launchUrl = buildLaunchURL(targetScheme, nextGrant.launch_code);
    try {
      await Linking.openURL(launchUrl);
    } catch {
      throw new TacuaApiError(0, "QA_BUILD_UNAVAILABLE", "The registered QA app could not be opened on this device.");
    }
  }, [targetScheme]);

  async function start(build: RegisteredBuild) {
    if (
      launchInFlightRef.current
      || bindingRef.current.client !== client
      || bindingRef.current.targetScheme !== targetScheme
    ) return;
    launchInFlightRef.current = true;
    const requestId = launchRequestSequence.current + 1;
    launchRequestSequence.current = requestId;
    const requestClient = client;
    const requestScheme = targetScheme;
    const isCurrentRequest = () => (
      requestId === launchRequestSequence.current
      && bindingRef.current.client === requestClient
      && bindingRef.current.targetScheme === requestScheme
    );
    setLaunchingBuildId(build.build_id);
    setGrant(null);
    setLaunchError(null);
    try {
      const nextGrant = await requestClient.createLaunchGrant(build.build_id);
      if (!isCurrentRequest()) return;
      if (nextGrant.build_identity_digest !== build.build_identity_digest) {
        throw new TacuaApiError(502, "BUILD_BINDING_MISMATCH", "The launch grant was issued for another build.");
      }
      setGrant(nextGrant);
      await openGrant(nextGrant);
    } catch (caught) {
      if (isCurrentRequest()) {
        setLaunchError(caught instanceof Error ? caught.message : "Tacua could not start this review.");
      }
    } finally {
      if (isCurrentRequest()) {
        launchInFlightRef.current = false;
        setLaunchingBuildId(null);
      }
    }
  }

  async function retryGrant(nextGrant: StartLaunchGrant) {
    if (
      launchInFlightRef.current
      || bindingRef.current.client !== client
      || bindingRef.current.targetScheme !== targetScheme
      || grant?.launch_id !== nextGrant.launch_id
    ) return;
    launchInFlightRef.current = true;
    const requestId = launchRequestSequence.current + 1;
    launchRequestSequence.current = requestId;
    const requestClient = client;
    const requestScheme = targetScheme;
    const isCurrentRequest = () => (
      requestId === launchRequestSequence.current
      && bindingRef.current.client === requestClient
      && bindingRef.current.targetScheme === requestScheme
    );
    setLaunchingBuildId(nextGrant.launch_id);
    setLaunchError(null);
    try {
      await openGrant(nextGrant);
    } catch (caught) {
      if (isCurrentRequest()) {
        setLaunchError(caught instanceof Error ? caught.message : "The QA app could not be opened.");
      }
    } finally {
      if (isCurrentRequest()) {
        launchInFlightRef.current = false;
        setLaunchingBuildId(null);
      }
    }
  }

  return (
    <SectionCard title="Start a review">
      <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
        Tacua opens the registered QA build. That app shows the exact consent screen before app-only recording or upload begins, and capture stops after 30 minutes.
      </Text>
      {loading ? <Text selectable style={{ color: colors.tertiaryLabel }}>Loading registered builds…</Text> : null}
      {!loading && builds.length === 0 && !loadError ? (
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
          <Pressable
            accessibilityRole="button"
            accessibilityState={{ disabled: launchingBuildId !== null }}
            disabled={launchingBuildId !== null}
            onPress={() => void retryGrant(grant)}
            style={{ minHeight: 44, justifyContent: "center", opacity: launchingBuildId !== null ? 0.5 : 1 }}
          >
            <Text style={{ color: colors.primary, fontWeight: "800" }}>Try opening the QA build again</Text>
          </Pressable>
        </View>
      ) : null}
      {loadError ? (
        <View style={{ gap: 7 }}>
          <Text selectable accessibilityRole="alert" style={{ color: colors.orange, lineHeight: 20 }}>{loadError}</Text>
          <Pressable accessibilityRole="button" accessibilityState={{ disabled: loading }} disabled={loading} onPress={() => void loadBuilds()} style={{ minHeight: 44, justifyContent: "center" }}>
            <Text style={{ color: colors.primary, fontWeight: "800" }}>Reload registered builds</Text>
          </Pressable>
        </View>
      ) : null}
      {launchError ? <Text selectable accessibilityRole="alert" style={{ color: colors.orange, lineHeight: 20 }}>{launchError}</Text> : null}
    </SectionCard>
  );
}
