// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from "react";
import { Linking, Platform, Pressable, Text, View } from "react-native";

import { TacuaApiError, type TacuaApiClient } from "@/api/client";
import { launchCodeRetentionMilliseconds } from "@/api/launch-code-retention";
import type {
  ReviewerBootstrap,
  ReviewerBootstrapBuild,
  ReviewerStartLaunchLink,
} from "@/api/types";
import { LaunchQRCode } from "@/components/launch-qr-code";
import { SectionCard } from "@/components/section-card";
import { colors } from "@/theme/colors";
import { formatDate } from "@/utils/format";
import { shouldAttemptSameDeviceLaunch } from "@/utils/launch-device";

type Props = {
  readonly bootstrap: ReviewerBootstrap;
  readonly client: TacuaApiClient;
};

export function LaunchReviewCard({ bootstrap, client }: Props) {
  const [sameDeviceLaunch] = useState(shouldAttemptSameDeviceLaunch);
  const [launchingBuildId, setLaunchingBuildId] = useState<string | null>(null);
  const [launchLink, setLaunchLink] = useState<ReviewerStartLaunchLink | null>(null);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const launchRequestSequence = useRef(0);
  const launchInFlightRef = useRef(false);
  const bindingRef = useRef({ bootstrap, client });
  bindingRef.current = { bootstrap, client };

  useEffect(() => {
    // A live code is bound to the issuing reviewer session and the exact
    // sealed bootstrap projection. Never carry it across either change.
    launchRequestSequence.current += 1;
    launchInFlightRef.current = false;
    setLaunchingBuildId(null);
    setLaunchLink(null);
    setLaunchError(null);
  }, [bootstrap, client]);
  useEffect(() => () => {
    launchRequestSequence.current += 1;
    launchInFlightRef.current = false;
  }, []);
  useEffect(() => {
    if (!launchLink) return;
    // State supplies either the immediate same-device retry or the desktop QR.
    // This timer bounds how long either affordance retains the live code.
    const timer = setTimeout(
      () => setLaunchLink(null),
      launchCodeRetentionMilliseconds(launchLink.grant.expires_at),
    );
    return () => clearTimeout(timer);
  }, [launchLink]);

  const openLaunchLink = useCallback(async (nextLink: ReviewerStartLaunchLink) => {
    try {
      // Open the exact backend-validated URL. The reviewer never reconstructs
      // or guesses a custom app scheme locally.
      await Linking.openURL(nextLink.launch_url);
    } catch {
      throw new TacuaApiError(0, "QA_BUILD_UNAVAILABLE", "The registered QA app could not be opened on this device.");
    }
  }, []);

  async function start(build: ReviewerBootstrapBuild) {
    const launchScheme = build.launch_scheme;
    if (
      launchScheme === null
      || launchInFlightRef.current
      || launchLink !== null
      || bindingRef.current.client !== client
      || bindingRef.current.bootstrap !== bootstrap
    ) return;
    launchInFlightRef.current = true;
    const requestId = launchRequestSequence.current + 1;
    launchRequestSequence.current = requestId;
    const requestBinding = bindingRef.current;
    const isCurrentRequest = () => (
      requestId === launchRequestSequence.current
      && bindingRef.current.client === requestBinding.client
      && bindingRef.current.bootstrap === requestBinding.bootstrap
    );
    setLaunchingBuildId(build.build_id);
    setLaunchLink(null);
    setLaunchError(null);
    try {
      const nextLink = await requestBinding.client.createLaunchLink(
        build.build_id,
        launchScheme,
        build.build_identity_digest,
      );
      if (!isCurrentRequest()) return;
      if (nextLink.grant.build_identity_digest !== build.build_identity_digest) {
        throw new TacuaApiError(502, "BUILD_BINDING_MISMATCH", "The launch link was issued for another build.");
      }
      setLaunchLink(nextLink);
      // Browser URL handlers require a second, synchronous user gesture after
      // this asynchronous request. Native Linking may open immediately.
      if (Platform.OS !== "web") await openLaunchLink(nextLink);
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

  async function retryLaunchLink(nextLink: ReviewerStartLaunchLink) {
    if (
      launchInFlightRef.current
      || bindingRef.current.client !== client
      || bindingRef.current.bootstrap !== bootstrap
      || launchLink?.grant.launch_id !== nextLink.grant.launch_id
      || launchLink.launch_url !== nextLink.launch_url
    ) return;
    launchInFlightRef.current = true;
    const requestId = launchRequestSequence.current + 1;
    launchRequestSequence.current = requestId;
    const requestBinding = bindingRef.current;
    const isCurrentRequest = () => (
      requestId === launchRequestSequence.current
      && bindingRef.current.client === requestBinding.client
      && bindingRef.current.bootstrap === requestBinding.bootstrap
    );
    setLaunchingBuildId(nextLink.grant.launch_id);
    setLaunchError(null);
    try {
      await openLaunchLink(nextLink);
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
        {sameDeviceLaunch
          ? Platform.OS === "web"
            ? "Choose the registered QA build to prepare a one-time launch, then tap Open when it is ready. The app shows the exact consent screen before app-only recording or upload begins."
            : "Choose the registered QA build to open it on this device. The app shows the exact consent screen before app-only recording or upload begins, and capture stops after 30 minutes."
          : "This reviewer is open on a computer. Choose the registered QA build to create a private one-time QR code, then scan it with the iPhone that has the QA build."}
      </Text>
      {bootstrap.builds.length === 0 ? (
        <Text selectable style={{ color: colors.orange }}>This deployment has no registered iOS QA build.</Text>
      ) : null}
      {bootstrap.builds.map((build) => {
        const launching = launchingBuildId === build.build_id;
        const legacyBuild = build.launch_scheme === null;
        const launchUnavailable = launchingBuildId !== null || launchLink !== null || legacyBuild;
        return (
          <View key={build.build_id} style={{ gap: 6 }}>
            <Pressable
              accessibilityLabel={legacyBuild
                ? `${build.application_id} QA build launch unavailable`
                : sameDeviceLaunch
                  ? Platform.OS === "web"
                    ? `Prepare ${build.application_id} QA build launch on this device`
                    : `Open ${build.application_id} QA build on this device`
                  : `Create iPhone launch QR code for ${build.application_id}`}
              accessibilityRole="button"
              accessibilityState={{ busy: launching, disabled: launchUnavailable }}
              disabled={launchUnavailable}
              onPress={() => void start(build)}
              style={({ pressed }) => ({
                borderColor: colors.separator,
                borderWidth: 1,
                borderRadius: 14,
                borderCurve: "continuous",
                padding: 13,
                gap: 5,
                opacity: launchUnavailable ? 0.55 : pressed ? 0.7 : 1,
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
                <Text style={{ color: legacyBuild ? colors.orange : colors.primary, fontWeight: "800" }}>
                  {legacyBuild
                    ? "Upgrade required"
                    : launching
                      ? "Preparing…"
                      : sameDeviceLaunch
                        ? Platform.OS === "web" ? "Prepare" : "Open"
                        : "Create QR"}
                </Text>
              </View>
            </Pressable>
            {legacyBuild ? (
              <Text selectable accessibilityRole="alert" style={{ color: colors.orange, fontSize: 13, lineHeight: 18 }}>
                This legacy QA build does not seal its launch scheme. Rebuild it with Tacua SDK transport 1.2 before launching; existing sessions remain readable.
              </Text>
            ) : null}
          </View>
        );
      })}
      {launchLink ? (
        <View accessibilityLiveRegion="polite" style={{ backgroundColor: colors.groupedBackground, borderRadius: 12, borderCurve: "continuous", padding: 12, gap: 7 }}>
          <Text selectable style={{ color: colors.label, fontWeight: "700" }}>
            {sameDeviceLaunch ? "One-time launch ready" : "Scan on the QA iPhone"}
          </Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13, lineHeight: 18 }}>
            {sameDeviceLaunch
              ? `Expires ${formatDate(launchLink.grant.expires_at)}. The server-provided link contains only the short-lived launch code.`
              : `Open Camera on the iPhone and scan this code. It expires ${formatDate(launchLink.grant.expires_at)}. Custom URL schemes are not exclusive, so keep the QR private until it is used or expires.`}
          </Text>
          {!sameDeviceLaunch ? (
            <>
              <LaunchQRCode launchUrl={launchLink.launch_url} />
              <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13, lineHeight: 18 }}>
                Keep this QR private until it expires. Tacua generates it in this browser and never sends it to a QR service; it contains no administrator credential or backend address.
              </Text>
              <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13, lineHeight: 18 }}>
                If scanning is not available, open this reviewer page on the QA iPhone and choose the build there.
              </Text>
            </>
          ) : null}
          <Pressable
            accessibilityLabel={sameDeviceLaunch
              ? Platform.OS === "web"
                ? "Open the QA build"
                : "Try opening the QA build again"
              : "Open the QA build on this device instead"}
            accessibilityRole="button"
            accessibilityState={{ disabled: launchingBuildId !== null }}
            disabled={launchingBuildId !== null}
            onPress={() => void retryLaunchLink(launchLink)}
            style={{ minHeight: 44, justifyContent: "center", opacity: launchingBuildId !== null ? 0.5 : 1 }}
          >
            <Text style={{ color: colors.primary, fontWeight: "800" }}>
              {sameDeviceLaunch
                ? Platform.OS === "web"
                  ? "Open the QA build"
                  : "Try opening the QA build again"
                : "Open on this device instead"}
            </Text>
          </Pressable>
        </View>
      ) : null}
      {launchError ? <Text selectable accessibilityRole="alert" style={{ color: colors.orange, lineHeight: 20 }}>{launchError}</Text> : null}
    </SectionCard>
  );
}
