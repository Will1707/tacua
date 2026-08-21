// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from "react";
import { Linking, Platform, Pressable, Text, View } from "react-native";

import { TacuaApiError, type TacuaApiClient } from "@/api/client";
import { launchCodeRetentionMilliseconds } from "@/api/launch-code-retention";
import type {
  CaptureSession,
  ReviewerBootstrap,
  ReviewerResumeLaunchLink,
} from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { LaunchQRCode } from "@/components/launch-qr-code";
import { SectionCard } from "@/components/section-card";
import { colors } from "@/theme/colors";
import { formatDate } from "@/utils/format";
import { shouldAttemptSameDeviceLaunch } from "@/utils/launch-device";

type Props = {
  readonly bootstrap: ReviewerBootstrap;
  readonly client: TacuaApiClient;
  readonly disabled?: boolean;
  readonly session: CaptureSession;
};

export function ResumeSessionCard({ bootstrap, client, disabled = false, session }: Props) {
  const [sameDeviceLaunch] = useState(shouldAttemptSameDeviceLaunch);
  const build = bootstrap.builds.find((item) => item.build_id === session.build_id) ?? null;
  const buildMatches = build?.build_identity_digest === session.build_identity_digest;
  const launchScheme = buildMatches ? build?.launch_scheme ?? null : null;
  const unavailableReason = build === null
    ? "This session's QA build is not present in the sealed reviewer bootstrap, so recovery is locked."
    : !buildMatches
      ? "This session's build identity does not match the sealed reviewer bootstrap, so recovery is locked."
      : launchScheme === null
        ? "This legacy QA build does not seal its launch scheme. Rebuild it with Tacua SDK transport 1.2 before using recovery."
        : null;
  const [launchLink, setLaunchLink] = useState<ReviewerResumeLaunchLink | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestSequence = useRef(0);
  const requestInFlightRef = useRef(false);
  const bindingRef = useRef({
    bootstrap,
    client,
    disabled,
    sessionId: session.session_id,
    buildIdentityDigest: session.build_identity_digest,
    scopeDigest: session.scope_digest,
    launchScheme,
  });
  bindingRef.current = {
    bootstrap,
    client,
    disabled,
    sessionId: session.session_id,
    buildIdentityDigest: session.build_identity_digest,
    scopeDigest: session.scope_digest,
    launchScheme,
  };

  useEffect(() => {
    // A recovery code is valid only for this exact reviewer session, sealed
    // bootstrap, app scheme, and immutable capture-session binding.
    requestSequence.current += 1;
    requestInFlightRef.current = false;
    setLoading(false);
    setLaunchLink(null);
    setError(null);
  }, [
    bootstrap,
    client,
    disabled,
    launchScheme,
    session.build_identity_digest,
    session.scope_digest,
    session.session_id,
  ]);
  useEffect(() => () => {
    requestSequence.current += 1;
    requestInFlightRef.current = false;
  }, []);

  useEffect(() => {
    if (!launchLink) return;
    const timer = setTimeout(
      () => setLaunchLink(null),
      launchCodeRetentionMilliseconds(launchLink.grant.expires_at),
    );
    return () => clearTimeout(timer);
  }, [launchLink]);

  const openLaunchLink = useCallback(async (nextLink: ReviewerResumeLaunchLink) => {
    try {
      // Open the exact backend-validated URL. The reviewer never reconstructs
      // or guesses a custom app scheme locally.
      await Linking.openURL(nextLink.launch_url);
    } catch {
      throw new TacuaApiError(
        0,
        "QA_BUILD_UNAVAILABLE",
        "The QA app holding this session could not be opened on this device.",
      );
    }
  }, []);

  const openRecovery = useCallback(async () => {
    const currentBinding = bindingRef.current;
    if (
      disabled
      || launchScheme === null
      || requestInFlightRef.current
      || currentBinding.client !== client
      || currentBinding.bootstrap !== bootstrap
      || currentBinding.disabled
      || currentBinding.sessionId !== session.session_id
      || currentBinding.buildIdentityDigest !== session.build_identity_digest
      || currentBinding.scopeDigest !== session.scope_digest
      || currentBinding.launchScheme !== launchScheme
    ) return;
    requestInFlightRef.current = true;
    const requestId = requestSequence.current + 1;
    requestSequence.current = requestId;
    const requestBinding = bindingRef.current;
    const isCurrentRequest = () => {
      const current = bindingRef.current;
      return requestId === requestSequence.current
        && !current.disabled
        && current.client === requestBinding.client
        && current.bootstrap === requestBinding.bootstrap
        && current.sessionId === requestBinding.sessionId
        && current.buildIdentityDigest === requestBinding.buildIdentityDigest
        && current.scopeDigest === requestBinding.scopeDigest
        && current.launchScheme === requestBinding.launchScheme;
    };
    setLoading(true);
    setLaunchLink(null);
    setError(null);
    try {
      const nextLink = await requestBinding.client.createResumeLaunchLink(
        requestBinding.sessionId,
        launchScheme,
        requestBinding.buildIdentityDigest,
      );
      if (!isCurrentRequest()) return;
      if (nextLink.grant.build_identity_digest !== requestBinding.buildIdentityDigest) {
        throw new TacuaApiError(
          502,
          "BUILD_BINDING_MISMATCH",
          "The recovery link was issued for another QA build.",
        );
      }
      if (nextLink.grant.scope_digest !== requestBinding.scopeDigest) {
        throw new TacuaApiError(
          502,
          "SCOPE_BINDING_MISMATCH",
          "The recovery link was issued for another capture scope.",
        );
      }
      setLaunchLink(nextLink);
      // Preserve transient browser activation by requiring a second explicit
      // tap after the asynchronous request settles.
      if (Platform.OS !== "web") await openLaunchLink(nextLink);
    } catch (caught) {
      if (isCurrentRequest()) {
        setError(
          caught instanceof TacuaApiError
            && caught.code === "CREDENTIAL_ROTATION_LIMIT_REACHED"
            ? "This session has used all 64 V1 recovery credentials. Delete it from the backend, then start a new capture."
            : caught instanceof Error
              ? caught.message
              : "Tacua could not open session recovery.",
        );
      }
    } finally {
      if (isCurrentRequest()) {
        requestInFlightRef.current = false;
        setLoading(false);
      }
    }
  }, [
    bootstrap,
    client,
    disabled,
    launchScheme,
    openLaunchLink,
    session.build_identity_digest,
    session.scope_digest,
    session.session_id,
  ]);

  const retryLaunchLink = useCallback(async (nextLink: ReviewerResumeLaunchLink) => {
    const currentBinding = bindingRef.current;
    if (
      disabled
      || launchScheme === null
      || requestInFlightRef.current
      || currentBinding.client !== client
      || currentBinding.bootstrap !== bootstrap
      || currentBinding.disabled
      || currentBinding.sessionId !== session.session_id
      || currentBinding.buildIdentityDigest !== session.build_identity_digest
      || currentBinding.scopeDigest !== session.scope_digest
      || currentBinding.launchScheme !== launchScheme
      || launchLink?.grant.launch_id !== nextLink.grant.launch_id
      || launchLink.launch_url !== nextLink.launch_url
    ) return;
    requestInFlightRef.current = true;
    const requestId = requestSequence.current + 1;
    requestSequence.current = requestId;
    const requestBinding = bindingRef.current;
    const isCurrentRequest = () => {
      const current = bindingRef.current;
      return requestId === requestSequence.current
        && !current.disabled
        && current.client === requestBinding.client
        && current.bootstrap === requestBinding.bootstrap
        && current.sessionId === requestBinding.sessionId
        && current.buildIdentityDigest === requestBinding.buildIdentityDigest
        && current.scopeDigest === requestBinding.scopeDigest
        && current.launchScheme === requestBinding.launchScheme;
    };
    setLoading(true);
    setError(null);
    try {
      await openLaunchLink(nextLink);
    } catch (caught) {
      if (isCurrentRequest()) {
        setError(caught instanceof Error ? caught.message : "The QA app could not be opened.");
      }
    } finally {
      if (isCurrentRequest()) {
        requestInFlightRef.current = false;
        setLoading(false);
      }
    }
  }, [
    bootstrap,
    client,
    disabled,
    launchLink,
    launchScheme,
    openLaunchLink,
    session.build_identity_digest,
    session.scope_digest,
    session.session_id,
  ]);

  const recoveryDisabled = disabled || launchScheme === null;
  return (
    <SectionCard title={sameDeviceLaunch ? "Continue on this device" : "Continue this session"}>
      <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
        {sameDeviceLaunch
          ? "Open the QA build to retry an interrupted upload, submit verified partial capture, complete this session, or delete its local evidence. The one-time link is bound to this exact backend session."
          : "Create a private one-time recovery QR, then scan it with the iPhone that holds this session. The link is bound to this exact backend session."}
      </Text>
      <ActionButton
        label={sameDeviceLaunch
          ? Platform.OS === "web" ? "Prepare QA build recovery" : "Open QA build recovery"
          : "Create recovery QR code"}
        onPress={() => void openRecovery()}
        disabled={recoveryDisabled}
        loading={loading}
      />
      {unavailableReason ? (
        <Text selectable accessibilityRole="alert" style={{ color: colors.orange, lineHeight: 20 }}>
          {unavailableReason}
        </Text>
      ) : null}
      {launchLink ? (
        <View style={{ backgroundColor: colors.groupedBackground, borderRadius: 12, borderCurve: "continuous", padding: 12, gap: 7 }}>
          <Text selectable style={{ color: colors.label, fontWeight: "700" }}>
            {sameDeviceLaunch ? "One-time recovery link ready" : "Scan on the QA iPhone"}
          </Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13 }}>
            Expires {formatDate(launchLink.grant.expires_at)}. It contains no recording or reusable upload credential.
          </Text>
          {!sameDeviceLaunch ? (
            <>
              <LaunchQRCode launchUrl={launchLink.launch_url} />
              <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13, lineHeight: 18 }}>
                Keep this QR private until it expires. Tacua generates it locally and never sends it to a QR service.
              </Text>
            </>
          ) : null}
          <Pressable
            accessibilityLabel={sameDeviceLaunch
              ? Platform.OS === "web"
                ? "Open prepared QA build recovery"
                : "Try opening QA build recovery again"
              : "Open QA build recovery on this device instead"}
            accessibilityRole="button"
            accessibilityState={{ disabled: recoveryDisabled || loading }}
            disabled={recoveryDisabled || loading}
            onPress={() => void retryLaunchLink(launchLink)}
            style={{ minHeight: 44, justifyContent: "center", opacity: recoveryDisabled || loading ? 0.5 : 1 }}
          >
            <Text style={{ color: colors.primary, fontWeight: "800" }}>
              {sameDeviceLaunch
                ? Platform.OS === "web" ? "Open the QA build" : "Try opening again"
                : "Open on this device instead"}
            </Text>
          </Pressable>
        </View>
      ) : null}
      {error ? <Text selectable accessibilityRole="alert" style={{ color: colors.orange, lineHeight: 20 }}>{error}</Text> : null}
    </SectionCard>
  );
}
