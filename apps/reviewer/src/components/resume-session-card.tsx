// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef, useState } from "react";
import { Linking, Pressable, Text, View } from "react-native";

import { TacuaApiError, type TacuaApiClient } from "@/api/client";
import { launchCodeRetentionMilliseconds } from "@/api/launch-code-retention";
import { buildLaunchURL } from "@/api/launch-grant-validation";
import type { CaptureSession, ResumeLaunchGrant } from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { SectionCard } from "@/components/section-card";
import { colors } from "@/theme/colors";
import { formatDate } from "@/utils/format";

type Props = {
  readonly client: TacuaApiClient;
  readonly disabled?: boolean;
  readonly session: CaptureSession;
  readonly targetScheme: string;
};

export function ResumeSessionCard({ client, disabled = false, session, targetScheme }: Props) {
  const [grant, setGrant] = useState<ResumeLaunchGrant | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestSequence = useRef(0);
  const requestInFlightRef = useRef(false);
  const bindingRef = useRef({
    client,
    disabled,
    sessionId: session.session_id,
    buildIdentityDigest: session.build_identity_digest,
    scopeDigest: session.scope_digest,
    targetScheme,
  });
  bindingRef.current = {
    client,
    disabled,
    sessionId: session.session_id,
    buildIdentityDigest: session.build_identity_digest,
    scopeDigest: session.scope_digest,
    targetScheme,
  };

  useEffect(() => {
    // A recovery code is valid only for this exact backend, app scheme, and
    // immutable session binding. A refresh/configuration change releases it.
    requestSequence.current += 1;
    requestInFlightRef.current = false;
    setLoading(false);
    setGrant(null);
    setError(null);
  }, [client, disabled, session.build_identity_digest, session.scope_digest, session.session_id, targetScheme]);
  useEffect(() => () => {
    requestSequence.current += 1;
    requestInFlightRef.current = false;
  }, []);

  useEffect(() => {
    if (!grant) return;
    const timer = setTimeout(
      () => setGrant(null),
      launchCodeRetentionMilliseconds(grant.expires_at),
    );
    return () => clearTimeout(timer);
  }, [grant]);

  const openGrant = useCallback(async (nextGrant: ResumeLaunchGrant) => {
    try {
      await Linking.openURL(buildLaunchURL(
        targetScheme,
        nextGrant.launch_code,
        nextGrant.session_id,
      ));
    } catch {
      throw new TacuaApiError(
        0,
        "QA_BUILD_UNAVAILABLE",
        "The QA app holding this session could not be opened on this device.",
      );
    }
  }, [targetScheme]);

  const openRecovery = useCallback(async () => {
    const currentBinding = bindingRef.current;
    if (
      disabled
      || requestInFlightRef.current
      || currentBinding.client !== client
      || currentBinding.disabled
      || currentBinding.sessionId !== session.session_id
      || currentBinding.buildIdentityDigest !== session.build_identity_digest
      || currentBinding.scopeDigest !== session.scope_digest
      || currentBinding.targetScheme !== targetScheme
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
        && current.sessionId === requestBinding.sessionId
        && current.buildIdentityDigest === requestBinding.buildIdentityDigest
        && current.scopeDigest === requestBinding.scopeDigest
        && current.targetScheme === requestBinding.targetScheme;
    };
    setLoading(true);
    setGrant(null);
    setError(null);
    try {
      const nextGrant = await requestBinding.client.createResumeGrant(requestBinding.sessionId);
      if (!isCurrentRequest()) return;
      if (nextGrant.build_identity_digest !== requestBinding.buildIdentityDigest) {
        throw new TacuaApiError(
          502,
          "BUILD_BINDING_MISMATCH",
          "The recovery grant was issued for another QA build.",
        );
      }
      if (nextGrant.scope_digest !== requestBinding.scopeDigest) {
        throw new TacuaApiError(
          502,
          "SCOPE_BINDING_MISMATCH",
          "The recovery grant was issued for another capture scope.",
        );
      }
      setGrant(nextGrant);
      await openGrant(nextGrant);
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
  }, [client, disabled, openGrant, session.build_identity_digest, session.scope_digest, session.session_id, targetScheme]);

  const retryGrant = useCallback(async (nextGrant: ResumeLaunchGrant) => {
    const currentBinding = bindingRef.current;
    if (
      disabled
      || requestInFlightRef.current
      || currentBinding.client !== client
      || currentBinding.disabled
      || currentBinding.sessionId !== session.session_id
      || currentBinding.buildIdentityDigest !== session.build_identity_digest
      || currentBinding.scopeDigest !== session.scope_digest
      || currentBinding.targetScheme !== targetScheme
      || grant?.launch_id !== nextGrant.launch_id
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
        && current.sessionId === requestBinding.sessionId
        && current.buildIdentityDigest === requestBinding.buildIdentityDigest
        && current.scopeDigest === requestBinding.scopeDigest
        && current.targetScheme === requestBinding.targetScheme;
    };
    setLoading(true);
    setError(null);
    try {
      await openGrant(nextGrant);
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
  }, [client, disabled, grant?.launch_id, openGrant, session.build_identity_digest, session.scope_digest, session.session_id, targetScheme]);

  return (
    <SectionCard title="Continue on this device">
      <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
        Open the QA build to retry an interrupted upload, submit verified partial capture,
        complete this session, or delete its local evidence. The one-time link is bound to
        this exact backend session.
      </Text>
      <ActionButton
        label="Open QA build recovery"
        onPress={() => void openRecovery()}
        disabled={disabled}
        loading={loading}
      />
      {grant ? (
        <View style={{ backgroundColor: colors.groupedBackground, borderRadius: 12, borderCurve: "continuous", padding: 12, gap: 7 }}>
          <Text selectable style={{ color: colors.label, fontWeight: "700" }}>
            One-time recovery link ready
          </Text>
          <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13 }}>
            Expires {formatDate(grant.expires_at)}. It contains no recording or reusable upload credential.
          </Text>
          <Pressable
            accessibilityRole="button"
            accessibilityState={{ disabled: disabled || loading }}
            disabled={disabled || loading}
            onPress={() => void retryGrant(grant)}
            style={{ minHeight: 44, justifyContent: "center", opacity: disabled || loading ? 0.5 : 1 }}
          >
            <Text style={{ color: colors.primary, fontWeight: "800" }}>Try opening again</Text>
          </Pressable>
        </View>
      ) : null}
      {error ? <Text selectable accessibilityRole="alert" style={{ color: colors.orange, lineHeight: 20 }}>{error}</Text> : null}
    </SectionCard>
  );
}
