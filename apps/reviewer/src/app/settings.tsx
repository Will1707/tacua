// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from "react";
import { Platform, ScrollView, Text, TextInput, View } from "react-native";

import { ActionButton } from "@/components/action-button";
import { useBackend } from "@/hooks/use-backend";
import { useAppDialog } from "@/providers/app-dialog";
import { colors } from "@/theme/colors";
import { formatDate } from "@/utils/format";

export default function SettingsRoute() {
  const {
    status,
    config,
    session,
    bootstrap,
    pairing,
    error,
    migrationRequired,
    reload,
    configureEndpoint,
    beginPairing,
    cancelPairing,
    disconnect,
  } = useBackend();
  const showDialog = useAppDialog();
  const [baseUrl, setBaseUrl] = useState(config?.baseUrl ?? "");
  const [savingEndpoint, setSavingEndpoint] = useState(false);
  const savingRef = useRef(false);

  useEffect(() => {
    if (config !== null) setBaseUrl(config.baseUrl);
  }, [config]);

  async function saveEndpoint() {
    if (savingRef.current || status === "loading") return;
    savingRef.current = true;
    setSavingEndpoint(true);
    try {
      await configureEndpoint(baseUrl);
    } catch (caught) {
      showDialog(
        "Endpoint was not saved",
        caught instanceof Error ? caught.message : "The backend endpoint is invalid.",
      );
    } finally {
      savingRef.current = false;
      setSavingEndpoint(false);
    }
  }

  const endpointChanged = config === null || baseUrl.trim().replace(/\/$/, "") !== config.baseUrl;
  const endpointReady = baseUrl.trim().length > 0;
  const pairingAvailable = status === "pairing_required" && !endpointChanged;

  return (
    <ScrollView
      contentInsetAdjustmentBehavior="automatic"
      keyboardShouldPersistTaps="handled"
      contentContainerStyle={{ padding: 20, gap: 18 }}
    >
      <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 21 }}>
        {Platform.OS === "web"
          ? "This reviewer uses the backend on the page’s exact HTTPS origin. Access comes from a Tailscale app capability or a revocable same-origin pairing cookie; Tacua stores no administrator secret in the browser."
          : "This reviewer stores the backend endpoint and either a revocable reviewer session or a temporary pairing-recovery credential in this device’s secure storage. Reviewer identity and QA launch schemes come from the backend."}
      </Text>

      {Platform.OS === "web" ? (
        <ConnectionValue label="Backend origin" value={config?.baseUrl ?? "Checking this page’s origin…"} />
      ) : (
        <View style={{ gap: 7 }}>
          <Text style={{ color: colors.label, fontWeight: "700" }}>Backend URL</Text>
          <TextInput
            accessibilityLabel="Backend URL"
            autoCapitalize="none"
            autoCorrect={false}
            editable={status !== "loading" && status !== "pairing_pending" && status !== "connected"}
            keyboardType="url"
            onChangeText={setBaseUrl}
            placeholder="https://mini-pc.example.ts.net"
            placeholderTextColor={colors.tertiaryLabel}
            selectionColor={colors.primary}
            value={baseUrl}
            style={{
              color: colors.label,
              backgroundColor: colors.secondaryBackground,
              borderColor: colors.separator,
              borderWidth: 1,
              minHeight: 48,
              borderRadius: 12,
              borderCurve: "continuous",
              paddingHorizontal: 13,
              fontSize: 16,
            }}
          />
          {status !== "connected" && status !== "pairing_pending" ? (
            <ActionButton
              disabled={!endpointReady || !endpointChanged || status === "loading"}
              label={config === null ? "Use this endpoint" : "Update endpoint"}
              loading={savingEndpoint}
              onPress={() => void saveEndpoint()}
            />
          ) : null}
        </View>
      )}

      {status === "loading" ? (
        <Text selectable accessibilityRole="progressbar" style={{ color: colors.tertiaryLabel }}>
          Verifying reviewer access…
        </Text>
      ) : null}

      {error ? (
        <View accessibilityRole="alert" style={{ backgroundColor: colors.secondaryBackground, borderColor: colors.red, borderWidth: 1, borderRadius: 14, borderCurve: "continuous", padding: 14, gap: 6 }}>
          <Text selectable style={{ color: colors.red, fontWeight: "700" }}>
            {migrationRequired ? "Server update required" : "Connection needs attention"}
          </Text>
          <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>{error}</Text>
        </View>
      ) : null}

      {status === "pairing_required" ? (
        <View style={{ gap: 10 }}>
          <Text selectable style={{ color: colors.label, fontSize: 17, fontWeight: "700" }}>
            Pair this reviewer
          </Text>
          <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 21 }}>
            Request a short-lived code, approve it once on the backend host, and Tacua will connect automatically. The pairing secret never appears on this screen; native keeps it in device-only secure storage only until pairing or cleanup finishes.
          </Text>
          <ActionButton
            disabled={!pairingAvailable || migrationRequired}
            label="Request pairing code"
            onPress={() => void beginPairing()}
          />
        </View>
      ) : null}

      {status === "pairing_pending" && pairing !== null ? (
        <View style={{ backgroundColor: colors.secondaryBackground, borderColor: colors.separator, borderWidth: 1, borderRadius: 16, borderCurve: "continuous", padding: 16, gap: 10 }}>
          <Text selectable style={{ color: colors.label, fontSize: 17, fontWeight: "700" }}>Approve this pairing code</Text>
          <Text selectable accessibilityLabel={`Pairing code ${pairing.human_code}`} style={{ color: colors.label, fontSize: 28, fontWeight: "800", letterSpacing: 2, fontVariant: ["tabular-nums"] }}>
            {pairing.human_code}
          </Text>
          <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
            On the backend host, run the reviewer pairing approval command with this code. Tacua is waiting and will connect as soon as approval succeeds.
          </Text>
          <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 13 }}>
            Expires {formatDate(pairing.expires_at)}
          </Text>
          <ActionButton destructive label="Cancel pairing" onPress={() => void cancelPairing()} />
        </View>
      ) : null}

      {status === "connected" && session !== null && bootstrap !== null ? (
        <View style={{ gap: 12 }}>
          <ConnectionValue label="Reviewer" value={bootstrap.reviewer_id} />
          <ConnectionValue
            label="Access"
            value={session.auth_kind === "tailscale_capability" ? "Tailscale app capability" : "Paired reviewer session"}
          />
          {session.device_label ? <ConnectionValue label="Device" value={session.device_label} /> : null}
          {session.expires_at ? <ConnectionValue label="Access expires" value={formatDate(session.expires_at)} /> : null}
          <ConnectionValue label="SDK-enabled builds" value={String(bootstrap.builds.length)} />
          {session.auth_kind === "tailscale_capability" ? (
            <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13, lineHeight: 19 }}>
              This capability is managed by your tailnet policy and cannot be revoked from Tacua. Remove the app capability from that policy to disconnect access.
            </Text>
          ) : (
            <ActionButton
              destructive
              label="Disconnect paired reviewer"
              onPress={() => showDialog(
                "Disconnect this reviewer?",
                "This revokes the current reviewer session. It does not delete backend evidence.",
                [
                  { text: "Cancel", style: "cancel" },
                  { text: "Disconnect", style: "destructive", onPress: () => void disconnect() },
                ],
              )}
            />
          )}
        </View>
      ) : null}

      {status === "error" ? <ActionButton label="Try again" onPress={() => void reload()} /> : null}
    </ScrollView>
  );
}

function ConnectionValue({ label, value }: { readonly label: string; readonly value: string }) {
  return (
    <View style={{ gap: 4 }}>
      <Text style={{ color: colors.tertiaryLabel, fontSize: 13, fontWeight: "700", textTransform: "uppercase" }}>{label}</Text>
      <Text selectable style={{ color: colors.label, fontSize: 16 }}>{value}</Text>
    </View>
  );
}
