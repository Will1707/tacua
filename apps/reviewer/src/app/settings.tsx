// SPDX-License-Identifier: Apache-2.0

import { router } from "expo-router";
import type { ComponentProps } from "react";
import { useEffect, useRef, useState } from "react";
import { Platform, ScrollView, Text, TextInput, View } from "react-native";

import { ActionButton } from "@/components/action-button";
import { TacuaApiClient } from "@/api/client";
import { verifyAndPersistBackendConfig } from "@/api/backend-config-verification";
import { probeTacuaBackend } from "@/api/version-probe";
import { clearBackendConfig, loadBackendConfig, saveBackendConfig } from "@/config/backend-config";
import { useBackend } from "@/hooks/use-backend";
import { useAppDialog } from "@/providers/app-dialog";
import { colors } from "@/theme/colors";

function initialBaseUrl(): string {
  return Platform.OS === "web"
    && typeof globalThis.location?.origin === "string"
    ? globalThis.location.origin
    : "";
}

export default function SettingsRoute() {
  const { reload } = useBackend();
  const showDialog = useAppDialog();
  const [baseUrl, setBaseUrl] = useState(initialBaseUrl);
  const [adminToken, setAdminToken] = useState("");
  const [reviewerId, setReviewerId] = useState("reviewer_owner");
  const [targetScheme, setTargetScheme] = useState("tacua-qa-app");
  const [loadingConfig, setLoadingConfig] = useState(true);
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [configurationError, setConfigurationError] = useState<string | null>(null);
  const savingRef = useRef(false);
  const clearingRef = useRef(false);

  useEffect(() => {
    let active = true;
    void loadBackendConfig()
      .then((config) => {
        if (!active || !config) return;
        setBaseUrl(config.baseUrl);
        setReviewerId(config.reviewerId);
        setTargetScheme(config.targetScheme);
        setAdminToken(config.adminToken);
      })
      .catch((caught) => {
        if (active) {
          setConfigurationError(caught instanceof Error
            ? caught.message
            : "Tacua could not read the secure backend configuration.");
        }
      })
      .finally(() => { if (active) setLoadingConfig(false); });
    return () => { active = false; };
  }, []);

  async function save() {
    if (loadingConfig || clearingRef.current || savingRef.current) return;
    savingRef.current = true;
    setSaving(true);
    setConfigurationError(null);
    try {
      await verifyAndPersistBackendConfig(
        { baseUrl, adminToken, reviewerId, targetScheme },
        {
          probeBackend: probeTacuaBackend,
          createClient: (config) => new TacuaApiClient(config),
          persistConfig: saveBackendConfig,
        },
      );
      await reload();
      router.back();
    } catch (caught) {
      showDialog("Configuration was not saved", caught instanceof Error ? caught.message : "The configuration is invalid.");
    } finally {
      savingRef.current = false;
      setSaving(false);
    }
  }

  async function forget() {
    if (loadingConfig || savingRef.current || clearingRef.current) return;
    clearingRef.current = true;
    setClearing(true);
    setConfigurationError(null);
    try {
      await clearBackendConfig();
      // Release the in-memory copy before dismissing this screen.
      setAdminToken("");
      setBaseUrl(initialBaseUrl());
      setReviewerId("reviewer_owner");
      setTargetScheme("tacua-qa-app");
      await reload();
      router.back();
    } catch (caught) {
      const message = caught instanceof Error
        ? caught.message
        : "Tacua could not remove the secure backend configuration.";
      setConfigurationError(message);
      showDialog("Configuration was not forgotten", message);
    } finally {
      clearingRef.current = false;
      setClearing(false);
    }
  }

  const formDisabled = loadingConfig || saving || clearing;
  return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" keyboardShouldPersistTaps="handled" contentContainerStyle={{ padding: 20, gap: 18 }}>
      <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 21 }}>
        {Platform.OS === "web"
          ? "Tacua connects to the backend on this page’s exact HTTPS origin. The administrator credential stays in this tab’s session storage and is never included in a launch link."
          : "Tacua connects directly to your self-hosted deployment. The administrator credential stays in this device’s secure storage and is never included in a launch link."}
      </Text>
      {loadingConfig ? <Text selectable accessibilityRole="progressbar" style={{ color: colors.tertiaryLabel }}>Loading secure configuration…</Text> : null}
      {configurationError ? <Text selectable accessibilityRole="alert" style={{ color: colors.red, lineHeight: 20 }}>{configurationError}</Text> : null}
      <Field editable={!formDisabled} label="Backend URL" value={baseUrl} onChangeText={setBaseUrl} placeholder="https://tacua.example.com" autoCapitalize="none" keyboardType="url" />
      <Field editable={!formDisabled} label="Administrator token" value={adminToken} onChangeText={setAdminToken} placeholder="Mounted backend secret" autoCapitalize="none" secureTextEntry />
      <Field editable={!formDisabled} label="Reviewer ID" value={reviewerId} onChangeText={setReviewerId} placeholder="reviewer_owner" autoCapitalize="none" />
      <Field editable={!formDisabled} label="QA app URL scheme" value={targetScheme} onChangeText={setTargetScheme} placeholder="tacua-qa-app" autoCapitalize="none" />
      <ActionButton disabled={loadingConfig || clearing} label="Save and connect" loading={saving} onPress={() => void save()} />
      <ActionButton
        destructive
        disabled={loadingConfig || saving}
        label="Forget this backend"
        loading={clearing}
        onPress={() => showDialog(
          "Forget backend configuration?",
          "This removes the local endpoint and administrator credential. It does not delete backend evidence.",
          [
            { text: "Cancel", style: "cancel" },
            { text: "Forget", style: "destructive", onPress: () => void forget() },
          ],
        )}
      />
    </ScrollView>
  );
}

function Field(props: ComponentProps<typeof TextInput> & { readonly label: string }) {
  const { label, ...input } = props;
  return (
    <View style={{ gap: 7 }}>
      <Text style={{ color: colors.label, fontWeight: "700" }}>{label}</Text>
      <TextInput {...input} accessibilityLabel={label} autoCorrect={false} placeholderTextColor={colors.tertiaryLabel} selectionColor={colors.primary} style={{ color: colors.label, backgroundColor: colors.secondaryBackground, borderColor: colors.separator, borderWidth: 1, minHeight: 48, borderRadius: 12, borderCurve: "continuous", paddingHorizontal: 13, fontSize: 16 }} />
    </View>
  );
}
