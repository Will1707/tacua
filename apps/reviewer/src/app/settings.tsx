// SPDX-License-Identifier: Apache-2.0

import { router } from "expo-router";
import type { ComponentProps } from "react";
import { useEffect, useState } from "react";
import { Alert, ScrollView, Text, TextInput, View } from "react-native";

import { ActionButton } from "@/components/action-button";
import { clearBackendConfig, loadBackendConfig, saveBackendConfig } from "@/config/backend-config";
import { useBackend } from "@/hooks/use-backend";
import { colors } from "@/theme/colors";

export default function SettingsRoute() {
  const { reload } = useBackend();
  const [baseUrl, setBaseUrl] = useState("");
  const [adminToken, setAdminToken] = useState("");
  const [reviewerId, setReviewerId] = useState("reviewer_owner");
  const [targetScheme, setTargetScheme] = useState("kuzaba-tacua-qa");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void loadBackendConfig().then((config) => {
      if (!config) return;
      setBaseUrl(config.baseUrl);
      setReviewerId(config.reviewerId);
      setTargetScheme(config.targetScheme);
      setAdminToken(config.adminToken);
    });
  }, []);

  async function save() {
    setSaving(true);
    try {
      await saveBackendConfig({ baseUrl, adminToken, reviewerId, targetScheme });
      await reload();
      router.back();
    } catch (caught) {
      Alert.alert("Configuration was not saved", caught instanceof Error ? caught.message : "The configuration is invalid.");
    } finally { setSaving(false); }
  }

  return (
    <ScrollView contentInsetAdjustmentBehavior="automatic" keyboardShouldPersistTaps="handled" contentContainerStyle={{ padding: 20, gap: 18 }}>
      <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 21 }}>Tacua connects directly to your self-hosted deployment. The administrator credential stays in this device’s secure storage and is never included in a launch link.</Text>
      <Field label="Backend URL" value={baseUrl} onChangeText={setBaseUrl} placeholder="https://tacua.example.com" autoCapitalize="none" keyboardType="url" />
      <Field label="Administrator token" value={adminToken} onChangeText={setAdminToken} placeholder="Mounted backend secret" autoCapitalize="none" secureTextEntry />
      <Field label="Reviewer ID" value={reviewerId} onChangeText={setReviewerId} placeholder="reviewer_owner" autoCapitalize="none" />
      <Field label="QA app URL scheme" value={targetScheme} onChangeText={setTargetScheme} placeholder="kuzaba-tacua-qa" autoCapitalize="none" />
      <ActionButton label="Save and connect" loading={saving} onPress={() => void save()} />
      <ActionButton destructive label="Forget this backend" onPress={() => Alert.alert("Forget backend configuration?", "This removes the local endpoint and administrator credential. It does not delete backend evidence.", [{ text: "Cancel", style: "cancel" }, { text: "Forget", style: "destructive", onPress: () => void clearBackendConfig().then(reload).then(() => router.back()) }])} />
    </ScrollView>
  );
}

function Field(props: ComponentProps<typeof TextInput> & { readonly label: string }) {
  const { label, ...input } = props;
  return (
    <View style={{ gap: 7 }}>
      <Text style={{ color: colors.label, fontWeight: "700" }}>{label}</Text>
      <TextInput {...input} accessibilityLabel={label} autoCorrect={false} style={{ color: colors.label, backgroundColor: colors.secondaryBackground, minHeight: 48, borderRadius: 12, borderCurve: "continuous", paddingHorizontal: 13, fontSize: 16 }} />
    </View>
  );
}
