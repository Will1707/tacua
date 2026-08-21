// SPDX-License-Identifier: Apache-2.0

import * as SecureStore from "expo-secure-store";

import {
  type BackendConfig,
  validateBackendConfig,
} from "./backend-config-validation";

export { normalizeBaseUrl } from "./base-url";
export { validateBackendConfig } from "./backend-config-validation";
export type { BackendConfig } from "./backend-config-validation";

const configurationKey = "tacua.backend.configuration.v4";
const supersededConfigurationKeys = [
  "tacua.backend.configuration.v3",
  "tacua.backend.configuration.v2",
] as const;
const legacyKeys = [
  "tacua.backend.base-url.v1",
  "tacua.backend.admin-token.v1",
  "tacua.reviewer.id.v1",
  "tacua.target.scheme.v1",
] as const;

type PersistedBackendConfig = BackendConfig & { readonly storageVersion: 4 };

function parsePersistedConfig(value: string): BackendConfig | null {
  try {
    const parsed = JSON.parse(value) as Partial<PersistedBackendConfig>;
    if (
      !parsed
      || typeof parsed !== "object"
      || parsed.storageVersion !== 4
      || typeof parsed.baseUrl !== "string"
      || (parsed.sessionToken !== null && typeof parsed.sessionToken !== "string")
      || Object.keys(parsed).length !== 3
      || Object.keys(parsed).some((key) => !["storageVersion", "baseUrl", "sessionToken"].includes(key))
    ) {
      return null;
    }
    return validateBackendConfig({
      baseUrl: parsed.baseUrl,
      sessionToken: parsed.sessionToken ?? null,
    });
  } catch {
    return null;
  }
}

async function removeSupersededConfiguration(): Promise<void> {
  await Promise.all([
    ...supersededConfigurationKeys.map((key) => SecureStore.deleteItemAsync(key)),
    ...legacyKeys.map((key) => SecureStore.deleteItemAsync(key)),
  ]);
}

export async function loadBackendConfig(): Promise<BackendConfig | null> {
  const persisted = await SecureStore.getItemAsync(configurationKey);
  await removeSupersededConfiguration();
  if (persisted === null) return null;
  const parsed = parsePersistedConfig(persisted);
  if (parsed === null) await SecureStore.deleteItemAsync(configurationKey);
  return parsed;
}

export async function saveBackendConfig(config: BackendConfig): Promise<void> {
  const validated = validateBackendConfig(config);
  const persisted: PersistedBackendConfig = { storageVersion: 4, ...validated };
  await SecureStore.setItemAsync(configurationKey, JSON.stringify(persisted), {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  await removeSupersededConfiguration();
}

export async function clearBackendConfig(): Promise<void> {
  await Promise.all([
    SecureStore.deleteItemAsync(configurationKey),
    ...supersededConfigurationKeys.map((key) => SecureStore.deleteItemAsync(key)),
    ...legacyKeys.map((key) => SecureStore.deleteItemAsync(key)),
  ]);
}
