// SPDX-License-Identifier: Apache-2.0

import * as SecureStore from "expo-secure-store";

import {
  type BackendConfig,
  validateBackendConfig,
} from "./backend-config-validation";

export { normalizeBaseUrl } from "./base-url";
export { validateBackendConfig } from "./backend-config-validation";
export type { BackendConfig } from "./backend-config-validation";

const configurationKey = "tacua.backend.configuration.v3";
const supersededConfigurationKey = "tacua.backend.configuration.v2";
const legacyKeys = {
  baseUrl: "tacua.backend.base-url.v1",
  adminToken: "tacua.backend.admin-token.v1",
  reviewerId: "tacua.reviewer.id.v1",
  targetScheme: "tacua.target.scheme.v1",
} as const;

type PersistedBackendConfig = BackendConfig & { readonly storageVersion: 3 };

function parsePersistedConfig(value: string): BackendConfig | null {
  try {
    const parsed = JSON.parse(value) as Partial<PersistedBackendConfig>;
    if (
      !parsed
      || typeof parsed !== "object"
      || parsed.storageVersion !== 3
      || typeof parsed.baseUrl !== "string"
      || typeof parsed.adminToken !== "string"
      || typeof parsed.reviewerId !== "string"
      || typeof parsed.targetScheme !== "string"
      || Object.keys(parsed).some((key) => !["storageVersion", "baseUrl", "adminToken", "reviewerId", "targetScheme"].includes(key))
    ) {
      return null;
    }
    return validateBackendConfig(parsed as BackendConfig);
  } catch {
    return null;
  }
}

async function persistBackendConfig(config: BackendConfig): Promise<void> {
  const persisted: PersistedBackendConfig = { storageVersion: 3, ...config };
  await SecureStore.setItemAsync(configurationKey, JSON.stringify(persisted), {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

export async function loadBackendConfig(): Promise<BackendConfig | null> {
  const persisted = await SecureStore.getItemAsync(configurationKey);
  if (persisted !== null) return parsePersistedConfig(persisted);
  // V3 intentionally does not migrate any earlier configuration. Earlier
  // releases prefilled a plausible generic target scheme, so preserving a
  // syntactically valid value could send a live grant to the wrong handler.
  // Require the operator to re-enter and explicitly confirm the exact scheme.
  return null;
}

export async function saveBackendConfig(config: BackendConfig): Promise<void> {
  const validated = validateBackendConfig(config);
  await persistBackendConfig(validated);
  await Promise.allSettled([
    SecureStore.deleteItemAsync(supersededConfigurationKey),
    ...Object.values(legacyKeys).map((key) => SecureStore.deleteItemAsync(key)),
  ]);
}

export async function clearBackendConfig(): Promise<void> {
  await Promise.all([
    SecureStore.deleteItemAsync(configurationKey),
    SecureStore.deleteItemAsync(supersededConfigurationKey),
    ...Object.values(legacyKeys).map((key) => SecureStore.deleteItemAsync(key)),
  ]);
}
