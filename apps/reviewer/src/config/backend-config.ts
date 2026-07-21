// SPDX-License-Identifier: Apache-2.0

import * as SecureStore from "expo-secure-store";

const configurationKey = "tacua.backend.configuration.v2";
const legacyKeys = {
  baseUrl: "tacua.backend.base-url.v1",
  adminToken: "tacua.backend.admin-token.v1",
  reviewerId: "tacua.reviewer.id.v1",
  targetScheme: "tacua.target.scheme.v1",
} as const;

type PersistedBackendConfig = BackendConfig & { readonly storageVersion: 2 };

export type BackendConfig = {
  readonly baseUrl: string;
  readonly adminToken: string;
  readonly reviewerId: string;
  readonly targetScheme: string;
};

function requireIdentifier(value: string, field: string): string {
  const normalized = value.trim();
  if (!/^[a-z][a-z0-9_-]{2,63}$/.test(normalized)) {
    throw new Error(`${field} must be a Tacua identifier.`);
  }
  return normalized;
}

export function normalizeBaseUrl(value: string): string {
  if (value.length > 2_048) throw new Error("Backend URL is too long.");
  const normalized = value.trim().replace(/\/$/, "");
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("Backend URL must be a valid URL.");
  }
  const localDevelopment = __DEV__
    && parsed.protocol === "http:"
    && ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !localDevelopment) {
    throw new Error("Backend URL must use HTTPS (loopback HTTP is allowed only in development).");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname !== "" && parsed.pathname !== "/")) {
    throw new Error("Backend URL must contain only an origin, without credentials, path, query, or fragment.");
  }
  return parsed.origin;
}

function validateBackendConfig(config: BackendConfig): BackendConfig {
  const baseUrl = normalizeBaseUrl(config.baseUrl);
  const reviewerId = requireIdentifier(config.reviewerId, "Reviewer ID");
  const targetScheme = config.targetScheme.trim();
  if (!/^[a-z][a-z0-9+.-]{1,63}$/.test(targetScheme)) {
    throw new Error("Target app scheme is invalid.");
  }
  if (config.adminToken.length < 32 || config.adminToken.length > 4_096 || /\s/.test(config.adminToken)) {
    throw new Error("Administrator token is invalid.");
  }
  return { baseUrl, adminToken: config.adminToken, reviewerId, targetScheme };
}

function parsePersistedConfig(value: string): BackendConfig | null {
  try {
    const parsed = JSON.parse(value) as Partial<PersistedBackendConfig>;
    if (
      !parsed
      || typeof parsed !== "object"
      || parsed.storageVersion !== 2
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
  const persisted: PersistedBackendConfig = { storageVersion: 2, ...config };
  await SecureStore.setItemAsync(configurationKey, JSON.stringify(persisted), {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

export async function loadBackendConfig(): Promise<BackendConfig | null> {
  const persisted = await SecureStore.getItemAsync(configurationKey);
  if (persisted !== null) return parsePersistedConfig(persisted);

  const [baseUrl, adminToken, reviewerId, targetScheme] = await Promise.all([
    SecureStore.getItemAsync(legacyKeys.baseUrl),
    SecureStore.getItemAsync(legacyKeys.adminToken),
    SecureStore.getItemAsync(legacyKeys.reviewerId),
    SecureStore.getItemAsync(legacyKeys.targetScheme),
  ]);
  if (!baseUrl || !adminToken || !reviewerId || !targetScheme) return null;
  let migrated: BackendConfig;
  try {
    migrated = validateBackendConfig({ baseUrl, adminToken, reviewerId, targetScheme });
  } catch {
    return null;
  }
  await persistBackendConfig(migrated);
  await Promise.allSettled(Object.values(legacyKeys).map((key) => SecureStore.deleteItemAsync(key)));
  return migrated;
}

export async function saveBackendConfig(config: BackendConfig): Promise<void> {
  const validated = validateBackendConfig(config);
  await persistBackendConfig(validated);
  await Promise.allSettled(Object.values(legacyKeys).map((key) => SecureStore.deleteItemAsync(key)));
}

export async function clearBackendConfig(): Promise<void> {
  await Promise.all([
    SecureStore.deleteItemAsync(configurationKey),
    ...Object.values(legacyKeys).map((key) => SecureStore.deleteItemAsync(key)),
  ]);
}
