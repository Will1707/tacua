// SPDX-License-Identifier: Apache-2.0

import * as SecureStore from "expo-secure-store";

const keys = {
  baseUrl: "tacua.backend.base-url.v1",
  adminToken: "tacua.backend.admin-token.v1",
  reviewerId: "tacua.reviewer.id.v1",
  targetScheme: "tacua.target.scheme.v1",
} as const;

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
  const normalized = value.trim().replace(/\/$/, "");
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("Backend URL must be a valid URL.");
  }
  const localDevelopment = __DEV__ && parsed.protocol === "http:" && ["127.0.0.1", "localhost"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !localDevelopment) {
    throw new Error("Backend URL must use HTTPS (loopback HTTP is allowed only in development)." );
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname !== "" && parsed.pathname !== "/")) {
    throw new Error("Backend URL must contain only an origin, without credentials, path, query, or fragment.");
  }
  return parsed.origin;
}

export async function loadBackendConfig(): Promise<BackendConfig | null> {
  const [baseUrl, adminToken, reviewerId, targetScheme] = await Promise.all([
    SecureStore.getItemAsync(keys.baseUrl),
    SecureStore.getItemAsync(keys.adminToken),
    SecureStore.getItemAsync(keys.reviewerId),
    SecureStore.getItemAsync(keys.targetScheme),
  ]);
  if (!baseUrl || !adminToken || !reviewerId || !targetScheme) return null;
  return { baseUrl, adminToken, reviewerId, targetScheme };
}

export async function saveBackendConfig(config: BackendConfig): Promise<void> {
  const baseUrl = normalizeBaseUrl(config.baseUrl);
  const reviewerId = requireIdentifier(config.reviewerId, "Reviewer ID");
  const targetScheme = config.targetScheme.trim();
  if (!/^[a-z][a-z0-9+.-]{1,63}$/.test(targetScheme)) {
    throw new Error("Target app scheme is invalid.");
  }
  if (config.adminToken.length < 32 || /\s/.test(config.adminToken)) {
    throw new Error("Administrator token is invalid.");
  }
  await Promise.all([
    SecureStore.setItemAsync(keys.baseUrl, baseUrl),
    SecureStore.setItemAsync(keys.adminToken, config.adminToken, {
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    }),
    SecureStore.setItemAsync(keys.reviewerId, reviewerId),
    SecureStore.setItemAsync(keys.targetScheme, targetScheme),
  ]);
}

export async function clearBackendConfig(): Promise<void> {
  await Promise.all(Object.values(keys).map((key) => SecureStore.deleteItemAsync(key)));
}
