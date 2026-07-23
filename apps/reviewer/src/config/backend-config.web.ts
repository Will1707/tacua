// SPDX-License-Identifier: Apache-2.0

import {
  type BackendConfig,
  validateBackendConfig,
} from "./backend-config-validation.ts";

export { normalizeBaseUrl } from "./base-url.ts";
export { validateBackendConfig } from "./backend-config-validation.ts";
export type { BackendConfig } from "./backend-config-validation.ts";

const configurationKey = "tacua.backend.configuration.web-session.v1";

type PersistedBackendConfig = BackendConfig & { readonly storageVersion: 1 };

function browserSessionStorage(): Storage {
  if (typeof globalThis.sessionStorage === "undefined") {
    throw new Error("Browser session storage is unavailable.");
  }
  return globalThis.sessionStorage;
}

function parsePersistedConfig(value: string): BackendConfig | null {
  try {
    const parsed = JSON.parse(value) as Partial<PersistedBackendConfig>;
    if (
      !parsed
      || typeof parsed !== "object"
      || parsed.storageVersion !== 1
      || typeof parsed.baseUrl !== "string"
      || typeof parsed.adminToken !== "string"
      || typeof parsed.reviewerId !== "string"
      || typeof parsed.targetScheme !== "string"
      || Object.keys(parsed).some((key) => ![
        "storageVersion",
        "baseUrl",
        "adminToken",
        "reviewerId",
        "targetScheme",
      ].includes(key))
    ) {
      return null;
    }
    return validateBackendConfig(parsed as BackendConfig);
  } catch {
    return null;
  }
}

export async function loadBackendConfig(): Promise<BackendConfig | null> {
  const persisted = browserSessionStorage().getItem(configurationKey);
  return persisted === null ? null : parsePersistedConfig(persisted);
}

export async function saveBackendConfig(config: BackendConfig): Promise<void> {
  const validated = validateBackendConfig(config);
  const persisted: PersistedBackendConfig = { storageVersion: 1, ...validated };
  browserSessionStorage().setItem(configurationKey, JSON.stringify(persisted));
}

export async function clearBackendConfig(): Promise<void> {
  browserSessionStorage().removeItem(configurationKey);
}
