// SPDX-License-Identifier: Apache-2.0

import * as SecureStore from "expo-secure-store";

import { validateReviewerPairingCancellationToken } from "../api/reviewer-auth-validation";
import {
  type BackendConfig,
  type BackendConfigState,
  type PendingPairingCleanup,
  validateBackendConfig,
} from "./backend-config-validation";

export { normalizeBaseUrl } from "./base-url";
export { validateBackendConfig } from "./backend-config-validation";
export type {
  BackendConfig,
  BackendConfigState,
  PendingPairingCleanup,
} from "./backend-config-validation";

const configurationKey = "tacua.backend.configuration.v5";
const legacyConfigurationKey = "tacua.backend.configuration.v4";
const supersededConfigurationKeys = [
  legacyConfigurationKey,
  "tacua.backend.configuration.v3",
  "tacua.backend.configuration.v2",
] as const;
const legacyKeys = [
  "tacua.backend.base-url.v1",
  "tacua.backend.admin-token.v1",
  "tacua.reviewer.id.v1",
  "tacua.target.scheme.v1",
] as const;

type PersistedAuthenticationState =
  | { readonly kind: "unauthenticated" }
  | { readonly kind: "session"; readonly sessionToken: string }
  | {
    readonly kind: "pending_pairing_cleanup";
    readonly pairingToken: string;
    readonly clientKind: "native";
  };

type PersistedBackendConfig = {
  readonly storageVersion: 5;
  readonly baseUrl: string;
  readonly authentication: PersistedAuthenticationState;
};

type PersistedLegacyBackendConfig = BackendConfig & { readonly storageVersion: 4 };

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) return null;
  return record;
}

function validatePendingPairingCleanup(value: unknown): PendingPairingCleanup {
  const record = exactRecord(value, ["pairingToken", "clientKind"]);
  if (record === null || record.clientKind !== "native") {
    throw new Error("Pending reviewer pairing cleanup is invalid.");
  }
  return {
    pairingToken: validateReviewerPairingCancellationToken(record.pairingToken),
    clientKind: "native",
  };
}

function parsePersistedConfig(value: string): BackendConfigState {
  let decoded: unknown;
  try {
    decoded = JSON.parse(value);
  } catch {
    throw new Error("Stored backend configuration V5 is invalid.");
  }
  const persisted = exactRecord(decoded, ["storageVersion", "baseUrl", "authentication"]);
  if (
    persisted === null
    || persisted.storageVersion !== 5
    || typeof persisted.baseUrl !== "string"
  ) throw new Error("Stored backend configuration V5 is invalid.");

  const authentication = persisted.authentication;
  const authenticationRecord = authentication !== null
    && typeof authentication === "object"
    && !Array.isArray(authentication)
    ? authentication as Record<string, unknown>
    : null;
  if (authenticationRecord?.kind === "unauthenticated") {
    if (exactRecord(authenticationRecord, ["kind"]) === null) {
      throw new Error("Stored backend configuration V5 is invalid.");
    }
    return {
      config: validateBackendConfig({
        baseUrl: persisted.baseUrl,
        sessionToken: null,
      }),
      pendingPairingCleanup: null,
    };
  }
  if (authenticationRecord?.kind === "session") {
    if (exactRecord(authenticationRecord, ["kind", "sessionToken"]) === null) {
      throw new Error("Stored backend configuration V5 is invalid.");
    }
    return {
      config: validateBackendConfig({
        baseUrl: persisted.baseUrl,
        sessionToken: authenticationRecord.sessionToken as string,
      }),
      pendingPairingCleanup: null,
    };
  }
  if (authenticationRecord?.kind === "pending_pairing_cleanup") {
    const pendingPairingCleanup = validatePendingPairingCleanup({
      pairingToken: authenticationRecord.pairingToken,
      clientKind: authenticationRecord.clientKind,
    });
    if (
      exactRecord(authenticationRecord, ["kind", "pairingToken", "clientKind"]) === null
    ) throw new Error("Stored backend configuration V5 is invalid.");
    return {
      config: validateBackendConfig({
        baseUrl: persisted.baseUrl,
        sessionToken: null,
      }),
      pendingPairingCleanup,
    };
  }
  throw new Error("Stored backend configuration V5 is invalid.");
}

function parseLegacyPersistedConfig(value: string): BackendConfig | null {
  try {
    const parsed = JSON.parse(value) as Partial<PersistedLegacyBackendConfig>;
    if (
      !parsed
      || typeof parsed !== "object"
      || Array.isArray(parsed)
      || parsed.storageVersion !== 4
      || typeof parsed.baseUrl !== "string"
      || (parsed.sessionToken !== null && typeof parsed.sessionToken !== "string")
      || Object.keys(parsed).length !== 3
      || Object.keys(parsed).some((key) => !["storageVersion", "baseUrl", "sessionToken"].includes(key))
    ) return null;
    return validateBackendConfig({
      baseUrl: parsed.baseUrl,
      sessionToken: parsed.sessionToken ?? null,
    });
  } catch {
    return null;
  }
}

async function removeSupersededConfigurationBestEffort(): Promise<void> {
  await Promise.allSettled([
    ...supersededConfigurationKeys.map((key) => SecureStore.deleteItemAsync(key)),
    ...legacyKeys.map((key) => SecureStore.deleteItemAsync(key)),
  ]);
}

function encodeBackendConfigState(state: BackendConfigState): PersistedBackendConfig {
  const config = validateBackendConfig(state.config);
  if (state.pendingPairingCleanup !== null) {
    if (config.sessionToken !== null) {
      throw new Error("A reviewer session and pending pairing cleanup cannot be stored together.");
    }
    const pendingPairingCleanup = validatePendingPairingCleanup(state.pendingPairingCleanup);
    return {
      storageVersion: 5,
      baseUrl: config.baseUrl,
      authentication: {
        kind: "pending_pairing_cleanup",
        ...pendingPairingCleanup,
      },
    };
  }
  return {
    storageVersion: 5,
    baseUrl: config.baseUrl,
    authentication: config.sessionToken === null
      ? { kind: "unauthenticated" }
      : { kind: "session", sessionToken: config.sessionToken },
  };
}

async function persistBackendConfigState(state: BackendConfigState): Promise<void> {
  const persisted = encodeBackendConfigState(state);
  await SecureStore.setItemAsync(configurationKey, JSON.stringify(persisted), {
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
  await removeSupersededConfigurationBestEffort();
}

export async function loadBackendConfigState(): Promise<BackendConfigState | null> {
  const persisted = await SecureStore.getItemAsync(configurationKey);
  if (persisted !== null) {
    const parsed = parsePersistedConfig(persisted);
    await removeSupersededConfigurationBestEffort();
    return parsed;
  }

  const legacyPersisted = await SecureStore.getItemAsync(legacyConfigurationKey);
  if (legacyPersisted === null) {
    await removeSupersededConfigurationBestEffort();
    return null;
  }
  const legacyConfig = parseLegacyPersistedConfig(legacyPersisted);
  if (legacyConfig === null) {
    await SecureStore.deleteItemAsync(legacyConfigurationKey);
    await removeSupersededConfigurationBestEffort();
    return null;
  }
  const migrated: BackendConfigState = {
    config: legacyConfig,
    pendingPairingCleanup: null,
  };
  await persistBackendConfigState(migrated);
  return migrated;
}

export async function saveBackendConfig(config: BackendConfig): Promise<void> {
  await persistBackendConfigState({
    config,
    pendingPairingCleanup: null,
  });
}

export async function savePendingPairingCleanup(
  config: BackendConfig,
  pendingPairingCleanup: PendingPairingCleanup,
): Promise<void> {
  await persistBackendConfigState({
    config,
    pendingPairingCleanup,
  });
}

export async function clearBackendConfig(): Promise<void> {
  // V4 remains a migration fallback whenever V5 is absent. Remove that
  // fallback authoritatively before deleting V5; otherwise a failed retired-
  // key cleanup could resurrect an old bearer on the next load. Either
  // deletion failure leaves V5 in place and fails closed.
  await SecureStore.deleteItemAsync(legacyConfigurationKey);
  await SecureStore.deleteItemAsync(configurationKey);
  await removeSupersededConfigurationBestEffort();
}
