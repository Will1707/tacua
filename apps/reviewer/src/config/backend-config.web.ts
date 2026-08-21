// SPDX-License-Identifier: Apache-2.0

import {
  type BackendConfig,
  type BackendConfigState,
  type PendingPairingCleanup,
  validateBackendConfig,
} from "./backend-config-validation.ts";

export { normalizeBaseUrl } from "./base-url.ts";
export { validateBackendConfig } from "./backend-config-validation.ts";
export type {
  BackendConfig,
  BackendConfigState,
  PendingPairingCleanup,
} from "./backend-config-validation.ts";

// Web authentication is an HttpOnly same-origin cookie or a header injected by
// Tailscale Serve. No endpoint, identity, launch scheme, or bearer credential is
// persisted in browser storage.
const obsoleteSessionKeys = [
  "tacua.backend.configuration.v5",
  "tacua.backend.configuration.web-session.v2",
  "tacua.backend.configuration.web-session.v1",
  "tacua.backend.configuration.v4",
  "tacua.backend.configuration.v3",
  "tacua.backend.configuration.v2",
  "tacua.backend.base-url.v1",
  "tacua.backend.admin-token.v1",
  "tacua.reviewer.id.v1",
  "tacua.target.scheme.v1",
] as const;

function exactBrowserOrigin(): string {
  if (typeof globalThis.location?.origin !== "string") {
    throw new Error("The reviewer browser origin is unavailable.");
  }
  return globalThis.location.origin;
}

function forgetObsoleteBrowserConfiguration(): void {
  let storage: Storage | undefined;
  try {
    storage = globalThis.sessionStorage;
  } catch {
    // Access to browser storage can be denied even though the same-origin
    // reviewer itself needs no storage. Removing legacy secrets is best-effort
    // and must not block cookie- or capability-based authentication.
    return;
  }
  if (storage === undefined) return;
  for (const key of obsoleteSessionKeys) {
    try {
      storage.removeItem(key);
    } catch {
      // A browser may expose Storage but reject individual mutations. Keep
      // trying the remaining obsolete keys without making storage mandatory.
    }
  }
}

export async function loadBackendConfigState(): Promise<BackendConfigState> {
  forgetObsoleteBrowserConfiguration();
  const origin = exactBrowserOrigin();
  return {
    config: validateBackendConfig({ baseUrl: origin, sessionToken: null }, origin),
    pendingPairingCleanup: null,
  };
}

export async function saveBackendConfig(config: BackendConfig): Promise<void> {
  const origin = exactBrowserOrigin();
  const validated = validateBackendConfig(config, origin);
  if (validated.sessionToken !== null) {
    throw new Error("The web reviewer cannot store a bearer credential.");
  }
  forgetObsoleteBrowserConfiguration();
}

export async function savePendingPairingCleanup(
  _config: BackendConfig,
  _pendingPairingCleanup: PendingPairingCleanup,
): Promise<void> {
  throw new Error("The web reviewer cannot persist a pairing secret.");
}

export async function clearBackendConfig(): Promise<void> {
  forgetObsoleteBrowserConfiguration();
}
