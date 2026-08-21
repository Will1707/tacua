// SPDX-License-Identifier: Apache-2.0

import {
  type BackendConfig,
  validateBackendConfig,
} from "./backend-config-validation.ts";

export { normalizeBaseUrl } from "./base-url.ts";
export { validateBackendConfig } from "./backend-config-validation.ts";
export type { BackendConfig } from "./backend-config-validation.ts";

// Web authentication is an HttpOnly same-origin cookie or a header injected by
// Tailscale Serve. No endpoint, identity, launch scheme, or bearer credential is
// persisted in browser storage.
const obsoleteSessionKeys = [
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
  if (typeof globalThis.sessionStorage === "undefined") return;
  for (const key of obsoleteSessionKeys) globalThis.sessionStorage.removeItem(key);
}

export async function loadBackendConfig(): Promise<BackendConfig> {
  forgetObsoleteBrowserConfiguration();
  const origin = exactBrowserOrigin();
  return validateBackendConfig({ baseUrl: origin, sessionToken: null }, origin);
}

export async function saveBackendConfig(config: BackendConfig): Promise<void> {
  const origin = exactBrowserOrigin();
  const validated = validateBackendConfig(config, origin);
  if (validated.sessionToken !== null) {
    throw new Error("The web reviewer cannot store a bearer credential.");
  }
  forgetObsoleteBrowserConfiguration();
}

export async function clearBackendConfig(): Promise<void> {
  forgetObsoleteBrowserConfiguration();
}
