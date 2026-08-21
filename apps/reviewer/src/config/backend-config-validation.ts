// SPDX-License-Identifier: Apache-2.0

import { normalizeBaseUrl } from "./base-url.ts";

export type BackendConfig = {
  readonly baseUrl: string;
  readonly sessionToken: string | null;
};

export type PendingPairingCleanup = {
  readonly pairingToken: string;
  readonly clientKind: "native";
};

export type BackendConfigState = {
  readonly config: BackendConfig;
  readonly pendingPairingCleanup: PendingPairingCleanup | null;
};

const reviewerSessionTokenPattern = /^rsess_[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/;

export function validateBackendConfig(
  config: BackendConfig,
  browserOrigin: string | null = null,
): BackendConfig {
  if (
    config === null
    || typeof config !== "object"
    || Array.isArray(config)
    || typeof config.baseUrl !== "string"
    || (config.sessionToken !== null && typeof config.sessionToken !== "string")
    || Object.keys(config).some((key) => !["baseUrl", "sessionToken"].includes(key))
    || Object.keys(config).length !== 2
  ) {
    throw new Error("Backend configuration is invalid.");
  }
  const baseUrl = normalizeBaseUrl(config.baseUrl, browserOrigin);
  if (config.sessionToken !== null && !reviewerSessionTokenPattern.test(config.sessionToken)) {
    throw new Error("Reviewer session credential is invalid.");
  }
  return { baseUrl, sessionToken: config.sessionToken };
}
