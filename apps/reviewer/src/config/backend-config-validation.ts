// SPDX-License-Identifier: Apache-2.0

import { normalizeBaseUrl } from "./base-url.ts";
import { normalizeTargetScheme } from "./target-scheme.ts";

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

export function validateBackendConfig(config: BackendConfig): BackendConfig {
  const baseUrl = normalizeBaseUrl(config.baseUrl);
  const reviewerId = requireIdentifier(config.reviewerId, "Reviewer ID");
  const targetScheme = normalizeTargetScheme(config.targetScheme);
  if (
    config.adminToken.length < 32
    || config.adminToken.length > 4_096
    || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(config.adminToken)
  ) {
    throw new Error("Administrator token is invalid.");
  }
  return { baseUrl, adminToken: config.adminToken, reviewerId, targetScheme };
}
