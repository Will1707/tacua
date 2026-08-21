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

function validateAdministratorToken(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length < 32
    || value.length > 4_096
    || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(value)
  ) {
    throw new Error("Administrator token is invalid.");
  }
  return value;
}

/** Validate only fields needed for the authenticated bootstrap request. */
export function validateBackendConnectionConfig(config: BackendConfig): BackendConfig {
  if (
    config === null
    || typeof config !== "object"
    || typeof config.baseUrl !== "string"
    || typeof config.reviewerId !== "string"
    || typeof config.targetScheme !== "string"
    || config.reviewerId.length > 256
    || config.targetScheme.length > 256
  ) {
    throw new Error("Backend configuration is invalid.");
  }
  const baseUrl = normalizeBaseUrl(config.baseUrl);
  const adminToken = validateAdministratorToken(config.adminToken);
  return {
    baseUrl,
    adminToken,
    reviewerId: config.reviewerId.trim(),
    targetScheme: config.targetScheme.trim(),
  };
}

export function validateBackendConfig(config: BackendConfig): BackendConfig {
  const connection = validateBackendConnectionConfig(config);
  return {
    ...connection,
    reviewerId: requireIdentifier(connection.reviewerId, "Reviewer ID"),
    targetScheme: normalizeTargetScheme(connection.targetScheme),
  };
}
