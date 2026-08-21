// SPDX-License-Identifier: Apache-2.0

import type { ReviewerClientKind } from "./types.ts";
import { isReviewerSessionToken } from "./reviewer-auth-validation.ts";

export type ReviewerApiClientConfig = {
  readonly baseUrl: string;
  readonly clientKind: ReviewerClientKind;
  /** Native-only scoped reviewer bearer. Never store or supply this on web. */
  readonly sessionToken?: string;
  /** Origin-bound token returned by the current reviewer principal. */
  readonly csrfToken?: string;
};

export type LegacyAdminApiClientConfig = {
  readonly baseUrl: string;
  readonly adminToken: string;
  readonly csrfToken?: string;
};

type ValidatedReviewerApiClientConfig = ReviewerApiClientConfig & {
  readonly authentication: "reviewer";
};

type ValidatedLegacyAdminApiClientConfig = LegacyAdminApiClientConfig & {
  readonly authentication: "legacy_admin";
  readonly clientKind: "legacy_admin";
};

export type ValidatedApiClientConfig =
  | ValidatedReviewerApiClientConfig
  | ValidatedLegacyAdminApiClientConfig;

export type ReviewerRequestPolicy = {
  readonly credentials: "omit" | "same-origin";
  readonly headers: Headers;
};

export class ReviewerRequestPolicyError extends Error {
  readonly code:
    | "INVALID_CLIENT_CONFIG"
    | "INVALID_REQUEST_HEADERS"
    | "REVIEWER_CSRF_REQUIRED";

  constructor(code: ReviewerRequestPolicyError["code"]) {
    super(code);
    this.name = "ReviewerRequestPolicyError";
    this.code = code;
  }
}

function fail(code: ReviewerRequestPolicyError["code"]): never {
  throw new ReviewerRequestPolicyError(code);
}

function exactOrigin(value: unknown): string {
  if (typeof value !== "string" || value.length > 2_048) fail("INVALID_CLIENT_CONFIG");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    fail("INVALID_CLIENT_CONFIG");
  }
  const localDevelopment = typeof __DEV__ !== "undefined" && __DEV__
    && parsed.protocol === "http:"
    && ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (
    parsed.origin !== value
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.search !== ""
    || parsed.hash !== ""
    || (parsed.pathname !== "" && parsed.pathname !== "/")
    || (parsed.protocol !== "https:" && !localDevelopment)
  ) fail("INVALID_CLIENT_CONFIG");
  return parsed.origin;
}

function hasOnlyKeys(value: object, required: readonly string[], optional: readonly string[]): boolean {
  const keys = Object.keys(value);
  const permitted = new Set([...required, ...optional]);
  return required.every((key) => keys.includes(key))
    && keys.every((key) => key.normalize("NFC") === key && permitted.has(key));
}

function csrfToken(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    fail("INVALID_CLIENT_CONFIG");
  }
  return value;
}

export function validateReviewerApiClientConfig(
  value: ReviewerApiClientConfig,
): ValidatedReviewerApiClientConfig {
  if (
    value === null
    || typeof value !== "object"
    || !hasOnlyKeys(value, ["baseUrl", "clientKind"], ["sessionToken", "csrfToken"])
    || (value.clientKind !== "web" && value.clientKind !== "native")
  ) fail("INVALID_CLIENT_CONFIG");
  const baseUrl = exactOrigin(value.baseUrl);
  const validatedCsrf = csrfToken(value.csrfToken);
  if (value.clientKind === "web") {
    if (value.sessionToken !== undefined) fail("INVALID_CLIENT_CONFIG");
    return {
      baseUrl,
      clientKind: "web",
      ...(validatedCsrf === undefined ? {} : { csrfToken: validatedCsrf }),
      authentication: "reviewer",
    };
  }
  if (value.sessionToken !== undefined && !isReviewerSessionToken(value.sessionToken)) {
    fail("INVALID_CLIENT_CONFIG");
  }
  return {
    baseUrl,
    clientKind: "native",
    ...(value.sessionToken === undefined ? {} : { sessionToken: value.sessionToken }),
    ...(validatedCsrf === undefined ? {} : { csrfToken: validatedCsrf }),
    authentication: "reviewer",
  };
}

export function validateLegacyAdminApiClientConfig(
  value: LegacyAdminApiClientConfig,
): ValidatedLegacyAdminApiClientConfig {
  if (
    value === null
    || typeof value !== "object"
    || !hasOnlyKeys(value, ["baseUrl", "adminToken"], ["csrfToken"])
    || typeof value.adminToken !== "string"
    || value.adminToken.length < 32
    || value.adminToken.length > 4_096
    || !/^[A-Za-z0-9._~+/-]+={0,2}$/.test(value.adminToken)
  ) fail("INVALID_CLIENT_CONFIG");
  const validatedCsrf = csrfToken(value.csrfToken);
  return {
    baseUrl: exactOrigin(value.baseUrl),
    clientKind: "legacy_admin",
    adminToken: value.adminToken,
    ...(validatedCsrf === undefined ? {} : { csrfToken: validatedCsrf }),
    authentication: "legacy_admin",
  };
}

const protectedHeaders = [
  "Authorization",
  "Cookie",
  "Origin",
  "Tacua-CSRF-Token",
  "Tailscale-App-Capabilities",
] as const;

function isUnsafeMethod(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

export function buildReviewerRequestPolicy(
  config: ValidatedApiClientConfig,
  initHeaders: HeadersInit | undefined,
  method: string,
  options: { readonly csrfProtected?: boolean } = {},
): ReviewerRequestPolicy {
  const headers = new Headers(initHeaders);
  if (protectedHeaders.some((name) => headers.has(name))) fail("INVALID_REQUEST_HEADERS");
  const unsafe = isUnsafeMethod(method);
  if (options.csrfProtected && !unsafe) fail("INVALID_REQUEST_HEADERS");

  if (config.authentication === "legacy_admin") {
    headers.set("Authorization", `Bearer ${config.adminToken}`);
  } else if (config.clientKind === "native" && config.sessionToken !== undefined) {
    headers.set("Authorization", `Bearer ${config.sessionToken}`);
  }

  if (unsafe && config.clientKind !== "web") {
    headers.set("Origin", config.baseUrl);
  }
  if (options.csrfProtected) {
    if (config.csrfToken === undefined) fail("REVIEWER_CSRF_REQUIRED");
    headers.set("Tacua-CSRF-Token", config.csrfToken);
  }

  return {
    credentials: config.clientKind === "web" ? "same-origin" : "omit",
    headers,
  };
}
