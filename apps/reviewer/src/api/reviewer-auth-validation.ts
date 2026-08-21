// SPDX-License-Identifier: Apache-2.0

import type {
  ReviewerClientKind,
  ReviewerNativePairingExchange,
  ReviewerPairingCancellation,
  ReviewerPairingExchange,
  ReviewerPairingRequest,
  ReviewerPrincipal,
  ReviewerScope,
  ReviewerSession,
  ReviewerWebPairingExchange,
} from "./types.ts";

const reviewerScopes = Object.freeze([
  "reviewer.launch",
  "reviewer.read",
  "reviewer.write",
] as const satisfies readonly ReviewerScope[]);

const maximumPairingResponseBytes = 4 * 1_024;
const maximumPairingCancellationResponseBytes = 256;
const maximumSessionResponseBytes = 4 * 1_024;

export const maximumReviewerPairingResponseBytes = maximumPairingResponseBytes;
export const maximumReviewerPairingCancellationResponseBytes = maximumPairingCancellationResponseBytes;
export const maximumReviewerSessionResponseBytes = maximumSessionResponseBytes;

export type ReviewerAuthValidationCode =
  | "INVALID_PAIRING_CANCELLATION"
  | "INVALID_PAIRING_REQUEST"
  | "INVALID_PAIRING_EXCHANGE"
  | "INVALID_REVIEWER_PRINCIPAL"
  | "INVALID_REVIEWER_SESSION";

export class ReviewerAuthValidationError extends Error {
  readonly code: ReviewerAuthValidationCode;

  constructor(code: ReviewerAuthValidationCode) {
    super(code);
    this.name = "ReviewerAuthValidationError";
    this.code = code;
  }
}

function fail(code: ReviewerAuthValidationCode): never {
  throw new ReviewerAuthValidationError(code);
}

function exact(
  value: unknown,
  keys: readonly string[],
  code: ReviewerAuthValidationCode,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(code);
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.some((key) => key.normalize("NFC") !== key)
    || actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) fail(code);
  return record;
}

function identifier(value: unknown, code: ReviewerAuthValidationCode): string {
  if (typeof value !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(value)) fail(code);
  return value;
}

function pairingIdentifier(value: unknown, code: ReviewerAuthValidationCode): string {
  if (typeof value !== "string" || !/^rpair_[a-f0-9]{32}$/.test(value)) fail(code);
  return value;
}

function sessionIdentifier(value: unknown, code: ReviewerAuthValidationCode): string {
  if (typeof value !== "string" || !/^rsess_[a-f0-9]{32}$/.test(value)) fail(code);
  return value;
}

export function isReviewerSessionToken(value: unknown): value is string {
  return typeof value === "string"
    && /^rsess_[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/.test(value);
}

function pairingToken(value: unknown, code: ReviewerAuthValidationCode): string {
  if (
    typeof value !== "string"
    || !/^rpair_[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$/.test(value)
  ) fail(code);
  return value;
}

export function validateReviewerPairingToken(value: unknown): string {
  return pairingToken(value, "INVALID_PAIRING_EXCHANGE");
}

export function validateReviewerPairingCancellationToken(value: unknown): string {
  return pairingToken(value, "INVALID_PAIRING_CANCELLATION");
}

function timestamp(value: unknown, code: ReviewerAuthValidationCode): string {
  if (
    typeof value !== "string"
    || value.startsWith("0000-")
    || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(value)
  ) fail(code);
  const parsed = new Date(value);
  if (
    Number.isNaN(parsed.valueOf())
    || parsed.toISOString() !== `${value.slice(0, -1)}.000Z`
  ) fail(code);
  return value;
}

function deviceLabel(value: unknown, code: ReviewerAuthValidationCode): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value !== value.trim()
    || value !== value.normalize("NFC")
    || Array.from(value).length > 64
    || new TextEncoder().encode(value).byteLength > 128
    || /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}]/u.test(value)
  ) fail(code);
  return value;
}

export function validateReviewerDeviceLabel(value: unknown): string {
  return deviceLabel(value, "INVALID_PAIRING_REQUEST");
}

function scopes(value: unknown, code: ReviewerAuthValidationCode): readonly ReviewerScope[] {
  if (
    !Array.isArray(value)
    || value.length !== reviewerScopes.length
    || value.some((scope, index) => scope !== reviewerScopes[index])
  ) fail(code);
  return [...reviewerScopes];
}

function csrfToken(value: unknown, code: ReviewerAuthValidationCode): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) fail(code);
  return value;
}

function principal(
  value: unknown,
  code: "INVALID_PAIRING_EXCHANGE" | "INVALID_REVIEWER_PRINCIPAL",
  expectedClientKind?: ReviewerClientKind,
): ReviewerPrincipal {
  const record = exact(value, [
    "reviewer_id",
    "auth_kind",
    "session_id",
    "device_label",
    "client_kind",
    "scopes",
    "expires_at",
    "csrf_token",
  ], code);
  const reviewerId = identifier(record.reviewer_id, code);
  const validatedScopes = scopes(record.scopes, code);
  const csrf = csrfToken(record.csrf_token, code);

  if (record.auth_kind === "session") {
    if (
      (record.client_kind !== "web" && record.client_kind !== "native")
      || (expectedClientKind !== undefined && record.client_kind !== expectedClientKind)
    ) fail(code);
    return {
      reviewer_id: reviewerId,
      auth_kind: "session",
      session_id: sessionIdentifier(record.session_id, code),
      device_label: deviceLabel(record.device_label, code),
      client_kind: record.client_kind,
      scopes: validatedScopes,
      expires_at: timestamp(record.expires_at, code),
      csrf_token: csrf,
    };
  }

  if (expectedClientKind !== undefined) fail(code);
  if (
    record.auth_kind === "legacy_admin"
    && record.session_id === null
    && record.device_label === null
    && record.client_kind === "legacy_web"
    && record.expires_at === null
  ) {
    return {
      reviewer_id: reviewerId,
      auth_kind: "legacy_admin",
      session_id: null,
      device_label: null,
      client_kind: "legacy_web",
      scopes: validatedScopes,
      expires_at: null,
      csrf_token: csrf,
    };
  }
  if (
    record.auth_kind === "tailscale_capability"
    && record.session_id === null
    && record.device_label === null
    && record.client_kind === "tailscale_web"
    && record.expires_at === null
  ) {
    return {
      reviewer_id: reviewerId,
      auth_kind: "tailscale_capability",
      session_id: null,
      device_label: null,
      client_kind: "tailscale_web",
      scopes: validatedScopes,
      expires_at: null,
      csrf_token: csrf,
    };
  }
  fail(code);
}

export function validateReviewerPrincipal(value: unknown): ReviewerPrincipal {
  return principal(value, "INVALID_REVIEWER_PRINCIPAL");
}

export function validateReviewerPairingRequest(value: unknown): ReviewerPairingRequest {
  const code = "INVALID_PAIRING_REQUEST";
  const record = exact(value, [
    "pairing_id",
    "pairing_token",
    "human_code",
    "device_label",
    "client_kind",
    "created_at",
    "expires_at",
  ], code);
  const pairingId = pairingIdentifier(record.pairing_id, code);
  const token = pairingToken(record.pairing_token, code);
  if (!token.startsWith(`${pairingId}.`)) fail(code);
  if (
    typeof record.human_code !== "string"
    || !/^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$/.test(record.human_code)
    || (record.client_kind !== "web" && record.client_kind !== "native")
  ) fail(code);
  const createdAt = timestamp(record.created_at, code);
  const expiresAt = timestamp(record.expires_at, code);
  if (Date.parse(expiresAt) - Date.parse(createdAt) !== 10 * 60 * 1_000) fail(code);
  return {
    pairing_id: pairingId,
    pairing_token: token,
    human_code: record.human_code,
    device_label: deviceLabel(record.device_label, code),
    client_kind: record.client_kind,
    created_at: createdAt,
    expires_at: expiresAt,
  };
}

export function validateReviewerPairingExchange(
  value: unknown,
  expectedClientKind: ReviewerClientKind,
): ReviewerPairingExchange {
  const code = "INVALID_PAIRING_EXCHANGE";
  if (expectedClientKind === "web") {
    return principal(value, code, "web") as ReviewerWebPairingExchange;
  }
  const record = exact(value, [
    "reviewer_id",
    "auth_kind",
    "session_id",
    "device_label",
    "client_kind",
    "scopes",
    "expires_at",
    "csrf_token",
    "session_token",
  ], code);
  if (!isReviewerSessionToken(record.session_token)) fail(code);
  const { session_token: sessionToken, ...principalRecord } = record;
  const validated = principal(principalRecord, code, "native");
  if (!sessionToken.startsWith(`${validated.session_id}.`)) fail(code);
  return { ...validated, session_token: sessionToken } as ReviewerNativePairingExchange;
}

export function validateReviewerPairingCancellation(
  value: unknown,
): ReviewerPairingCancellation {
  const code = "INVALID_PAIRING_CANCELLATION";
  const record = exact(value, ["status"], code);
  if (record.status !== "canceled") fail(code);
  return { status: "canceled" };
}

function reviewerSession(value: unknown): ReviewerSession {
  const code = "INVALID_REVIEWER_SESSION";
  const record = exact(value, [
    "session_id",
    "reviewer_id",
    "device_label",
    "client_kind",
    "scopes",
    "created_at",
    "expires_at",
    "revoked_at",
  ], code);
  if (record.client_kind !== "web" && record.client_kind !== "native") fail(code);
  const createdAt = timestamp(record.created_at, code);
  const expiresAt = timestamp(record.expires_at, code);
  const revokedAt = record.revoked_at === null ? null : timestamp(record.revoked_at, code);
  if (
    Date.parse(expiresAt) - Date.parse(createdAt) !== 30 * 24 * 60 * 60 * 1_000
    || (
      revokedAt !== null
      && (
        Date.parse(revokedAt) < Date.parse(createdAt)
        || Date.parse(revokedAt) >= Date.parse(expiresAt)
      )
    )
  ) fail(code);
  return {
    session_id: sessionIdentifier(record.session_id, code),
    reviewer_id: identifier(record.reviewer_id, code),
    device_label: deviceLabel(record.device_label, code),
    client_kind: record.client_kind,
    scopes: scopes(record.scopes, code),
    created_at: createdAt,
    expires_at: expiresAt,
    revoked_at: revokedAt,
  };
}

export function validateRevokedReviewerSession(value: unknown): ReviewerSession {
  const code = "INVALID_REVIEWER_SESSION";
  const envelope = exact(value, ["session"], code);
  const session = reviewerSession(envelope.session);
  if (session.revoked_at === null) fail(code);
  return session;
}
