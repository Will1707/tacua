// SPDX-License-Identifier: Apache-2.0

import type { ResumeLaunchGrant, StartLaunchGrant } from "@/api/types";
import { isSafeTargetScheme } from "../config/target-scheme.ts";

export class LaunchGrantValidationError extends Error {
  readonly code: "INVALID_LAUNCH_GRANT" | "LAUNCH_GRANT_BINDING_MISMATCH";

  constructor(code: "INVALID_LAUNCH_GRANT" | "LAUNCH_GRANT_BINDING_MISMATCH") {
    super(code);
    this.name = "LaunchGrantValidationError";
    this.code = code;
  }
}

function exactKeys(value: object, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function identifier(value: unknown): value is string {
  return typeof value === "string" && /^[a-z][a-z0-9_-]{2,63}$/.test(value);
}

function digest(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

function timestamp(value: unknown): value is string {
  if (
    typeof value !== "string"
    || value.startsWith("0000-")
    || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(value)
  ) return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.valueOf())
    && parsed.toISOString() === `${value.slice(0, -1)}.000Z`;
}

function shared(value: Record<string, unknown>): boolean {
  return identifier(value.launch_id)
    && typeof value.launch_code === "string"
    && /^[A-Za-z0-9_-]{32,512}$/.test(value.launch_code)
    && digest(value.build_identity_digest)
    && timestamp(value.expires_at);
}

export function validateStartLaunchGrant(value: unknown): StartLaunchGrant {
  if (
    value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || !exactKeys(value, [
      "launch_id", "launch_code", "exchange_kind", "session_id",
      "build_identity_digest", "scope_policy_digest", "expires_at",
    ])
  ) throw new LaunchGrantValidationError("INVALID_LAUNCH_GRANT");
  const grant = value as Record<string, unknown>;
  if (
    !shared(grant)
    || grant.exchange_kind !== "start_session"
    || grant.session_id !== null
    || !digest(grant.scope_policy_digest)
  ) throw new LaunchGrantValidationError("INVALID_LAUNCH_GRANT");
  return value as StartLaunchGrant;
}

export function validateResumeLaunchGrant(
  value: unknown,
  expectedSessionId: string,
): ResumeLaunchGrant {
  if (
    !identifier(expectedSessionId)
    || value === null
    || typeof value !== "object"
    || Array.isArray(value)
    || !exactKeys(value, [
      "launch_id", "launch_code", "exchange_kind", "session_id",
      "build_identity_digest", "scope_digest", "expires_at",
    ])
  ) throw new LaunchGrantValidationError("INVALID_LAUNCH_GRANT");
  const grant = value as Record<string, unknown>;
  if (
    !shared(grant)
    || grant.exchange_kind !== "resume_session"
    || !identifier(grant.session_id)
    || !digest(grant.scope_digest)
  ) throw new LaunchGrantValidationError("INVALID_LAUNCH_GRANT");
  if (grant.session_id !== expectedSessionId) {
    throw new LaunchGrantValidationError("LAUNCH_GRANT_BINDING_MISMATCH");
  }
  return value as ResumeLaunchGrant;
}

export function buildLaunchURL(
  targetScheme: string,
  launchCode: string,
  expectedSessionId?: string,
): string {
  if (
    !isSafeTargetScheme(targetScheme)
    || !/^[A-Za-z0-9_-]{32,512}$/.test(launchCode)
    || (expectedSessionId !== undefined && !identifier(expectedSessionId))
  ) throw new LaunchGrantValidationError("INVALID_LAUNCH_GRANT");
  const sessionBinding = expectedSessionId === undefined
    ? ""
    : `&session_id=${encodeURIComponent(expectedSessionId)}`;
  return `${targetScheme}://tacua/start?launch_code=${encodeURIComponent(launchCode)}${sessionBinding}`;
}
