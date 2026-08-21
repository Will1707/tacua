// SPDX-License-Identifier: Apache-2.0

import type {
  ReviewerBootstrap,
  ReviewerBootstrapBuild,
} from "./types.ts";
import { isSafeTargetScheme } from "../config/target-scheme.ts";

const reviewerBootstrapContract = "tacua.reviewer-bootstrap@1.0.0";
const maximumBootstrapBuilds = 100;

// The closed projection is smaller than 100 KiB at all field maxima. Keep a
// little transport headroom without falling back to the generic 2 MiB cap.
export const maximumReviewerBootstrapResponseBytes = 128 * 1_024;

export class ReviewerBootstrapValidationError extends Error {
  readonly code = "INVALID_REVIEWER_BOOTSTRAP";

  constructor() {
    super("INVALID_REVIEWER_BOOTSTRAP");
    this.name = "ReviewerBootstrapValidationError";
  }
}

function fail(): never {
  throw new ReviewerBootstrapValidationError();
}

function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.some((key) => key.normalize("NFC") !== key)
    || actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) fail();
  return record;
}

function identifier(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z][a-z0-9_-]{2,63}$/.test(value)) fail();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value)) fail();
  return value;
}

function boundedVersion(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > 128
    || !/^[A-Za-z0-9._+/-]+$/.test(value)
  ) fail();
  return value;
}

function bundleIdentifier(value: unknown): string {
  if (
    typeof value !== "string"
    || value.length < 3
    || value.length > 255
    || !/^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$/.test(value)
  ) fail();
  return value;
}

function distribution(value: unknown): ReviewerBootstrapBuild["distribution"] {
  if (value !== "local" && value !== "internal" && value !== "testflight") fail();
  return value;
}

function launchScheme(value: unknown): string | null {
  if (value === null) return null;
  if (!isSafeTargetScheme(value)) fail();
  return value;
}

function build(value: unknown): ReviewerBootstrapBuild {
  const record = exact(value, [
    "build_id",
    "application_id",
    "bundle_identifier",
    "native_version",
    "native_build",
    "distribution",
    "build_identity_digest",
    "launch_scheme",
  ]);
  return {
    build_id: identifier(record.build_id),
    application_id: identifier(record.application_id),
    bundle_identifier: bundleIdentifier(record.bundle_identifier),
    native_version: boundedVersion(record.native_version),
    native_build: boundedVersion(record.native_build),
    distribution: distribution(record.distribution),
    build_identity_digest: digest(record.build_identity_digest),
    launch_scheme: launchScheme(record.launch_scheme),
  };
}

export function validateReviewerBootstrap(value: unknown): ReviewerBootstrap {
  const envelope = exact(value, ["contract_version", "reviewer_id", "builds"]);
  if (envelope.contract_version !== reviewerBootstrapContract) fail();
  if (!Array.isArray(envelope.builds) || envelope.builds.length > maximumBootstrapBuilds) fail();
  const builds = envelope.builds.map(build);
  if (
    new Set(builds.map((item) => item.build_id)).size !== builds.length
    || new Set(builds.map((item) => item.build_identity_digest)).size !== builds.length
  ) fail();
  return {
    contract_version: reviewerBootstrapContract,
    reviewer_id: identifier(envelope.reviewer_id),
    builds,
  };
}
