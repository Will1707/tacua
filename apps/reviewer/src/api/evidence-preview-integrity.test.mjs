// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  EvidencePreviewIntegrityError,
  verifyEvidencePreviewBytes,
} from "./evidence-preview-integrity.ts";

async function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function rejectsIntegrity(options, code) {
  await assert.rejects(
    () => verifyEvidencePreviewBytes({ ...options, digest }),
    (error) => error instanceof EvidencePreviewIntegrityError && error.code === code,
  );
}

test("accepts only bytes matching the declared length and SHA-256 digest", async () => {
  const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]);
  await verifyEvidencePreviewBytes({
    bytes,
    declaredLength: bytes.byteLength,
    expectedDigest: await digest(bytes),
    digest,
  });
});

test("rejects substituted bytes even when the expected digest header is unchanged", async () => {
  const expected = new Uint8Array([1, 2, 3, 4]);
  const substituted = new Uint8Array([1, 2, 3, 5]);
  await rejectsIntegrity({
    bytes: substituted,
    declaredLength: substituted.byteLength,
    expectedDigest: await digest(expected),
  }, "PREVIEW_DIGEST_MISMATCH");
});

test("rejects truncated bytes and malformed expected digests", async () => {
  const bytes = new Uint8Array([1, 2, 3]);
  await rejectsIntegrity({
    bytes,
    declaredLength: bytes.byteLength + 1,
    expectedDigest: await digest(bytes),
  }, "PREVIEW_LENGTH_MISMATCH");
  await rejectsIntegrity({
    bytes,
    declaredLength: bytes.byteLength,
    expectedDigest: "sha256:not-a-digest",
  }, "INVALID_PREVIEW_DIGEST");
});
