// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  conservativeMaximumSessionDetailBytes,
  maximumSessionDetailResponseBytes,
  sessionDetailResponseBudget,
} from "./response-limits.ts";

test("session detail has one explicit finite cap above its closed V1 projection budget", () => {
  assert.deepEqual(
    {
      credentials: sessionDetailResponseBudget.maximumCredentials,
      diagnostics: sessionDetailResponseBudget.maximumDiagnostics,
      jobs: sessionDetailResponseBudget.maximumJobs,
      segments: sessionDetailResponseBudget.maximumSegments,
    },
    { credentials: 64, diagnostics: 2_048, jobs: 1, segments: 2_048 },
  );
  assert.equal(maximumSessionDetailResponseBytes, 16_777_216);
  assert.ok(conservativeMaximumSessionDetailBytes < 10 * 1_024 * 1_024);
  assert.ok(conservativeMaximumSessionDetailBytes < maximumSessionDetailResponseBytes);
});
