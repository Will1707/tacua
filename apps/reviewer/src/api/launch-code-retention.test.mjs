// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  launchCodeRetentionMilliseconds,
  maximumLocalLaunchCodeRetentionMilliseconds,
} from "./launch-code-retention.ts";

const now = Date.parse("2026-07-22T12:00:00Z");

test("bounds live launch codes by both backend expiry and a five-minute local ceiling", () => {
  assert.equal(launchCodeRetentionMilliseconds("2026-07-22T12:02:00Z", now), 120_000);
  assert.equal(
    launchCodeRetentionMilliseconds("2026-07-22T13:00:00Z", now),
    maximumLocalLaunchCodeRetentionMilliseconds,
  );
});

test("immediately releases expired, malformed, or clock-invalid launch codes", () => {
  assert.equal(launchCodeRetentionMilliseconds("2026-07-22T11:59:59Z", now), 0);
  assert.equal(launchCodeRetentionMilliseconds("not-a-timestamp", now), 0);
  assert.equal(launchCodeRetentionMilliseconds("2026-07-22T12:02:00Z", Number.NaN), 0);
});
