// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  isApprovedHandoffCacheFilename,
  maximumApprovedHandoffCacheAgeMilliseconds,
  maximumApprovedHandoffShareFileBytes,
  planApprovedHandoffCacheCleanup,
} from "./share-cache-policy.ts";

const now = 2_000_000_000_000;
const uuid = (index) => `${String(index).padStart(8, "0")}-0000-4000-8000-000000000000`;
const entry = (index, overrides = {}) => ({
  name: `tacua-handoff-ticket-v1-${uuid(index)}.json`,
  isFile: true,
  isDirectChild: true,
  size: 100,
  lastModified: now - index,
  ...overrides,
});

test("recognizes only bounded safe share filenames", () => {
  assert.equal(isApprovedHandoffCacheFilename(entry(1).name), true);
  assert.equal(isApprovedHandoffCacheFilename("../tacua-handoff-ticket-v1-00000001-0000-4000-8000-000000000000.json"), false);
  assert.equal(isApprovedHandoffCacheFilename("tacua-ticket.json"), false);
  assert.equal(isApprovedHandoffCacheFilename("tacua-handoff-ticket-v0-00000001-0000-4000-8000-000000000000.json"), false);
});

test("keeps at most ten newest files and reserves a slot before sharing", () => {
  const entries = Array.from({ length: 12 }, (_, index) => entry(index + 1));
  const normal = planApprovedHandoffCacheCleanup(entries, now);
  assert.equal(normal.retainedNames.length, 10);
  assert.deepEqual(new Set(normal.deleteNames), new Set([entry(11).name, entry(12).name]));
  const reserved = planApprovedHandoffCacheCleanup(entries, now, 1);
  assert.equal(reserved.retainedNames.length, 9);
  assert.deepEqual(new Set(reserved.deleteNames), new Set([entry(10).name, entry(11).name, entry(12).name]));
});

test("expires old, empty, oversized, and implausibly future-dated managed files", () => {
  const entries = [
    entry(1, { lastModified: now - maximumApprovedHandoffCacheAgeMilliseconds }),
    entry(2, { lastModified: now - maximumApprovedHandoffCacheAgeMilliseconds - 1 }),
    entry(3, { size: 0 }),
    entry(4, { size: maximumApprovedHandoffShareFileBytes + 1 }),
    entry(5, { lastModified: now + 60_001 }),
  ];
  const plan = planApprovedHandoffCacheCleanup(entries, now);
  assert.deepEqual(plan.retainedNames, [entry(1).name]);
  assert.deepEqual(new Set(plan.deleteNames), new Set(entries.slice(1).map((item) => item.name)));
});

test("never selects an unsafe prefix, nested path, or directory for deletion", () => {
  const entries = [
    entry(1, { name: "unrelated.json", lastModified: 0 }),
    entry(2, { isDirectChild: false, lastModified: 0 }),
    entry(3, { isFile: false, lastModified: 0 }),
  ];
  const plan = planApprovedHandoffCacheCleanup(entries, now);
  assert.deepEqual(plan.deleteNames, []);
  assert.deepEqual(plan.retainedNames, []);
});
