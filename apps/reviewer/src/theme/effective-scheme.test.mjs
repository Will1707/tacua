// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { effectiveReviewerScheme } from "./effective-scheme.ts";

test("web navigation stays on the same audited light palette as web components", () => {
  assert.equal(effectiveReviewerScheme("web", "dark"), "light");
  assert.equal(effectiveReviewerScheme("web", "light"), "light");
  assert.equal(effectiveReviewerScheme("web", null), "light");
});

test("native platforms retain their adaptive light and dark navigation themes", () => {
  assert.equal(effectiveReviewerScheme("ios", "dark"), "dark");
  assert.equal(effectiveReviewerScheme("ios", "light"), "light");
  assert.equal(effectiveReviewerScheme("android", undefined), "light");
});
