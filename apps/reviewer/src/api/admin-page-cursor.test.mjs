// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  AdminPageCursorError,
  adminPageHeaders,
  isAdminPageCursor,
} from "./admin-page-cursor.ts";

test("admin list clients omit the first-page header and replay one opaque cursor exactly", () => {
  assert.equal(adminPageHeaders(), undefined);
  assert.deepEqual(
    adminPageHeaders("eyJraW5kIjoiam9icyJ9"),
    { "Tacua-Page-Cursor": "eyJraW5kIjoiam9icyJ9" },
  );
});

test("admin list clients reject empty, malformed, and oversized cursors locally", () => {
  for (const cursor of ["", "a", "not*base64", "a".repeat(513)]) {
    assert.equal(isAdminPageCursor(cursor), false);
    assert.throws(() => adminPageHeaders(cursor), AdminPageCursorError);
  }
  assert.equal(isAdminPageCursor(null), true);
});
