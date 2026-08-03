// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { isLikelyIOSBrowser } from "../utils/launch-device-detection.ts";

test("recognizes iPhone and iPad browsers as same-device launch targets", () => {
  assert.equal(isLikelyIOSBrowser({
    maxTouchPoints: 5,
    userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit Mobile Safari",
  }), true);
  assert.equal(isLikelyIOSBrowser({
    maxTouchPoints: 5,
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit Version/18.0 Mobile Safari",
  }), true);
});

test("keeps desktop and non-iOS mobile browsers on the QR handoff path", () => {
  assert.equal(isLikelyIOSBrowser({
    maxTouchPoints: 0,
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit Chrome Safari",
  }), false);
  assert.equal(isLikelyIOSBrowser({
    userAgent: "Mozilla/5.0 (Linux; Android 15) AppleWebKit Chrome Mobile Safari",
  }), false);
  assert.equal(isLikelyIOSBrowser({}), false);
});
