// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { normalizeBaseUrl } from "./base-url.ts";

test("browser deployments accept only their exact same backend origin", () => {
  assert.equal(
    normalizeBaseUrl("https://reviewer.example/", "https://reviewer.example"),
    "https://reviewer.example",
  );
  assert.throws(
    () => normalizeBaseUrl("https://api.example", "https://reviewer.example"),
    /must use its own HTTPS origin/u,
  );
  assert.throws(
    () => normalizeBaseUrl("https://reviewer.example", "not an origin"),
    /browser origin is invalid/u,
  );
});

test("native normalization remains independent of a browser origin", () => {
  assert.equal(
    normalizeBaseUrl(" HTTPS://Tacua.Example:443/ ", null),
    "https://tacua.example",
  );
});
