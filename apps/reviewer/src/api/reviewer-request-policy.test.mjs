// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildReviewerRequestPolicy,
  ReviewerRequestPolicyError,
  validateLegacyAdminApiClientConfig,
  validateReviewerApiClientConfig,
} from "./reviewer-request-policy.ts";

const sessionToken = `rsess_${"a".repeat(32)}.${"S".repeat(43)}`;
const csrfToken = "C".repeat(43);

function rejects(fn, code) {
  assert.throws(
    fn,
    (error) => error instanceof ReviewerRequestPolicyError && error.code === code,
  );
}

test("web uses same-origin cookies without exposing bearer or Origin headers", () => {
  const config = validateReviewerApiClientConfig({
    baseUrl: "https://tacua.example",
    clientKind: "web",
    csrfToken,
  });
  const get = buildReviewerRequestPolicy(config, { Accept: "application/json" }, "GET");
  assert.equal(get.credentials, "same-origin");
  assert.equal(get.headers.get("Authorization"), null);
  assert.equal(get.headers.get("Origin"), null);
  assert.equal(get.headers.get("Tacua-CSRF-Token"), null);

  const post = buildReviewerRequestPolicy(config, undefined, "POST", { csrfProtected: true });
  assert.equal(post.credentials, "same-origin");
  assert.equal(post.headers.get("Authorization"), null);
  assert.equal(post.headers.get("Origin"), null);
  assert.equal(post.headers.get("Tacua-CSRF-Token"), csrfToken);
});

test("native omits cookies and adds only its scoped bearer plus exact POST origin", () => {
  const config = validateReviewerApiClientConfig({
    baseUrl: "https://mini-pc.example.ts.net",
    clientKind: "native",
    sessionToken,
    csrfToken,
  });
  const get = buildReviewerRequestPolicy(config, undefined, "GET");
  assert.equal(get.credentials, "omit");
  assert.equal(get.headers.get("Authorization"), `Bearer ${sessionToken}`);
  assert.equal(get.headers.get("Origin"), null);

  const post = buildReviewerRequestPolicy(config, undefined, "POST", { csrfProtected: true });
  assert.equal(post.headers.get("Origin"), "https://mini-pc.example.ts.net");
  assert.equal(post.headers.get("Tacua-CSRF-Token"), csrfToken);
  assert.equal(post.headers.get("Cookie"), null);
});

test("native pre-pairing POST sends an origin without inventing credentials", () => {
  const config = validateReviewerApiClientConfig({
    baseUrl: "https://mini-pc.example.ts.net",
    clientKind: "native",
  });
  const policy = buildReviewerRequestPolicy(config, undefined, "POST");
  assert.equal(policy.credentials, "omit");
  assert.equal(policy.headers.get("Origin"), "https://mini-pc.example.ts.net");
  assert.equal(policy.headers.get("Authorization"), null);
  assert.equal(policy.headers.get("Tacua-CSRF-Token"), null);

  const capability = validateReviewerApiClientConfig({
    baseUrl: "https://mini-pc.example.ts.net",
    clientKind: "native",
    csrfToken,
  });
  const capabilityPost = buildReviewerRequestPolicy(
    capability,
    undefined,
    "POST",
    { csrfProtected: true },
  );
  assert.equal(capabilityPost.headers.get("Authorization"), null);
  assert.equal(capabilityPost.headers.get("Origin"), "https://mini-pc.example.ts.net");
  assert.equal(capabilityPost.headers.get("Tacua-CSRF-Token"), csrfToken);
});

test("rejects token leakage, malformed configs, caller credential smuggling, and missing CSRF", () => {
  rejects(() => validateReviewerApiClientConfig({
    baseUrl: "https://tacua.example",
    clientKind: "web",
    sessionToken,
  }), "INVALID_CLIENT_CONFIG");
  rejects(() => validateLegacyAdminApiClientConfig({
    baseUrl: "https://tacua.example",
    adminToken: "A".repeat(32),
    debug: true,
  }), "INVALID_CLIENT_CONFIG");
  rejects(() => validateReviewerApiClientConfig({
    baseUrl: "https://tacua.example/path",
    clientKind: "native",
  }), "INVALID_CLIENT_CONFIG");
  assert.equal(validateReviewerApiClientConfig({
    baseUrl: "https://tacua.example",
    clientKind: "native",
    csrfToken,
  }).csrfToken, csrfToken);
  rejects(() => validateReviewerApiClientConfig({
    baseUrl: "http://tacua.example",
    clientKind: "native",
  }), "INVALID_CLIENT_CONFIG");
  rejects(() => validateReviewerApiClientConfig({
    baseUrl: "https://tacua.example",
    clientKind: "native",
    debug: true,
  }), "INVALID_CLIENT_CONFIG");

  const native = validateReviewerApiClientConfig({
    baseUrl: "https://tacua.example",
    clientKind: "native",
    sessionToken,
  });
  rejects(
    () => buildReviewerRequestPolicy(native, { Authorization: "Bearer admin" }, "GET"),
    "INVALID_REQUEST_HEADERS",
  );
  rejects(
    () => buildReviewerRequestPolicy(native, { "Tailscale-App-Capabilities": "{}" }, "GET"),
    "INVALID_REQUEST_HEADERS",
  );
  rejects(
    () => buildReviewerRequestPolicy(native, undefined, "POST", { csrfProtected: true }),
    "REVIEWER_CSRF_REQUIRED",
  );
});

test("legacy administrator compatibility is explicit and still origin-bound", () => {
  const config = validateLegacyAdminApiClientConfig({
    baseUrl: "https://tacua.example",
    adminToken: "A".repeat(32),
    csrfToken,
  });
  const policy = buildReviewerRequestPolicy(config, undefined, "POST", { csrfProtected: true });
  assert.equal(policy.credentials, "omit");
  assert.equal(policy.headers.get("Authorization"), `Bearer ${"A".repeat(32)}`);
  assert.equal(policy.headers.get("Origin"), "https://tacua.example");
  assert.equal(policy.headers.get("Tacua-CSRF-Token"), csrfToken);
});
