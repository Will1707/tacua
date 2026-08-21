// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  maximumReviewerPairingResponseBytes,
  maximumReviewerSessionResponseBytes,
  ReviewerAuthValidationError,
  validateReviewerPairingExchange,
  validateReviewerPairingRequest,
  validateReviewerPrincipal,
  validateRevokedReviewerSession,
} from "./reviewer-auth-validation.ts";

const pairingId = `rpair_${"a".repeat(32)}`;
const sessionId = `rsess_${"b".repeat(32)}`;
const pairingSecret = "P".repeat(43);
const sessionSecret = "S".repeat(43);
const csrfToken = "C".repeat(43);
const scopes = ["reviewer.launch", "reviewer.read", "reviewer.write"];

function principal(overrides = {}) {
  return {
    reviewer_id: "reviewer_owner",
    auth_kind: "session",
    session_id: sessionId,
    device_label: "Will's reviewer",
    client_kind: "web",
    scopes,
    expires_at: "2026-09-20T12:00:00Z",
    csrf_token: csrfToken,
    ...overrides,
  };
}

function pairing(overrides = {}) {
  return {
    pairing_id: pairingId,
    pairing_token: `${pairingId}.${pairingSecret}`,
    human_code: "2345-6789",
    device_label: "Will's reviewer",
    client_kind: "web",
    created_at: "2026-08-21T12:00:00Z",
    expires_at: "2026-08-21T12:10:00Z",
    ...overrides,
  };
}

function rejects(fn, code) {
  assert.throws(
    fn,
    (error) => error instanceof ReviewerAuthValidationError && error.code === code,
  );
}

test("accepts the exact bounded pairing request and both exchange representations", () => {
  assert.deepEqual(validateReviewerPairingRequest(pairing()), pairing());
  const web = principal();
  assert.deepEqual(validateReviewerPairingExchange(web, "web"), web);
  const native = principal({
    client_kind: "native",
    session_token: `${sessionId}.${sessionSecret}`,
  });
  assert.deepEqual(validateReviewerPairingExchange(native, "native"), native);
  assert.ok(maximumReviewerPairingResponseBytes <= 4 * 1_024);
  assert.ok(maximumReviewerSessionResponseBytes <= 4 * 1_024);
});

test("rejects pairing substitution, drift, invalid labels, and non-canonical lifetimes", () => {
  rejects(() => validateReviewerPairingRequest({ ...pairing(), debug: true }), "INVALID_PAIRING_REQUEST");
  rejects(() => validateReviewerPairingRequest(pairing({ pairing_token: `rpair_${"c".repeat(32)}.${pairingSecret}` })), "INVALID_PAIRING_REQUEST");
  rejects(() => validateReviewerPairingRequest(pairing({ human_code: "ABIO-1234" })), "INVALID_PAIRING_REQUEST");
  rejects(() => validateReviewerPairingRequest(pairing({ device_label: " padded " })), "INVALID_PAIRING_REQUEST");
  rejects(() => validateReviewerPairingRequest(pairing({ device_label: "e\u0301" })), "INVALID_PAIRING_REQUEST");
  rejects(() => validateReviewerPairingRequest(pairing({ device_label: "ok\nnot-ok" })), "INVALID_PAIRING_REQUEST");
  rejects(() => validateReviewerPairingRequest(pairing({ expires_at: "2026-08-21T12:10:01Z" })), "INVALID_PAIRING_REQUEST");
});

test("pins pairing exchange kind and binds the native bearer to its session", () => {
  rejects(() => validateReviewerPairingExchange(principal(), "native"), "INVALID_PAIRING_EXCHANGE");
  rejects(
    () => validateReviewerPairingExchange({ ...principal(), session_token: `${sessionId}.${sessionSecret}` }, "web"),
    "INVALID_PAIRING_EXCHANGE",
  );
  rejects(
    () => validateReviewerPairingExchange(principal({
      client_kind: "native",
      session_token: `rsess_${"c".repeat(32)}.${sessionSecret}`,
    }), "native"),
    "INVALID_PAIRING_EXCHANGE",
  );
  rejects(
    () => validateReviewerPairingExchange(principal({ scopes: [...scopes].reverse() }), "web"),
    "INVALID_PAIRING_EXCHANGE",
  );
});

test("accepts only internally consistent session, capability, and legacy principals", () => {
  const firstSession = validateReviewerPrincipal(principal());
  assert.equal(firstSession.auth_kind, "session");
  firstSession.scopes[0] = "attacker.scope";
  assert.deepEqual(validateReviewerPrincipal(principal()).scopes, scopes);
  const tailscale = principal({
    auth_kind: "tailscale_capability",
    session_id: null,
    device_label: null,
    client_kind: "tailscale_web",
    expires_at: null,
  });
  assert.deepEqual(validateReviewerPrincipal(tailscale), tailscale);
  const legacy = principal({
    auth_kind: "legacy_admin",
    session_id: null,
    device_label: null,
    client_kind: "legacy_web",
    expires_at: null,
  });
  assert.deepEqual(validateReviewerPrincipal(legacy), legacy);

  rejects(() => validateReviewerPrincipal({ ...tailscale, session_id: sessionId }), "INVALID_REVIEWER_PRINCIPAL");
  rejects(() => validateReviewerPrincipal({ ...legacy, expires_at: "2026-09-20T12:00:00Z" }), "INVALID_REVIEWER_PRINCIPAL");
  rejects(() => validateReviewerPrincipal(principal({ csrf_token: "short" })), "INVALID_REVIEWER_PRINCIPAL");
});

test("validates the exact revoked-session envelope and 30-day lifetime", () => {
  const session = {
    session_id: sessionId,
    reviewer_id: "reviewer_owner",
    device_label: "Will's reviewer",
    client_kind: "native",
    scopes,
    created_at: "2026-08-21T12:00:00Z",
    expires_at: "2026-09-20T12:00:00Z",
    revoked_at: "2026-08-22T12:00:00Z",
  };
  assert.deepEqual(validateRevokedReviewerSession({ session }), session);
  rejects(
    () => validateRevokedReviewerSession({ session: { ...session, revoked_at: null } }),
    "INVALID_REVIEWER_SESSION",
  );
  rejects(
    () => validateRevokedReviewerSession({ session: { ...session, expires_at: "2026-09-20T12:00:01Z" } }),
    "INVALID_REVIEWER_SESSION",
  );
  rejects(
    () => validateRevokedReviewerSession({ session: { ...session, revoked_at: session.expires_at } }),
    "INVALID_REVIEWER_SESSION",
  );
  rejects(
    () => validateRevokedReviewerSession({ session, extra: true }),
    "INVALID_REVIEWER_SESSION",
  );
});
