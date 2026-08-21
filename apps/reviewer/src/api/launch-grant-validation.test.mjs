// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildLaunchURL,
  LaunchGrantValidationError,
  maximumReviewerLaunchLinkResponseBytes,
  ReviewerLaunchLinkValidationError,
  validateReviewerResumeLaunchLink,
  validateReviewerStartLaunchLink,
  validateResumeLaunchGrant,
  validateStartLaunchGrant,
} from "./launch-grant-validation.ts";

const digest = `sha256:${"a".repeat(64)}`;
const common = {
  launch_id: "launch_example_001",
  launch_code: "A".repeat(43),
  build_identity_digest: digest,
  expires_at: "2026-07-22T12:00:00Z",
};

test("accepts exact start and session-bound resume grants", () => {
  assert.equal(validateStartLaunchGrant({
    ...common,
    exchange_kind: "start_session",
    session_id: null,
    scope_policy_digest: digest,
  }).exchange_kind, "start_session");
  assert.equal(validateResumeLaunchGrant({
    ...common,
    exchange_kind: "resume_session",
    session_id: "session_example_001",
    scope_digest: digest,
  }, "session_example_001").session_id, "session_example_001");
});

test("rejects grant confusion, unknown keys, bad timestamps, and session substitution", () => {
  const resume = {
    ...common,
    exchange_kind: "resume_session",
    session_id: "session_example_001",
    scope_digest: digest,
  };
  assert.throws(() => validateStartLaunchGrant(resume), LaunchGrantValidationError);
  assert.throws(
    () => validateResumeLaunchGrant({ ...resume, extra: true }, "session_example_001"),
    LaunchGrantValidationError,
  );
  assert.throws(
    () => validateResumeLaunchGrant({ ...resume, expires_at: "2026-07-22T12:00:00.000Z" }, "session_example_001"),
    LaunchGrantValidationError,
  );
  assert.throws(
    () => validateResumeLaunchGrant(resume, "session_other_001"),
    (error) => error instanceof LaunchGrantValidationError
      && error.code === "LAUNCH_GRANT_BINDING_MISMATCH",
  );
});

test("constructs only the fixed target-app launch route", () => {
  const code = "Ab_-".repeat(8);
  assert.equal(
    buildLaunchURL("kuzaba-qa", code),
    `kuzaba-qa://tacua/start?launch_code=${code}`,
  );
  const sixtyFourCharacterScheme = `a${"b".repeat(63)}`;
  assert.equal(
    buildLaunchURL(sixtyFourCharacterScheme, code),
    `${sixtyFourCharacterScheme}://tacua/start?launch_code=${code}`,
  );
  assert.equal(
    buildLaunchURL("kuzaba-qa", code, "session_example_001"),
    `kuzaba-qa://tacua/start?launch_code=${code}&session_id=session_example_001`,
  );
  assert.throws(
    () => buildLaunchURL("kuzaba-qa", code, "not a session"),
    LaunchGrantValidationError,
  );
  assert.throws(() => buildLaunchURL("a", code), LaunchGrantValidationError);
  assert.throws(() => buildLaunchURL(`a${"b".repeat(64)}`, code), LaunchGrantValidationError);
  for (const scheme of [
    "about", "blob", "data", "facetime", "facetime-audio", "file", "ftp", "ftps",
    "http", "https", "itms", "itms-apps", "javascript", "mailto", "sms", "tacua",
    "tel", "webcal", "ws", "wss",
  ]) {
    assert.throws(() => buildLaunchURL(scheme, code), LaunchGrantValidationError);
  }
  assert.throws(() => buildLaunchURL("bad://host", "A".repeat(43)), LaunchGrantValidationError);
});

test("validates server-provided launch links against sealed scheme, grant, and build", () => {
  const startGrant = {
    ...common,
    exchange_kind: "start_session",
    session_id: null,
    scope_policy_digest: digest,
  };
  const start = {
    contract_version: "tacua.reviewer-launch-link@1.0.0",
    launch_url: `kuzaba-qa://tacua/start?launch_code=${common.launch_code}`,
    grant: startGrant,
  };
  assert.deepEqual(
    validateReviewerStartLaunchLink(start, "kuzaba-qa", digest),
    start,
  );

  const resumeGrant = {
    ...common,
    exchange_kind: "resume_session",
    session_id: "session_example_001",
    scope_digest: digest,
  };
  const resume = {
    contract_version: "tacua.reviewer-launch-link@1.0.0",
    launch_url: `kuzaba-qa://tacua/start?launch_code=${common.launch_code}&session_id=session_example_001`,
    grant: resumeGrant,
  };
  assert.deepEqual(
    validateReviewerResumeLaunchLink(
      resume,
      "session_example_001",
      "kuzaba-qa",
      digest,
    ),
    resume,
  );
  assert.ok(maximumReviewerLaunchLinkResponseBytes <= 8 * 1_024);
});

test("rejects launch-link origin, query, kind, session, build, and envelope substitution", () => {
  const start = {
    contract_version: "tacua.reviewer-launch-link@1.0.0",
    launch_url: `kuzaba-qa://tacua/start?launch_code=${common.launch_code}`,
    grant: {
      ...common,
      exchange_kind: "start_session",
      session_id: null,
      scope_policy_digest: digest,
    },
  };
  for (const invalid of [
    { ...start, debug: true },
    { ...start, contract_version: "tacua.reviewer-launch-link@2.0.0" },
    { ...start, launch_url: `evil-qa://tacua/start?launch_code=${common.launch_code}` },
    { ...start, launch_url: `${start.launch_url}&debug=true` },
    { ...start, grant: { ...start.grant, exchange_kind: "resume_session" } },
  ]) {
    assert.throws(
      () => validateReviewerStartLaunchLink(invalid, "kuzaba-qa", digest),
      ReviewerLaunchLinkValidationError,
    );
  }
  assert.throws(
    () => validateReviewerStartLaunchLink(start, "kuzaba-qa", `sha256:${"b".repeat(64)}`),
    (error) => error instanceof ReviewerLaunchLinkValidationError
      && error.code === "REVIEWER_LAUNCH_LINK_BINDING_MISMATCH",
  );
});
