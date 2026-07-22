// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildLaunchURL,
  LaunchGrantValidationError,
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
