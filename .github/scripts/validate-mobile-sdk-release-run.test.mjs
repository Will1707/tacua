// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { requireSuccessfulVerifyRun } from "./validate-mobile-sdk-release-run.mjs";

const commit = "a".repeat(40);
const branch = "main";

function response(overrides = {}) {
  return {
    workflow_runs: [
      {
        conclusion: "success",
        event: "push",
        head_branch: branch,
        head_sha: commit,
        id: 123,
        status: "completed",
        ...overrides,
      },
    ],
  };
}

test("accepts only a successful default-branch push run for the exact commit", () => {
  assert.equal(requireSuccessfulVerifyRun(response(), commit, branch).id, 123);
  for (const overrides of [
    { conclusion: "failure" },
    { event: "pull_request" },
    { head_branch: "feature" },
    { head_sha: "b".repeat(40) },
    { status: "in_progress" },
  ]) {
    assert.throws(
      () => requireSuccessfulVerifyRun(response(overrides), commit, branch),
      /no successful Verify push run/,
    );
  }
});

test("rejects malformed or unbounded workflow-run responses", () => {
  assert.throws(
    () => requireSuccessfulVerifyRun({}, commit, branch),
    /invalid Verify workflow-run response/,
  );
  assert.throws(
    () =>
      requireSuccessfulVerifyRun(
        { workflow_runs: Array.from({ length: 101 }, () => ({})) },
        commit,
        branch,
      ),
    /invalid Verify workflow-run response/,
  );
});
