// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

function fail(message) {
  throw new Error(message);
}

export function requireSuccessfulVerifyRun(payload, tagCommit, defaultBranch) {
  if (
    typeof tagCommit !== "string" ||
    !/^[a-f0-9]{40,64}$/u.test(tagCommit) ||
    typeof defaultBranch !== "string" ||
    defaultBranch.length < 1 ||
    defaultBranch.length > 255 ||
    /[\u0000-\u001f\u007f]/u.test(defaultBranch) ||
    !payload ||
    typeof payload !== "object" ||
    !Array.isArray(payload.workflow_runs) ||
    payload.workflow_runs.length > 100
  ) {
    fail("GitHub returned an invalid Verify workflow-run response");
  }

  const greenRuns = payload.workflow_runs.filter(
    (run) =>
      run &&
      typeof run === "object" &&
      Number.isSafeInteger(run.id) &&
      run.id > 0 &&
      run.head_sha === tagCommit &&
      run.head_branch === defaultBranch &&
      run.event === "push" &&
      run.status === "completed" &&
      run.conclusion === "success",
  );
  if (greenRuns.length < 1) {
    fail("the tagged default-branch commit has no successful Verify push run");
  }
  return greenRuns[0];
}

function main() {
  const [runsPath, tagCommit, defaultBranch] = process.argv.slice(2);
  if (!runsPath || !tagCommit || !defaultBranch || process.argv.length !== 5) {
    fail("usage: validate-mobile-sdk-release-run.mjs RUNS_JSON COMMIT BRANCH");
  }
  const payload = JSON.parse(readFileSync(path.resolve(runsPath), "utf8"));
  const run = requireSuccessfulVerifyRun(payload, tagCommit, defaultBranch);
  process.stdout.write(`${JSON.stringify({ runId: run.id, status: "ok" })}\n`);
}

if (
  process.argv[1] &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`release verification gate failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
