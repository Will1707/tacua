// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const script = path.join(root, ".github/scripts/verify-processor-container.sh");
const scriptSource = readFileSync(script, "utf8");

function imageConfigValidator() {
  const match = /docker image inspect "\$image" \| python3 -B -c '\n(?<program>[\s\S]*?)\n'\n/u.exec(
    scriptSource,
  );
  assert.ok(match?.groups?.program, "embedded image-config validator is missing");
  return match.groups.program;
}

test("processor verifier shell is valid and rejects unsafe controls before Docker", () => {
  const syntax = spawnSync("bash", ["-n", script], {
    cwd: root,
    encoding: "utf8",
  });
  assert.equal(syntax.status, 0, syntax.stderr);

  const keep = spawnSync("bash", [script], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, TACUA_KEEP_VERIFIED_IMAGES: "yes" },
  });
  assert.equal(keep.status, 2);
  assert.match(keep.stderr, /must be true or false/u);

  const identifier = spawnSync("bash", [script], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, TACUA_PROCESSOR_TEST_ID: "../unsafe" },
  });
  assert.equal(identifier.status, 2);
  assert.match(identifier.stderr, /is invalid/u);
});

test("accepts Docker inspect output that omits empty OCI config members", () => {
  const result = spawnSync("python3", ["-B", "-c", imageConfigValidator()], {
    cwd: root,
    encoding: "utf8",
    input: JSON.stringify([
      {
        Config: {
          Env: [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
          ],
          WorkingDir: "/",
        },
      },
    ]),
  });
  assert.equal(result.status, 0, result.stderr);
});
