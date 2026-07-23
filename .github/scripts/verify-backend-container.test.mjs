// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

const sourceScript = readFileSync(
  new URL("./verify-backend-container.sh", import.meta.url),
  "utf8",
);

function makeFixture(testContext) {
  const root = mkdtempSync(path.join(tmpdir(), "tacua-container-script-test-"));
  testContext.after(() => rmSync(root, { force: true, recursive: true }));
  mkdirSync(path.join(root, ".github/scripts"), { recursive: true });
  mkdirSync(path.join(root, "services/backend"), { recursive: true });
  writeFileSync(
    path.join(root, ".github/scripts/verify-backend-container.sh"),
    sourceScript,
    { mode: 0o755 },
  );
  writeFileSync(path.join(root, "services/backend/Dockerfile"), "FROM scratch\n");
  writeFileSync(path.join(root, "services/backend/config.example.json"), "{}\n");
  const fakeBin = path.join(root, "fake-bin");
  mkdirSync(fakeBin);
  return { fakeBin, root };
}

function writeExecutable(destination, contents) {
  writeFileSync(destination, contents, { mode: 0o755 });
  chmodSync(destination, 0o755);
}

function runFixture(root, fakeBin, extraEnvironment = {}) {
  return spawnSync("bash", [".github/scripts/verify-backend-container.sh"], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      ...extraEnvironment,
      PATH: `${fakeBin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      RUNNER_TEMP: root,
      TACUA_CONTAINER_TEST_ID: "script-test",
    },
  });
}

test("a services/backend/local symlink is rejected before Docker or file mutation", (t) => {
  const { fakeBin, root } = makeFixture(t);
  const outside = path.join(root, "outside");
  const dockerMarker = path.join(root, "docker-was-called");
  mkdirSync(outside);
  writeFileSync(path.join(outside, "sentinel"), "keep\n");
  symlinkSync(outside, path.join(root, "services/backend/local"), "dir");
  writeExecutable(
    path.join(fakeBin, "docker"),
    "#!/bin/sh\nprintf called > \"$TACUA_DOCKER_MARKER\"\nexit 99\n",
  );

  const result = runFixture(root, fakeBin, {
    TACUA_DOCKER_MARKER: dockerMarker,
  });

  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /must be absent or a real directory/u);
  assert.equal(existsSync(dockerMarker), false);
  assert.equal(readFileSync(path.join(outside, "sentinel"), "utf8"), "keep\n");
});

for (const precreateLocalDirectory of [false, true]) {
  test(
    `a partial config copy is cleaned while ${
      precreateLocalDirectory ? "preserving" : "removing"
    } the original local-directory state`,
    (t) => {
      const { fakeBin, root } = makeFixture(t);
      const localDirectory = path.join(root, "services/backend/local");
      if (precreateLocalDirectory) {
        mkdirSync(localDirectory);
        chmodSync(localDirectory, 0o700);
      }
      writeExecutable(path.join(fakeBin, "docker"), "#!/bin/sh\nexit 0\n");
      writeExecutable(
        path.join(fakeBin, "install"),
        "#!/bin/sh\nfor tacua_last_arg do :; done\nprintf partial > \"$tacua_last_arg\"\nexit 23\n",
      );

      const result = runFixture(root, fakeBin);

      assert.equal(result.status, 23, result.stderr);
      assert.equal(
        existsSync(path.join(localDirectory, "config.json")),
        false,
      );
      assert.equal(
        existsSync(localDirectory),
        precreateLocalDirectory,
      );
      if (precreateLocalDirectory) {
        assert.deepEqual(readdirSync(localDirectory), []);
      }
    },
  );
}

test("a non-private pre-existing local directory is rejected before Docker", (t) => {
  const { fakeBin, root } = makeFixture(t);
  const localDirectory = path.join(root, "services/backend/local");
  const dockerMarker = path.join(root, "docker-was-called");
  mkdirSync(localDirectory);
  chmodSync(localDirectory, 0o755);
  writeExecutable(
    path.join(fakeBin, "docker"),
    "#!/bin/sh\nprintf called > \"$TACUA_DOCKER_MARKER\"\nexit 99\n",
  );

  const result = runFixture(root, fakeBin, {
    TACUA_DOCKER_MARKER: dockerMarker,
  });

  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /operator-owned mode-0700 directory/u);
  assert.equal(existsSync(dockerMarker), false);
  assert.deepEqual(readdirSync(localDirectory), []);
});

test("a Docker discovery error fails before creating verification inputs", (t) => {
  const { fakeBin, root } = makeFixture(t);
  writeExecutable(path.join(fakeBin, "docker"), "#!/bin/sh\nexit 47\n");

  const result = runFixture(root, fakeBin);

  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /cannot list Docker containers safely/u);
  assert.equal(
    existsSync(path.join(root, "services/backend/local")),
    false,
  );
});

test("an exact pre-existing Compose state volume is never adopted", (t) => {
  const { fakeBin, root } = makeFixture(t);
  writeExecutable(
    path.join(fakeBin, "docker"),
    `#!/bin/sh
if [ "$1" = volume ] && [ "$2" = ls ]; then
  printf '%s\\n' tacua-backend-script-test-compose_tacua-state
fi
exit 0
`,
  );

  const result = runFixture(root, fakeBin);

  assert.equal(result.status, 1, result.stderr);
  assert.match(
    result.stderr,
    /refusing to replace existing Docker volume: tacua-backend-script-test-compose_tacua-state/u,
  );
  assert.equal(
    existsSync(path.join(root, "services/backend/local")),
    false,
  );
});
