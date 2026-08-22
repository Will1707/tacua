// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  collectInputRecords,
  MAX_BACKEND_IMAGE_INPUT_FILE_BYTES,
  validateDockerDefinition,
  validateInputRecords,
} from "./validate-backend-image-inputs.mjs";

const pinnedDockerfile =
  "FROM python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91\n";
const validDockerfile = readFileSync(
  new URL("../../services/backend/Dockerfile", import.meta.url),
  "utf8",
);
const validDockerignore = readFileSync(
  new URL("../../services/backend/Dockerfile.dockerignore", import.meta.url),
  "utf8",
);
const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);

function privateBackendInputTree(context) {
  const temporary = mkdtempSync(path.join(tmpdir(), "tacua-private-backend-"));
  context.after(() => rmSync(temporary, { force: true, recursive: true }));
  for (const record of collectInputRecords(repositoryRoot)) {
    const destination = path.join(temporary, record.path);
    mkdirSync(path.dirname(destination), { mode: 0o700, recursive: true });
    cpSync(path.join(repositoryRoot, record.path), destination);
    chmodSync(destination, 0o600);
  }
  return temporary;
}

test("a floating base and broad source copy are rejected", () => {
  assert.throws(
    () => validateDockerDefinition("FROM python:3.13-slim\n", "**\n"),
    /exact Python patch and OCI digest/,
  );
  assert.throws(
    () =>
      validateDockerDefinition(
        `FROM python:3.13.14-slim-trixie@sha256:${"a".repeat(64)}\n`,
        "**\n",
      ),
    /exact Python patch and OCI digest/,
  );
  assert.throws(
    () =>
      validateDockerDefinition(
        `# syntax=docker/dockerfile:1\n${pinnedDockerfile}`,
        "**\n",
      ),
    /parser or frontend directives/,
  );
  assert.throws(
    () =>
      validateDockerDefinition(
        `${pinnedDockerfile}COPY services/backend/src/ /app/src/\n`,
        "**\n",
      ),
    /COPY boundary differs/,
  );
});

test("case and whitespace cannot hide added or changed Docker instructions", () => {
  for (const changed of [
    `${validDockerfile}\n  uSeR root\n`,
    `${validDockerfile}\n\taDd services/backend /tmp/backend\n`,
    validDockerfile.replace(
      "ENTRYPOINT [\"python\", \"-m\", \"tacua_backend\"]",
      "  entrypoint [\"/bin/sh\"]",
    ),
    `  # EsCaPe=\u0060\n${validDockerfile}`,
  ]) {
    assert.throws(
      () => validateDockerDefinition(changed, validDockerignore),
      /closed instruction policy|COPY boundary|parser or frontend directives/,
    );
  }
});

test("every backend image input has an explicit immutable image mode", () => {
  assert.throws(
    () => validateDockerDefinition(
      validDockerfile.replace(
        "COPY --chown=root:root --chmod=0444 LICENSE NOTICE /app/",
        "COPY --chown=root:root LICENSE NOTICE /app/",
      ),
      validDockerignore,
    ),
    /COPY boundary differs|closed instruction policy/u,
  );
});

test("every backend image directory is explicit, root-owned, and traversable", () => {
  const directoryInstall =
    "&& install -d -o root -g root -m 0555 \\\n        /app";
  assert.ok(validDockerfile.includes(directoryInstall));

  for (const changed of [
    validDockerfile.replace(
      directoryInstall,
      directoryInstall.replace("0555", "0444"),
    ),
    validDockerfile.replace(
      "        /app/services/backend/src/tacua_backend\n",
      "        /app/services/backend/src/tacua-backend\n",
    ),
  ]) {
    assert.notEqual(changed, validDockerfile);
    assert.throws(
      () => validateDockerDefinition(changed, validDockerignore),
      /closed instruction policy/u,
    );
  }
});

test("a real owner-private backend input tree remains valid", (context) => {
  const privateRoot = privateBackendInputTree(context);
  const privateRecords = collectInputRecords(privateRoot);

  assert.doesNotThrow(() => validateInputRecords(privateRecords));
  assert.ok(privateRecords.every((record) => record.mode === 0o600));
  assert.ok(privateRecords.every((record) => record.readable === true));
  assert.throws(
    () => validateInputRecords([
      { ...privateRecords[0], readable: false },
      ...privateRecords.slice(1),
    ]),
    /unsafe or oversized input file/u,
  );
});

test("unsafe and symlinked backend directory ancestry is rejected", (context) => {
  const privateRoot = privateBackendInputTree(context);
  const target = path.join(privateRoot, "services/backend/src");

  const linkedRoot = `${privateRoot}-link`;
  context.after(() => rmSync(linkedRoot, { force: true }));
  symlinkSync(privateRoot, linkedRoot, "dir");
  assert.throws(
    () => collectInputRecords(linkedRoot),
    /root is not a safe real directory/u,
  );

  for (const mode of [0o777, 0o1700]) {
    chmodSync(target, mode);
    assert.throws(
      () => collectInputRecords(privateRoot),
      /directory ancestry is unsafe/u,
    );
    chmodSync(target, 0o700);
  }

  const realTarget = `${target}-real`;
  renameSync(target, realTarget);
  symlinkSync(realTarget, target, "dir");
  assert.throws(
    () => collectInputRecords(privateRoot),
    /directory ancestry is unsafe/u,
  );
});

test("an oversized source-shaped image input is rejected", () => {
  assert.throws(
    () =>
      validateInputRecords([
        {
          links: 1,
          mode: 0o644,
          path: "services/backend/src/tacua_backend/recording.py",
          regular: true,
          size: MAX_BACKEND_IMAGE_INPUT_FILE_BYTES + 1,
          symbolicLink: false,
        },
      ]),
    /oversized input file/,
  );
  assert.throws(
    () =>
      validateInputRecords([
        {
          links: 1,
          mode: 0o644,
          path: "services/backend/src/tacua_backend/private_recording.py",
          regular: true,
          size: 1,
          symbolicLink: false,
        },
      ]),
    /unsafe or oversized input file/,
  );
});

test("backend inputs with executable or special source modes are rejected", () => {
  const records = collectInputRecords();
  for (const mode of [0o555, 0o1644]) {
    assert.throws(
      () => validateInputRecords([
        { ...records[0], mode },
        ...records.slice(1),
      ]),
      /unsafe or oversized input file/u,
    );
  }
});
