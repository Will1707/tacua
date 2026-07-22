// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
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

test("an oversized source-shaped image input is rejected", () => {
  assert.throws(
    () =>
      validateInputRecords([
        {
          links: 1,
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
          path: "services/backend/src/tacua_backend/private_recording.py",
          regular: true,
          size: 1,
          symbolicLink: false,
        },
      ]),
    /unsafe or oversized input file/,
  );
});
