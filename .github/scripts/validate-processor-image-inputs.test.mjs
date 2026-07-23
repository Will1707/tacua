// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  validateProcessorDockerDefinition,
  validateProcessorRepository,
} from "./validate-processor-image-inputs.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const dockerfile = readFileSync(
  path.join(root, "services/processor/Dockerfile"),
  "utf8",
);
const dockerignore = readFileSync(
  path.join(root, "services/processor/Dockerfile.dockerignore"),
  "utf8",
);

test("accepts the exact offline processor image boundary", () => {
  assert.deepEqual(validateProcessorRepository(root), {
    files: 4,
    status: "ok",
    whisper_revision: "f24588a272ae8e23280d9c220536437164e6ed28",
  });
});

test("rejects mutable source, revision, context, and runtime authority", () => {
  assert.throws(
    () => validateProcessorDockerDefinition(
      dockerfile.replace(/debian:trixie-slim@sha256:[a-f0-9]{64}/u, "debian:latest"),
      dockerignore,
    ),
    /closed instruction policy/u,
  );
  assert.throws(
    () => validateProcessorDockerDefinition(
      dockerfile.replace(
        "f24588a272ae8e23280d9c220536437164e6ed28",
        "main",
      ),
      dockerignore,
    ),
    /closed instruction policy/u,
  );
  assert.throws(
    () => validateProcessorDockerDefinition(
      dockerfile,
      `${dockerignore}!services/backend/\n`,
    ),
    /ignore boundary/u,
  );
  assert.throws(
    () => validateProcessorDockerDefinition(
      `${dockerfile}\nENTRYPOINT [\"/bin/sh\"]\n`,
      dockerignore,
    ),
    /closed instruction policy/u,
  );
});
