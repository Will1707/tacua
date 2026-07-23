// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import {
  cpSync,
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
import { fileURLToPath } from "node:url";

import {
  validateDockerDefinition,
  validateReviewerExport,
} from "./validate-reviewer-web-image-inputs.mjs";
import {
  validateFallbackAuditRows,
} from "./generate-reviewer-third-party-notices.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const dockerfile = readFileSync(
  path.join(root, "services/reviewer-web/Dockerfile"),
  "utf8",
);
const dockerignore = readFileSync(
  path.join(root, "services/reviewer-web/Dockerfile.dockerignore"),
  "utf8",
);
const exportRoot = path.join(root, "apps/reviewer/dist");
const verifier = readFileSync(
  path.join(root, ".github/scripts/verify-reviewer-web-container.sh"),
  "utf8",
);

test("accepts the exact reviewer Docker boundary and generated export", () => {
  validateDockerDefinition(dockerfile, dockerignore);
  const result = validateReviewerExport(exportRoot);
  assert.equal(result.status, "ok");
  assert.match(result.bundle, /^_expo\/static\/js\/web\/entry-[a-f0-9]{32}\.js$/u);
});

test("stops the healthy reviewer before normal verification cleanup", () => {
  const stop = 'docker container stop --time 10 "$container" >/dev/null';
  const remove = 'docker container rm "$container" >/dev/null';
  const stopIndex = verifier.lastIndexOf(stop);
  const removeIndex = verifier.lastIndexOf(remove);

  assert.notEqual(stopIndex, -1, "successful cleanup must stop the container");
  assert.notEqual(removeIndex, -1, "successful cleanup must remove the container");
  assert.ok(
    stopIndex < removeIndex,
    "successful cleanup must stop the reviewer before removing it",
  );
});

test("rejects mutable image, expanded build context, and added authority", () => {
  assert.throws(
    () => validateDockerDefinition(
      dockerfile.replace(
        /^FROM .+$/mu,
        "FROM python:3.13-slim",
      ),
      dockerignore,
    ),
    /closed instruction policy/u,
  );
  assert.throws(
    () => validateDockerDefinition(dockerfile, `${dockerignore}!services/backend/\n`),
    /ignore boundary/u,
  );
  assert.throws(
    () => validateDockerDefinition(
      `${dockerfile}\nCOPY services/backend/local /run/tacua\n`,
      dockerignore,
    ),
    /closed instruction policy/u,
  );
});

test("rejects any unaudited missing-notice fallback inventory", () => {
  assert.throws(
    () => validateFallbackAuditRows([]),
    /differs from the audited set/u,
  );
  assert.throws(
    () => validateFallbackAuditRows([{
      install_key: "node_modules/synthetic",
      integrity: "sha512:synthetic",
      license: "MIT",
      name: "synthetic",
      repository: "https://example.invalid/synthetic",
      version: "1.0.0",
    }]),
    /differs from the audited set/u,
  );
});

test("rejects links, source maps, mutated bundles, localStorage, and inline script", (context) => {
  const temporary = mkdtempSync(path.join(tmpdir(), "tacua-reviewer-export-"));
  context.after(() => rmSync(temporary, { recursive: true, force: true }));
  cpSync(exportRoot, temporary, { recursive: true });

  const entryDirectory = path.join(temporary, "_expo/static/js/web");
  const entryName = readdirSync(entryDirectory)[0];
  const entryPath = path.join(entryDirectory, entryName);
  const originalBundle = readFileSync(entryPath, "utf8");
  writeFileSync(entryPath, `${originalBundle}\n`, "utf8");
  assert.throws(
    () => validateReviewerExport(temporary),
    /immutable filename/u,
  );

  writeFileSync(entryPath, `${originalBundle}\nlocalStorage\n`, "utf8");
  assert.throws(
    () => validateReviewerExport(temporary),
    /immutable filename/u,
  );
  writeFileSync(entryPath, originalBundle, "utf8");

  writeFileSync(path.join(temporary, "unexpected.map"), "{}", "utf8");
  assert.throws(
    () => validateReviewerExport(temporary),
    /unexpected artifact/u,
  );
  rmSync(path.join(temporary, "unexpected.map"));

  const indexPath = path.join(temporary, "index.html");
  const index = readFileSync(indexPath, "utf8");
  writeFileSync(indexPath, index.replace("</body>", "<script>alert(1)</script></body>"));
  assert.throws(
    () => validateReviewerExport(temporary),
    /SPA shell/u,
  );
  writeFileSync(indexPath, index);

  symlinkSync(indexPath, path.join(temporary, "linked.html"));
  assert.throws(
    () => validateReviewerExport(temporary),
    /must not contain links|path is unsafe/u,
  );
});
