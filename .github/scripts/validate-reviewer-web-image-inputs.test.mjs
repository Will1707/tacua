// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  linkSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  truncateSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  maximumReviewerFileBytes,
  reviewerImageInputPaths,
  validateDockerDefinition,
  validateReviewerImageInputs,
  validateReviewerExport,
} from "./validate-reviewer-web-image-inputs.mjs";
import {
  validateFallbackAuditRows,
} from "./generate-reviewer-third-party-notices.mjs";
import {
  RetryableBrowserStartupError,
  runWithBrowserStartupRetry,
} from "./smoke-reviewer-web-browser.mjs";

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

function applyExportModes(rootDirectory, directoryMode, fileMode) {
  const pending = [rootDirectory];
  while (pending.length) {
    const current = pending.pop();
    chmodSync(current, directoryMode);
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(absolute);
      else chmodSync(absolute, fileMode);
    }
  }
}

function reviewerInputFixture(context) {
  const temporary = mkdtempSync(path.join(tmpdir(), "tacua-reviewer-inputs-"));
  context.after(() => rmSync(temporary, { recursive: true, force: true }));
  for (const relativePath of reviewerImageInputPaths) {
    const destination = path.join(temporary, relativePath);
    mkdirSync(path.dirname(destination), { mode: 0o700, recursive: true });
    writeFileSync(destination, `synthetic ${relativePath}\n`, { mode: 0o600 });
    chmodSync(destination, 0o600);
  }
  return temporary;
}

test("accepts the exact reviewer Docker boundary and generated export", () => {
  validateDockerDefinition(dockerfile, dockerignore);
  assert.equal(validateReviewerImageInputs(root).files, 5);
  const result = validateReviewerExport(exportRoot);
  assert.equal(result.status, "ok");
  assert.match(result.bundle, /^_expo\/static\/js\/web\/entry-[a-f0-9]{32}\.js$/u);
});

test("all copied reviewer inputs accept only the closed safe modes", (context) => {
  const temporary = reviewerInputFixture(context);
  for (const mode of [0o444, 0o600, 0o644]) {
    for (const relativePath of reviewerImageInputPaths) {
      chmodSync(path.join(temporary, relativePath), mode);
    }
    assert.equal(validateReviewerImageInputs(temporary).files, 5);
  }
});

test("rejects non-export input replacement after its initial inspection", (context) => {
  const temporary = reviewerInputFixture(context);
  const target = path.join(temporary, "services/reviewer-web/server.py");
  const replacement = `${target}.replacement`;

  assert.throws(
    () => validateReviewerImageInputs(temporary, {
      beforeFinalRevalidation() {
        writeFileSync(replacement, readFileSync(target), { mode: 0o600 });
        renameSync(replacement, target);
      },
    }),
    /changed during validation/u,
  );
});

test("every copied reviewer input rejects unsafe modes and links", (context) => {
  const temporary = reviewerInputFixture(context);
  for (const relativePath of reviewerImageInputPaths) {
    const target = path.join(temporary, relativePath);
    const original = readFileSync(target);

    for (const mode of [0o666, 0o755, 0o1644]) {
      chmodSync(target, mode);
      assert.throws(
        () => validateReviewerImageInputs(temporary),
        /unsafe copied input/u,
      );
    }
    chmodSync(target, 0o600);

    truncateSync(target, maximumReviewerFileBytes + 1);
    assert.throws(
      () => validateReviewerImageInputs(temporary),
      /unsafe copied input/u,
    );
    writeFileSync(target, original, { mode: 0o600 });
    chmodSync(target, 0o600);

    unlinkSync(target);
    symlinkSync(path.join(temporary, relativePath === "LICENSE" ? "NOTICE" : "LICENSE"), target);
    assert.throws(
      () => validateReviewerImageInputs(temporary),
      /unsafe copied input/u,
    );
    unlinkSync(target);
    writeFileSync(target, original, { mode: 0o600 });
    chmodSync(target, 0o600);

    unlinkSync(target);
    const fifo = spawnSync("mkfifo", [target], { encoding: "utf8" });
    assert.equal(fifo.status, 0, fifo.stderr);
    assert.throws(
      () => validateReviewerImageInputs(temporary),
      /unsafe copied input/u,
    );
    unlinkSync(target);
    writeFileSync(target, original, { mode: 0o600 });
    chmodSync(target, 0o600);

    const alias = `${target}.hardlink`;
    linkSync(target, alias);
    assert.throws(
      () => validateReviewerImageInputs(temporary),
      /unsafe copied input/u,
    );
    unlinkSync(alias);
  }
});

test("accepts an owner-private export because image modes are explicit", (context) => {
  const temporary = mkdtempSync(path.join(tmpdir(), "tacua-private-reviewer-export-"));
  context.after(() => rmSync(temporary, { recursive: true, force: true }));
  cpSync(exportRoot, temporary, { recursive: true });
  applyExportModes(temporary, 0o700, 0o600);

  const result = validateReviewerExport(temporary);
  assert.equal(result.status, "ok");
  assert.throws(
    () => validateDockerDefinition(
      dockerfile.replace(
        "COPY --chown=root:root --chmod=0444 apps/reviewer/dist/index.html",
        "COPY --chown=root:root apps/reviewer/dist/index.html",
      ),
      dockerignore,
    ),
    /closed instruction policy/u,
  );
});

test("rejects export replacement after all validated content was read", (context) => {
  const temporary = mkdtempSync(path.join(tmpdir(), "tacua-reviewer-export-race-"));
  context.after(() => rmSync(temporary, { recursive: true, force: true }));
  cpSync(exportRoot, temporary, { recursive: true });
  applyExportModes(temporary, 0o755, 0o644);
  const entryDirectory = path.join(temporary, "_expo/static/js/web");
  const entryPath = path.join(entryDirectory, readdirSync(entryDirectory)[0]);
  const replacement = `${entryPath}.replacement`;

  assert.throws(
    () => validateReviewerExport(temporary, {
      beforeFinalRevalidation() {
        writeFileSync(replacement, readFileSync(entryPath), { mode: 0o644 });
        renameSync(replacement, entryPath);
      },
    }),
    /changed during validation/u,
  );
});

test("requires at least one export asset for every wildcard COPY", (context) => {
  const temporary = mkdtempSync(path.join(tmpdir(), "tacua-reviewer-assets-"));
  context.after(() => rmSync(temporary, { recursive: true, force: true }));
  const assetDirectories = [
    "assets/node_modules/expo-router/assets",
    "assets/node_modules/expo-router/assets/react-navigation/elements",
  ];

  for (const [index, assetDirectory] of assetDirectories.entries()) {
    const fixture = path.join(temporary, `fixture-${index}`);
    cpSync(exportRoot, fixture, { recursive: true });
    const absoluteAssetDirectory = path.join(fixture, assetDirectory);
    for (const entry of readdirSync(absoluteAssetDirectory, {
      withFileTypes: true,
    })) {
      if (entry.isFile() && entry.name.endsWith(".png")) {
        unlinkSync(path.join(absoluteAssetDirectory, entry.name));
      }
    }

    assert.throws(
      () => validateReviewerExport(fixture),
      /every Docker-copied asset family/u,
    );
  }
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

test("browser smoke retries only one bounded fresh-Chrome startup timeout", async () => {
  const attempts = [];
  const result = await runWithBrowserStartupRetry(async (attempt) => {
    attempts.push(attempt);
    if (attempt === 1) throw new RetryableBrowserStartupError();
    return "completed";
  });
  assert.equal(result, "completed");
  assert.deepEqual(attempts, [1, 2]);

  const nonStartupAttempts = [];
  await assert.rejects(
    () => runWithBrowserStartupRetry(async (attempt) => {
      nonStartupAttempts.push(attempt);
      throw new Error("application assertion failed");
    }),
    /application assertion failed/u,
  );
  assert.deepEqual(nonStartupAttempts, [1]);

  const boundedAttempts = [];
  await assert.rejects(
    () => runWithBrowserStartupRetry(async (attempt) => {
      boundedAttempts.push(attempt);
      throw new RetryableBrowserStartupError();
    }),
    RetryableBrowserStartupError,
  );
  assert.deepEqual(boundedAttempts, [1, 2]);
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
  chmodSync(temporary, 0o755);

  const entryDirectory = path.join(temporary, "_expo/static/js/web");
  const entryName = readdirSync(entryDirectory)[0];
  const entryPath = path.join(entryDirectory, entryName);
  const originalBundle = readFileSync(entryPath, "utf8");
  chmodSync(temporary, 0o750);
  assert.throws(
    () => validateReviewerExport(temporary),
    /root must be one real directory/u,
  );
  chmodSync(temporary, 0o755);

  chmodSync(entryPath, 0o640);
  assert.throws(
    () => validateReviewerExport(temporary),
    /unsafe file/u,
  );
  chmodSync(entryPath, 0o644);
  chmodSync(entryPath, 0o1644);
  assert.throws(
    () => validateReviewerExport(temporary),
    /unsafe file/u,
  );
  chmodSync(entryPath, 0o644);

  chmodSync(entryDirectory, 0o750);
  assert.throws(
    () => validateReviewerExport(temporary),
    /non-container-readable directory/u,
  );
  chmodSync(entryDirectory, 0o755);
  chmodSync(entryDirectory, 0o1755);
  assert.throws(
    () => validateReviewerExport(temporary),
    /non-container-readable directory/u,
  );
  chmodSync(entryDirectory, 0o755);

  const unexpectedAssetDirectory = path.join(temporary, "assets/private");
  mkdirSync(unexpectedAssetDirectory);
  writeFileSync(path.join(unexpectedAssetDirectory, "unexpected.png"), "x");
  assert.throws(
    () => validateReviewerExport(temporary),
    /non-container-readable directory/u,
  );
  rmSync(unexpectedAssetDirectory, { recursive: true });

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
