// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_RUNTIME_FILE_BYTES,
  MAX_TARBALL_BYTES,
  validateReproduciblePack,
  validateReportedPackageBounds,
  validateRuntimePath,
  validateRuntimeText,
} from "./package-mobile-sdk.mjs";

function report(overrides = {}) {
  return {
    bundled: [],
    entryCount: 1,
    files: [{ mode: 0o644, path: "src/index.ts", size: 10 }],
    size: 8,
    unpackedSize: 10,
    ...overrides,
  };
}

test("release paths are closed to an audited runtime file set", () => {
  for (const path of [
    "ios/AppAudioAppendAccounting.swift",
    "ios/CaptureModels.swift",
    "ios/TacuaSDKLocalRetention.swift",
    "ios/TacuaCaptureSpike.podspec",
    "plugin/config.js",
    "src/index.ts",
    "README.md",
  ]) {
    assert.doesNotThrow(() => validateRuntimePath(path));
  }

  for (const path of [
    "ios/private-recording.mov",
    "ios/RenamedRecording.swift",
    "ios/private/Leak.swift",
    "plugin/session-token.json",
    "src/evidence.png",
    "src/index.ts.bak",
  ]) {
    assert.throws(
      () => validateRuntimePath(path),
      /non-runtime path entered the SDK tarball/,
    );
  }
});

test("release inputs must be strict text without private-key material", () => {
  assert.doesNotThrow(() =>
    validateRuntimeText("src/index.ts", Buffer.from("export {};\n", "utf8")),
  );
  assert.throws(
    () => validateRuntimeText("src/index.ts", Buffer.from([0xff, 0xfe])),
    /not strict UTF-8 text/,
  );
  assert.throws(
    () =>
      validateRuntimeText(
        "src/index.ts",
        Buffer.from("-----BEGIN PRIVATE KEY-----\nsynthetic\n", "utf8"),
      ),
    /forbidden binary or private material/,
  );
});

test("release metadata enforces file, aggregate, and tarball byte bounds", () => {
  assert.doesNotThrow(() => validateReportedPackageBounds(report()));

  assert.throws(
    () =>
      validateReportedPackageBounds(
        report({
          files: [
            {
              mode: 0o644,
              path: "src/index.ts",
              size: MAX_RUNTIME_FILE_BYTES + 1,
            },
          ],
          unpackedSize: MAX_RUNTIME_FILE_BYTES + 1,
        }),
      ),
    /oversized runtime package file/,
  );
  assert.throws(
    () =>
      validateReportedPackageBounds(
        report({ size: MAX_TARBALL_BYTES + 1 }),
      ),
    /package size metadata exceeds/,
  );
  assert.throws(
    () => validateReportedPackageBounds(report({ unpackedSize: 11 })),
    /package size metadata exceeds/,
  );
  assert.throws(
    () => validateReportedPackageBounds(report({ bundled: ["dependency"] })),
    /invalid or bundled package file set/,
  );
});

test("release archives must be byte-identical across isolated pack runs", () => {
  const first = report({
    integrity: "sha512-synthetic",
    shasum: "a".repeat(40),
  });
  const second = structuredClone(first);
  assert.doesNotThrow(() =>
    validateReproduciblePack(
      first,
      second,
      Buffer.from("same"),
      Buffer.from("same"),
    ),
  );
  assert.throws(
    () =>
      validateReproduciblePack(
        first,
        second,
        Buffer.from("first"),
        Buffer.from("second"),
      ),
    /byte-identical artifact/,
  );
  assert.throws(
    () =>
      validateReproduciblePack(
        first,
        { ...second, shasum: "b".repeat(40) },
        Buffer.from("same"),
        Buffer.from("same"),
      ),
    /byte-identical artifact/,
  );
});
