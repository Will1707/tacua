// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const generator = resolve(packageRoot, "../scripts/generate_app_audio_acceptance.py");

function captureManifest() {
  return {
    appAudioAppendAccountingComplete: true,
    appAudioAppendAccountingVersion: 1,
    appAudioAppendAttemptsObserved: 1000,
    appAudioAppendReservedThroughIndex: 1000,
    appAudioAppendUnknownRanges: [],
    appAudioSamplesObserved: 998,
    buildId: "build-ios-001",
    errorCodes: [],
    expectedApplicationId: "dev.tacua.sample",
    expectedBuildNumber: "42",
    gaps: [],
    resumeCount: 0,
    schemaVersion: 4,
    sessionId: "session-physical-audio-001",
    segments: [
      {
        appAudioAppendAttemptStartIndex: 1,
        appAudioAppendAttempts: 1000,
        appAudioAppendDrops: [
          { attemptIndex: 300, cause: "input_backpressure" },
          { attemptIndex: 700, cause: "append_rejected" },
        ],
        appAudioSamples: 998,
        droppedAppAudioSamples: 2,
        index: 0,
      },
    ],
    startedHostUptimeSeconds: 100,
    state: "completed",
    stoppedHostUptimeSeconds: 1900,
  };
}

test("CLI emits deterministic canonical JSON only after validator acceptance", () => {
  const root = mkdtempSync(join(tmpdir(), "tacua-app-audio-generator-"));
  try {
    const manifest = join(root, "manifest.json");
    const output = join(root, "acceptance.json");
    writeFileSync(manifest, JSON.stringify(captureManifest()));
    const result = spawnSync(
      "python3",
      [
        generator,
        manifest,
        "--run-id",
        "physical-audio-001",
        "--evidence-class",
        "synthetic_conformance",
        "--output",
        output,
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stderr, /generated and validated/);
    const first = readFileSync(output, "utf8");
    assert.equal(first.endsWith("\n"), true);
    assert.equal(first.includes(": "), false);

    const second = spawnSync(
      "python3",
      [
        generator,
        manifest,
        "--run-id",
        "physical-audio-001",
        "--evidence-class",
        "synthetic_conformance",
      ],
      { encoding: "utf8" },
    );
    assert.equal(second.status, 0, second.stderr);
    assert.equal(second.stdout, first);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("CLI refuses legacy manifests and does not publish an artifact", () => {
  const root = mkdtempSync(join(tmpdir(), "tacua-app-audio-generator-"));
  try {
    const candidate = captureManifest();
    candidate.schemaVersion = 3;
    const manifest = join(root, "manifest.json");
    const output = join(root, "acceptance.json");
    writeFileSync(manifest, JSON.stringify(candidate));
    const result = spawnSync(
      "python3",
      [
        generator,
        manifest,
        "--run-id",
        "physical-audio-001",
        "--evidence-class",
        "synthetic_conformance",
        "--output",
        output,
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /LEGACY_MANIFEST_UNACCOUNTED/);
    assert.throws(() => readFileSync(output));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("CLI requires an explicit evidence class", () => {
  const root = mkdtempSync(join(tmpdir(), "tacua-app-audio-generator-"));
  try {
    const manifest = join(root, "manifest.json");
    writeFileSync(manifest, JSON.stringify(captureManifest()));
    const result = spawnSync(
      "python3",
      [generator, manifest, "--run-id", "physical-audio-001"],
      { encoding: "utf8" },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /--evidence-class/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
