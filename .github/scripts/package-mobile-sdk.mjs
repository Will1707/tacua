// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { TextDecoder } from "node:util";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../..");
const packageDirectory = path.join(
  repositoryRoot,
  "experiments/ios-capture-spike/package",
);
const backendConfigTemplatePath = path.join(
  repositoryRoot,
  "services/backend/config.template.example.json",
);

const allowedRuntimePaths = new Set([
  "CONFIG_PLUGIN.md",
  "LICENSE",
  "NOTICE",
  "README.md",
  "app.plugin.js",
  "expo-module.config.json",
  "ios/AppAudioAppendAccounting.swift",
  "ios/CaptureFaultInjection.swift",
  "ios/CaptureModels.swift",
  "ios/CapturePolicy.swift",
  "ios/CaptureTransportPolicy.swift",
  "ios/SegmentWriter.swift",
  "ios/TacuaBackendConfiguration.swift",
  "ios/TacuaCanonicalJSON.swift",
  "ios/TacuaCaptureAdmission.swift",
  "ios/TacuaCaptureDeletionCoordinator.swift",
  "ios/TacuaCaptureSession.swift",
  "ios/TacuaCaptureSpike.podspec",
  "ios/TacuaCaptureSpikeModule.swift",
  "ios/TacuaCaptureUploadCoordinator.swift",
  "ios/TacuaCredentialStore.swift",
  "ios/TacuaDiagnosticJournal.swift",
  "ios/TacuaLocalHarnessPolicy.swift",
  "ios/TacuaLaunchLink.swift",
  "ios/TacuaSDKBackendClient.swift",
  "ios/TacuaSDKBackendProtocol.swift",
  "ios/TacuaSDKBackendRequests.swift",
  "ios/TacuaSDKBuildProfile.swift",
  "ios/TacuaSDKHostIntegration.swift",
  "ios/TacuaSDKLocalRetention.swift",
  "ios/TacuaSDKResumeJournal.swift",
  "ios/TacuaSDKResumeLifecycle.swift",
  "ios/TacuaSDKSessionDiscovery.swift",
  "ios/TacuaSDKStartJournal.swift",
  "ios/TacuaSDKStartLifecycle.swift",
  "ios/TacuaTransportQueue.swift",
  "ios/TacuaTransportQueueFileStore.swift",
  "package.json",
  "plugin/config.js",
  "plugin/withTacua.js",
  "src/BackendManagedHostController.ts",
  "src/TacuaCaptureSpikeModule.ts",
  "src/index.ts",
]);
const requiredPaths = allowedRuntimePaths;
const forbiddenLifecycleScripts = new Set([
  "install",
  "postinstall",
  "preinstall",
  "prepare",
  "prepack",
  "postpack",
]);
const forbiddenPathPattern =
  /(^|\/)(?:\.env(?:\.|$)|[^/]+\.(?:cer|der|jks|key|keystore|mobileprovision|p12|p8|pem|pfx))$/iu;
const privateKeyMaterialPattern =
  /-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----/u;
const expectedManifestKeys = new Set([
  "bugs",
  "dependencies",
  "description",
  "exports",
  "files",
  "homepage",
  "license",
  "main",
  "name",
  "peerDependencies",
  "private",
  "repository",
  "types",
  "version",
]);
const expectedDependencyVersions = Object.freeze({
  "expo-modules-core": "~56.0.17",
});
const expectedPeerDependencyVersions = Object.freeze({
  expo: ">=56.0.16 <57",
  "react-native": ">=0.85.3 <0.86",
});
export const MAX_PACKAGE_FILES = 256;
export const MAX_RUNTIME_FILE_BYTES = 1_048_576;
export const MAX_UNPACKED_PACKAGE_BYTES = 8_388_608;
export const MAX_TARBALL_BYTES = 8_388_608;

function fail(message) {
  throw new Error(message);
}

function requireExactStringMap(actual, expected, field) {
  if (!actual || typeof actual !== "object" || Array.isArray(actual)) {
    fail(`${field} must be an exact object`);
  }
  const actualEntries = Object.entries(actual).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  const expectedEntries = Object.entries(expected).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  if (
    actualEntries.length !== expectedEntries.length ||
    actualEntries.some(
      ([key, value], index) =>
        key !== expectedEntries[index][0] || value !== expectedEntries[index][1],
    )
  ) {
    fail(`${field} differs from the audited release dependency set`);
  }
}

function parseArguments(argv) {
  const result = { dryRun: false, outDirectory: null, tag: null };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--dry-run") {
      result.dryRun = true;
      continue;
    }
    if (argument === "--out-dir" || argument === "--tag") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        fail(`${argument} requires a value`);
      }
      if (argument === "--out-dir") {
        result.outDirectory = path.resolve(value);
      } else {
        result.tag = value;
      }
      index += 1;
      continue;
    }
    fail(`unsupported argument: ${argument}`);
  }

  if (!result.tag) {
    fail("--tag is required");
  }
  if (result.dryRun && result.outDirectory) {
    fail("--dry-run and --out-dir are mutually exclusive");
  }
  if (!result.dryRun && !result.outDirectory) {
    fail("--out-dir is required unless --dry-run is used");
  }
  return result;
}

function readPackageManifest() {
  const manifestPath = path.join(packageDirectory, "package.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

  if (manifest.name !== "@tacua/mobile-sdk") {
    fail(`unexpected package name: ${String(manifest.name)}`);
  }
  if (!/^0\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u.test(manifest.version)) {
    fail(`the pre-release SDK version is invalid: ${String(manifest.version)}`);
  }
  if (manifest.private !== true) {
    fail("the SDK must remain private to disable npm registry publication");
  }
  if (Object.hasOwn(manifest, "publishConfig")) {
    fail("publishConfig is forbidden while registry publication is disabled");
  }
  if (manifest.license !== "Apache-2.0") {
    fail(`unexpected package license: ${String(manifest.license)}`);
  }
  if (manifest.main !== "src/index.ts" || manifest.types !== "src/index.ts") {
    fail("the SDK TypeScript entry points changed unexpectedly");
  }
  if (manifest.exports?.["."] !== "./src/index.ts") {
    fail("the SDK root export changed unexpectedly");
  }

  const manifestKeys = Object.keys(manifest);
  if (
    manifestKeys.length !== expectedManifestKeys.size ||
    manifestKeys.some((key) => !expectedManifestKeys.has(key))
  ) {
    fail("package.json contains an unaudited release field");
  }

  requireExactStringMap(
    manifest.dependencies,
    expectedDependencyVersions,
    "dependencies",
  );
  requireExactStringMap(
    manifest.peerDependencies,
    expectedPeerDependencyVersions,
    "peerDependencies",
  );

  if (
    !Array.isArray(manifest.files) ||
    manifest.files.length !== 9 ||
    [...manifest.files].sort().join("\n") !==
      [
        "CONFIG_PLUGIN.md",
        "LICENSE",
        "NOTICE",
        "README.md",
        "app.plugin.js",
        "expo-module.config.json",
        "ios",
        "plugin",
        "src",
      ]
        .sort()
        .join("\n")
  ) {
    fail("package.json files differs from the audited release roots");
  }

  for (const scriptName of forbiddenLifecycleScripts) {
    if (Object.hasOwn(manifest.scripts ?? {}, scriptName)) {
      fail(`forbidden package lifecycle script: ${scriptName}`);
    }
  }

  const configTemplate = JSON.parse(readFileSync(backendConfigTemplatePath, "utf8"));
  const sdkPin = configTemplate.approved_handoff?.build_identity?.sdk;
  if (
    sdkPin?.package_name !== manifest.name ||
    sdkPin?.package_version !== manifest.version
  ) {
    fail("the backend handoff SDK package pin does not match package.json");
  }

  return manifest;
}

export function validateRuntimePath(packedPath) {
  if (
    typeof packedPath !== "string" ||
    !allowedRuntimePaths.has(packedPath)
  ) {
    fail(`non-runtime path entered the SDK tarball: ${String(packedPath)}`);
  }
  if (packedPath.startsWith("tests/") || forbiddenPathPattern.test(packedPath)) {
    fail(`forbidden path entered the SDK tarball: ${packedPath}`);
  }
}

export function validateRuntimeText(packedPath, bytes) {
  validateRuntimePath(packedPath);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 1) {
    fail(`SDK tarball input must contain bounded text: ${packedPath}`);
  }
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes);
  } catch {
    fail(`SDK tarball input is not strict UTF-8 text: ${packedPath}`);
  }
  if (
    decoded.startsWith("\ufeff") ||
    decoded.includes("\u0000") ||
    privateKeyMaterialPattern.test(decoded)
  ) {
    fail(`SDK tarball input contains forbidden binary or private material: ${packedPath}`);
  }
}

export function validateReportedPackageBounds(report) {
  const files = report?.files;
  if (
    !Array.isArray(files) ||
    files.length < 1 ||
    files.length > MAX_PACKAGE_FILES ||
    report.entryCount !== files.length ||
    !Array.isArray(report.bundled) ||
    report.bundled.length !== 0
  ) {
    fail("npm reported an invalid or bundled package file set");
  }
  let unpackedBytes = 0;
  for (const entry of files) {
    if (
      !entry ||
      typeof entry !== "object" ||
      !Number.isSafeInteger(entry.size) ||
      entry.size < 1 ||
      entry.size > MAX_RUNTIME_FILE_BYTES ||
      entry.mode !== 0o644
    ) {
      fail("npm reported an invalid or oversized runtime package file");
    }
    validateRuntimePath(entry.path);
    unpackedBytes += entry.size;
  }
  if (
    unpackedBytes > MAX_UNPACKED_PACKAGE_BYTES ||
    report.unpackedSize !== unpackedBytes ||
    !Number.isSafeInteger(report.size) ||
    report.size < 1 ||
    report.size > MAX_TARBALL_BYTES
  ) {
    fail("npm package size metadata exceeds or differs from the release bounds");
  }
}

function validatePackedFiles(files) {
  const packedPaths = files.map((entry) => entry.path).sort();
  const packedPathSet = new Set(packedPaths);

  if (packedPathSet.size !== packedPaths.length) {
    fail("npm reported a duplicate tarball path");
  }

  for (const requiredPath of requiredPaths) {
    if (!packedPathSet.has(requiredPath)) {
      fail(`required runtime package file is missing: ${requiredPath}`);
    }
  }

  for (const packedPath of packedPaths) {
    validateRuntimePath(packedPath);

    const sourcePath = path.join(packageDirectory, packedPath);
    const metadata = lstatSync(sourcePath);
    if (
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      metadata.nlink !== 1
    ) {
      fail(`SDK tarball inputs must be regular files: ${packedPath}`);
    }
    const resolvedSourcePath = realpathSync(sourcePath);
    const resolvedPackageDirectory = `${realpathSync(packageDirectory)}${path.sep}`;
    if (!resolvedSourcePath.startsWith(resolvedPackageDirectory)) {
      fail(`SDK tarball input escaped the package directory: ${packedPath}`);
    }
    const reportEntry = files.find((entry) => entry.path === packedPath);
    if (metadata.size !== reportEntry.size || metadata.mode & 0o111) {
      fail(`SDK tarball metadata differs from its source: ${packedPath}`);
    }
    validateRuntimeText(packedPath, readFileSync(sourcePath));
  }

  return packedPaths;
}

export function validateReproduciblePack(
  firstReport,
  secondReport,
  firstArchive,
  secondArchive,
) {
  const reportProjection = (report) => ({
    bundled: report.bundled,
    entryCount: report.entryCount,
    filename: report.filename,
    files: [...report.files].sort((left, right) =>
      left.path.localeCompare(right.path),
    ),
    integrity: report.integrity,
    name: report.name,
    shasum: report.shasum,
    size: report.size,
    unpackedSize: report.unpackedSize,
    version: report.version,
  });
  if (
    JSON.stringify(reportProjection(firstReport)) !==
      JSON.stringify(reportProjection(secondReport)) ||
    !(firstArchive instanceof Uint8Array) ||
    !(secondArchive instanceof Uint8Array) ||
    !Buffer.from(firstArchive).equals(Buffer.from(secondArchive))
  ) {
    fail("two isolated npm pack runs did not produce one byte-identical artifact");
  }
}

function runNpmPack({ dryRun, outDirectory }) {
  const npmCache = mkdtempSync(path.join(tmpdir(), "tacua-mobile-sdk-npm-cache-"));
  try {
    const arguments_ = ["pack", "--ignore-scripts", "--json"];
    if (dryRun) {
      arguments_.push("--dry-run");
    } else {
      mkdirSync(outDirectory, { recursive: true, mode: 0o700 });
      arguments_.push("--pack-destination", outDirectory);
    }

    const result = spawnSync("npm", arguments_, {
      cwd: packageDirectory,
      encoding: "utf8",
      env: { ...process.env, npm_config_cache: npmCache },
      shell: false,
    });
    if (result.status !== 0) {
      fail(`npm pack failed:\n${result.stderr || result.stdout}`);
    }

    const reports = JSON.parse(result.stdout);
    if (!Array.isArray(reports) || reports.length !== 1) {
      fail("npm pack did not report exactly one package");
    }
    return reports[0];
  } finally {
    rmSync(npmCache, { recursive: true, force: true });
  }
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const manifest = readPackageManifest();
  const expectedTag = `mobile-sdk-v${manifest.version}`;
  if (options.tag !== expectedTag) {
    fail(`release tag ${options.tag} must exactly equal ${expectedTag}`);
  }

  const report = runNpmPack(options);
  if (report.name !== manifest.name || report.version !== manifest.version) {
    fail("npm pack metadata does not match package.json");
  }
  const expectedFilename = `tacua-mobile-sdk-${manifest.version}.tgz`;
  if (report.filename !== expectedFilename) {
    fail(`unexpected npm tarball filename: ${String(report.filename)}`);
  }
  validateReportedPackageBounds(report);
  const packedPaths = validatePackedFiles(report.files ?? []);

  let sha256 = null;
  let checksumFilename = null;
  if (!options.dryRun) {
    const tarballPath = path.join(options.outDirectory, expectedFilename);
    const tarballMetadata = lstatSync(tarballPath);
    if (
      !tarballMetadata.isFile() ||
      tarballMetadata.isSymbolicLink() ||
      tarballMetadata.size !== report.size ||
      tarballMetadata.size > MAX_TARBALL_BYTES
    ) {
      fail("npm tarball metadata differs from its bounded package report");
    }
    const tarballBytes = readFileSync(tarballPath);
    const reproducibilityDirectory = mkdtempSync(
      path.join(tmpdir(), "tacua-mobile-sdk-reproducibility-"),
    );
    try {
      const repeatedReport = runNpmPack({
        dryRun: false,
        outDirectory: reproducibilityDirectory,
      });
      if (
        repeatedReport.name !== manifest.name ||
        repeatedReport.version !== manifest.version ||
        repeatedReport.filename !== expectedFilename
      ) {
        fail("repeated npm pack metadata does not match package.json");
      }
      validateReportedPackageBounds(repeatedReport);
      validatePackedFiles(repeatedReport.files ?? []);
      validateReproduciblePack(
        report,
        repeatedReport,
        tarballBytes,
        readFileSync(path.join(reproducibilityDirectory, expectedFilename)),
      );
    } finally {
      rmSync(reproducibilityDirectory, { recursive: true, force: true });
    }

    sha256 = createHash("sha256").update(tarballBytes).digest("hex");
    checksumFilename = `${expectedFilename}.sha256`;
    writeFileSync(
      path.join(options.outDirectory, checksumFilename),
      `${sha256}  ${expectedFilename}\n`,
      { encoding: "utf8", flag: "wx", mode: 0o644 },
    );
  }

  process.stdout.write(
    `${JSON.stringify(
      {
        checksumFilename,
        files: packedPaths,
        name: manifest.name,
        sha256,
        tag: expectedTag,
        tarballFilename: expectedFilename,
        version: manifest.version,
      },
      null,
      2,
    )}\n`,
  );
}

if (
  process.argv[1] &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`mobile SDK package validation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
