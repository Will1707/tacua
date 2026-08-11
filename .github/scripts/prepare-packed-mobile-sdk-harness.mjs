// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { MAX_TARBALL_BYTES } from "./package-mobile-sdk.mjs";

const SOURCE_HARNESS_NAME = "@tacua/ios-capture-harness";
const PACKED_HARNESS_NAME = "@tacua/packed-sdk-release-harness";
const SDK_NAME = "@tacua/mobile-sdk";
const SOURCE_SDK_SPEC = "file:../package";
const SOURCE_SDK_PACKAGE_KEY = "../package";
const INSTALLED_SDK_PACKAGE_KEY = "node_modules/@tacua/mobile-sdk";

function fail(message) {
  throw new Error(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalJSON(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalJSON);
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalJSON(value[key])]),
    );
  }
  return value;
}

function requireMatchingJSON(actual, expected, message) {
  if (
    JSON.stringify(canonicalJSON(actual)) !==
    JSON.stringify(canonicalJSON(expected))
  ) {
    fail(message);
  }
}

function readJSON(filePath, label) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(filePath, "utf8"));
  } catch {
    fail(`${label} is not valid JSON`);
  }
  if (!isRecord(parsed)) {
    fail(`${label} must contain a JSON object`);
  }
  return parsed;
}

function validateInputs(sourceManifest, sourceLock, sdkManifest) {
  if (
    sourceManifest.name !== SOURCE_HARNESS_NAME ||
    sourceManifest.private !== true ||
    !isRecord(sourceManifest.dependencies) ||
    sourceManifest.dependencies[SDK_NAME] !== SOURCE_SDK_SPEC
  ) {
    fail("source harness manifest is not the expected private workspace harness");
  }
  if (
    sourceLock.name !== SOURCE_HARNESS_NAME ||
    sourceLock.lockfileVersion !== 3 ||
    sourceLock.requires !== true ||
    !isRecord(sourceLock.packages) ||
    !isRecord(sourceLock.packages[""]) ||
    sourceLock.packages[""].name !== SOURCE_HARNESS_NAME ||
    !isRecord(sourceLock.packages[""].dependencies) ||
    sourceLock.packages[""].dependencies[SDK_NAME] !== SOURCE_SDK_SPEC
  ) {
    fail("source harness lock is not a matching lockfileVersion 3 workspace lock");
  }

  const sourceSDKPackage = sourceLock.packages[SOURCE_SDK_PACKAGE_KEY];
  const linkedSDKPackage = sourceLock.packages[INSTALLED_SDK_PACKAGE_KEY];
  if (
    !isRecord(linkedSDKPackage) ||
    linkedSDKPackage.link !== true ||
    linkedSDKPackage.resolved !== SOURCE_SDK_PACKAGE_KEY
  ) {
    fail("source harness lock does not contain the expected workspace SDK link");
  }
  if (
    sdkManifest.name !== SDK_NAME ||
    sdkManifest.private !== true ||
    typeof sdkManifest.version !== "string" ||
    !/^0\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u.test(sdkManifest.version) ||
    typeof sdkManifest.license !== "string" ||
    !isRecord(sdkManifest.dependencies) ||
    !isRecord(sdkManifest.peerDependencies)
  ) {
    fail("SDK manifest is not the expected bounded prerelease package manifest");
  }

  requireMatchingJSON(
    sourceSDKPackage,
    {
      name: sdkManifest.name,
      version: sdkManifest.version,
      license: sdkManifest.license,
      dependencies: sdkManifest.dependencies,
      peerDependencies: sdkManifest.peerDependencies,
    },
    "source harness lock metadata does not match the SDK manifest",
  );
}

export function preparePackedHarnessDocuments({
  sourceManifest,
  sourceLock,
  sdkManifest,
  tarballBytes,
  tarballPath,
  lockPath,
}) {
  validateInputs(sourceManifest, sourceLock, sdkManifest);
  if (!(tarballBytes instanceof Uint8Array) || tarballBytes.byteLength < 1) {
    fail("SDK tarball must contain bounded bytes");
  }
  if (tarballBytes.byteLength > MAX_TARBALL_BYTES) {
    fail("SDK tarball exceeds the release-package byte bound");
  }
  const expectedFilename = `tacua-mobile-sdk-${sdkManifest.version}.tgz`;
  if (path.basename(tarballPath) !== expectedFilename) {
    fail(`SDK tarball filename must exactly equal ${expectedFilename}`);
  }

  const absoluteTarballPath = path.resolve(tarballPath);
  const absoluteLockPath = path.resolve(lockPath);
  const relativeTarballPath = path.relative(
    path.dirname(absoluteLockPath),
    absoluteTarballPath,
  );
  if (!relativeTarballPath || path.isAbsolute(relativeTarballPath)) {
    fail("SDK tarball must resolve to a distinct local file");
  }
  const manifestTarballSpec = pathToFileURL(absoluteTarballPath).href;
  const lockTarballSpec = `file:${relativeTarballPath.split(path.sep).join("/")}`;
  const integrity = `sha512-${createHash("sha512")
    .update(tarballBytes)
    .digest("base64")}`;

  const packedManifest = structuredClone(sourceManifest);
  packedManifest.name = PACKED_HARNESS_NAME;
  packedManifest.dependencies[SDK_NAME] = manifestTarballSpec;

  const packedLock = structuredClone(sourceLock);
  packedLock.name = PACKED_HARNESS_NAME;
  packedLock.packages[""].name = PACKED_HARNESS_NAME;
  packedLock.packages[""].dependencies[SDK_NAME] = manifestTarballSpec;
  delete packedLock.packages[SOURCE_SDK_PACKAGE_KEY];
  packedLock.packages[INSTALLED_SDK_PACKAGE_KEY] = {
    version: sdkManifest.version,
    resolved: lockTarballSpec,
    integrity,
    license: sdkManifest.license,
    dependencies: structuredClone(sdkManifest.dependencies),
    peerDependencies: structuredClone(sdkManifest.peerDependencies),
  };

  return { packedManifest, packedLock };
}

export function preparePackedHarnessFiles({
  sourceManifestPath,
  destinationManifestPath,
  destinationLockPath,
  sdkManifestPath,
  tarballPath,
}) {
  const tarballMetadata = lstatSync(tarballPath);
  if (
    !tarballMetadata.isFile() ||
    tarballMetadata.isSymbolicLink() ||
    tarballMetadata.size < 1 ||
    tarballMetadata.size > MAX_TARBALL_BYTES
  ) {
    fail("SDK tarball must be one bounded regular file");
  }
  const { packedManifest, packedLock } = preparePackedHarnessDocuments({
    sourceManifest: readJSON(sourceManifestPath, "source harness manifest"),
    sourceLock: readJSON(destinationLockPath, "source harness lock"),
    sdkManifest: readJSON(sdkManifestPath, "SDK manifest"),
    tarballBytes: readFileSync(tarballPath),
    tarballPath,
    lockPath: destinationLockPath,
  });
  writeFileSync(
    destinationManifestPath,
    `${JSON.stringify(packedManifest, null, 2)}\n`,
    { encoding: "utf8", flag: "wx", mode: 0o600 },
  );
  writeFileSync(
    destinationLockPath,
    `${JSON.stringify(packedLock, null, 2)}\n`,
    { encoding: "utf8", mode: 0o600 },
  );
}

function main() {
  const [
    sourceManifestPath,
    destinationManifestPath,
    destinationLockPath,
    sdkManifestPath,
    tarballPath,
  ] = process.argv.slice(2);
  if (
    !sourceManifestPath ||
    !destinationManifestPath ||
    !destinationLockPath ||
    !sdkManifestPath ||
    !tarballPath ||
    process.argv.length !== 7
  ) {
    fail(
      "usage: prepare-packed-mobile-sdk-harness.mjs SOURCE_MANIFEST DESTINATION_MANIFEST DESTINATION_LOCK SDK_MANIFEST SDK_TARBALL",
    );
  }
  preparePackedHarnessFiles({
    sourceManifestPath: path.resolve(sourceManifestPath),
    destinationManifestPath: path.resolve(destinationManifestPath),
    destinationLockPath: path.resolve(destinationLockPath),
    sdkManifestPath: path.resolve(sdkManifestPath),
    tarballPath: path.resolve(tarballPath),
  });
}

if (
  process.argv[1] &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`packed SDK harness preparation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
