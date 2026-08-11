// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { preparePackedHarnessDocuments } from "./prepare-packed-mobile-sdk-harness.mjs";

const sdkManifest = Object.freeze({
  name: "@tacua/mobile-sdk",
  version: "0.2.0",
  private: true,
  license: "Apache-2.0",
  dependencies: { "expo-modules-core": "~56.0.17" },
  peerDependencies: {
    expo: ">=56.0.16 <57",
    "react-native": ">=0.85.3 <0.86",
  },
});

function sourceManifest() {
  return {
    name: "@tacua/ios-capture-harness",
    version: "0.0.1",
    private: true,
    dependencies: {
      "@tacua/mobile-sdk": "file:../package",
      expo: "~56.0.12",
    },
  };
}

function sourceLock() {
  return {
    name: "@tacua/ios-capture-harness",
    version: "0.0.1",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": {
        name: "@tacua/ios-capture-harness",
        version: "0.0.1",
        dependencies: {
          "@tacua/mobile-sdk": "file:../package",
          expo: "~56.0.12",
        },
      },
      "../package": {
        name: sdkManifest.name,
        version: sdkManifest.version,
        license: sdkManifest.license,
        dependencies: structuredClone(sdkManifest.dependencies),
        peerDependencies: structuredClone(sdkManifest.peerDependencies),
      },
      "node_modules/@tacua/mobile-sdk": {
        resolved: "../package",
        link: true,
      },
      "node_modules/expo": {
        version: "56.0.16",
        resolved: "https://registry.npmjs.org/expo/-/expo-56.0.16.tgz",
        integrity: "sha512-synthetic",
      },
    },
  };
}

test("rewrites the workspace link into one integrity-sealed local tarball entry", () => {
  const harnessManifest = sourceManifest();
  const harnessLock = sourceLock();
  const originalManifest = structuredClone(harnessManifest);
  const originalLock = structuredClone(harnessLock);
  const tarballBytes = Buffer.from("synthetic deterministic SDK tarball", "utf8");
  const lockPath = "/tmp/packed-harness/package-lock.json";
  const tarballPath = "/tmp/mobile-sdk/tacua-mobile-sdk-0.2.0.tgz";

  const { packedManifest, packedLock } = preparePackedHarnessDocuments({
    sourceManifest: harnessManifest,
    sourceLock: harnessLock,
    sdkManifest,
    tarballBytes,
    tarballPath,
    lockPath,
  });

  assert.deepEqual(harnessManifest, originalManifest);
  assert.deepEqual(harnessLock, originalLock);
  assert.equal(packedManifest.name, "@tacua/packed-sdk-release-harness");
  assert.equal(
    packedManifest.dependencies["@tacua/mobile-sdk"],
    pathToFileURL(tarballPath).href,
  );
  assert.equal(packedLock.name, packedManifest.name);
  assert.equal(packedLock.packages[""].name, packedManifest.name);
  assert.equal(
    packedLock.packages[""].dependencies["@tacua/mobile-sdk"],
    pathToFileURL(tarballPath).href,
  );
  assert.equal(packedLock.packages["../package"], undefined);
  assert.deepEqual(packedLock.packages["node_modules/@tacua/mobile-sdk"], {
    version: "0.2.0",
    resolved: "file:../mobile-sdk/tacua-mobile-sdk-0.2.0.tgz",
    integrity: `sha512-${createHash("sha512")
      .update(tarballBytes)
      .digest("base64")}`,
    license: "Apache-2.0",
    dependencies: { "expo-modules-core": "~56.0.17" },
    peerDependencies: {
      expo: ">=56.0.16 <57",
      "react-native": ">=0.85.3 <0.86",
    },
  });
  assert.equal(packedLock.packages["node_modules/expo"].version, "56.0.16");
  assert.equal(packedManifest.dependencies.expo, "~56.0.12");
});

test("rejects stale SDK metadata and a non-workspace source lock", () => {
  const mismatchedLock = sourceLock();
  mismatchedLock.packages["../package"].peerDependencies.expo = "*";
  assert.throws(
    () =>
      preparePackedHarnessDocuments({
        sourceManifest: sourceManifest(),
        sourceLock: mismatchedLock,
        sdkManifest,
        tarballBytes: Buffer.from("archive"),
        tarballPath: "/tmp/tacua-mobile-sdk-0.2.0.tgz",
        lockPath: "/tmp/harness/package-lock.json",
      }),
    /lock metadata does not match the SDK manifest/,
  );

  const nonWorkspaceLock = sourceLock();
  nonWorkspaceLock.packages["node_modules/@tacua/mobile-sdk"] = {
    version: "0.2.0",
  };
  assert.throws(
    () =>
      preparePackedHarnessDocuments({
        sourceManifest: sourceManifest(),
        sourceLock: nonWorkspaceLock,
        sdkManifest,
        tarballBytes: Buffer.from("archive"),
        tarballPath: "/tmp/tacua-mobile-sdk-0.2.0.tgz",
        lockPath: "/tmp/harness/package-lock.json",
      }),
    /expected workspace SDK link/,
  );
});

test("rejects a tarball whose filename does not match the sealed SDK version", () => {
  assert.throws(
    () =>
      preparePackedHarnessDocuments({
        sourceManifest: sourceManifest(),
        sourceLock: sourceLock(),
        sdkManifest,
        tarballBytes: Buffer.from("archive"),
        tarballPath: "/tmp/tacua-mobile-sdk-0.1.0.tgz",
        lockPath: "/tmp/harness/package-lock.json",
      }),
    /filename must exactly equal tacua-mobile-sdk-0\.2\.0\.tgz/,
  );
});
