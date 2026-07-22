// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const {
  applyInfoPlist,
  canonicalJSON,
  defaultMicrophonePermission,
  digest,
  normalizeBackendOrigin,
  readSdkProfile,
  validateBundleIdentifier,
  validateOptions,
} = require("../plugin/config.js");

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const profilePath = path.resolve(testDirectory, "../../../../services/backend/sdk-profile.example.json");
const profileText = fs.readFileSync(profilePath, "utf8");
const valid = {
  backendOrigin: "https://qa.example.com",
  buildVariant: "preview",
  captureEnabled: true,
  distribution: "testflight",
  launchScheme: "example-tacua-qa",
  sdkProfilePath: profilePath,
};

function resealProfile(profile) {
  profile.transport_configuration_digest = digest(profile.transport_configuration);
  profile.build_identity.transport_configuration_digest = profile.transport_configuration_digest;
  const buildSubject = { ...profile.build_identity };
  delete buildSubject.build_identity_digest;
  profile.build_identity.build_identity_digest = digest(buildSubject);
  profile.capture_scope_policy.build_id = profile.build_identity.build_id;
  profile.capture_scope_policy.build_identity_digest = profile.build_identity.build_identity_digest;
  const subject = { ...profile };
  delete subject.profile_digest;
  profile.profile_digest = digest(subject);
  return `${canonicalJSON(profile)}\n`;
}

function temporaryProfile(contents) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tacua-profile-test-"));
  const file = path.join(directory, "sdk-profile.json");
  fs.writeFileSync(file, contents, { encoding: "utf8", mode: 0o644 });
  return { directory, file };
}

test("seals one explicit non-production QA plugin configuration from the backend profile", () => {
  const options = validateOptions(valid);
  assert.equal(options.backendOrigin, "https://qa.example.com");
  assert.equal(options.buildVariant, "preview");
  assert.equal(options.distribution, "testflight");
  assert.equal(options.sdkProfile.build_identity.bundle_identifier, "com.example.app");
  assert.equal(options.sdkProfileCanonicalJSON, profileText.trimEnd());
  assert.equal(
    validateOptions(
      { ...valid, sdkProfilePath: path.basename(profilePath) },
      path.dirname(profilePath),
    ).sdkProfile.profile_digest,
    options.sdkProfile.profile_digest,
  );
  validateBundleIdentifier("com.example.app", options);
  assert.throws(() => validateBundleIdentifier("com.attacker.app", options), /does not match/);

  const infoPlist = applyInfoPlist({}, options);
  assert.deepEqual(infoPlist.CFBundleURLTypes, [{ CFBundleURLSchemes: ["example-tacua-qa"] }]);
  assert.equal(infoPlist.NSMicrophoneUsageDescription, defaultMicrophonePermission);
  assert.equal(infoPlist.TacuaBackendOrigin, "https://qa.example.com");
  assert.equal(infoPlist.TacuaCaptureBuildVariant, "preview");
  assert.equal(infoPlist.TacuaCaptureDistribution, "testflight");
  assert.equal(infoPlist.TacuaSDKProfileJSON, profileText.trimEnd());
  assert.equal(infoPlist.TacuaSDKProfileDigest, options.sdkProfile.profile_digest);
  assert.strictEqual(applyInfoPlist(infoPlist, options), infoPlist);
  assert.equal(infoPlist.CFBundleURLTypes.length, 1);
  assert.equal(normalizeBackendOrigin("https://QA.EXAMPLE.COM:443", false), "https://qa.example.com");
});

test("fails closed on conflicting or malformed native configuration", () => {
  const options = validateOptions(valid);
  assert.throws(() => applyInfoPlist({ TacuaBackendOrigin: "https://other.example.com" }, options), /conflicts/);
  assert.throws(() => applyInfoPlist({ TacuaSDKProfileDigest: `sha256:${"0".repeat(64)}` }, options), /conflicts/);
  assert.throws(() => applyInfoPlist({ CFBundleURLTypes: {} }, options), /CFBundleURLTypes/);
  const existing = {
    CFBundleURLTypes: [
      { CFBundleURLName: "other", CFBundleURLSchemes: ["other-app"] },
      { CFBundleURLName: "qa", CFBundleURLSchemes: ["example-tacua-qa"] },
    ],
  };
  applyInfoPlist(existing, options);
  assert.equal(existing.CFBundleURLTypes.length, 2);
});

test("allows HTTP only for a profile-pinned local development build", () => {
  const profile = JSON.parse(profileText);
  profile.backend_origin = "http://127.0.0.1:8080";
  profile.transport_configuration.backend_origin = profile.backend_origin;
  profile.build_identity.build_variant = "development";
  profile.build_identity.distribution = "local";
  const temporary = temporaryProfile(resealProfile(profile));
  try {
    assert.equal(
      validateOptions({
        ...valid,
        allowInsecureLoopback: true,
        backendOrigin: "http://127.0.0.1:8080",
        buildVariant: "development",
        distribution: "local",
        sdkProfilePath: temporary.file,
      }).backendOrigin,
      "http://127.0.0.1:8080",
    );
    assert.throws(
      () => validateOptions({
        ...valid,
        backendOrigin: "http://127.0.0.1:8080",
        buildVariant: "development",
        distribution: "local",
        sdkProfilePath: temporary.file,
      }),
      /explicitly enabled loopback/,
    );
  } finally {
    fs.rmSync(temporary.directory, { recursive: true, force: true });
  }
});

test("rejects missing, stale, or contradictory profile pins", () => {
  for (const options of [
    { ...valid, sdkProfilePath: undefined },
    { ...valid, backendOrigin: "https://other.example.com" },
    { ...valid, buildVariant: "development" },
    { ...valid, distribution: "internal" },
    { ...valid, captureEnabled: false },
    { ...valid, captureEnabled: undefined },
    { ...valid, buildVariant: "production" },
    { ...valid, distribution: "appstore" },
    { ...valid, launchScheme: "Tacua-QA" },
    { ...valid, backendOrgin: "https://typo.example.com" },
  ]) {
    assert.throws(() => validateOptions(options));
  }
});

test("uses one 2-64 character dedicated QA launch-scheme policy", () => {
  assert.equal(validateOptions({ ...valid, launchScheme: `a${"b".repeat(63)}` }).launchScheme.length, 64);
  assert.throws(() => validateOptions({ ...valid, launchScheme: `a${"b".repeat(64)}` }));
  const reservedSchemes = [
    "about", "blob", "data", "facetime", "facetime-audio", "file", "ftp", "ftps",
    "http", "https", "itms", "itms-apps", "javascript", "mailto", "sms", "tacua",
    "tel", "webcal", "ws", "wss",
  ];
  for (const launchScheme of reservedSchemes) {
    assert.throws(
      () => validateOptions({ ...valid, launchScheme }),
      /dedicated QA-app URL scheme/,
    );
  }
});

test("rejects tampering even when an attacker recomputes the outer profile digest", () => {
  const cases = [
    (profile) => { profile.capture_scope_policy.organization_id = "Org-invalid"; },
    (profile) => { profile.capture_scope_policy.consent.microphone = "optional"; },
    (profile) => { profile.capture_scope_policy.retention.raw_media_days = 31; },
    (profile) => { profile.build_identity.build_identity_digest = `sha256:${"0".repeat(64)}`; },
    (profile) => { profile.transport_configuration.transport_policy_version = "tacua.sdk-transport@2.0.0"; },
    (profile) => { profile.admin_secret = "must-not-be-embedded"; },
  ];
  for (const mutate of cases) {
    const profile = JSON.parse(profileText);
    mutate(profile);
    const subject = { ...profile };
    delete subject.profile_digest;
    profile.profile_digest = digest(subject);
    const temporary = temporaryProfile(`${canonicalJSON(profile)}\n`);
    try {
      assert.throws(() => readSdkProfile(temporary.file));
    } finally {
      fs.rmSync(temporary.directory, { recursive: true, force: true });
    }
  }
});

test("rejects noncanonical bytes, duplicate keys, floats, BOM, invalid UTF-8, and symlinks", () => {
  const duplicate = profileText.replace("{", '{"backend_origin":"https://qa.example.com",', 1);
  const malformedCases = [
    ` ${profileText}`,
    `${profileText}\n`,
    duplicate,
    profileText.replace('"raw_media_days":30', '"raw_media_days":30.0'),
    `\ufeff${profileText}`,
  ];
  for (const contents of malformedCases) {
    const temporary = temporaryProfile(contents);
    try {
      assert.throws(() => readSdkProfile(temporary.file));
    } finally {
      fs.rmSync(temporary.directory, { recursive: true, force: true });
    }
  }

  const invalid = temporaryProfile(profileText);
  fs.writeFileSync(invalid.file, Buffer.from([0xff, 0xfe, 0xfd]));
  try {
    assert.throws(() => readSdkProfile(invalid.file), /UTF-8/);
  } finally {
    fs.rmSync(invalid.directory, { recursive: true, force: true });
  }

  const oversized = temporaryProfile("x".repeat((64 * 1024) + 1));
  try {
    assert.throws(() => readSdkProfile(oversized.file), /size/);
  } finally {
    fs.rmSync(oversized.directory, { recursive: true, force: true });
  }

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tacua-profile-symlink-"));
  const link = path.join(directory, "profile-link.json");
  fs.symlinkSync(profilePath, link);
  try {
    assert.throws(() => readSdkProfile(link), /non-symlink/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects unsafe permission copy and invalid option containers", () => {
  assert.throws(() => validateOptions(null));
  assert.throws(() => validateOptions([]));
  assert.throws(() => validateOptions({ ...valid, microphonePermission: "too short" }));
  assert.throws(() => validateOptions({ ...valid, microphonePermission: `${"A".repeat(24)}\nsecret` }), /microphonePermission/);
  assert.throws(() => validateOptions({ ...valid, microphonePermission: `${"A".repeat(23)}e\u0301` }), /microphonePermission/);
});
