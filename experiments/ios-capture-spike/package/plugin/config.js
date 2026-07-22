// SPDX-License-Identifier: Apache-2.0

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { TextDecoder } = require("node:util");

const MAX_SDK_PROFILE_BYTES = 64 * 1024;
const PROFILE_CONTRACT = "tacua.sdk-profile@1.0.0";
const PROTOCOL_VERSION = "tacua.sdk-backend@1.0.0";
const TRANSPORT_POLICY_VERSION = "tacua.sdk-transport@1.0.0";
const SCOPE_POLICY_CONTRACT = "tacua.capture-scope-policy@1.0.0";
const RETENTION_POLICY_VERSION = "tacua.retention-v1";
const ID_PATTERN = /^[a-z][a-z0-9_-]{2,63}$/u;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const TIMESTAMP_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/u;
const VERSION_PATTERN = /^[A-Za-z0-9._+/-]{1,128}$/u;
const BUNDLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$/u;
const forbiddenSecretKeys = new Set([
  "access_token", "admin_secret", "api_key", "authorization", "client_secret",
  "cookie", "password", "private_key", "refresh_token", "secret", "session_cookie", "token",
]);
const allowedOptionKeys = new Set([
  "allowInsecureLoopback",
  "backendOrigin",
  "buildVariant",
  "captureEnabled",
  "distribution",
  "launchScheme",
  "microphonePermission",
  "sdkProfilePath",
]);
// Keep aligned with TacuaLaunchLinkConfiguration and the reviewer target-scheme validator.
// These schemes route a launch code to a browser, an OS service, or the Tacua reviewer rather
// than to the QA application.
const reservedLaunchSchemes = new Set([
  "about", "blob", "data", "facetime", "facetime-audio", "file", "ftp", "ftps",
  "http", "https", "itms", "itms-apps", "javascript", "mailto", "sms", "tacua",
  "tel", "webcal", "ws", "wss",
]);

const defaultMicrophonePermission =
  "Tacua records your spoken QA narration alongside an in-app screen recording only after you start a review.";

function requireNfcText(value, field, minimum, maximum) {
  if (
    typeof value !== "string"
    || value.length < minimum
    || value.length > maximum
    || value.normalize("NFC") !== value
    || /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error(`${field} is invalid.`);
  }
  return value;
}

function normalizeBackendOrigin(value, allowInsecureLoopback) {
  const raw = requireNfcText(value, "backendOrigin", 1, 2_048);
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("backendOrigin must be an absolute HTTP(S) origin.");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol)
    || parsed.username
    || parsed.password
    || parsed.pathname !== "/"
    || parsed.search
    || parsed.hash
  ) {
    throw new Error("backendOrigin must contain only an HTTP(S) scheme and host.");
  }
  const host = parsed.hostname.toLowerCase();
  if (!host || /[^\x00-\x7f]/u.test(host) || host.includes("%")) {
    throw new Error("backendOrigin must use an ASCII or punycode host.");
  }
  const loopback = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  if (parsed.protocol === "http:" && (!allowInsecureLoopback || !loopback)) {
    throw new Error("HTTP is allowed only for an explicitly enabled loopback development origin.");
  }
  if (allowInsecureLoopback && (!loopback || parsed.protocol !== "http:")) {
    throw new Error("allowInsecureLoopback is valid only with a loopback HTTP origin.");
  }
  return parsed.origin.toLowerCase();
}

function requireExactKeys(value, expected, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new Error(`${field} contains missing or unknown fields.`);
  }
}

function validatePublicJSON(value, field = "sdkProfile") {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error(`${field} contains a non-integer or unsafe number.`);
    return;
  }
  if (typeof value === "string") {
    if (value.normalize("NFC") !== value || /[\u0000-\u001f\u007f]/u.test(value)) {
      throw new Error(`${field} contains invalid text.`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => validatePublicJSON(item, `${field}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") throw new Error(`${field} contains an invalid JSON value.`);
  for (const [key, item] of Object.entries(value)) {
    validatePublicJSON(key, `${field} key`);
    if (forbiddenSecretKeys.has(key.toLowerCase().replaceAll("-", "_"))) {
      throw new Error("sdkProfile must not contain secret-bearing fields.");
    }
    validatePublicJSON(item, `${field}.${key}`);
  }
}

function canonicalJSON(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
}

function digest(value) {
  return `sha256:${crypto.createHash("sha256").update(canonicalJSON(value), "utf8").digest("hex")}`;
}

function requireValue(condition, field) {
  if (!condition) throw new Error(`${field} is invalid.`);
}

function isCanonicalTimestamp(value) {
  if (typeof value !== "string" || !TIMESTAMP_PATTERN.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds)
    && new Date(milliseconds).toISOString().replace(".000Z", "Z") === value;
}

function validateBuildIdentity(build) {
  requireExactKeys(build, [
    "build_id", "build_identity_digest", "build_variant", "bundle_identifier", "created_at",
    "distribution", "expo", "message_type", "native_build", "native_version", "platform",
    "protocol_version", "react_native_version", "source", "transport_configuration_digest",
  ], "sdkProfile.build_identity");
  requireValue(build.protocol_version === PROTOCOL_VERSION, "sdkProfile.build_identity.protocol_version");
  requireValue(build.message_type === "build_identity", "sdkProfile.build_identity.message_type");
  requireValue(ID_PATTERN.test(build.build_id), "sdkProfile.build_identity.build_id");
  requireValue(build.platform === "ios", "sdkProfile.build_identity.platform");
  requireValue(typeof build.bundle_identifier === "string" && build.bundle_identifier.length <= 255 && BUNDLE_PATTERN.test(build.bundle_identifier), "sdkProfile.build_identity.bundle_identifier");
  for (const key of ["native_version", "native_build", "react_native_version"]) {
    requireValue(typeof build[key] === "string" && VERSION_PATTERN.test(build[key]), `sdkProfile.build_identity.${key}`);
  }
  requireValue(["development", "preview"].includes(build.build_variant), "sdkProfile.build_identity.build_variant");
  requireValue(["local", "internal", "testflight"].includes(build.distribution), "sdkProfile.build_identity.distribution");
  requireValue(!(
    (build.build_variant === "development" && build.distribution === "testflight")
    || (build.build_variant === "preview" && build.distribution === "local")
  ), "sdkProfile.build_identity distribution pin");
  requireValue(isCanonicalTimestamp(build.created_at), "sdkProfile.build_identity.created_at");
  requireValue(DIGEST_PATTERN.test(build.transport_configuration_digest), "sdkProfile.build_identity.transport_configuration_digest");
  requireValue(DIGEST_PATTERN.test(build.build_identity_digest), "sdkProfile.build_identity.build_identity_digest");
  const buildSubject = { ...build };
  delete buildSubject.build_identity_digest;
  requireValue(digest(buildSubject) === build.build_identity_digest, "sdkProfile.build_identity.build_identity_digest");
  requireExactKeys(build.source, ["git_revision", "working_tree_dirty"], "sdkProfile.build_identity.source");
  requireValue(typeof build.source.git_revision === "string" && /^[a-f0-9]{7,64}$/u.test(build.source.git_revision), "sdkProfile.build_identity.source.git_revision");
  requireValue(typeof build.source.working_tree_dirty === "boolean", "sdkProfile.build_identity.source.working_tree_dirty");
  if (build.expo !== null) {
    requireExactKeys(build.expo, ["runtime_version", "sdk_version", "update_channel", "update_id"], "sdkProfile.build_identity.expo");
    requireValue(VERSION_PATTERN.test(build.expo.sdk_version), "sdkProfile.build_identity.expo.sdk_version");
    requireValue(VERSION_PATTERN.test(build.expo.runtime_version), "sdkProfile.build_identity.expo.runtime_version");
    const validUpdate = build.expo.update_id === null
      ? build.expo.update_channel === null
      : typeof build.expo.update_id === "string" && build.expo.update_id.length >= 1 && build.expo.update_id.length <= 512
        && typeof build.expo.update_channel === "string" && build.expo.update_channel.length >= 1 && build.expo.update_channel.length <= 512;
    requireValue(validUpdate, "sdkProfile.build_identity.expo update binding");
  }
}

function validateScopePolicy(policy, profile) {
  requireExactKeys(policy, [
    "application_id", "build_id", "build_identity_digest", "capture_scope", "consent",
    "contract_version", "organization_id", "project_id", "protocol_version", "retention",
  ], "sdkProfile.capture_scope_policy");
  requireValue(policy.contract_version === SCOPE_POLICY_CONTRACT, "sdkProfile.capture_scope_policy.contract_version");
  requireValue(policy.protocol_version === PROTOCOL_VERSION, "sdkProfile.capture_scope_policy.protocol_version");
  for (const key of ["organization_id", "project_id", "application_id", "build_id"]) {
    requireValue(ID_PATTERN.test(policy[key]), `sdkProfile.capture_scope_policy.${key}`);
  }
  requireValue(policy.build_id === profile.build_identity.build_id, "sdkProfile.capture_scope_policy.build_id pin");
  requireValue(policy.build_identity_digest === profile.build_identity.build_identity_digest, "sdkProfile.capture_scope_policy.build_identity_digest pin");
  requireValue(policy.capture_scope === "app_only", "sdkProfile.capture_scope_policy.capture_scope");
  requireExactKeys(policy.consent, ["diagnostics", "microphone", "policy_version", "raw_media_upload", "screen_recording"], "sdkProfile.capture_scope_policy.consent");
  requireValue(typeof policy.consent.policy_version === "string" && VERSION_PATTERN.test(policy.consent.policy_version), "sdkProfile.capture_scope_policy.consent.policy_version");
  for (const key of ["diagnostics", "microphone", "raw_media_upload", "screen_recording"]) {
    requireValue(policy.consent[key] === "required", `sdkProfile.capture_scope_policy.consent.${key}`);
  }
  requireExactKeys(policy.retention, ["derived_data_days", "policy_version", "raw_media_days"], "sdkProfile.capture_scope_policy.retention");
  requireValue(policy.retention.policy_version === RETENTION_POLICY_VERSION, "sdkProfile.capture_scope_policy.retention.policy_version");
  requireValue(Number.isInteger(policy.retention.raw_media_days) && policy.retention.raw_media_days >= 1 && policy.retention.raw_media_days <= 30, "sdkProfile.capture_scope_policy.retention.raw_media_days");
  requireValue(Number.isInteger(policy.retention.derived_data_days) && policy.retention.derived_data_days >= 1 && policy.retention.derived_data_days <= 365, "sdkProfile.capture_scope_policy.retention.derived_data_days");
}

function validateSdkProfile(profile, serialized) {
  validatePublicJSON(profile);
  requireExactKeys(profile, [
    "backend_origin", "build_identity", "capture_scope_policy", "contract_version", "profile_digest",
    "transport_configuration", "transport_configuration_digest",
  ], "sdkProfile");
  requireValue(profile.contract_version === PROFILE_CONTRACT, "sdkProfile.contract_version");
  requireValue(DIGEST_PATTERN.test(profile.profile_digest), "sdkProfile.profile_digest");
  const subject = { ...profile };
  delete subject.profile_digest;
  requireValue(digest(subject) === profile.profile_digest, "sdkProfile.profile_digest");
  validateBuildIdentity(profile.build_identity);
  validateScopePolicy(profile.capture_scope_policy, profile);
  requireExactKeys(profile.transport_configuration, ["backend_origin", "transport_policy_version"], "sdkProfile.transport_configuration");
  requireValue(profile.transport_configuration.transport_policy_version === TRANSPORT_POLICY_VERSION, "sdkProfile.transport_configuration.transport_policy_version");
  requireValue(profile.transport_configuration.backend_origin === profile.backend_origin, "sdkProfile.transport_configuration.backend_origin pin");
  const profileAllowsLoopback = profile.backend_origin.startsWith("http://");
  requireValue(
    normalizeBackendOrigin(profile.backend_origin, profileAllowsLoopback) === profile.backend_origin,
    "sdkProfile.backend_origin",
  );
  if (profileAllowsLoopback) {
    requireValue(
      profile.build_identity.build_variant === "development" && profile.build_identity.distribution === "local",
      "sdkProfile insecure transport build pin",
    );
  }
  requireValue(DIGEST_PATTERN.test(profile.transport_configuration_digest), "sdkProfile.transport_configuration_digest");
  requireValue(digest(profile.transport_configuration) === profile.transport_configuration_digest, "sdkProfile.transport_configuration_digest");
  requireValue(profile.build_identity.transport_configuration_digest === profile.transport_configuration_digest, "sdkProfile.build_identity transport pin");
  requireValue(serialized === `${canonicalJSON(profile)}\n`, "sdkProfile canonical bytes");
  return profile;
}

function readSdkProfile(profilePath, projectRoot = process.cwd()) {
  const configuredPath = requireNfcText(profilePath, "sdkProfilePath", 1, 4_096);
  const resolved = path.resolve(projectRoot, configuredPath);
  let descriptor;
  try {
    const before = fs.lstatSync(resolved);
    if (!before.isFile() || before.isSymbolicLink()) throw new Error("not a regular non-symlink file");
    descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size < 3 || stat.size > MAX_SDK_PROFILE_BYTES) throw new Error("profile size is invalid");
    const payload = Buffer.alloc(stat.size + 1);
    let offset = 0;
    while (offset < payload.length) {
      const count = fs.readSync(descriptor, payload, offset, payload.length - offset, null);
      if (count === 0) break;
      offset += count;
    }
    if (offset !== stat.size) throw new Error("profile changed while it was read");
    let serialized;
    try {
      serialized = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(payload.subarray(0, offset));
    } catch {
      throw new Error("profile is not strict UTF-8");
    }
    if (serialized.startsWith("\ufeff")) throw new Error("profile contains a UTF-8 BOM");
    let profile;
    try {
      profile = JSON.parse(serialized);
    } catch {
      throw new Error("profile is not valid JSON");
    }
    return Object.freeze({
      canonicalJSON: serialized.slice(0, -1),
      profile: validateSdkProfile(profile, serialized),
      resolvedPath: resolved,
    });
  } catch (error) {
    throw new Error(`Cannot load canonical Tacua SDK profile: ${error instanceof Error ? error.message : "read failed"}.`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function validateOptions(rawOptions, projectRoot = process.cwd()) {
  if (!rawOptions || typeof rawOptions !== "object" || Array.isArray(rawOptions)) {
    throw new Error("Tacua config-plugin options must be an object.");
  }
  const unknown = Object.keys(rawOptions).filter((key) => !allowedOptionKeys.has(key));
  if (unknown.length > 0) throw new Error(`Unknown Tacua config-plugin option: ${unknown.sort()[0]}.`);
  if (rawOptions.captureEnabled !== true) throw new Error("captureEnabled must be explicitly true for a Tacua QA build.");
  const allowInsecureLoopback = rawOptions.allowInsecureLoopback === true;
  if (rawOptions.allowInsecureLoopback !== undefined && typeof rawOptions.allowInsecureLoopback !== "boolean") {
    throw new Error("allowInsecureLoopback must be a boolean.");
  }
  const loaded = readSdkProfile(rawOptions.sdkProfilePath, projectRoot);
  const profile = loaded.profile;
  const backendOrigin = normalizeBackendOrigin(rawOptions.backendOrigin, allowInsecureLoopback);
  if (backendOrigin !== profile.backend_origin) throw new Error("backendOrigin does not match sdkProfilePath.");
  const buildVariant = rawOptions.buildVariant;
  if (buildVariant !== "development" && buildVariant !== "preview") throw new Error("buildVariant must be development or preview.");
  if (buildVariant !== profile.build_identity.build_variant) throw new Error("buildVariant does not match sdkProfilePath.");
  const distribution = rawOptions.distribution;
  if (!["local", "internal", "testflight"].includes(distribution)) throw new Error("distribution must be local, internal, or testflight.");
  if (distribution !== profile.build_identity.distribution) throw new Error("distribution does not match sdkProfilePath.");
  if (allowInsecureLoopback && (buildVariant !== "development" || distribution !== "local")) {
    throw new Error("Insecure loopback is allowed only for a local development build.");
  }
  const launchScheme = requireNfcText(rawOptions.launchScheme, "launchScheme", 2, 64);
  if (!/^[a-z][a-z0-9+.-]{1,63}$/u.test(launchScheme)) throw new Error("launchScheme must be a normalized lowercase URL scheme.");
  if (reservedLaunchSchemes.has(launchScheme)) throw new Error("launchScheme must be a dedicated QA-app URL scheme, not a browser, OS-service, or Tacua reviewer scheme.");
  const microphonePermission = requireNfcText(rawOptions.microphonePermission ?? defaultMicrophonePermission, "microphonePermission", 24, 512);
  return Object.freeze({
    allowInsecureLoopback,
    backendOrigin,
    buildVariant,
    captureEnabled: true,
    distribution,
    launchScheme,
    microphonePermission,
    sdkProfile: profile,
    sdkProfileCanonicalJSON: loaded.canonicalJSON,
  });
}

function validateBundleIdentifier(bundleIdentifier, options) {
  if (typeof bundleIdentifier !== "string" || !bundleIdentifier) {
    throw new Error("expo.ios.bundleIdentifier is required for a Tacua QA build.");
  }
  if (bundleIdentifier !== options.sdkProfile.build_identity.bundle_identifier) {
    throw new Error("expo.ios.bundleIdentifier does not match the registered Tacua SDK profile.");
  }
}

function setExact(infoPlist, key, value) {
  if (Object.prototype.hasOwnProperty.call(infoPlist, key) && infoPlist[key] !== value) {
    throw new Error(`ios.infoPlist.${key} conflicts with the Tacua QA configuration.`);
  }
  infoPlist[key] = value;
}

function applyInfoPlist(rawInfoPlist, options) {
  if (!rawInfoPlist || typeof rawInfoPlist !== "object" || Array.isArray(rawInfoPlist)) {
    throw new Error("The generated iOS Info.plist must be an object.");
  }
  const infoPlist = rawInfoPlist;
  setExact(infoPlist, "TacuaCaptureEnabled", true);
  setExact(infoPlist, "TacuaBackendOrigin", options.backendOrigin);
  setExact(infoPlist, "TacuaAllowInsecureLoopback", options.allowInsecureLoopback);
  setExact(infoPlist, "TacuaLaunchScheme", options.launchScheme);
  setExact(infoPlist, "TacuaCaptureBuildVariant", options.buildVariant);
  setExact(infoPlist, "TacuaCaptureDistribution", options.distribution);
  setExact(infoPlist, "TacuaSDKProfileJSON", options.sdkProfileCanonicalJSON);
  setExact(infoPlist, "TacuaSDKProfileDigest", options.sdkProfile.profile_digest);
  setExact(infoPlist, "NSMicrophoneUsageDescription", options.microphonePermission);

  const urlTypes = infoPlist.CFBundleURLTypes ?? [];
  if (!Array.isArray(urlTypes) || urlTypes.some((item) => !item || typeof item !== "object" || Array.isArray(item))) {
    throw new Error("ios.infoPlist.CFBundleURLTypes is invalid.");
  }
  const alreadyRegistered = urlTypes.some((item) => Array.isArray(item.CFBundleURLSchemes) && item.CFBundleURLSchemes.includes(options.launchScheme));
  if (!alreadyRegistered) urlTypes.push({ CFBundleURLSchemes: [options.launchScheme] });
  infoPlist.CFBundleURLTypes = urlTypes;
  return infoPlist;
}

module.exports = {
  applyInfoPlist,
  canonicalJSON,
  defaultMicrophonePermission,
  digest,
  normalizeBackendOrigin,
  readSdkProfile,
  validateBundleIdentifier,
  validateOptions,
  validateSdkProfile,
};
