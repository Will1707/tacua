// SPDX-License-Identifier: Apache-2.0

"use strict";

function loadHostConfigPlugins() {
  let resolved;
  try {
    resolved = require.resolve("expo/config-plugins", { paths: [process.cwd()] });
  } catch {
    throw new Error("Tacua requires the host Expo project's config-plugin runtime.");
  }
  return require(resolved);
}

const { createRunOncePlugin, withInfoPlist } = loadHostConfigPlugins();

const { applyInfoPlist, validateBundleIdentifier, validateOptions } = require("./config");
const packageMetadata = require("../package.json");

function withTacua(config, rawOptions) {
  const projectRoot = typeof config._internal?.projectRoot === "string"
    ? config._internal.projectRoot
    : process.cwd();
  const options = validateOptions(rawOptions, projectRoot);
  validateBundleIdentifier(config.ios?.bundleIdentifier, options);
  return withInfoPlist(config, (mod) => {
    mod.modResults = applyInfoPlist(mod.modResults, options);
    return mod;
  });
}

module.exports = createRunOncePlugin(
  withTacua,
  packageMetadata.name,
  packageMetadata.version,
);
