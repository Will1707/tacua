// SPDX-License-Identifier: Apache-2.0

const path = require("node:path");
const { getDefaultConfig } = require("expo/metro-config");

const projectRoot = __dirname;
const sdkRoot = path.resolve(projectRoot, "../package");
const hostModules = path.resolve(projectRoot, "node_modules");
const config = getDefaultConfig(projectRoot);

// The harness installs the SDK through a local file link. Resolve the linked
// package's React/React Native peers from the host exactly as a published npm
// installation would, while still watching SDK source changes during QA runs.
config.watchFolders = [...(config.watchFolders ?? []), sdkRoot];
config.resolver.nodeModulesPaths = [
  hostModules,
  ...(config.resolver.nodeModulesPaths ?? []),
];

module.exports = config;
