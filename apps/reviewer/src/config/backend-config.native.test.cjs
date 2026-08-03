// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");

const babel = require("@babel/core");
const transformModulesCommonJS = require("@babel/plugin-transform-modules-commonjs");
const transformTypeScript = require("@babel/plugin-transform-typescript");

const values = new Map();
const reads = [];
const secureStore = {
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: "when-unlocked-this-device-only",
  async deleteItemAsync(key) { values.delete(key); },
  async getItemAsync(key) {
    reads.push(key);
    return values.get(key) ?? null;
  },
  async setItemAsync(key, value, options) {
    assert.deepEqual(options, {
      keychainAccessible: "when-unlocked-this-device-only",
    });
    values.set(key, value);
  },
};

const originalLoad = Module._load;
const originalTypeScriptLoader = Module._extensions[".ts"];

function compileTypeScript(module, filename) {
  const result = babel.transformSync(fs.readFileSync(filename, "utf8"), {
    babelrc: false,
    configFile: false,
    filename,
    plugins: [
      [transformTypeScript, { allExtensions: true }],
      transformModulesCommonJS,
    ],
    sourceMaps: "inline",
  });
  module._compile(result.code, filename);
}

Module._extensions[".ts"] = compileTypeScript;
Module._load = function load(request, parent, isMain) {
  if (request === "expo-secure-store") return secureStore;
  return originalLoad.call(this, request, parent, isMain);
};

const {
  clearBackendConfig,
  loadBackendConfig,
  saveBackendConfig,
} = require(path.join(__dirname, "backend-config.ts"));

test("native V3 requires explicit reconfirmation and retires older stores", async () => {
  values.clear();
  reads.length = 0;
  const config = {
    baseUrl: "https://reviewer.example",
    adminToken: "a".repeat(32),
    reviewerId: "reviewer_owner",
    targetScheme: "legitimate-existing-scheme",
  };
  const currentKey = "tacua.backend.configuration.v3";
  const oldAtomicKey = "tacua.backend.configuration.v2";
  const oldSplitKeys = [
    "tacua.backend.base-url.v1",
    "tacua.backend.admin-token.v1",
    "tacua.reviewer.id.v1",
    "tacua.target.scheme.v1",
  ];
  values.set(oldAtomicKey, JSON.stringify({ storageVersion: 2, ...config }));
  for (const key of oldSplitKeys) values.set(key, "legacy-value");

  assert.equal(await loadBackendConfig(), null);
  assert.deepEqual(reads, [currentKey]);

  await saveBackendConfig(config);
  assert.equal(values.has(oldAtomicKey), false);
  assert.equal(oldSplitKeys.some((key) => values.has(key)), false);
  assert.deepEqual(JSON.parse(values.get(currentKey)), {
    storageVersion: 3,
    ...config,
  });
  assert.deepEqual(await loadBackendConfig(), config);

  await clearBackendConfig();
  assert.equal(values.size, 0);
});

test.after(() => {
  Module._load = originalLoad;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
});
