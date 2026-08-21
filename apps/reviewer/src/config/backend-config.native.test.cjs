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

const sessionToken = `rsess_${"a".repeat(32)}.${"B".repeat(43)}`;

test("native V4 stores only the endpoint and scoped reviewer bearer", async () => {
  values.clear();
  reads.length = 0;
  const config = {
    baseUrl: "https://reviewer.example",
    sessionToken,
  };
  const currentKey = "tacua.backend.configuration.v4";
  const retiredKeys = [
    "tacua.backend.configuration.v3",
    "tacua.backend.configuration.v2",
    "tacua.backend.base-url.v1",
    "tacua.backend.admin-token.v1",
    "tacua.reviewer.id.v1",
    "tacua.target.scheme.v1",
  ];
  for (const key of retiredKeys) values.set(key, "legacy-secret");

  assert.equal(await loadBackendConfig(), null);
  assert.deepEqual(reads, [currentKey]);
  assert.equal(retiredKeys.some((key) => values.has(key)), false);

  await saveBackendConfig(config);
  assert.equal(retiredKeys.some((key) => values.has(key)), false);
  assert.deepEqual(JSON.parse(values.get(currentKey)), {
    storageVersion: 4,
    baseUrl: "https://reviewer.example",
    sessionToken,
  });
  assert.deepEqual(await loadBackendConfig(), config);

  await saveBackendConfig({ baseUrl: config.baseUrl, sessionToken: null });
  assert.deepEqual(await loadBackendConfig(), {
    baseUrl: "https://reviewer.example",
    sessionToken: null,
  });
  await clearBackendConfig();
  assert.equal(values.size, 0);
});

test("native rejects an administrator token or malformed scoped bearer", async () => {
  await assert.rejects(
    saveBackendConfig({
      baseUrl: "https://reviewer.example",
      sessionToken: "administrator-secret",
    }),
    /Reviewer session credential is invalid/u,
  );
  await assert.rejects(
    saveBackendConfig({
      baseUrl: "https://reviewer.example",
      sessionToken: null,
      adminToken: "a".repeat(32),
    }),
    /Backend configuration is invalid/u,
  );
});

test("native removes an invalid current document instead of retaining a secret", async () => {
  const currentKey = "tacua.backend.configuration.v4";
  values.clear();
  values.set(currentKey, JSON.stringify({
    storageVersion: 4,
    baseUrl: "https://reviewer.example",
    sessionToken: "legacy-administrator-secret",
  }));
  assert.equal(await loadBackendConfig(), null);
  assert.equal(values.has(currentKey), false);
});

test.after(() => {
  Module._load = originalLoad;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
});
