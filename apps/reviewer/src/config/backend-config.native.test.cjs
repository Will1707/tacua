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
const deletes = [];
const readFailures = new Map();
const writeFailures = new Map();
const deleteFailures = new Map();
const secureStore = {
  WHEN_UNLOCKED_THIS_DEVICE_ONLY: "when-unlocked-this-device-only",
  async deleteItemAsync(key) {
    deletes.push(key);
    const failure = deleteFailures.get(key);
    if (failure) throw failure;
    values.delete(key);
  },
  async getItemAsync(key) {
    reads.push(key);
    const failure = readFailures.get(key);
    if (failure) throw failure;
    return values.get(key) ?? null;
  },
  async setItemAsync(key, value, options) {
    assert.deepEqual(options, {
      keychainAccessible: "when-unlocked-this-device-only",
    });
    const failure = writeFailures.get(key);
    if (failure) throw failure;
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
  loadBackendConfigState,
  saveBackendConfig,
  savePendingPairingCleanup,
} = require(path.join(__dirname, "backend-config.ts"));

const currentKey = "tacua.backend.configuration.v5";
const legacyV4Key = "tacua.backend.configuration.v4";
const sessionToken = `rsess_${"a".repeat(32)}.${"B".repeat(43)}`;
const pairingToken = `rpair_${"a".repeat(32)}.${"C".repeat(43)}`;

function resetStore() {
  values.clear();
  reads.length = 0;
  deletes.length = 0;
  readFailures.clear();
  writeFailures.clear();
  deleteFailures.clear();
}

test("native V5 stores an exact authentication union and no administrator secret", async () => {
  resetStore();
  const config = {
    baseUrl: "https://reviewer.example",
    sessionToken,
  };
  const retiredKeys = [
    "tacua.backend.configuration.v3",
    "tacua.backend.configuration.v2",
    "tacua.backend.base-url.v1",
    "tacua.backend.admin-token.v1",
    "tacua.reviewer.id.v1",
    "tacua.target.scheme.v1",
  ];
  for (const key of retiredKeys) values.set(key, "legacy-secret");

  assert.equal(await loadBackendConfigState(), null);
  assert.deepEqual(reads, [currentKey, legacyV4Key]);
  assert.equal(retiredKeys.some((key) => values.has(key)), false);

  await saveBackendConfig(config);
  assert.deepEqual(JSON.parse(values.get(currentKey)), {
    storageVersion: 5,
    baseUrl: "https://reviewer.example",
    authentication: { kind: "session", sessionToken },
  });
  assert.deepEqual(await loadBackendConfigState(), {
    config,
    pendingPairingCleanup: null,
  });

  await saveBackendConfig({ baseUrl: config.baseUrl, sessionToken: null });
  assert.deepEqual(JSON.parse(values.get(currentKey)), {
    storageVersion: 5,
    baseUrl: "https://reviewer.example",
    authentication: { kind: "unauthenticated" },
  });
  await clearBackendConfig();
  assert.equal(values.size, 0);
});

test("native V5 durably journals exact pairing cleanup before atomically replacing it", async () => {
  resetStore();
  const config = { baseUrl: "https://reviewer.example", sessionToken: null };
  const cleanup = { pairingToken, clientKind: "native" };

  await savePendingPairingCleanup(config, cleanup);
  assert.deepEqual(JSON.parse(values.get(currentKey)), {
    storageVersion: 5,
    baseUrl: "https://reviewer.example",
    authentication: {
      kind: "pending_pairing_cleanup",
      pairingToken,
      clientKind: "native",
    },
  });

  // A fresh module/process reads the exact token and kind needed to cancel an
  // exchange that may already have committed on the backend.
  assert.deepEqual(await loadBackendConfigState(), {
    config,
    pendingPairingCleanup: cleanup,
  });

  await saveBackendConfig({ ...config, sessionToken });
  assert.deepEqual(JSON.parse(values.get(currentKey)), {
    storageVersion: 5,
    baseUrl: "https://reviewer.example",
    authentication: { kind: "session", sessionToken },
  });
  assert.deepEqual(await loadBackendConfigState(), {
    config: { ...config, sessionToken },
    pendingPairingCleanup: null,
  });
});

test("native V5 rejects invalid cleanup state without replacing the committed document", async () => {
  resetStore();
  const committed = { baseUrl: "https://reviewer.example", sessionToken };
  await saveBackendConfig(committed);
  const before = values.get(currentKey);

  await assert.rejects(
    savePendingPairingCleanup(committed, { pairingToken, clientKind: "native" }),
    /cannot be stored together/u,
  );
  await assert.rejects(
    savePendingPairingCleanup(
      { baseUrl: committed.baseUrl, sessionToken: null },
      { pairingToken: "not-a-token", clientKind: "native" },
    ),
    /INVALID_PAIRING_CANCELLATION/u,
  );
  assert.equal(values.get(currentKey), before);
});

test("native migrates only the strict legacy V4 endpoint and bearer document", async () => {
  resetStore();
  values.set(legacyV4Key, JSON.stringify({
    storageVersion: 4,
    baseUrl: "https://legacy-reviewer.example",
    sessionToken,
  }));

  assert.deepEqual(await loadBackendConfigState(), {
    config: { baseUrl: "https://legacy-reviewer.example", sessionToken },
    pendingPairingCleanup: null,
  });
  assert.deepEqual(reads, [currentKey, legacyV4Key]);
  assert.equal(values.has(legacyV4Key), false);
  assert.deepEqual(JSON.parse(values.get(currentKey)), {
    storageVersion: 5,
    baseUrl: "https://legacy-reviewer.example",
    authentication: { kind: "session", sessionToken },
  });
});

test("native retains V4 when its authoritative V5 migration write fails", async () => {
  resetStore();
  const migrationFailure = new Error("simulated V5 migration failure");
  const legacy = JSON.stringify({
    storageVersion: 4,
    baseUrl: "https://legacy-reviewer.example",
    sessionToken: null,
  });
  values.set(legacyV4Key, legacy);
  writeFailures.set(currentKey, migrationFailure);

  await assert.rejects(loadBackendConfigState(), migrationFailure);
  assert.equal(values.get(legacyV4Key), legacy);
  assert.equal(values.has(currentKey), false);
});

test("native clear cannot resurrect a retained V4 session after cleanup failure", async () => {
  resetStore();
  const retainedV4DeletionFailure = new Error("simulated retained V4 deletion failure");
  const legacy = JSON.stringify({
    storageVersion: 4,
    baseUrl: "https://legacy-reviewer.example",
    sessionToken,
  });
  values.set(legacyV4Key, legacy);
  deleteFailures.set(legacyV4Key, retainedV4DeletionFailure);

  // Migration commits V5 first, so a failed best-effort V4 cleanup cannot
  // prevent V5 from becoming the sole active authority.
  assert.deepEqual(await loadBackendConfigState(), {
    config: { baseUrl: "https://legacy-reviewer.example", sessionToken },
    pendingPairingCleanup: null,
  });
  assert.equal(values.get(legacyV4Key), legacy);
  await saveBackendConfig({
    baseUrl: "https://legacy-reviewer.example",
    sessionToken: null,
  });
  assert.equal(values.get(legacyV4Key), legacy);

  deletes.length = 0;
  await assert.rejects(clearBackendConfig(), retainedV4DeletionFailure);
  assert.deepEqual(deletes, [legacyV4Key], "V5 must not be deleted after fallback deletion fails");
  assert.equal(values.has(currentKey), true);
  assert.deepEqual(await loadBackendConfigState(), {
    config: {
      baseUrl: "https://legacy-reviewer.example",
      sessionToken: null,
    },
    pendingPairingCleanup: null,
  });

  deleteFailures.delete(legacyV4Key);
  await clearBackendConfig();
  assert.equal(values.has(legacyV4Key), false);
  assert.equal(values.has(currentKey), false);
  assert.equal(await loadBackendConfigState(), null);
});

test("native V5 succeeds when retired-key cleanup fails and reloads its authority", async () => {
  resetStore();
  const retiredKey = "tacua.backend.admin-token.v1";
  const config = {
    baseUrl: "https://replacement-reviewer.example",
    sessionToken,
  };
  values.set(retiredKey, "legacy-administrator-secret");
  deleteFailures.set(retiredKey, new Error("simulated legacy cleanup failure"));

  await saveBackendConfig(config);
  assert.equal(values.get(retiredKey), "legacy-administrator-secret");
  assert.deepEqual(await loadBackendConfigState(), {
    config,
    pendingPairingCleanup: null,
  });
});

test("native fails closed and retains malformed current V5 state", async () => {
  resetStore();
  const malformedDocuments = [
    {
      storageVersion: 5,
      baseUrl: "https://reviewer.example",
      authentication: {
        kind: "pending_pairing_cleanup",
        pairingToken,
        clientKind: "web",
      },
    },
    {
      storageVersion: 5,
      baseUrl: "https://reviewer.example",
      authentication: {
        kind: "pending_pairing_cleanup",
        pairingToken,
        clientKind: "native",
        debug: true,
      },
    },
    {
      storageVersion: 5,
      baseUrl: "https://reviewer.example",
      authentication: { kind: "session", sessionToken: "administrator-secret" },
    },
  ];

  for (const malformed of malformedDocuments) {
    const encoded = JSON.stringify(malformed);
    values.set(currentKey, encoded);
    await assert.rejects(loadBackendConfigState(), /invalid|credential/u);
    assert.equal(values.get(currentKey), encoded);
  }
});

test("native propagates authoritative V5 read, write, and delete failures", async () => {
  resetStore();
  const readFailure = new Error("simulated current V5 read failure");
  readFailures.set(currentKey, readFailure);
  await assert.rejects(loadBackendConfigState(), readFailure);

  resetStore();
  const writeFailure = new Error("simulated current V5 write failure");
  writeFailures.set(currentKey, writeFailure);
  await assert.rejects(
    saveBackendConfig({ baseUrl: "https://reviewer.example", sessionToken: null }),
    writeFailure,
  );

  resetStore();
  const deleteFailure = new Error("simulated current V5 deletion failure");
  values.set(currentKey, JSON.stringify({
    storageVersion: 5,
    baseUrl: "https://reviewer.example",
    authentication: { kind: "unauthenticated" },
  }));
  deleteFailures.set(currentKey, deleteFailure);
  await assert.rejects(clearBackendConfig(), deleteFailure);
  assert.equal(values.has(currentKey), true);
});

test("native rejects an administrator token or malformed scoped bearer", async () => {
  resetStore();
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

test.after(() => {
  Module._load = originalLoad;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
});
