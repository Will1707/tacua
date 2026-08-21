// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  clearBackendConfig,
  loadBackendConfigState,
  saveBackendConfig,
  savePendingPairingCleanup,
} from "./backend-config.web.ts";

function createSessionStorage() {
  const values = new Map();
  return {
    get length() { return values.size; },
    clear() { values.clear(); },
    getItem(key) { return values.get(key) ?? null; },
    key(index) { return [...values.keys()][index] ?? null; },
    removeItem(key) { values.delete(key); },
    setItem(key, value) { values.set(key, String(value)); },
  };
}

function installBrowser(context, origin = "https://reviewer.example") {
  const storage = createSessionStorage();
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: storage });
  Object.defineProperty(globalThis, "location", { configurable: true, value: { origin } });
  context.after(() => {
    delete globalThis.sessionStorage;
    delete globalThis.location;
  });
  return storage;
}

test("web derives its backend from the exact origin and stores no configuration", async (context) => {
  const storage = installBrowser(context);
  storage.setItem("unrelated", "kept");
  storage.setItem("tacua.backend.configuration.v5", "native-pairing-secret");
  storage.setItem("tacua.backend.configuration.web-session.v2", "legacy-admin-secret");
  storage.setItem("tacua.backend.admin-token.v1", "legacy-admin-secret");

  const expected = { baseUrl: "https://reviewer.example", sessionToken: null };
  assert.deepEqual(await loadBackendConfigState(), {
    config: expected,
    pendingPairingCleanup: null,
  });
  assert.equal(storage.getItem("unrelated"), "kept");
  assert.equal(storage.getItem("tacua.backend.configuration.web-session.v2"), null);
  assert.equal(storage.getItem("tacua.backend.admin-token.v1"), null);
  assert.equal(storage.getItem("tacua.backend.configuration.v5"), null);

  await saveBackendConfig(expected);
  assert.equal(storage.length, 1);
  await clearBackendConfig();
  assert.equal(storage.length, 1);
});

test("web rejects cross-origin endpoints and bearer persistence", async (context) => {
  const storage = installBrowser(context);
  await assert.rejects(
    saveBackendConfig({ baseUrl: "https://api.example", sessionToken: null }),
    /must use its own HTTPS origin/u,
  );
  await assert.rejects(
    savePendingPairingCleanup(
      { baseUrl: "https://reviewer.example", sessionToken: null },
      {
        pairingToken: `rpair_${"a".repeat(32)}.${"B".repeat(43)}`,
        clientKind: "native",
      },
    ),
    /cannot persist a pairing secret/u,
  );
  await assert.rejects(
    saveBackendConfig({
      baseUrl: "https://reviewer.example",
      sessionToken: `rsess_${"a".repeat(32)}.${"B".repeat(43)}`,
    }),
    /cannot store a bearer credential/u,
  );
  assert.equal(storage.length, 0);
});

test("web capability setup ignores denied session-storage access", async (context) => {
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    get() { throw new DOMException("Storage is disabled.", "SecurityError"); },
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { origin: "https://reviewer.example" },
  });
  context.after(() => {
    delete globalThis.sessionStorage;
    delete globalThis.location;
  });

  const expected = { baseUrl: "https://reviewer.example", sessionToken: null };
  assert.deepEqual(await loadBackendConfigState(), {
    config: expected,
    pendingPairingCleanup: null,
  });
  await saveBackendConfig(expected);
  await clearBackendConfig();
});

test("web capability setup ignores denied obsolete-key removal", async (context) => {
  const storage = installBrowser(context);
  let removalAttempts = 0;
  storage.removeItem = () => {
    removalAttempts += 1;
    throw new DOMException("Storage mutation is disabled.", "SecurityError");
  };

  const expected = { baseUrl: "https://reviewer.example", sessionToken: null };
  assert.deepEqual(await loadBackendConfigState(), {
    config: expected,
    pendingPairingCleanup: null,
  });
  await saveBackendConfig(expected);
  await clearBackendConfig();
  assert.ok(removalAttempts > 0);
});

test("web fails closed without a valid browser origin", async (context) => {
  installBrowser(context, "not-an-origin");
  await assert.rejects(loadBackendConfigState(), /valid URL|HTTPS/u);
});
