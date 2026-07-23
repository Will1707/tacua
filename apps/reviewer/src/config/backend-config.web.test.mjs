// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  clearBackendConfig,
  loadBackendConfig,
  saveBackendConfig,
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

test("web configuration is one atomic document scoped to session storage", async (context) => {
  const storage = createSessionStorage();
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    value: storage,
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { origin: "https://reviewer.example" },
  });
  context.after(() => {
    delete globalThis.sessionStorage;
    delete globalThis.location;
  });

  const config = {
    baseUrl: "https://reviewer.example",
    adminToken: "a".repeat(32),
    reviewerId: "reviewer_owner",
    targetScheme: "tacua-qa-app",
  };
  assert.equal(await loadBackendConfig(), null);
  await saveBackendConfig(config);
  assert.equal(storage.length, 1);
  assert.deepEqual(await loadBackendConfig(), config);
  await clearBackendConfig();
  assert.equal(storage.length, 0);
  assert.equal(await loadBackendConfig(), null);
});

test("web configuration rejects a cross-origin backend before storage", async (context) => {
  const storage = createSessionStorage();
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    value: storage,
  });
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: { origin: "https://reviewer.example" },
  });
  context.after(() => {
    delete globalThis.sessionStorage;
    delete globalThis.location;
  });

  await assert.rejects(
    saveBackendConfig({
      baseUrl: "https://api.example",
      adminToken: "a".repeat(32),
      reviewerId: "reviewer_owner",
      targetScheme: "tacua-qa-app",
    }),
    /must use its own HTTPS origin/u,
  );
  assert.equal(storage.length, 0);
});
