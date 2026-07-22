// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  verifyAndPersistBackendConfig,
  verifyBackendConfig,
} from "./backend-config-verification.ts";

function candidate(overrides = {}) {
  return {
    baseUrl: " HTTPS://Tacua.Example:443/ ",
    adminToken: "a".repeat(32),
    reviewerId: " reviewer_owner ",
    targetScheme: " tacua-qa-app ",
    ...overrides,
  };
}

test("normalizes locally, probes the public protocol, then authenticates a bounded admin read", async () => {
  const calls = [];
  let clientConfig;
  const verified = await verifyBackendConfig(candidate(), {
    async probeBackend(baseUrl) {
      calls.push(`probe:${baseUrl}`);
    },
    createClient(config) {
      clientConfig = config;
      calls.push("client");
      return {
        async listBuilds() {
          calls.push("authenticated-read");
          return [];
        },
      };
    },
  });

  assert.deepEqual(verified, {
    baseUrl: "https://tacua.example",
    adminToken: "a".repeat(32),
    reviewerId: "reviewer_owner",
    targetScheme: "tacua-qa-app",
  });
  assert.deepEqual(clientConfig, verified);
  assert.deepEqual(calls, [
    "probe:https://tacua.example",
    "client",
    "authenticated-read",
  ]);
});

test("never creates an authenticated client or persists when local or public validation fails", async () => {
  for (const input of [
    candidate({ adminToken: "short" }),
    candidate(),
  ]) {
    let created = 0;
    let persisted = 0;
    const publicFailure = input.adminToken.length === 32;
    await assert.rejects(() => verifyAndPersistBackendConfig(input, {
      async probeBackend() {
        if (publicFailure) throw new Error("incompatible protocol");
      },
      createClient() {
        created += 1;
        return { async listBuilds() { return []; } };
      },
      async persistConfig() {
        persisted += 1;
      },
    }));
    assert.equal(created, 0);
    assert.equal(persisted, 0);
  }
});

test("rejects administrator tokens outside the bounded ASCII token68 grammar locally", async () => {
  for (const adminToken of [
    "é".repeat(32),
    `${"a".repeat(31)}\u0000`,
    `${"a".repeat(31)} `,
    `${"a".repeat(32)}=a`,
    `${"a".repeat(32)}===`,
  ]) {
    let probes = 0;
    let clients = 0;
    await assert.rejects(() => verifyBackendConfig(candidate({ adminToken }), {
      async probeBackend() { probes += 1; },
      createClient() {
        clients += 1;
        return { async listBuilds() { return []; } };
      },
    }), /Administrator token is invalid/);
    assert.equal(probes, 0);
    assert.equal(clients, 0);
  }

  const valid = `${"A0._~+/-".repeat(4)}==`;
  await verifyBackendConfig(candidate({ adminToken: valid }), {
    async probeBackend() {},
    createClient() { return { async listBuilds() { return []; } }; },
  });
});

test("rejects system, network, and reviewer-owned launch schemes before any request", async () => {
  for (const targetScheme of ["http", "https", "file", "mailto", "tacua", "wss"]) {
    let probes = 0;
    let clients = 0;
    await assert.rejects(() => verifyBackendConfig(candidate({ targetScheme }), {
      async probeBackend() { probes += 1; },
      createClient() {
        clients += 1;
        return { async listBuilds() { return []; } };
      },
    }), /custom scheme owned by the SDK-enabled QA app/);
    assert.equal(probes, 0);
    assert.equal(clients, 0);
  }
});

test("does not persist a typoed, expired, or insufficiently scoped administrator token", async () => {
  for (const failure of ["unauthorized", "expired", "scope denied"]) {
    let persisted = 0;
    await assert.rejects(() => verifyAndPersistBackendConfig(candidate(), {
      async probeBackend() {},
      createClient() {
        return {
          async listBuilds() {
            throw new Error(failure);
          },
        };
      },
      async persistConfig() {
        persisted += 1;
      },
    }), { message: failure });
    assert.equal(persisted, 0);
  }
});

test("persists exactly once and only after both public and authenticated checks succeed", async () => {
  const calls = [];
  let persisted;
  const verified = await verifyAndPersistBackendConfig(candidate(), {
    async probeBackend() {
      calls.push("probe");
    },
    createClient() {
      return {
        async listBuilds() {
          calls.push("authenticated-read");
        },
      };
    },
    async persistConfig(config) {
      calls.push("persist");
      persisted = config;
    },
  });

  assert.deepEqual(calls, ["probe", "authenticated-read", "persist"]);
  assert.deepEqual(persisted, verified);
});
