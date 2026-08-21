// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  loadVerifiedBackendConfig,
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

function bootstrap(overrides = {}) {
  return {
    contract_version: "tacua.reviewer-bootstrap@1.0.0",
    reviewer_id: "reviewer_owner",
    builds: [{
      build_id: "build_kuzaba_qa",
      application_id: "application_kuzaba_qa",
      bundle_identifier: "com.kuzaba.app",
      native_version: "0.1.0",
      native_build: "4",
      distribution: "internal",
      build_identity_digest: `sha256:${"a".repeat(64)}`,
      launch_scheme: "tacua-qa-app",
    }],
    ...overrides,
  };
}

function authenticatedClient({
  onBootstrap = () => {},
  onIdentityBinding = () => {},
} = {}) {
  return {
    async getReviewerBootstrap() {
      onBootstrap();
      return bootstrap();
    },
    async verifyReviewerIdentity() {
      onIdentityBinding();
    },
    async listBuilds() {
      throw new Error("legacy build fallback was unexpected");
    },
  };
}

test("normalizes locally, reads the authoritative bootstrap, then verifies its reviewer binding", async () => {
  const calls = [];
  const clientConfigs = [];
  const verified = await verifyBackendConfig(candidate(), {
    async probeBackend(baseUrl) {
      calls.push(`probe:${baseUrl}`);
    },
    createClient(config) {
      clientConfigs.push(config);
      calls.push("client");
      return authenticatedClient({
        onBootstrap: () => calls.push("authenticated-read"),
        onIdentityBinding: () => calls.push("identity-binding"),
      });
    },
  });

  assert.deepEqual(verified, {
    baseUrl: "https://tacua.example",
    adminToken: "a".repeat(32),
    reviewerId: "reviewer_owner",
    targetScheme: "tacua-qa-app",
  });
  assert.deepEqual(clientConfigs, [verified, verified]);
  assert.deepEqual(calls, [
    "probe:https://tacua.example",
    "client",
    "authenticated-read",
    "client",
    "identity-binding",
  ]);
});

test("derives reviewer identity and launch scheme from the authoritative bootstrap", async () => {
  const clientReviewerIds = [];
  const identityBindings = [];
  const verified = await verifyBackendConfig(candidate({
    reviewerId: "reviewer_typo",
    targetScheme: "wrong-but-safe-qa",
  }), {
    async probeBackend() {},
    createClient(config) {
      clientReviewerIds.push(config.reviewerId);
      return authenticatedClient({
        onIdentityBinding: () => identityBindings.push(config.reviewerId),
      });
    },
  });

  assert.equal(verified.reviewerId, "reviewer_owner");
  assert.equal(verified.targetScheme, "tacua-qa-app");
  assert.deepEqual(clientReviewerIds, ["reviewer_typo", "reviewer_owner"]);
  assert.deepEqual(identityBindings, ["reviewer_owner"]);
});

test("uses the manual transport 1.1 fields only when the additive endpoint is absent", async () => {
  const calls = [];
  const verified = await verifyBackendConfig(candidate(), {
    async probeBackend() {},
    createClient() {
      return {
        async getReviewerBootstrap() {
          calls.push("bootstrap");
          throw { status: 404 };
        },
        async verifyReviewerIdentity() {
          calls.push("identity-binding");
        },
        async listBuilds() {
          calls.push("legacy-builds");
          return [];
        },
      };
    },
  });

  assert.deepEqual(calls, ["bootstrap", "identity-binding", "legacy-builds"]);
  assert.equal(verified.reviewerId, "reviewer_owner");
  assert.equal(verified.targetScheme, "tacua-qa-app");
});

test("keeps the normalized manual scheme for a bootstrapped transport 1.1 build", async () => {
  const verified = await verifyBackendConfig(candidate({
    reviewerId: "reviewer_typo",
    targetScheme: "manual-legacy-qa",
  }), {
    async probeBackend() {},
    createClient() {
      return {
        async getReviewerBootstrap() {
          const document = bootstrap();
          document.builds[0].launch_scheme = null;
          return document;
        },
        async verifyReviewerIdentity() {},
        async listBuilds() { throw new Error("unexpected legacy fallback"); },
      };
    },
  });

  assert.equal(verified.reviewerId, "reviewer_owner");
  assert.equal(verified.targetScheme, "manual-legacy-qa");
});

test("rejects an ambiguous reviewer bootstrap before persistence", async () => {
  const oneBuild = bootstrap().builds[0];
  for (const builds of [[], [oneBuild, { ...oneBuild, build_id: "build_second" }]]) {
    let persisted = 0;
    await assert.rejects(() => verifyAndPersistBackendConfig(candidate(), {
      async probeBackend() {},
      createClient() {
        return {
          async getReviewerBootstrap() { return bootstrap({ builds }); },
          async verifyReviewerIdentity() { assert.fail("identity binding followed an ambiguous bootstrap"); },
          async listBuilds() { throw new Error("unexpected legacy fallback"); },
        };
      },
      async persistConfig() { persisted += 1; },
    }), /exactly one reviewer build/);
    assert.equal(persisted, 0);
  }
});

test("does not persist when the bootstrap-derived reviewer binding fails", async () => {
  let clients = 0;
  let persisted = 0;
  await assert.rejects(() => verifyAndPersistBackendConfig(candidate({
    reviewerId: "reviewer_typo",
  }), {
    async probeBackend() {},
    createClient() {
      clients += 1;
      if (clients === 1) return authenticatedClient();
      return authenticatedClient({
        onIdentityBinding: () => { throw new Error("authoritative identity rejected"); },
      });
    },
    async persistConfig() { persisted += 1; },
  }), /authoritative identity rejected/);
  assert.equal(clients, 2);
  assert.equal(persisted, 0);
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
        return authenticatedClient();
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
        return authenticatedClient();
      },
    }), /Administrator token is invalid/);
    assert.equal(probes, 0);
    assert.equal(clients, 0);
  }

  const valid = `${"A0._~+/-".repeat(4)}==`;
  await verifyBackendConfig(candidate({ adminToken: valid }), {
    async probeBackend() {},
    createClient() { return authenticatedClient(); },
  });
});

test("authoritative bootstrap replaces blank or unsafe manual identity and scheme fields", async () => {
  for (const targetScheme of ["", "http", "https", "file", "mailto", "tacua", "wss"]) {
    const verified = await verifyBackendConfig(candidate({
      reviewerId: "",
      targetScheme,
    }), {
      async probeBackend() {},
      createClient() { return authenticatedClient(); },
    });
    assert.equal(verified.reviewerId, "reviewer_owner");
    assert.equal(verified.targetScheme, "tacua-qa-app");
  }
});

test("legacy fallback validates manual identity and scheme only after bootstrap 404", async () => {
  for (const [overrides, pattern] of [
    [{ reviewerId: "" }, /Reviewer ID must be a Tacua identifier/u],
    [{ targetScheme: "https" }, /custom scheme owned by the SDK-enabled QA app/u],
  ]) {
    let probes = 0;
    let clients = 0;
    let persisted = 0;
    await assert.rejects(() => verifyAndPersistBackendConfig(candidate(overrides), {
      async probeBackend() { probes += 1; },
      createClient() {
        clients += 1;
        return {
          async getReviewerBootstrap() { throw { status: 404 }; },
          async verifyReviewerIdentity() { assert.fail("invalid legacy fields reached identity binding"); },
          async listBuilds() { assert.fail("invalid legacy fields reached the registry"); },
        };
      },
      async persistConfig() { persisted += 1; },
    }), pattern);
    assert.deepEqual({ probes, clients, persisted }, { probes: 1, clients: 1, persisted: 0 });
  }
});

test("does not persist a typoed, expired, or insufficiently scoped administrator token", async () => {
  for (const failure of ["unauthorized", "expired", "scope denied"]) {
    let persisted = 0;
    await assert.rejects(() => verifyAndPersistBackendConfig(candidate(), {
      async probeBackend() {},
      createClient() {
        return {
          async getReviewerBootstrap() {
            throw new Error(failure);
          },
          async verifyReviewerIdentity() { assert.fail("identity binding followed a failed bootstrap read"); },
          async listBuilds() { throw new Error("unexpected legacy fallback"); },
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
      return authenticatedClient({
        onBootstrap: () => calls.push("authenticated-read"),
        onIdentityBinding: () => calls.push("identity-binding"),
      });
    },
    async persistConfig(config) {
      calls.push("persist");
      persisted = config;
    },
  });

  assert.deepEqual(calls, ["probe", "authenticated-read", "identity-binding", "persist"]);
  assert.deepEqual(persisted, verified);
});

test("legacy fallback rejects an incorrect reviewer ID before persistence without echoing identities or secrets", async () => {
  const suppliedId = "reviewer_incorrect";
  const configuredId = "reviewer_configured";
  const adminToken = "PrivateAdminToken-1234567890-abcdef";
  let persisted = 0;
  let builds = 0;

  let caught;
  await assert.rejects(() => verifyAndPersistBackendConfig(
    candidate({ adminToken, reviewerId: suppliedId }),
    {
      async probeBackend() {},
      createClient() {
        return {
          async getReviewerBootstrap() {
            throw { status: 404 };
          },
          async verifyReviewerIdentity() {
            throw new Error("The reviewer identity does not match this deployment.");
          },
          async listBuilds() { builds += 1; },
        };
      },
      async persistConfig() { persisted += 1; },
    },
  ), (error) => {
    caught = error;
    return true;
  });

  assert.equal(persisted, 0);
  assert.equal(builds, 0);
  assert.ok(caught instanceof Error);
  assert.doesNotMatch(caught.message, new RegExp(`${suppliedId}|${configuredId}|${adminToken}`, "u"));
});

test("provider activation re-bootstraps saved metadata before exposing a client", async () => {
  const calls = [];
  const loaded = candidate({
    baseUrl: "https://tacua.example",
    reviewerId: "reviewer_previous",
    targetScheme: "stale-qa-app",
  });
  const clients = [];
  const active = await loadVerifiedBackendConfig({
    async loadConfig() {
      calls.push("load");
      return loaded;
    },
    createClient(config) {
      calls.push(`client:${config.reviewerId}`);
      const client = {
        async getReviewerBootstrap() {
          calls.push("bootstrap");
          return bootstrap();
        },
        async verifyReviewerIdentity() { calls.push("identity-binding"); },
        async listBuilds() { throw new Error("unexpected legacy fallback"); },
      };
      clients.push(client);
      return client;
    },
  });

  assert.deepEqual(calls, [
    "load",
    "client:reviewer_previous",
    "bootstrap",
    "client:reviewer_owner",
    "identity-binding",
  ]);
  assert.equal(active.client, clients[1]);
  assert.equal(active.config.reviewerId, "reviewer_owner");
  assert.equal(active.config.targetScheme, "tacua-qa-app");
});

test("provider activation keeps missing and identity-rejected settings unexposed", async () => {
  let clients = 0;
  assert.equal(await loadVerifiedBackendConfig({
    async loadConfig() { return null; },
    createClient() {
      clients += 1;
      return {
        async getReviewerBootstrap() { return bootstrap(); },
        async verifyReviewerIdentity() {},
        async listBuilds() { return []; },
      };
    },
  }), null);
  assert.equal(clients, 0);

  const staleId = "reviewer_previous";
  const configuredId = "reviewer_owner";
  const adminToken = "StalePrivateToken-1234567890-abcdef";
  let clientCount = 0;
  let caught;
  await assert.rejects(() => loadVerifiedBackendConfig({
    async loadConfig() {
      return candidate({
        baseUrl: "https://tacua.example",
        adminToken,
        reviewerId: staleId,
        targetScheme: "tacua-qa-app",
      });
    },
    createClient() {
      clientCount += 1;
      return {
        async getReviewerBootstrap() { return bootstrap(); },
        async verifyReviewerIdentity() {
          if (clientCount === 2) {
            throw new Error("The reviewer identity does not match this deployment.");
          }
        },
        async listBuilds() { throw new Error("unexpected legacy fallback"); },
      };
    },
  }), (error) => {
    caught = error;
    return true;
  });
  assert.ok(caught instanceof Error);
  assert.doesNotMatch(caught.message, new RegExp(`${staleId}|${configuredId}|${adminToken}`, "u"));
});
