// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");

const babel = require("@babel/core");
const transformModulesCommonJS = require("@babel/plugin-transform-modules-commonjs");
const transformReactJSX = require("@babel/plugin-transform-react-jsx");
const transformTypeScript = require("@babel/plugin-transform-typescript");
const React = require("react");
const TestRenderer = require("react-test-renderer");

global.IS_REACT_ACT_ENVIRONMENT = true;

const reviewerSourceRoot = path.resolve(__dirname, "..");
const originalLoad = Module._load;
const originalResolveFilename = Module._resolveFilename;
const originalTypeScriptLoader = Module._extensions[".ts"];
const originalTSXLoader = Module._extensions[".tsx"];

let storedConfig;
let api;
const mockPlatform = { OS: "web" };
const constructedConfigs = [];
const savedConfigs = [];

class TacuaApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

class TacuaApiClient {
  constructor(config) {
    this.config = config;
    constructedConfigs.push(config);
  }

  getReviewerSession() { return api.getReviewerSession(this.config); }
  getReviewerBootstrap() { return api.getReviewerBootstrap(this.config); }
  createPairingRequest(label) { return api.createPairingRequest(this.config, label); }
  exchangePairing(token) { return api.exchangePairing(this.config, token); }
  revokeReviewerSession() { return api.revokeReviewerSession(this.config); }
}

function compileTypeScript(module, filename) {
  const result = babel.transformSync(fs.readFileSync(filename, "utf8"), {
    babelrc: false,
    configFile: false,
    filename,
    plugins: [
      [transformTypeScript, { isTSX: filename.endsWith(".tsx"), allExtensions: true }],
      [transformReactJSX, { runtime: "automatic" }],
      transformModulesCommonJS,
    ],
    sourceMaps: "inline",
  });
  module._compile(result.code, filename);
}

Module._extensions[".ts"] = compileTypeScript;
Module._extensions[".tsx"] = compileTypeScript;
Module._resolveFilename = function resolveFilename(request, parent, isMain, options) {
  const resolvedRequest = request.startsWith("@/")
    ? path.join(reviewerSourceRoot, request.slice(2))
    : request;
  return originalResolveFilename.call(this, resolvedRequest, parent, isMain, options);
};
Module._load = function load(request, parent, isMain) {
  if (request === "react-native") return { Platform: mockPlatform };
  if (request === "@/api/client") return { TacuaApiClient, TacuaApiError };
  if (request === "@/api/version-probe") {
    return { probeTacuaBackend: (baseUrl) => api.probeTacuaBackend(baseUrl) };
  }
  if (request === "@/config/backend-config") {
    return {
      async loadBackendConfig() { return storedConfig; },
      async saveBackendConfig(config) {
        savedConfigs.push(config);
        storedConfig = config;
      },
      validateBackendConfig(config) { return config; },
    };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const {
  BackendContext,
  BackendProvider,
} = require(path.join(reviewerSourceRoot, "providers/backend-provider.tsx"));

const endpointConfig = {
  baseUrl: "https://tacua.example",
  sessionToken: null,
};

function principal(overrides = {}) {
  return {
    reviewer_id: "reviewer_owner",
    auth_kind: "session",
    session_id: "rsess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    device_label: "Tacua web reviewer",
    client_kind: "web",
    scopes: ["reviewer.read", "reviewer.launch", "reviewer.write"],
    expires_at: "2026-09-20T12:00:00Z",
    csrf_token: "csrf-token",
    ...overrides,
  };
}

function bootstrap(reviewerId = "reviewer_owner") {
  return {
    contract_version: "tacua.reviewer-bootstrap@1.0.0",
    reviewer_id: reviewerId,
    builds: [],
  };
}

function reset(overrides = {}) {
  storedConfig = endpointConfig;
  constructedConfigs.length = 0;
  savedConfigs.length = 0;
  api = {
    async probeTacuaBackend() {},
    async getReviewerSession() { return principal(); },
    async getReviewerBootstrap() { return bootstrap(); },
    async createPairingRequest() { throw new Error("unexpected pairing request"); },
    async exchangePairing() { throw new Error("unexpected pairing exchange"); },
    async revokeReviewerSession() { throw new Error("unexpected revocation"); },
    ...overrides,
  };
}

function Observer({ observe }) {
  observe(React.use(BackendContext));
  return React.createElement("Observer");
}

async function settle() {
  for (let index = 0; index < 8; index += 1) await Promise.resolve();
}

async function renderProvider() {
  let observed;
  let renderer;
  await TestRenderer.act(async () => {
    renderer = TestRenderer.create(
      React.createElement(
        BackendProvider,
        null,
        React.createElement(Observer, { observe: (value) => { observed = value; } }),
      ),
    );
    await settle();
  });
  return {
    get observed() { return observed; },
    renderer,
  };
}

test("web capability access connects from the exact origin without stored secrets", async () => {
  reset({
    async getReviewerSession() {
      return principal({
        auth_kind: "tailscale_capability",
        session_id: null,
        device_label: null,
        client_kind: "tailscale_web",
        expires_at: null,
      });
    },
  });
  const rendered = await renderProvider();
  assert.equal(rendered.observed.status, "connected");
  assert.equal(rendered.observed.session.auth_kind, "tailscale_capability");
  assert.equal(rendered.observed.bootstrap.reviewer_id, "reviewer_owner");
  assert.deepEqual(constructedConfigs, [
    { baseUrl: "https://tacua.example", clientKind: "web" },
    { baseUrl: "https://tacua.example", clientKind: "web", csrfToken: "csrf-token" },
  ]);
  assert.deepEqual(savedConfigs, []);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("native retries a valid capability immediately after clearing a stale bearer", async () => {
  mockPlatform.OS = "native";
  const staleToken = `rsess_${"a".repeat(32)}.${"B".repeat(43)}`;
  storedConfig = { baseUrl: "https://tacua.example", sessionToken: staleToken };
  constructedConfigs.length = 0;
  savedConfigs.length = 0;
  let sessionCalls = 0;
  api = {
    async probeTacuaBackend() {},
    async getReviewerSession(config) {
      sessionCalls += 1;
      if (config.sessionToken === staleToken) {
        throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
      }
      return principal({
        auth_kind: "tailscale_capability",
        session_id: null,
        device_label: null,
        client_kind: "tailscale_web",
        expires_at: null,
      });
    },
    async getReviewerBootstrap() { return bootstrap(); },
    async createPairingRequest() { throw new Error("unexpected pairing request"); },
    async exchangePairing() { throw new Error("unexpected pairing exchange"); },
    async revokeReviewerSession() { throw new Error("unexpected revocation"); },
  };
  const rendered = await renderProvider();
  try {
    assert.equal(rendered.observed.status, "connected");
    assert.equal(rendered.observed.session.auth_kind, "tailscale_capability");
    assert.equal(sessionCalls, 2);
    assert.deepEqual(savedConfigs, [{ baseUrl: "https://tacua.example", sessionToken: null }]);
    assert.deepEqual(constructedConfigs, [
      { baseUrl: "https://tacua.example", clientKind: "native", sessionToken: staleToken },
      { baseUrl: "https://tacua.example", clientKind: "native" },
      { baseUrl: "https://tacua.example", clientKind: "native", csrfToken: "csrf-token" },
    ]);
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
    mockPlatform.OS = "web";
  }
});

test("pairing starts only on an explicit action and keeps its bearer out of public state", async () => {
  let sessionCalls = 0;
  let resolveExchange;
  const exchange = new Promise((resolve) => { resolveExchange = resolve; });
  reset({
    async getReviewerSession() {
      sessionCalls += 1;
      if (sessionCalls === 1) {
        throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
      }
      return principal();
    },
    async createPairingRequest(_config, label) {
      assert.equal(label, "Tacua web reviewer");
      return {
        pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pairing_token: `rpair_${"a".repeat(32)}.${"B".repeat(43)}`,
        human_code: "ABCD-EFGH",
        device_label: label,
        client_kind: "web",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing(_config, token) {
      assert.match(token, /^rpair_/u);
      return exchange;
    },
  });
  const rendered = await renderProvider();
  assert.equal(rendered.observed.status, "pairing_required");
  assert.equal(sessionCalls, 1);

  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_pending");
  assert.equal(rendered.observed.pairing.human_code, "ABCD-EFGH");
  assert.equal("pairing_token" in rendered.observed.pairing, false);

  await TestRenderer.act(async () => {
    resolveExchange(principal());
    await exchange;
    await settle();
  });
  assert.equal(rendered.observed.status, "connected");
  assert.equal(sessionCalls, 2);
  assert.deepEqual(savedConfigs, []);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("a pairing exchange that succeeds after cancellation is revoked", async () => {
  let resolveExchange;
  let resolveRevoked;
  let revocationConfig;
  const exchange = new Promise((resolve) => { resolveExchange = resolve; });
  const revoked = new Promise((resolve) => { resolveRevoked = resolve; });
  reset({
    async getReviewerSession() {
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest(_config, label) {
      return {
        pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pairing_token: `rpair_${"a".repeat(32)}.${"B".repeat(43)}`,
        human_code: "ABCD-EFGH",
        device_label: label,
        client_kind: "web",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing() { return exchange; },
    async revokeReviewerSession(config) {
      revocationConfig = config;
      resolveRevoked();
      return {};
    },
  });
  const rendered = await renderProvider();
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_pending");

  await TestRenderer.act(async () => {
    rendered.observed.cancelPairing();
    resolveExchange(principal());
    await revoked;
    await settle();
  });

  assert.equal(rendered.observed.status, "pairing_required");
  assert.equal(rendered.observed.client, null);
  assert.deepEqual(revocationConfig, {
    baseUrl: "https://tacua.example",
    clientKind: "web",
    csrfToken: "csrf-token",
  });
  assert.deepEqual(savedConfigs, []);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("a canceled exchange fails closed when its issued session cannot be revoked", async () => {
  let resolveExchange;
  let revocationAttempts = 0;
  const exchange = new Promise((resolve) => { resolveExchange = resolve; });
  reset({
    async getReviewerSession() {
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest(_config, label) {
      return {
        pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pairing_token: `rpair_${"a".repeat(32)}.${"B".repeat(43)}`,
        human_code: "ABCD-EFGH",
        device_label: label,
        client_kind: "web",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing() { return exchange; },
    async revokeReviewerSession() {
      revocationAttempts += 1;
      throw new Error("network details must not be exposed");
    },
  });
  const rendered = await renderProvider();
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });

  await TestRenderer.act(async () => {
    rendered.observed.cancelPairing();
    resolveExchange(principal());
    await exchange;
    await settle();
  });

  assert.equal(rendered.observed.status, "error");
  assert.equal(rendered.observed.client, null);
  assert.ok(revocationAttempts >= 1);
  assert.match(rendered.observed.error, /could not safely revoke/u);
  assert.doesNotMatch(rendered.observed.error, /network details/u);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("a stale cleanup failure invalidates a newer pairing exchange", async () => {
  const firstPairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  const secondPairingToken = `rpair_${"b".repeat(32)}.${"C".repeat(43)}`;
  let requestCalls = 0;
  let resolveFirstExchange;
  let resolveSecondExchange;
  let revocationAttempts = 0;
  const firstExchange = new Promise((resolve) => { resolveFirstExchange = resolve; });
  const secondExchange = new Promise((resolve) => { resolveSecondExchange = resolve; });
  reset({
    async getReviewerSession() {
      if (requestCalls === 0) {
        throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
      }
      return principal();
    },
    async createPairingRequest(_config, label) {
      requestCalls += 1;
      const first = requestCalls === 1;
      return {
        pairing_id: first
          ? "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          : "rpair_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        pairing_token: first ? firstPairingToken : secondPairingToken,
        human_code: first ? "ABCD-EFGH" : "JKLM-NPQR",
        device_label: label,
        client_kind: "web",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing(_config, token) {
      return token === firstPairingToken ? firstExchange : secondExchange;
    },
    async revokeReviewerSession() {
      revocationAttempts += 1;
      if (revocationAttempts === 1) throw new Error("cleanup failed");
      return {};
    },
  });
  const rendered = await renderProvider();
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  await TestRenderer.act(async () => {
    rendered.observed.cancelPairing();
    await settle();
  });
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_pending");
  assert.equal(requestCalls, 2);

  await TestRenderer.act(async () => {
    resolveFirstExchange(principal());
    await firstExchange;
    await settle();
  });
  assert.equal(rendered.observed.status, "error");
  assert.match(rendered.observed.error, /could not safely revoke/u);

  await TestRenderer.act(async () => {
    resolveSecondExchange(principal());
    await secondExchange;
    await settle();
  });
  assert.equal(rendered.observed.status, "error");
  assert.equal(rendered.observed.client, null);
  assert.ok(revocationAttempts >= 2, "the invalidated newer exchange was also revoked");
  assert.deepEqual(savedConfigs, []);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("native pairing verifies the session and bootstrap before persisting its bearer", async () => {
  mockPlatform.OS = "native";
  const sessionId = "rsess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const sessionToken = `${sessionId}.${"B".repeat(43)}`;
  let sessionCalls = 0;
  let resolveRevoked;
  let revocationConfig;
  const revoked = new Promise((resolve) => { resolveRevoked = resolve; });
  reset({
    async getReviewerSession() {
      sessionCalls += 1;
      if (sessionCalls === 1) {
        throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
      }
      return principal({
        session_id: sessionId,
        device_label: "Tacua native reviewer",
        client_kind: "native",
      });
    },
    async createPairingRequest(_config, label) {
      return {
        pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pairing_token: `rpair_${"a".repeat(32)}.${"B".repeat(43)}`,
        human_code: "ABCD-EFGH",
        device_label: label,
        client_kind: "native",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing() {
      return {
        ...principal({
          session_id: sessionId,
          device_label: "Tacua native reviewer",
          client_kind: "native",
        }),
        session_token: sessionToken,
      };
    },
    async getReviewerBootstrap() { return bootstrap("reviewer_other"); },
    async revokeReviewerSession(config) {
      revocationConfig = config;
      resolveRevoked();
      return {};
    },
  });
  const rendered = await renderProvider();
  try {
    await TestRenderer.act(async () => {
      await rendered.observed.beginPairing();
      await revoked;
      await settle();
    });

    assert.equal(rendered.observed.status, "error");
    assert.equal(rendered.observed.client, null);
    assert.match(rendered.observed.error, /does not match/u);
    assert.equal(
      savedConfigs.some((config) => config.sessionToken !== null),
      false,
      "an unverified native bearer must never reach durable storage",
    );
    assert.deepEqual(revocationConfig, {
      baseUrl: "https://tacua.example",
      clientKind: "native",
      sessionToken,
      csrfToken: "csrf-token",
    });
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
    mockPlatform.OS = "web";
  }
});

test("rapid pairing actions create only one pending request", async () => {
  let requestCalls = 0;
  let resolveRequest;
  const request = new Promise((resolve) => { resolveRequest = resolve; });
  reset({
    async getReviewerSession() {
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest() {
      requestCalls += 1;
      return request;
    },
    async exchangePairing() {
      return new Promise(() => {});
    },
  });
  const rendered = await renderProvider();
  let first;
  let second;
  await TestRenderer.act(async () => {
    first = rendered.observed.beginPairing();
    second = rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(requestCalls, 1);
  await TestRenderer.act(async () => {
    resolveRequest({
      pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      pairing_token: `rpair_${"a".repeat(32)}.${"B".repeat(43)}`,
      human_code: "ABCD-EFGH",
      device_label: "Tacua web reviewer",
      client_kind: "web",
      created_at: "2026-08-21T12:00:00Z",
      expires_at: "2026-08-21T12:10:00Z",
    });
    await Promise.all([first, second]);
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_pending");
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("an unapproved exchange remains pending instead of becoming a connection error", async () => {
  reset({
    async getReviewerSession() {
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest() {
      return {
        pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pairing_token: `rpair_${"a".repeat(32)}.${"B".repeat(43)}`,
        human_code: "ABCD-EFGH",
        device_label: "Tacua web reviewer",
        client_kind: "web",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing() {
      throw new TacuaApiError(409, "PAIRING_NOT_APPROVED", "pairing request has not been approved");
    },
  });
  const rendered = await renderProvider();
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_pending");
  assert.equal(rendered.observed.error, null);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("legacy administrator mode produces migration guidance without a secret form", async () => {
  reset({
    async getReviewerSession() {
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest() {
      throw new TacuaApiError(404, "NOT_FOUND", "route was not found");
    },
  });
  const rendered = await renderProvider();
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_required");
  assert.equal(rendered.observed.migrationRequired, true);
  assert.match(rendered.observed.error, /legacy administrator authentication/u);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("reviewer session and bootstrap identities must match", async () => {
  reset({ async getReviewerBootstrap() { return bootstrap("reviewer_other"); } });
  const rendered = await renderProvider();
  assert.equal(rendered.observed.status, "error");
  assert.equal(rendered.observed.client, null);
  assert.match(rendered.observed.error, /does not match/u);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test.after(() => {
  Module._load = originalLoad;
  Module._resolveFilename = originalResolveFilename;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
  if (originalTSXLoader) Module._extensions[".tsx"] = originalTSXLoader;
  else delete Module._extensions[".tsx"];
});
