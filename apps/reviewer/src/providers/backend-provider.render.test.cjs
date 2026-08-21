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
let storedPairingCleanup;
let api;
let saveConfigHook;
let savePairingCleanupHook;
const mockPlatform = { OS: "web" };
const appStateListeners = new Set();
const mockAppState = {
  currentState: "active",
  addEventListener(event, listener) {
    assert.equal(event, "change");
    appStateListeners.add(listener);
    return { remove() { appStateListeners.delete(listener); } };
  },
};
const constructedConfigs = [];
const savedConfigs = [];
const savedPairingCleanups = [];

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
  cancelPairing(token) { return api.cancelPairing(this.config, token); }
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
  if (request === "react-native") return { AppState: mockAppState, Platform: mockPlatform };
  if (request === "@/api/client") return { TacuaApiClient, TacuaApiError };
  if (request === "@/api/version-probe") {
    return { probeTacuaBackend: (baseUrl) => api.probeTacuaBackend(baseUrl) };
  }
  if (request === "@/config/backend-config") {
    return {
      async loadBackendConfigState() {
        return storedConfig === null
          ? null
          : {
            config: storedConfig,
            // SecureStore JSON parsing produces a fresh object for each
            // concurrent activation even when the durable value is unchanged.
            pendingPairingCleanup: storedPairingCleanup === null
              ? null
              : { ...storedPairingCleanup },
          };
      },
      async saveBackendConfig(config) {
        savedConfigs.push(config);
        if (saveConfigHook) await saveConfigHook(config);
        storedConfig = config;
        storedPairingCleanup = null;
      },
      async savePendingPairingCleanup(config, cleanup) {
        savedPairingCleanups.push({ config, cleanup });
        if (savePairingCleanupHook) await savePairingCleanupHook(config, cleanup);
        storedConfig = config;
        storedPairingCleanup = cleanup;
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

function apiWith(overrides = {}) {
  return {
    async probeTacuaBackend() {},
    async getReviewerSession() { return principal(); },
    async getReviewerBootstrap() { return bootstrap(); },
    async createPairingRequest() { throw new Error("unexpected pairing request"); },
    async exchangePairing() { throw new Error("unexpected pairing exchange"); },
    async cancelPairing() { throw new Error("unexpected pairing cancellation"); },
    async revokeReviewerSession() { throw new Error("unexpected revocation"); },
    ...overrides,
  };
}

function reset(overrides = {}) {
  mockAppState.currentState = "active";
  storedConfig = endpointConfig;
  storedPairingCleanup = null;
  saveConfigHook = null;
  savePairingCleanupHook = null;
  constructedConfigs.length = 0;
  savedConfigs.length = 0;
  savedPairingCleanups.length = 0;
  api = apiWith(overrides);
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

function emitAppState(nextState) {
  mockAppState.currentState = nextState;
  for (const listener of [...appStateListeners]) listener(nextState);
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

test("web refresh replaces a revoked pairing principal and its CSRF-bound client", async () => {
  let sessionCalls = 0;
  reset({
    async getReviewerSession() {
      sessionCalls += 1;
      if (sessionCalls === 1) return principal();
      return principal({
        auth_kind: "tailscale_capability",
        session_id: null,
        device_label: null,
        client_kind: "tailscale_web",
        expires_at: null,
        csrf_token: "capability-csrf-token",
      });
    },
  });
  const rendered = await renderProvider();
  try {
    const pairedClient = rendered.observed.client;
    assert.equal(rendered.observed.session.auth_kind, "session");

    await TestRenderer.act(async () => {
      await rendered.observed.reload();
      await settle();
    });

    assert.equal(rendered.observed.status, "connected");
    assert.equal(rendered.observed.session.auth_kind, "tailscale_capability");
    assert.notStrictEqual(rendered.observed.client, pairedClient);
    assert.deepEqual(constructedConfigs.slice(-2), [
      { baseUrl: "https://tacua.example", clientKind: "web" },
      {
        baseUrl: "https://tacua.example",
        clientKind: "web",
        csrfToken: "capability-csrf-token",
      },
    ]);
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
  }
});

test("web foreground revalidates a replaced effective principal", async () => {
  let sessionCalls = 0;
  reset({
    async getReviewerSession() {
      sessionCalls += 1;
      if (sessionCalls === 1) return principal();
      return principal({
        auth_kind: "tailscale_capability",
        session_id: null,
        device_label: null,
        client_kind: "tailscale_web",
        expires_at: null,
        csrf_token: "foreground-capability-csrf-token",
      });
    },
  });
  const rendered = await renderProvider();
  try {
    const pairedClient = rendered.observed.client;
    await TestRenderer.act(async () => {
      emitAppState("background");
      emitAppState("active");
      await settle();
    });

    assert.equal(sessionCalls, 2);
    assert.equal(rendered.observed.status, "connected");
    assert.equal(rendered.observed.session.auth_kind, "tailscale_capability");
    assert.notStrictEqual(rendered.observed.client, pairedClient);
    assert.equal(
      constructedConfigs.at(-1).csrfToken,
      "foreground-capability-csrf-token",
    );
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
  }
});

test("session revalidation uses a fixed cadence when the device clock trails the backend", async (context) => {
  const now = Date.parse("2020-08-21T12:00:00Z");
  context.mock.timers.enable({ apis: ["Date", "setTimeout"], now });
  let sessionCalls = 0;
  reset({
    async getReviewerSession() {
      sessionCalls += 1;
      return principal({ expires_at: "2026-08-21T12:00:00Z" });
    },
  });
  const rendered = await renderProvider();
  try {
    context.mock.timers.tick(59_999);
    await settle();
    assert.equal(sessionCalls, 1);

    await TestRenderer.act(async () => {
      context.mock.timers.tick(1);
      await settle();
    });

    assert.equal(sessionCalls, 2);
    assert.equal(rendered.observed.status, "connected");
    assert.equal(rendered.observed.session.auth_kind, "session");
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
  }
});

test("session revalidation repeats on the fixed cadence when the device clock leads the backend", async (context) => {
  const now = Date.parse("2030-08-21T12:00:00Z");
  context.mock.timers.enable({ apis: ["Date", "setTimeout"], now });
  let sessionCalls = 0;
  reset({
    async getReviewerSession() {
      sessionCalls += 1;
      return principal({ expires_at: "2026-08-21T12:00:00Z" });
    },
  });
  const rendered = await renderProvider();
  try {
    context.mock.timers.tick(59_999);
    await settle();
    assert.equal(sessionCalls, 1, "a future device clock must not trigger an immediate loop");

    await TestRenderer.act(async () => {
      context.mock.timers.tick(1);
      await settle();
    });
    assert.equal(sessionCalls, 2);

    await TestRenderer.act(async () => {
      context.mock.timers.tick(60_000);
      await settle();
    });
    assert.equal(sessionCalls, 3, "the same live session must continue to be revalidated");
    assert.equal(rendered.observed.status, "connected");
    assert.equal(rendered.observed.session.auth_kind, "session");
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
  }
});

test("capability principals do not start periodic session revalidation", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  let sessionCalls = 0;
  reset({
    async getReviewerSession() {
      sessionCalls += 1;
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
  try {
    await TestRenderer.act(async () => {
      context.mock.timers.tick(600_000);
      await settle();
    });
    assert.equal(sessionCalls, 1);
    assert.equal(rendered.observed.status, "connected");
    assert.equal(rendered.observed.session.auth_kind, "tailscale_capability");
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
  }
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

test("native endpoint replacement revokes the persisted session before overwriting storage", async () => {
  mockPlatform.OS = "native";
  const sessionId = "rsess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const sessionToken = `${sessionId}.${"B".repeat(43)}`;
  const oldConfig = { baseUrl: "https://old-tacua.example", sessionToken };
  const replacementConfig = { baseUrl: "https://new-tacua.example", sessionToken: null };
  storedConfig = oldConfig;
  constructedConfigs.length = 0;
  savedConfigs.length = 0;
  let sessionCalls = 0;
  let resolveRevocation;
  const revocation = new Promise((resolve) => { resolveRevocation = resolve; });
  api = {
    async probeTacuaBackend() {},
    async getReviewerSession() {
      sessionCalls += 1;
      if (sessionCalls === 1) throw new Error("initial connection failed");
      if (sessionCalls === 2) {
        return principal({
          session_id: sessionId,
          device_label: "Tacua native reviewer",
          client_kind: "native",
        });
      }
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async getReviewerBootstrap() { throw new Error("unexpected bootstrap"); },
    async createPairingRequest() { throw new Error("unexpected pairing request"); },
    async exchangePairing() { throw new Error("unexpected pairing exchange"); },
    async revokeReviewerSession() {
      await revocation;
      return {
        session_id: sessionId,
        reviewer_id: "reviewer_owner",
        client_kind: "native",
      };
    },
  };
  const rendered = await renderProvider();
  try {
    assert.equal(rendered.observed.status, "error");
    let replacement;
    await TestRenderer.act(async () => {
      replacement = rendered.observed.configureEndpoint(replacementConfig.baseUrl);
      await settle();
    });
    assert.equal(rendered.observed.status, "loading");
    assert.strictEqual(storedConfig, oldConfig, "the old bearer remains durable until DELETE succeeds");
    assert.deepEqual(savedConfigs, []);

    await TestRenderer.act(async () => {
      resolveRevocation();
      await replacement;
      await settle();
    });

    assert.deepEqual(savedConfigs, [replacementConfig]);
    assert.deepEqual(storedConfig, replacementConfig);
    assert.equal(rendered.observed.status, "pairing_required");
    assert.deepEqual(constructedConfigs.slice(1, 3), [
      { baseUrl: oldConfig.baseUrl, clientKind: "native", sessionToken },
      {
        baseUrl: oldConfig.baseUrl,
        clientKind: "native",
        sessionToken,
        csrfToken: "csrf-token",
      },
    ]);
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
    mockPlatform.OS = "web";
  }
});

test("native endpoint replacement keeps a possibly-live session when revocation is ambiguous", async () => {
  mockPlatform.OS = "native";
  const sessionId = "rsess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const sessionToken = `${sessionId}.${"B".repeat(43)}`;
  const oldConfig = { baseUrl: "https://old-tacua.example", sessionToken };
  storedConfig = oldConfig;
  constructedConfigs.length = 0;
  savedConfigs.length = 0;
  let sessionCalls = 0;
  api = {
    async probeTacuaBackend() {},
    async getReviewerSession() {
      sessionCalls += 1;
      if (sessionCalls === 1) throw new Error("initial connection failed");
      return principal({
        session_id: sessionId,
        device_label: "Tacua native reviewer",
        client_kind: "native",
      });
    },
    async getReviewerBootstrap() { throw new Error("unexpected bootstrap"); },
    async createPairingRequest() { throw new Error("unexpected pairing request"); },
    async exchangePairing() { throw new Error("unexpected pairing exchange"); },
    async revokeReviewerSession() { throw new Error("network details must not be exposed"); },
  };
  const rendered = await renderProvider();
  try {
    assert.equal(rendered.observed.status, "error");
    await TestRenderer.act(async () => {
      await assert.rejects(
        rendered.observed.configureEndpoint("https://new-tacua.example"),
        /previous endpoint was kept/u,
      );
      await settle();
    });

    assert.strictEqual(storedConfig, oldConfig);
    assert.deepEqual(savedConfigs, []);
    assert.equal(rendered.observed.status, "error");
    assert.strictEqual(rendered.observed.config, oldConfig);
    assert.match(rendered.observed.error, /previous endpoint was kept/u);
    assert.doesNotMatch(rendered.observed.error, /network details/u);
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

test("web cancellation is the barrier before a new request and stale exchange cleanup", async () => {
  const firstPairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  const secondPairingToken = `rpair_${"b".repeat(32)}.${"C".repeat(43)}`;
  let requestCalls = 0;
  let cancellationCalls = 0;
  let resolveCancellation;
  let resolveFirstExchange;
  const events = [];
  const cancellation = new Promise((resolve) => { resolveCancellation = resolve; });
  const firstExchange = new Promise((resolve) => { resolveFirstExchange = resolve; });
  reset({
    async getReviewerSession() {
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest(_config, label) {
      requestCalls += 1;
      const first = requestCalls === 1;
      events.push(`request:${requestCalls}`);
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
      events.push(token === firstPairingToken ? "exchange:1" : "exchange:2");
      return token === firstPairingToken ? firstExchange : new Promise(() => {});
    },
    async cancelPairing(config, token) {
      assert.deepEqual(config, { baseUrl: "https://tacua.example", clientKind: "web" });
      assert.equal(token, firstPairingToken);
      cancellationCalls += 1;
      events.push(`cancel:start:${cancellationCalls}`);
      if (cancellationCalls === 1) await cancellation;
      events.push(`cancel:done:${cancellationCalls}`);
      return { status: "canceled" };
    },
  });
  const rendered = await renderProvider();
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  let canceled;
  await TestRenderer.act(async () => {
    canceled = rendered.observed.cancelPairing();
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(requestCalls, 1, "a second request cannot start while cancellation is unresolved");
  assert.equal(rendered.observed.status, "pairing_pending");

  await TestRenderer.act(async () => {
    resolveCancellation();
    await settle();
  });
  assert.equal(
    rendered.observed.status,
    "pairing_pending",
    "the delayed exchange response remains inside the cancellation barrier",
  );
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(requestCalls, 1);

  // Model the exchange transaction winning while its web 201/Set-Cookie is
  // delayed until after the first cancellation tombstone. A second token-bound
  // cancellation must complete after this response before pairing 2 can start.
  await TestRenderer.act(async () => {
    resolveFirstExchange(principal());
    await firstExchange;
    await canceled;
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_required");

  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(requestCalls, 2);
  assert.deepEqual(events.slice(0, 6), [
    "request:1",
    "exchange:1",
    "cancel:start:1",
    "cancel:done:1",
    "cancel:start:2",
    "cancel:done:2",
  ]);
  assert.deepEqual(events.slice(6), ["request:2", "exchange:2"]);
  assert.equal(rendered.observed.status, "pairing_pending");
  assert.equal(rendered.observed.client, null);
  assert.equal(events.filter((event) => event.startsWith("cancel:")).length, 4);
  assert.deepEqual(savedConfigs, []);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("failed cancellation retains the exact token and requires a successful retry", async () => {
  const firstPairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  let requestCalls = 0;
  let cancellationCalls = 0;
  let resolveExchange;
  const exchange = new Promise((resolve) => { resolveExchange = resolve; });
  reset({
    async getReviewerSession() {
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest(_config, label) {
      requestCalls += 1;
      return {
        pairing_id: requestCalls === 1
          ? "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          : "rpair_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        pairing_token: requestCalls === 1
          ? firstPairingToken
          : `rpair_${"b".repeat(32)}.${"C".repeat(43)}`,
        human_code: requestCalls === 1 ? "ABCD-EFGH" : "JKLM-NPQR",
        device_label: label,
        client_kind: "web",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing(_config, token) {
      return token === firstPairingToken ? exchange : new Promise(() => {});
    },
    async cancelPairing(_config, token) {
      cancellationCalls += 1;
      assert.equal(token, firstPairingToken);
      if (cancellationCalls === 2) throw new Error("network details must not be exposed");
      return { status: "canceled" };
    },
  });
  const rendered = await renderProvider();
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });

  let canceled;
  await TestRenderer.act(async () => {
    canceled = rendered.observed.cancelPairing();
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_pending");
  await TestRenderer.act(async () => {
    resolveExchange(principal());
    await exchange;
    await canceled;
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_pending");
  assert.equal(rendered.observed.pairing.human_code, "ABCD-EFGH");
  assert.match(rendered.observed.error, /Try Cancel pairing again/u);
  assert.doesNotMatch(rendered.observed.error, /network details/u);

  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(requestCalls, 1);

  await TestRenderer.act(async () => {
    await rendered.observed.cancelPairing();
    await settle();
  });
  assert.equal(rendered.observed.status, "pairing_required");
  assert.equal(cancellationCalls, 3);

  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });
  assert.equal(requestCalls, 2);
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("an invalid web exchange is cleaned by its pairing token without probing cookie identity", async () => {
  const token = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  let sessionCalls = 0;
  let canceledToken;
  reset({
    async getReviewerSession() {
      sessionCalls += 1;
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest(_config, label) {
      return {
        pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pairing_token: token,
        human_code: "ABCD-EFGH",
        device_label: label,
        client_kind: "web",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing() {
      throw new TacuaApiError(
        502,
        "INVALID_PAIRING_EXCHANGE",
        "The pairing exchange body was invalid.",
      );
    },
    async cancelPairing(config, pairingToken) {
      assert.deepEqual(config, { baseUrl: "https://tacua.example", clientKind: "web" });
      canceledToken = pairingToken;
      return { status: "canceled" };
    },
  });
  const rendered = await renderProvider();
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });

  assert.equal(rendered.observed.status, "error");
  assert.match(rendered.observed.error, /exchange body was invalid/u);
  assert.equal(canceledToken, token);
  assert.equal(sessionCalls, 1, "cleanup must not infer the issued session from ambient cookies");
  await TestRenderer.act(async () => rendered.renderer.unmount());
});

test("native restart cancels a committed exchange from V5 before probing or connecting", async () => {
  mockPlatform.OS = "native";
  const pairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  let serverSessionActive = false;
  let reportExchangeCommitted;
  const exchangeCommitted = new Promise((resolve) => { reportExchangeCommitted = resolve; });
  const firstProcessEvents = [];
  reset({
    async getReviewerSession() {
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest(_config, label) {
      return {
        pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pairing_token: pairingToken,
        human_code: "ABCD-EFGH",
        device_label: label,
        client_kind: "native",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing(_config, token) {
      assert.equal(token, pairingToken);
      assert.deepEqual(storedPairingCleanup, {
        pairingToken,
        clientKind: "native",
      });
      firstProcessEvents.push("exchange:committed");
      serverSessionActive = true;
      reportExchangeCommitted();
      return new Promise(() => {});
    },
  });
  savePairingCleanupHook = async (_config, cleanup) => {
    firstProcessEvents.push(`journal:${cleanup.clientKind}`);
  };

  const firstProcess = await renderProvider();
  await TestRenderer.act(async () => {
    await firstProcess.observed.beginPairing();
    await exchangeCommitted;
    await settle();
  });
  assert.deepEqual(firstProcessEvents, ["journal:native", "exchange:committed"]);
  assert.equal(serverSessionActive, true);
  assert.equal(storedConfig.sessionToken, null);
  assert.deepEqual(storedPairingCleanup, { pairingToken, clientKind: "native" });

  // Simulate process termination: hook state disappears, while SecureStore and
  // the possibly committed backend session survive into a fresh provider.
  await TestRenderer.act(async () => firstProcess.renderer.unmount());
  constructedConfigs.length = 0;
  savedConfigs.length = 0;
  savedPairingCleanups.length = 0;
  savePairingCleanupHook = null;
  const restartEvents = [];
  api = apiWith({
    async cancelPairing(config, token) {
      restartEvents.push("cancel");
      assert.deepEqual(config, {
        baseUrl: "https://tacua.example",
        clientKind: "native",
      });
      assert.equal(token, pairingToken);
      serverSessionActive = false;
      return { status: "canceled" };
    },
    async probeTacuaBackend() {
      restartEvents.push("probe");
      assert.equal(serverSessionActive, false);
    },
    async getReviewerSession() {
      restartEvents.push("session");
      assert.equal(serverSessionActive, false);
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
  });
  saveConfigHook = async (config) => {
    assert.equal(config.sessionToken, null);
    restartEvents.push("journal:cleared");
  };

  const restarted = await renderProvider();
  try {
    assert.equal(restarted.observed.status, "pairing_required");
    assert.deepEqual(restartEvents, ["cancel", "journal:cleared", "probe", "session"]);
    assert.equal(serverSessionActive, false);
    assert.equal(storedPairingCleanup, null);
    assert.deepEqual(savedConfigs, [
      { baseUrl: "https://tacua.example", sessionToken: null },
    ]);
  } finally {
    await TestRenderer.act(async () => restarted.renderer.unmount());
    saveConfigHook = null;
    mockPlatform.OS = "web";
  }
});

test("native restart remains fail closed until durable pairing cleanup succeeds", async () => {
  mockPlatform.OS = "native";
  const pairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  let cancellationAttempts = 0;
  let probes = 0;
  let pairingRequests = 0;
  reset({
    async cancelPairing(config, token) {
      cancellationAttempts += 1;
      assert.deepEqual(config, {
        baseUrl: "https://tacua.example",
        clientKind: "native",
      });
      assert.equal(token, pairingToken);
      throw new Error("simulated offline restart");
    },
    async probeTacuaBackend() { probes += 1; },
    async createPairingRequest() { pairingRequests += 1; },
  });
  storedPairingCleanup = { pairingToken, clientKind: "native" };

  const rendered = await renderProvider();
  try {
    assert.equal(rendered.observed.status, "error");
    assert.match(rendered.observed.error, /could not confirm/u);
    assert.equal(cancellationAttempts, 1);
    assert.equal(probes, 0, "startup must not probe while exact cleanup is unconfirmed");

    await TestRenderer.act(async () => {
      await rendered.observed.beginPairing();
      await assert.rejects(
        rendered.observed.configureEndpoint("https://replacement.example"),
        /Cancel the current pairing/u,
      );
      await settle();
    });
    assert.equal(pairingRequests, 0);
    assert.equal(probes, 0);
    assert.deepEqual(storedPairingCleanup, { pairingToken, clientKind: "native" });

    api = apiWith({
      async cancelPairing(_config, token) {
        cancellationAttempts += 1;
        assert.equal(token, pairingToken);
        return { status: "canceled" };
      },
      async probeTacuaBackend() { probes += 1; },
      async getReviewerSession() {
        throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
      },
    });
    await TestRenderer.act(async () => {
      await rendered.observed.reload();
      await settle();
    });
    assert.equal(rendered.observed.status, "pairing_required");
    assert.equal(cancellationAttempts, 2);
    assert.equal(probes, 1);
    assert.equal(storedPairingCleanup, null);
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
    mockPlatform.OS = "web";
  }
});

test("concurrent native recovery activations clear equivalent journals by value", async () => {
  mockPlatform.OS = "native";
  const pairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  let releaseCancellation;
  let reportCancellationStarted;
  const cancellationRelease = new Promise((resolve) => { releaseCancellation = resolve; });
  const cancellationStarted = new Promise((resolve) => { reportCancellationStarted = resolve; });
  const events = [];
  let cancellationCalls = 0;
  reset({
    async cancelPairing(config, token) {
      cancellationCalls += 1;
      events.push("cancel:start");
      assert.deepEqual(config, {
        baseUrl: "https://tacua.example",
        clientKind: "native",
      });
      assert.equal(token, pairingToken);
      reportCancellationStarted();
      await cancellationRelease;
      events.push("cancel:done");
      return { status: "canceled" };
    },
    async probeTacuaBackend(baseUrl) {
      events.push(`probe:${baseUrl}`);
    },
    async getReviewerSession(config) {
      events.push(`session:${config.baseUrl}`);
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
  });
  storedPairingCleanup = { pairingToken, clientKind: "native" };
  saveConfigHook = async (config) => {
    events.push(`save:${config.baseUrl}`);
  };

  const rendered = await renderProvider();
  try {
    await cancellationStarted;
    assert.equal(rendered.observed.status, "loading");

    // A second activation reloads the same V5 bytes into an equivalent but
    // distinct cleanup object and joins the first token-bound cancellation.
    let concurrentReload;
    await TestRenderer.act(async () => {
      concurrentReload = rendered.observed.reload();
      await settle();
    });
    assert.equal(cancellationCalls, 1);

    await TestRenderer.act(async () => {
      releaseCancellation();
      await concurrentReload;
      await settle();
    });
    assert.equal(rendered.observed.status, "pairing_required");
    assert.equal(storedPairingCleanup, null);
    assert.deepEqual(events, [
      "cancel:start",
      "cancel:done",
      "save:https://tacua.example",
      "probe:https://tacua.example",
      "session:https://tacua.example",
    ]);
    assert.deepEqual(savedConfigs, [
      { baseUrl: "https://tacua.example", sessionToken: null },
    ]);

    // Successful authoritative cleanup must clear the in-memory blocker even
    // though the joining activation held a different deserialized object.
    await TestRenderer.act(async () => {
      await rendered.observed.configureEndpoint("https://replacement.example");
      await settle();
    });
    assert.equal(rendered.observed.status, "pairing_required");
    assert.equal(rendered.observed.config.baseUrl, "https://replacement.example");
    assert.equal(cancellationCalls, 1, "endpoint replacement must not repeat recovery cancellation");
    assert.deepEqual(savedConfigs, [
      { baseUrl: "https://tacua.example", sessionToken: null },
      { baseUrl: "https://replacement.example", sessionToken: null },
    ]);
    assert.deepEqual(events.slice(5), [
      "save:https://replacement.example",
      "probe:https://replacement.example",
      "session:https://replacement.example",
    ]);
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
    saveConfigHook = null;
    mockPlatform.OS = "web";
  }
});

test("native pairing verifies the session and bootstrap before persisting its bearer", async () => {
  mockPlatform.OS = "native";
  const sessionId = "rsess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const sessionToken = `${sessionId}.${"B".repeat(43)}`;
  const pairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  let sessionCalls = 0;
  let resolveCanceled;
  let cancellationConfig;
  let canceledToken;
  const canceled = new Promise((resolve) => { resolveCanceled = resolve; });
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
        pairing_token: pairingToken,
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
    async cancelPairing(config, token) {
      cancellationConfig = config;
      canceledToken = token;
      resolveCanceled();
      return { status: "canceled" };
    },
  });
  const rendered = await renderProvider();
  try {
    await TestRenderer.act(async () => {
      await rendered.observed.beginPairing();
      await canceled;
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
    assert.equal(canceledToken, pairingToken);
    assert.deepEqual(cancellationConfig, {
      baseUrl: "https://tacua.example",
      clientKind: "native",
    });
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
    mockPlatform.OS = "web";
  }
});

test("native cancellation waits for an older bearer write before durably clearing it", async () => {
  mockPlatform.OS = "native";
  const sessionId = "rsess_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const sessionToken = `${sessionId}.${"B".repeat(43)}`;
  const pairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  let sessionCalls = 0;
  let releaseBearerWrite;
  let reportBearerWriteStarted;
  const bearerWriteRelease = new Promise((resolve) => { releaseBearerWrite = resolve; });
  const bearerWriteStarted = new Promise((resolve) => { reportBearerWriteStarted = resolve; });
  const persistenceEvents = [];
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
        pairing_token: pairingToken,
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
    async cancelPairing(_config, token) {
      assert.equal(token, pairingToken);
      return { status: "canceled" };
    },
  });
  saveConfigHook = async (config) => {
    if (config.sessionToken === sessionToken) {
      persistenceEvents.push("bearer:start");
      reportBearerWriteStarted();
      await bearerWriteRelease;
      persistenceEvents.push("bearer:done");
    } else if (config.sessionToken === null) {
      persistenceEvents.push("clear:done");
    }
  };

  const rendered = await renderProvider();
  try {
    await TestRenderer.act(async () => {
      await rendered.observed.beginPairing();
      await bearerWriteStarted;
      await settle();
    });
    assert.equal(rendered.observed.status, "pairing_pending");
    assert.equal(storedConfig.sessionToken, null);

    let cancellationSettled = false;
    let cancellation;
    await TestRenderer.act(async () => {
      cancellation = rendered.observed.cancelPairing().then(() => {
        cancellationSettled = true;
      });
      await settle();
    });
    assert.equal(cancellationSettled, false);
    assert.equal(rendered.observed.status, "pairing_pending");
    assert.deepEqual(persistenceEvents, ["bearer:start"]);

    await TestRenderer.act(async () => {
      releaseBearerWrite();
      await cancellation;
      await settle();
    });
    assert.equal(rendered.observed.status, "pairing_required");
    assert.deepEqual(persistenceEvents, ["bearer:start", "bearer:done", "clear:done"]);
    assert.deepEqual(storedConfig, { baseUrl: "https://tacua.example", sessionToken: null });
    assert.deepEqual(savedConfigs, [
      { baseUrl: "https://tacua.example", sessionToken },
      { baseUrl: "https://tacua.example", sessionToken: null },
    ]);
  } finally {
    await TestRenderer.act(async () => rendered.renderer.unmount());
    saveConfigHook = null;
    mockPlatform.OS = "web";
  }
});

for (const [name, exchangeError] of [
  [
    "invalid 201 body",
    new TacuaApiError(502, "INVALID_PAIRING_EXCHANGE", "The 201 pairing body was invalid."),
  ],
  [
    "timed-out response",
    new TacuaApiError(408, "REQUEST_TIMEOUT", "The pairing exchange response timed out."),
  ],
]) {
  test(`native ${name} is canceled by pairing token before another pairing`, async () => {
    mockPlatform.OS = "native";
    const pairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
    let canceledToken;
    let cancellationConfig;
    reset({
      async getReviewerSession() {
        throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
      },
      async createPairingRequest(_config, label) {
        return {
          pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          pairing_token: pairingToken,
          human_code: "ABCD-EFGH",
          device_label: label,
          client_kind: "native",
          created_at: "2026-08-21T12:00:00Z",
          expires_at: "2026-08-21T12:10:00Z",
        };
      },
      async exchangePairing() { throw exchangeError; },
      async cancelPairing(config, token) {
        cancellationConfig = config;
        canceledToken = token;
        return { status: "canceled" };
      },
    });
    const rendered = await renderProvider();
    try {
      await TestRenderer.act(async () => {
        await rendered.observed.beginPairing();
        await settle();
      });

      assert.equal(rendered.observed.status, "error");
      assert.equal(rendered.observed.client, null);
      assert.equal(canceledToken, pairingToken);
      assert.deepEqual(cancellationConfig, {
        baseUrl: "https://tacua.example",
        clientKind: "native",
      });
      assert.deepEqual(savedConfigs, [
        { baseUrl: "https://tacua.example", sessionToken: null },
      ]);
    } finally {
      await TestRenderer.act(async () => rendered.renderer.unmount());
      mockPlatform.OS = "web";
    }
  });
}

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

test("a 401 exchange is token-canceled before offering a replacement code", async () => {
  const pairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;
  let canceledToken;
  reset({
    async getReviewerSession() {
      throw new TacuaApiError(401, "REVIEWER_AUTHENTICATION_FAILED", "reviewer authentication failed");
    },
    async createPairingRequest() {
      return {
        pairing_id: "rpair_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        pairing_token: pairingToken,
        human_code: "ABCD-EFGH",
        device_label: "Tacua web reviewer",
        client_kind: "web",
        created_at: "2026-08-21T12:00:00Z",
        expires_at: "2026-08-21T12:10:00Z",
      };
    },
    async exchangePairing() {
      // A retry can receive 401 after an earlier transaction consumed this
      // token and issued a session, so 401 is not itself cleanup proof.
      throw new TacuaApiError(401, "PAIRING_EXCHANGE_INVALID", "pairing token is invalid");
    },
    async cancelPairing(_config, token) {
      canceledToken = token;
      return { status: "canceled" };
    },
  });
  const rendered = await renderProvider();
  await TestRenderer.act(async () => {
    await rendered.observed.beginPairing();
    await settle();
  });

  assert.equal(canceledToken, pairingToken);
  assert.equal(rendered.observed.status, "pairing_required");
  assert.match(rendered.observed.error, /expired/u);
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
