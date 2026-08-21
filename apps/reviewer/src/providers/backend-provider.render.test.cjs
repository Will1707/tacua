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
const activationQueue = [];
const activationCalls = [];
const originalLoad = Module._load;
const originalResolveFilename = Module._resolveFilename;
const originalTypeScriptLoader = Module._extensions[".ts"];
const originalTSXLoader = Module._extensions[".tsx"];

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

function deferred(label) {
  let resolve;
  let reject;
  const promise = new Promise((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return { label, promise, reject, resolve };
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
  if (request === "@/api/backend-config-verification") {
    return {
      async loadVerifiedBackendConfig() {
        const activation = activationQueue.shift();
        activationCalls.push(activation?.label ?? "unexpected");
        assert.ok(activation, "an unexpected backend verification started");
        return activation.promise;
      },
    };
  }
  if (request === "@/api/client") {
    return { TacuaApiClient: class TacuaApiClient {} };
  }
  if (request === "@/config/backend-config") {
    return { async loadBackendConfig() { return null; } };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const {
  BackendContext,
  BackendProvider,
} = require(path.join(reviewerSourceRoot, "providers/backend-provider.tsx"));

function config(reviewerId, adminToken) {
  return {
    baseUrl: "https://tacua.example",
    adminToken,
    reviewerId,
    targetScheme: "tacua-qa-app",
  };
}

function Observer({ observe }) {
  observe(React.use(BackendContext));
  return React.createElement("Observer");
}

async function runOutOfOrderReload(latestActivation) {
  const older = deferred("older");
  const latest = deferred("latest");
  activationQueue.push(older, latest);
  activationCalls.length = 0;
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
    await Promise.resolve();
  });
  assert.deepEqual(activationCalls, ["older"]);
  assert.equal(observed.loading, true);
  assert.equal(observed.client, null);

  let latestReload;
  await TestRenderer.act(async () => {
    latestReload = observed.reload();
    await Promise.resolve();
  });
  assert.deepEqual(activationCalls, ["older", "latest"]);

  latest.resolve(latestActivation);
  await TestRenderer.act(async () => latestReload);
  const stateAfterLatest = observed;
  assert.equal(stateAfterLatest.loading, false);
  assert.equal(stateAfterLatest.error, null);

  const staleConfig = config(
    "reviewer_previous",
    "StalePrivateToken-1234567890-abcdef",
  );
  const staleClient = { label: "stale-client" };
  older.resolve({ config: staleConfig, client: staleClient });
  await TestRenderer.act(async () => {
    await older.promise;
    await Promise.resolve();
  });

  assert.equal(observed.loading, false);
  assert.equal(observed.error, null);
  assert.equal(observed.config, stateAfterLatest.config);
  assert.equal(observed.client, stateAfterLatest.client);
  assert.notEqual(observed.config, staleConfig);
  assert.notEqual(observed.client, staleClient);

  await TestRenderer.act(async () => renderer.unmount());
  assert.equal(activationQueue.length, 0);
  const completedCalls = [...activationCalls];
  await observed.reload();
  assert.deepEqual(activationCalls, completedCalls);
  return observed;
}

test("a newer forget reload cannot be undone by an older verification", async () => {
  const observed = await runOutOfOrderReload(null);
  assert.equal(observed.config, null);
  assert.equal(observed.client, null);
});

test("a newer save reload cannot be replaced by superseded credentials", async () => {
  const latestConfig = config(
    "reviewer_current",
    "CurrentPrivateToken-1234567890-abcdef",
  );
  const latestClient = { label: "latest-client" };
  const observed = await runOutOfOrderReload({
    config: latestConfig,
    client: latestClient,
  });
  assert.equal(observed.config, latestConfig);
  assert.equal(observed.client, latestClient);
});

test.after(() => {
  Module._load = originalLoad;
  Module._resolveFilename = originalResolveFilename;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
  if (originalTSXLoader) Module._extensions[".tsx"] = originalTSXLoader;
  else delete Module._extensions[".tsx"];
});
