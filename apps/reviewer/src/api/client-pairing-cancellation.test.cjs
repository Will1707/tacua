// SPDX-License-Identifier: Apache-2.0

const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");

const babel = require("@babel/core");
const transformModulesCommonJS = require("@babel/plugin-transform-modules-commonjs");
const transformTypeScript = require("@babel/plugin-transform-typescript");

const reviewerSourceRoot = path.resolve(__dirname, "..");
const originalLoad = Module._load;
const originalResolveFilename = Module._resolveFilename;
const originalTypeScriptLoader = Module._extensions[".ts"];

let fetchHandler;

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
Module._resolveFilename = function resolveFilename(request, parent, isMain, options) {
  const resolvedRequest = request.startsWith("@/")
    ? path.join(reviewerSourceRoot, request.slice(2))
    : request;
  return originalResolveFilename.call(this, resolvedRequest, parent, isMain, options);
};
Module._load = function load(request, parent, isMain) {
  if (request === "expo/fetch") {
    return { fetch: (...args) => fetchHandler(...args) };
  }
  if (request === "expo-crypto") {
    return {
      CryptoDigestAlgorithm: { SHA256: "SHA-256" },
      async digest() { throw new Error("unexpected digest"); },
    };
  }
  return originalLoad.call(this, request, parent, isMain);
};

const {
  TacuaApiClient,
  TacuaApiError,
} = require(path.join(reviewerSourceRoot, "api/client.ts"));

const pairingToken = `rpair_${"a".repeat(32)}.${"B".repeat(43)}`;

function canonicalResponse(document, status = 200) {
  const body = JSON.stringify(document);
  const response = new Response(body, {
    status,
    headers: {
      "Content-Length": String(Buffer.byteLength(body)),
      "Content-Type": "application/json",
    },
  });
  Object.defineProperty(response, "url", {
    configurable: true,
    value: "https://tacua.example/v1/reviewer/pairing-cancellations",
  });
  return response;
}

test("web cancellation posts the exact token-bound document and validates exact success", async () => {
  let request;
  fetchHandler = async (endpoint, init) => {
    request = { endpoint, init };
    return canonicalResponse({ status: "canceled" });
  };
  const client = new TacuaApiClient({
    baseUrl: "https://tacua.example",
    clientKind: "web",
  });

  assert.deepEqual(await client.cancelPairing(pairingToken), { status: "canceled" });
  assert.equal(request.endpoint.href, "https://tacua.example/v1/reviewer/pairing-cancellations");
  assert.equal(request.init.method, "POST");
  assert.equal(request.init.credentials, "same-origin");
  assert.equal(request.init.redirect, "error");
  assert.equal(request.init.body, JSON.stringify({
    pairing_token: pairingToken,
    client_kind: "web",
  }));
  assert.equal(request.init.headers.get("Accept"), "application/json");
  assert.equal(request.init.headers.get("Cache-Control"), "no-store");
  assert.equal(request.init.headers.get("Content-Type"), "application/json");
  assert.equal(request.init.headers.has("Authorization"), false);
  assert.equal(request.init.headers.has("Origin"), false);
  assert.equal(request.init.headers.has("Tacua-CSRF-Token"), false);
});

test("native cancellation uses the public origin policy without a session bearer", async () => {
  let request;
  fetchHandler = async (endpoint, init) => {
    request = { endpoint, init };
    return canonicalResponse({ status: "canceled" });
  };
  const client = new TacuaApiClient({
    baseUrl: "https://tacua.example",
    clientKind: "native",
  });

  await client.cancelPairing(pairingToken);
  assert.equal(request.init.credentials, "omit");
  assert.equal(request.init.headers.get("Origin"), "https://tacua.example");
  assert.equal(request.init.headers.has("Authorization"), false);
  assert.equal(request.init.body, JSON.stringify({
    pairing_token: pairingToken,
    client_kind: "native",
  }));
});

test("cancellation rejects malformed tokens and non-exact success bodies", async () => {
  let calls = 0;
  fetchHandler = async () => {
    calls += 1;
    return canonicalResponse({ session_id: "rsess_attacker", status: "canceled" });
  };
  const client = new TacuaApiClient({
    baseUrl: "https://tacua.example",
    clientKind: "web",
  });

  await assert.rejects(
    client.cancelPairing("not-a-pairing-token"),
    (error) => error instanceof TacuaApiError
      && error.status === 0
      && error.code === "INVALID_PAIRING_CANCELLATION",
  );
  assert.equal(calls, 0);
  await assert.rejects(
    client.cancelPairing(pairingToken),
    (error) => error instanceof TacuaApiError
      && error.status === 502
      && error.code === "INVALID_PAIRING_CANCELLATION",
  );
  assert.equal(calls, 1);
});

test.after(() => {
  Module._load = originalLoad;
  Module._resolveFilename = originalResolveFilename;
  if (originalTypeScriptLoader) Module._extensions[".ts"] = originalTypeScriptLoader;
  else delete Module._extensions[".ts"];
});
