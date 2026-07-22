// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { probeTacuaBackend, TacuaBackendProbeError } from "./version-probe.ts";

const encoder = new TextEncoder();
const golden = '{"protocol_version":"tacua.sdk-backend@1.0.0","service":"tacua-backend","version":"0.2.0"}';

function response(serialized = golden, overrides = {}) {
  const bytes = encoder.encode(serialized);
  return {
    body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }),
    headers: new Headers({ "Content-Type": "application/json", "Content-Length": String(bytes.byteLength) }),
    redirected: false,
    status: 200,
    url: "https://tacua.example/version",
    ...overrides,
  };
}

test("probes the public exact-origin version endpoint without credentials", async () => {
  let captured;
  const version = await probeTacuaBackend("https://tacua.example", async (url, init) => {
    captured = { url, init };
    return response();
  });
  assert.deepEqual(version, {
    protocol_version: "tacua.sdk-backend@1.0.0",
    service: "tacua-backend",
    version: "0.2.0",
  });
  assert.equal(captured.url.toString(), "https://tacua.example/version");
  assert.equal(captured.init.credentials, "omit");
  assert.equal(captured.init.redirect, "error");
  const headers = new Headers(captured.init.headers);
  assert.equal(headers.get("Accept"), "application/json");
  assert.equal(headers.get("Authorization"), null);
  assert.equal(headers.get("Cookie"), null);
});

test("rejects redirects, origin changes, and protocol drift", async () => {
  await assert.rejects(
    () => probeTacuaBackend("https://tacua.example", async () => response(golden, { redirected: true })),
    (error) => error instanceof TacuaBackendProbeError && error.code === "UNEXPECTED_PROBE_ORIGIN",
  );
  await assert.rejects(
    () => probeTacuaBackend("https://tacua.example", async () => response(golden, { url: "https://other.example/version" })),
    (error) => error instanceof TacuaBackendProbeError && error.code === "UNEXPECTED_PROBE_ORIGIN",
  );
  const incompatible = '{"protocol_version":"tacua.sdk-backend@2.0.0","service":"tacua-backend","version":"0.2.0"}';
  await assert.rejects(
    () => probeTacuaBackend("https://tacua.example", async () => response(incompatible)),
    (error) => error instanceof TacuaBackendProbeError && error.code === "INCOMPATIBLE_BACKEND",
  );
});
