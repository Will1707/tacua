// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  CanonicalJsonResponseError,
  assertExpectedSuccessStatus,
  decodeTacuaCanonicalJson,
  readBoundedResponseBytes,
  readCanonicalJsonResponse,
  validateGenericErrorEnvelope,
} from "./canonical-json-response.ts";

const encoder = new TextEncoder();

function streamResponse(chunks, headers = {}) {
  return {
    headers: new Headers(headers),
    body: new ReadableStream({
      start(controller) {
        chunks.forEach((chunk) => controller.enqueue(chunk));
        controller.close();
      },
    }),
  };
}

function rejectsCode(callback, code) {
  assert.throws(callback, (error) => error instanceof CanonicalJsonResponseError && error.code === code);
}

async function rejectsCodeAsync(callback, code) {
  await assert.rejects(callback, (error) => error instanceof CanonicalJsonResponseError && error.code === code);
}

test("reads a multi-chunk bounded canonical JSON response", async () => {
  const first = encoder.encode('{"error":{"code":"NOT_FOUND",');
  const second = encoder.encode('"message":"not found"}}');
  const response = streamResponse([first, second], {
    "Content-Type": "application/json",
    "Content-Length": String(first.byteLength + second.byteLength),
  });
  const parsed = await readCanonicalJsonResponse(response, 256);
  assert.deepEqual(validateGenericErrorEnvelope(parsed.document), { code: "NOT_FOUND", message: "not found" });
});

test("enforces stream and declared byte bounds before concatenation", async () => {
  await rejectsCodeAsync(
    () => readBoundedResponseBytes(streamResponse([new Uint8Array(5), new Uint8Array(5)]), 8),
    "RESPONSE_TOO_LARGE",
  );
  await rejectsCodeAsync(
    () => readBoundedResponseBytes(streamResponse([new Uint8Array(2)], { "Content-Length": "3" }), 8),
    "RESPONSE_LENGTH_MISMATCH",
  );
  await rejectsCodeAsync(
    () => readBoundedResponseBytes(streamResponse([new Uint8Array(1)], { "Content-Length": "09" }), 16),
    "INVALID_RESPONSE_LENGTH",
  );
});

test("rejects invalid UTF-8, BOMs, duplicate keys, unsafe numbers, and noncanonical bytes", () => {
  rejectsCode(() => decodeTacuaCanonicalJson(new Uint8Array([0xff])), "INVALID_RESPONSE_ENCODING");
  rejectsCode(() => decodeTacuaCanonicalJson(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d])), "JSON_BOM_FORBIDDEN");
  rejectsCode(() => decodeTacuaCanonicalJson(encoder.encode('{"a":1,"a":2}')), "NON_CANONICAL_JSON");
  rejectsCode(() => decodeTacuaCanonicalJson(encoder.encode('{"value":1.5}')), "INVALID_NUMBER");
  rejectsCode(() => decodeTacuaCanonicalJson(encoder.encode('{"value":9007199254740993}')), "INVALID_NUMBER");
  rejectsCode(() => decodeTacuaCanonicalJson(encoder.encode('{"value":"é"}')), "NON_CANONICAL_UNICODE");
  rejectsCode(() => decodeTacuaCanonicalJson(encoder.encode('{ "value":1}')), "NON_CANONICAL_JSON");
  rejectsCode(() => decodeTacuaCanonicalJson(encoder.encode('{"z":1,"a":2}')), "NON_CANONICAL_JSON");
});

test("accepts only the exact bounded generic error envelope", () => {
  assert.deepEqual(validateGenericErrorEnvelope({ error: { code: "SESSION_NOT_FOUND", message: "session was not found" } }), {
    code: "SESSION_NOT_FOUND",
    message: "session was not found",
  });
  for (const invalid of [
    {},
    { error: { code: "lowercase", message: "bad" } },
    { error: { code: "BAD_CODE", message: "bad", detail: "leak" } },
    { error: { code: "BAD_CODE", message: "bad" }, debug: true },
  ]) {
    rejectsCode(() => validateGenericErrorEnvelope(invalid), "INVALID_ERROR_ENVELOPE");
  }
});

test("rejects a canonical response carried by any unpinned 2xx status", () => {
  assert.doesNotThrow(() => assertExpectedSuccessStatus(200, [200]));
  assert.doesNotThrow(() => assertExpectedSuccessStatus(200, [200, 201]));
  assert.doesNotThrow(() => assertExpectedSuccessStatus(201, [200, 201]));
  rejectsCode(() => assertExpectedSuccessStatus(204, [200]), "UNEXPECTED_RESPONSE_STATUS");
  rejectsCode(() => assertExpectedSuccessStatus(202, [200, 201]), "UNEXPECTED_RESPONSE_STATUS");
  rejectsCode(() => assertExpectedSuccessStatus(200, []), "INVALID_EXPECTED_STATUS_SET");
});
