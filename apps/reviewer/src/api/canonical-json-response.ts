// SPDX-License-Identifier: Apache-2.0

import {
  ApprovedHandoffValidationError,
  parseTacuaCanonicalJson,
} from "../approved-handoff/contract.ts";

export const maximumGenericErrorBytes = 16_384;

export class CanonicalJsonResponseError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "CanonicalJsonResponseError";
  }
}

function fail(code: string): never {
  throw new CanonicalJsonResponseError(code);
}

export function assertExpectedSuccessStatus(
  status: number,
  expectedStatuses: readonly number[],
): void {
  if (
    expectedStatuses.length < 1
    || new Set(expectedStatuses).size !== expectedStatuses.length
    || expectedStatuses.some((value) => !Number.isInteger(value) || value < 200 || value > 299)
  ) fail("INVALID_EXPECTED_STATUS_SET");
  if (!expectedStatuses.includes(status)) fail("UNEXPECTED_RESPONSE_STATUS");
}

export async function readBoundedResponseBytes(
  response: Pick<Response, "body" | "headers">,
  maximumBytes: number,
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1) fail("INVALID_RESPONSE_LIMIT");
  const declared = response.headers.get("Content-Length");
  let declaredLength: number | null = null;
  if (declared !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(declared)) fail("INVALID_RESPONSE_LENGTH");
    declaredLength = Number(declared);
    if (!Number.isSafeInteger(declaredLength) || declaredLength < 1) fail("INVALID_RESPONSE_LENGTH");
    if (declaredLength > maximumBytes) fail("RESPONSE_TOO_LARGE");
  }
  if (!response.body) fail("RESPONSE_STREAM_REQUIRED");

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel();
        fail("RESPONSE_TOO_LARGE");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }

  if (length < 1 || (declaredLength !== null && declaredLength !== length)) {
    fail("RESPONSE_LENGTH_MISMATCH");
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export function decodeTacuaCanonicalJson(bytes: Uint8Array): Record<string, unknown> {
  if (
    bytes.byteLength >= 3
    && bytes[0] === 0xef
    && bytes[1] === 0xbb
    && bytes[2] === 0xbf
  ) {
    fail("JSON_BOM_FORBIDDEN");
  }
  let serialized: string;
  try {
    serialized = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    fail("INVALID_RESPONSE_ENCODING");
  }
  try {
    return parseTacuaCanonicalJson(serialized);
  } catch (error) {
    if (error instanceof ApprovedHandoffValidationError) {
      throw new CanonicalJsonResponseError(error.code);
    }
    throw error;
  }
}

export async function readCanonicalJsonResponse(
  response: Pick<Response, "body" | "headers">,
  maximumBytes: number,
  expectedContentType = "application/json",
): Promise<{ readonly bytes: Uint8Array; readonly document: Record<string, unknown> }> {
  const contentType = response.headers.get("Content-Type");
  if (contentType?.toLowerCase() !== expectedContentType.toLowerCase()) {
    fail("INVALID_RESPONSE_CONTENT_TYPE");
  }
  const bytes = await readBoundedResponseBytes(response, maximumBytes);
  return { bytes, document: decodeTacuaCanonicalJson(bytes) };
}

export function validateGenericErrorEnvelope(value: unknown): {
  readonly code: string;
  readonly message: string;
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("INVALID_ERROR_ENVELOPE");
  const envelope = value as Record<string, unknown>;
  if (Object.keys(envelope).length !== 1 || !("error" in envelope)) fail("INVALID_ERROR_ENVELOPE");
  if (envelope.error === null || typeof envelope.error !== "object" || Array.isArray(envelope.error)) fail("INVALID_ERROR_ENVELOPE");
  const error = envelope.error as Record<string, unknown>;
  if (Object.keys(error).length !== 2 || !("code" in error) || !("message" in error)) fail("INVALID_ERROR_ENVELOPE");
  if (typeof error.code !== "string" || !/^[A-Z][A-Z0-9_]{2,63}$/.test(error.code)) fail("INVALID_ERROR_ENVELOPE");
  if (typeof error.message !== "string" || Array.from(error.message).length < 1 || Array.from(error.message).length > 512) fail("INVALID_ERROR_ENVELOPE");
  return { code: error.code, message: error.message };
}
