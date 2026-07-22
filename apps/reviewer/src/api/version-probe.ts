// SPDX-License-Identifier: Apache-2.0

import {
  CanonicalJsonResponseError,
  readCanonicalJsonResponse,
} from "./canonical-json-response.ts";
import { normalizeBaseUrl } from "../config/base-url.ts";

const expectedProtocol = "tacua.sdk-backend@1.0.0";
const maximumVersionResponseBytes = 1_024;

type ProbeFetch = (input: URL, init: RequestInit) => Promise<Response>;

export class TacuaBackendProbeError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "TacuaBackendProbeError";
  }
}

export type TacuaBackendVersion = {
  readonly service: "tacua-backend";
  readonly version: string;
  readonly protocol_version: "tacua.sdk-backend@1.0.0";
};

export function validateBackendVersionDocument(value: unknown): TacuaBackendVersion {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TacuaBackendProbeError("INVALID_VERSION_RESPONSE", "The endpoint is not a Tacua backend.");
  }
  const document = value as Record<string, unknown>;
  const keys = Object.keys(document).sort();
  if (
    keys.length !== 3
    || keys[0] !== "protocol_version"
    || keys[1] !== "service"
    || keys[2] !== "version"
    || document.service !== "tacua-backend"
    || document.protocol_version !== expectedProtocol
    || typeof document.version !== "string"
    || document.version.length > 64
    || !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$/.test(document.version)
  ) {
    throw new TacuaBackendProbeError("INCOMPATIBLE_BACKEND", "The endpoint does not expose the supported Tacua SDK/backend protocol.");
  }
  return document as TacuaBackendVersion;
}

export async function probeTacuaBackend(
  baseUrl: string,
  fetchImplementation: ProbeFetch = globalThis.fetch,
): Promise<TacuaBackendVersion> {
  const origin = normalizeBaseUrl(baseUrl);
  const endpoint = new URL("/version", `${origin}/`);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetchImplementation(endpoint, {
      method: "GET",
      credentials: "omit",
      redirect: "error",
      headers: {
        Accept: "application/json",
        "Cache-Control": "no-store",
      },
      signal: controller.signal,
    });
    if (
      response.redirected
      || !response.url
      || new URL(response.url).origin !== origin
      || new URL(response.url).pathname !== "/version"
    ) {
      throw new TacuaBackendProbeError("UNEXPECTED_PROBE_ORIGIN", "The backend probe returned from an unexpected origin.");
    }
    if (response.status !== 200) {
      throw new TacuaBackendProbeError("VERSION_PROBE_FAILED", "The Tacua version probe was not accepted.");
    }
    const { document } = await readCanonicalJsonResponse(response, maximumVersionResponseBytes);
    return validateBackendVersionDocument(document);
  } catch (error) {
    if (error instanceof TacuaBackendProbeError) throw error;
    if (error instanceof CanonicalJsonResponseError) {
      throw new TacuaBackendProbeError(error.code, "The backend version response was not bounded canonical JSON.");
    }
    if (error instanceof Error && error.name === "AbortError") {
      throw new TacuaBackendProbeError("VERSION_PROBE_TIMEOUT", "The Tacua backend did not answer the version probe in time.");
    }
    throw new TacuaBackendProbeError("VERSION_PROBE_NETWORK_ERROR", "Tacua could not reach the backend version endpoint.");
  } finally {
    clearTimeout(timeout);
  }
}
