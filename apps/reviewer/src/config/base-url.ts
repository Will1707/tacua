// SPDX-License-Identifier: Apache-2.0

function currentBrowserOrigin(): string | null {
  if (
    typeof globalThis !== "object"
    || !("location" in globalThis)
    || typeof globalThis.location !== "object"
    || globalThis.location === null
    || typeof globalThis.location.origin !== "string"
  ) {
    return null;
  }
  try {
    const parsed = new URL(globalThis.location.origin);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.origin : null;
  } catch {
    return null;
  }
}

/** Normalize the backend origin without importing native credential storage. */
export function normalizeBaseUrl(
  value: string,
  browserOrigin: string | null = currentBrowserOrigin(),
): string {
  if (value.length > 2_048) throw new Error("Backend URL is too long.");
  const normalized = value.trim().replace(/\/$/, "");
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("Backend URL must be a valid URL.");
  }
  const localDevelopment = typeof __DEV__ !== "undefined" && __DEV__
    && parsed.protocol === "http:"
    && ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !localDevelopment) {
    throw new Error("Backend URL must use HTTPS (loopback HTTP is allowed only in development).");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname !== "" && parsed.pathname !== "/")) {
    throw new Error("Backend URL must contain only an origin, without credentials, path, query, or fragment.");
  }
  if (browserOrigin !== null) {
    let normalizedBrowserOrigin: string;
    try {
      normalizedBrowserOrigin = new URL(browserOrigin).origin;
    } catch {
      throw new Error("The reviewer browser origin is invalid.");
    }
    if (parsed.origin !== normalizedBrowserOrigin) {
      throw new Error("The web reviewer must use its own HTTPS origin for the backend.");
    }
  }
  return parsed.origin;
}
