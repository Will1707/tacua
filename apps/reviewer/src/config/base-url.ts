// SPDX-License-Identifier: Apache-2.0

/** Normalize the backend origin without importing native credential storage. */
export function normalizeBaseUrl(value: string): string {
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
  return parsed.origin;
}
