// SPDX-License-Identifier: Apache-2.0

const targetSchemePattern = /^[a-z][a-z0-9+.-]{1,63}$/;

// Launch links carry a live, one-time backend code. These schemes are handled
// by the reviewer itself, the operating system, or network/browser surfaces;
// none can identify the SDK-enabled QA app. Sending a code to one of them is
// therefore both a configuration error and a potential credential disclosure.
const forbiddenTargetSchemes: ReadonlySet<string> = new Set([
  "about",
  "blob",
  "data",
  "facetime",
  "facetime-audio",
  "file",
  "ftp",
  "ftps",
  "http",
  "https",
  "itms",
  "itms-apps",
  "javascript",
  "mailto",
  "sms",
  "tacua",
  "tel",
  "webcal",
  "ws",
  "wss",
]);

export function isSafeTargetScheme(value: unknown): value is string {
  return typeof value === "string"
    && targetSchemePattern.test(value)
    && !forbiddenTargetSchemes.has(value);
}

export function normalizeTargetScheme(value: string): string {
  const normalized = value.trim();
  if (!isSafeTargetScheme(normalized)) {
    throw new Error("Target app scheme must be a custom scheme owned by the SDK-enabled QA app.");
  }
  return normalized;
}
