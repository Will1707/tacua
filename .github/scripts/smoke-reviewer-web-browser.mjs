// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
} from "node:fs";
import https from "node:https";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../..");
const reviewerExport = path.join(repositoryRoot, "apps/reviewer/dist");
const handoffPath = path.join(
  repositoryRoot,
  "contracts/approved-handoff/fixtures/positive/approved-handoff.json",
);
const obsoleteConfigurationKeys = [
  "tacua.backend.configuration.web-session.v2",
  "tacua.backend.configuration.web-session.v1",
  "tacua.backend.admin-token.v1",
  "tacua.reviewer.id.v1",
  "tacua.target.scheme.v1",
];
const reviewerId = "reviewer_browser";
const targetScheme = "tacua-smoke-app";
const reviewerCsrfToken = "C".repeat(43);
const reviewerSessionId = `rsess_${"a".repeat(32)}`;
const reviewerSessionCookieValue = `${reviewerSessionId}.${"B".repeat(43)}`;
const reviewerCookie = `__Host-tacua-reviewer=${reviewerSessionCookieValue}`;
const commandTimeoutMilliseconds = 15_000;
const browserStartupTimeoutMilliseconds = 30_000;
const smokeTimeoutMilliseconds = 20_000;
const maximumBrowserStartupAttempts = 2;

const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".jpeg", "image/jpeg"],
  [".jpg", "image/jpeg"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".ttf", "font/ttf"],
  [".webp", "image/webp"],
  [".woff2", "font/woff2"],
]);

const contentSecurityPolicy = [
  "default-src 'none'",
  "script-src 'self'",
  "connect-src 'self'",
  "img-src 'self' blob: data:",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "manifest-src 'none'",
  "worker-src 'none'",
].join("; ");

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function canonicalJson(value) {
  function encode(child) {
    if (child === null) return "null";
    if (typeof child === "boolean") return child ? "true" : "false";
    if (typeof child === "number") {
      assert.ok(Number.isSafeInteger(child), "fixture contains a non-integer");
      return String(child);
    }
    if (typeof child === "string") return JSON.stringify(child);
    if (Array.isArray(child)) return `[${child.map(encode).join(",")}]`;
    assert.equal(typeof child, "object", "fixture contains a non-JSON value");
    const keys = Object.keys(child).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${encode(child[key])}`).join(",")}}`;
  }
  return encode(value);
}

function responseSecurityHeaders(response, cacheControl = "no-store") {
  response.setHeader("Cache-Control", cacheControl);
  response.setHeader("Content-Security-Policy", contentSecurityPolicy);
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader(
    "Permissions-Policy",
    "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  );
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Strict-Transport-Security", "max-age=31536000");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
}

function sendBytes(
  response,
  status,
  bytes,
  contentType,
  additionalHeaders = {},
) {
  response.statusCode = status;
  responseSecurityHeaders(response);
  response.setHeader("Content-Type", contentType);
  response.setHeader("Content-Length", String(bytes.byteLength));
  for (const [name, value] of Object.entries(additionalHeaders)) {
    response.setHeader(name, value);
  }
  response.end(bytes);
}

function sendCanonicalJson(
  response,
  status,
  value,
  additionalHeaders = {},
) {
  sendBytes(
    response,
    status,
    Buffer.from(canonicalJson(value), "utf8"),
    "application/json",
    additionalHeaders,
  );
}

function evidenceView(candidate, manifest) {
  return {
    contract_version: "tacua.candidate-evidence-view@1.0.0",
    candidate_id: candidate.candidate_id,
    candidate_version: candidate.candidate_version,
    candidate_digest: candidate.candidate_digest,
    evidence_manifest_digest: candidate.evidence_manifest.manifest_digest,
    items: manifest.items.map((item) => ({
      evidence_id: item.evidence_id,
      evidence_type: item.evidence_type,
      availability: item.availability,
      description: item.description,
      time_range: item.time_range,
      source: item.source,
      reference: item.reference === null
        ? null
        : {
          content_type: item.reference.content_type,
          size_bytes: item.reference.size_bytes,
          content_digest: item.reference.content_digest,
        },
      unavailable: item.unavailable,
      preview: item.evidence_type === "media.keyframe"
        ? {
          status: "unavailable",
          content_type: null,
          size_bytes: null,
          content_digest: null,
        }
        : {
          status: "not_applicable",
          content_type: null,
          size_bytes: null,
          content_digest: null,
        },
    })),
    diagnostic_events: [],
  };
}

function createCertificate(directory) {
  const keyPath = path.join(directory, "localhost-key.pem");
  const certificatePath = path.join(directory, "localhost-certificate.pem");
  const openssl = process.env.TACUA_OPENSSL_BINARY || "openssl";
  const result = spawnSync(openssl, [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-sha256",
    "-nodes",
    "-keyout",
    keyPath,
    "-out",
    certificatePath,
    "-subj",
    "/CN=localhost",
    "-days",
    "1",
    "-addext",
    "subjectAltName=DNS:localhost,IP:127.0.0.1",
  ], {
    encoding: "utf8",
    stdio: ["ignore", "ignore", "pipe"],
  });
  if (result.status !== 0) {
    throw new Error(
      `OpenSSL could not create the ephemeral smoke certificate: ${
        result.stderr?.trim() || result.error?.message || "unknown error"
      }`,
    );
  }
  return {
    key: readFileSync(keyPath),
    cert: readFileSync(certificatePath),
  };
}

async function createFixtureServer(temporaryDirectory) {
  assert.ok(
    statSync(path.join(reviewerExport, "index.html")).isFile(),
    "reviewer web export is missing; run export:web first",
  );
  const exportRoot = realpathSync(reviewerExport);
  const handoffBytes = readFileSync(handoffPath);
  const handoff = JSON.parse(handoffBytes.toString("utf8"));
  const candidate = JSON.parse(handoff.source_candidate.canonical_json);
  const candidateBytes = Buffer.from(handoff.source_candidate.canonical_json);
  const projectedEvidence = evidenceView(candidate, handoff.evidence_manifest);
  const handoffBodyDigest = sha256(handoffBytes);
  const protocolErrors = [];
  const requests = [];
  let fixtureOrigin = null;
  let reviewerAuthMode = "capability";
  const expectedCandidatePath =
    `/v1/reviewer/candidates/${encodeURIComponent(candidate.candidate_id)}`;
  const expectedVersionPath =
    `${expectedCandidatePath}/versions/${candidate.candidate_version}`;

  function requireScopedReviewerRequest(request, unsafe = false) {
    if (request.headers.authorization !== undefined) {
      protocolErrors.push(
        `${request.method} ${request.url} exposed an authorization bearer`,
      );
      return false;
    }
    if (
      (reviewerAuthMode === "capability" && request.headers.cookie !== undefined)
      || (reviewerAuthMode === "session" && request.headers.cookie !== reviewerCookie)
    ) {
      protocolErrors.push(
        `${request.method} ${request.url} did not use the expected scoped reviewer authentication`,
      );
      return false;
    }
    if (
      unsafe
      && (
        request.headers.origin !== fixtureOrigin
        || request.headers["tacua-csrf-token"] !== reviewerCsrfToken
      )
    ) {
      protocolErrors.push(
        `${request.method} ${request.url} did not bind its exact origin and CSRF token`,
      );
      return false;
    }
    return true;
  }

  function reviewerPrincipal() {
    const paired = reviewerAuthMode === "session";
    return {
      reviewer_id: reviewerId,
      auth_kind: paired ? "session" : "tailscale_capability",
      session_id: paired ? reviewerSessionId : null,
      device_label: paired ? "Tacua browser smoke" : null,
      client_kind: paired ? "web" : "tailscale_web",
      scopes: ["reviewer.launch", "reviewer.read", "reviewer.write"],
      expires_at: paired ? "2026-09-20T12:00:00Z" : null,
      csrf_token: reviewerCsrfToken,
    };
  }

  const server = https.createServer(
    createCertificate(temporaryDirectory),
    (request, response) => {
      const requestUrl = new URL(request.url ?? "/", "https://localhost");
      const pathname = requestUrl.pathname;
      requests.push(`${request.method} ${pathname}`);

      if (
        request.method === "DELETE"
        && pathname === "/v1/reviewer/session"
      ) {
        if (!requireScopedReviewerRequest(request, true)) {
          sendCanonicalJson(response, 403, {
            error: {
              code: "REVIEWER_CSRF_FORBIDDEN",
              message: "The browser smoke fixture rejected reviewer CSRF.",
            },
          });
          return;
        }
        reviewerAuthMode = "capability";
        sendCanonicalJson(response, 200, {
          session: {
            session_id: reviewerSessionId,
            reviewer_id: reviewerId,
            device_label: "Tacua browser smoke",
            client_kind: "web",
            scopes: ["reviewer.launch", "reviewer.read", "reviewer.write"],
            created_at: "2026-08-21T12:00:00Z",
            expires_at: "2026-09-20T12:00:00Z",
            revoked_at: "2026-08-21T12:05:00Z",
          },
        }, {
          "Set-Cookie": "__Host-tacua-reviewer=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        });
        return;
      }

      if (request.method !== "GET" && request.method !== "HEAD") {
        sendCanonicalJson(response, 405, {
          error: {
            code: "METHOD_NOT_ALLOWED",
            message: "The browser smoke fixture accepts only reads.",
          },
        });
        return;
      }

      if (pathname === "/version") {
        sendCanonicalJson(response, 200, {
          protocol_version: "tacua.sdk-backend@1.0.0",
          service: "tacua-backend",
          version: "0.1.0",
        });
        return;
      }

      if (pathname.startsWith("/v1/reviewer/")) {
        if (!requireScopedReviewerRequest(request)) {
          sendCanonicalJson(response, 401, {
            error: {
              code: "REVIEWER_AUTHENTICATION_FAILED",
              message: "reviewer authentication failed",
            },
          });
          return;
        }
        if (pathname === "/v1/reviewer/session") {
          sendCanonicalJson(response, 200, reviewerPrincipal());
          return;
        }
        if (pathname === "/v1/reviewer/bootstrap") {
          sendCanonicalJson(response, 200, {
            contract_version: "tacua.reviewer-bootstrap@1.0.0",
            reviewer_id: reviewerId,
            builds: [
              {
                build_id: "build_browser_smoke",
                application_id: "application_browser_smoke",
                bundle_identifier: "com.example.tacua.browser-smoke",
                native_version: "1.0.0",
                native_build: "1",
                distribution: "local",
                build_identity_digest: `sha256:${"b".repeat(64)}`,
                launch_scheme: targetScheme,
              },
            ],
          });
          return;
        }
        if (pathname === "/v1/reviewer/sessions") {
          sendCanonicalJson(response, 200, {
            next_cursor: null,
            sessions: [],
          });
          return;
        }
        if (pathname === expectedCandidatePath) {
          sendBytes(
            response,
            200,
            candidateBytes,
            "application/json",
            { ETag: `"${candidate.candidate_digest}"` },
          );
          return;
        }
        if (pathname === `${expectedCandidatePath}/supersession`) {
          sendCanonicalJson(response, 404, {
            error: {
              code: "SUPERSESSION_NOT_FOUND",
              message: "The candidate has no supersession record.",
            },
          });
          return;
        }
        if (pathname === `${expectedVersionPath}/evidence`) {
          sendCanonicalJson(
            response,
            200,
            projectedEvidence,
            {
              ETag: `"${candidate.candidate_digest}"`,
              "Tacua-Evidence-Manifest-Digest":
                candidate.evidence_manifest.manifest_digest,
            },
          );
          return;
        }
        if (pathname === `${expectedVersionPath}/handoff.json`) {
          sendBytes(
            response,
            200,
            handoffBytes,
            "application/vnd.tacua.approved-handoff+json;version=1.1.0",
            {
              ETag: `"${handoffBodyDigest}"`,
              "Tacua-Body-Digest": handoffBodyDigest,
              "Tacua-Candidate-Digest": candidate.candidate_digest,
              "Tacua-Candidate-Version": String(candidate.candidate_version),
              "Tacua-Handoff-Digest": handoff.handoff_digest,
            },
          );
          return;
        }
        sendCanonicalJson(response, 404, {
          error: {
            code: "NOT_FOUND",
            message: "The browser smoke fixture does not expose this API.",
          },
        });
        return;
      }

      let relative = "index.html";
      if (
        pathname.startsWith("/_expo/")
        || pathname.startsWith("/assets/")
        || pathname === "/metadata.json"
      ) {
        try {
          relative = decodeURIComponent(pathname.slice(1));
        } catch {
          relative = "";
        }
      }
      const candidatePath = path.resolve(exportRoot, relative);
      if (
        !relative
        || (
          candidatePath !== path.join(exportRoot, "index.html")
          && !candidatePath.startsWith(`${exportRoot}${path.sep}`)
        )
        || !existsSync(candidatePath)
        || !statSync(candidatePath).isFile()
      ) {
        sendBytes(
          response,
          404,
          Buffer.from("Not found\n"),
          "text/plain; charset=utf-8",
        );
        return;
      }
      const bytes = readFileSync(candidatePath);
      const extension = path.extname(candidatePath).toLowerCase();
      const immutable = /^entry-[a-f0-9]{32}\.js$/u.test(path.basename(candidatePath));
      response.statusCode = 200;
      responseSecurityHeaders(
        response,
        immutable
          ? "public, max-age=31536000, immutable"
          : "no-store",
      );
      response.setHeader(
        "Content-Type",
        contentTypes.get(extension) ?? "application/octet-stream",
      );
      response.setHeader("Content-Length", String(bytes.byteLength));
      response.end(request.method === "HEAD" ? undefined : bytes);
    },
  );
  server.keepAliveTimeout = 2_000;
  server.headersTimeout = 5_000;

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  fixtureOrigin = `https://localhost:${address.port}`;
  return {
    candidate,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections?.();
    }),
    handoff,
    handoffBytes,
    origin: fixtureOrigin,
    protocolErrors,
    requests,
    usePairedSession: () => {
      reviewerAuthMode = "session";
    },
  };
}

function executableFromPath(command) {
  const result = spawnSync(
    process.platform === "win32" ? "where" : "which",
    [command],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] },
  );
  if (result.status !== 0) return null;
  return result.stdout.split(/\r?\n/u).find((entry) => entry.trim())?.trim() ?? null;
}

function findBrowser() {
  const configured =
    process.env.TACUA_BROWSER_BINARY
    || process.env.CHROME_PATH;
  if (configured) {
    if (!existsSync(configured)) {
      throw new Error(`Configured Chrome/Chromium binary does not exist: ${configured}`);
    }
    return configured;
  }
  const absoluteCandidates = process.platform === "darwin"
    ? [
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ]
    : process.platform === "win32"
      ? [
        path.join(
          process.env.PROGRAMFILES ?? "C:\\Program Files",
          "Google/Chrome/Application/chrome.exe",
        ),
      ]
      : [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
      ];
  const absolute = absoluteCandidates.find((candidate) => existsSync(candidate));
  if (absolute) return absolute;
  for (const command of [
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
  ]) {
    const located = executableFromPath(command);
    if (located) return located;
  }
  return null;
}

class DevToolsPipe {
  constructor(child) {
    this.child = child;
    this.nextId = 0;
    this.pending = new Map();
    this.listeners = new Set();
    this.buffer = Buffer.alloc(0);
    this.closed = false;
    this.input = child.stdio[3];
    this.output = child.stdio[4];
    assert.ok(this.input && this.output, "Chrome debugging pipe is unavailable");
    this.output.on("data", (chunk) => this.read(chunk));
    this.output.on("error", (error) => this.failAll(error));
    this.input.on("error", (error) => this.failAll(error));
    child.once("error", (error) => this.failAll(error));
    child.once("exit", (code, signal) => {
      this.failAll(
        new Error(`Chrome exited before the smoke completed (${code ?? signal ?? "unknown"}).`),
      );
    });
  }

  read(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const separator = this.buffer.indexOf(0);
      if (separator < 0) return;
      const frame = this.buffer.subarray(0, separator);
      this.buffer = this.buffer.subarray(separator + 1);
      if (!frame.length) continue;
      let message;
      try {
        message = JSON.parse(frame.toString("utf8"));
      } catch {
        this.failAll(new Error("Chrome emitted malformed DevTools protocol JSON."));
        return;
      }
      if (message.id !== undefined) {
        const pending = this.pending.get(message.id);
        if (!pending) continue;
        this.pending.delete(message.id);
        clearTimeout(pending.timeout);
        if (message.error) {
          pending.reject(
            new Error(
              `${pending.method} failed: ${message.error.message ?? "unknown CDP error"}`,
            ),
          );
        } else {
          pending.resolve(message.result ?? {});
        }
        continue;
      }
      for (const listener of this.listeners) listener(message);
    }
  }

  failAll(error) {
    if (this.closed) return;
    this.closed = true;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(error);
    }
    this.pending.clear();
  }

  onEvent(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  send(
    method,
    params = {},
    sessionId,
    timeoutMilliseconds = commandTimeoutMilliseconds,
  ) {
    if (this.closed) return Promise.reject(new Error("Chrome debugging pipe is closed."));
    const id = this.nextId + 1;
    this.nextId = id;
    const message = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} exceeded the DevTools command timeout.`));
      }, timeoutMilliseconds);
      this.pending.set(id, { method, reject, resolve, timeout });
      this.input.write(`${JSON.stringify(message)}\0`, "utf8", (error) => {
        if (!error) return;
        const pending = this.pending.get(id);
        if (!pending) return;
        this.pending.delete(id);
        clearTimeout(timeout);
        reject(error);
      });
    });
  }
}

export class RetryableBrowserStartupError extends Error {
  constructor() {
    super("Chrome did not create a fresh DevTools target within the startup bound.");
    this.name = "RetryableBrowserStartupError";
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitFor(label, predicate, timeout = smokeTimeoutMilliseconds) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    try {
      if (await predicate()) return;
    } catch (error) {
      lastError = error;
    }
    await delay(75);
  }
  throw new Error(
    `Timed out waiting for ${label}${lastError ? `: ${lastError.message}` : ""}`,
  );
}

function stringifyRemoteObject(object) {
  if (Object.hasOwn(object, "value")) return String(object.value);
  return object.description ?? object.type ?? "unknown";
}

async function runBrowserSmokeAttempt(
  browser,
  fixture,
  temporaryDirectory,
  attempt,
) {
  const profileDirectory = path.join(
    temporaryDirectory,
    `chrome-profile-${attempt}`,
  );
  const downloadDirectory = path.join(
    temporaryDirectory,
    `downloads-${attempt}`,
  );
  const child = spawn(browser, [
    "--headless=new",
    "--allow-insecure-localhost",
    "--disable-background-networking",
    "--disable-breakpad",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-sync",
    "--ignore-certificate-errors",
    "--metrics-recording-only",
    "--mute-audio",
    "--no-default-browser-check",
    "--no-first-run",
    "--password-store=basic",
    "--remote-debugging-pipe",
    `--user-data-dir=${profileDirectory}`,
    "--window-size=1280,900",
    "about:blank",
  ], {
    stdio: ["ignore", "ignore", "pipe", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr = `${stderr}${chunk}`.slice(-32_768);
  });
  const devtools = new DevToolsPipe(child);
  const browserErrors = [];
  const unsubscribe = devtools.onEvent((message) => {
    if (message.method === "Runtime.exceptionThrown") {
      browserErrors.push(
        `uncaught exception: ${
          message.params?.exceptionDetails?.exception?.description
          ?? message.params?.exceptionDetails?.text
          ?? "unknown"
        }`,
      );
    }
    if (
      message.method === "Runtime.consoleAPICalled"
      && ["assert", "error"].includes(message.params?.type)
    ) {
      browserErrors.push(
        `console.${message.params.type}: ${
          (message.params.args ?? []).map(stringifyRemoteObject).join(" ")
        }`,
      );
    }
    if (
      message.method === "Log.entryAdded"
      && message.params?.entry?.level === "error"
    ) {
      const expectedSupersessionMiss = `${
        fixture.origin
      }/v1/reviewer/candidates/${
        encodeURIComponent(fixture.candidate.candidate_id)
      }/supersession`;
      if (
        message.params.entry.url === expectedSupersessionMiss
        && /^Failed to load resource:.*\b404\b/u.test(
          message.params.entry.text ?? "",
        )
      ) {
        return;
      }
      browserErrors.push(
        `browser log: ${message.params.entry.text ?? "unknown error"} (${
          message.params.entry.url ?? "unknown URL"
        })`,
      );
    }
  });

  let sessionId;
  try {
    let target;
    try {
      target = await devtools.send(
        "Target.createTarget",
        { url: "about:blank" },
        undefined,
        browserStartupTimeoutMilliseconds,
      );
    } catch (error) {
      if (
        error instanceof Error
        && error.message === "Target.createTarget exceeded the DevTools command timeout."
      ) {
        throw new RetryableBrowserStartupError();
      }
      throw error;
    }
    const attached = await devtools.send(
      "Target.attachToTarget",
      { flatten: true, targetId: target.targetId },
    );
    sessionId = attached.sessionId;
    await Promise.all([
      devtools.send("Runtime.enable", {}, sessionId),
      devtools.send("Page.enable", {}, sessionId),
      devtools.send("Log.enable", {}, sessionId),
      devtools.send("Network.enable", {}, sessionId),
    ]);
    try {
      await devtools.send("Browser.setDownloadBehavior", {
        behavior: "allow",
        downloadPath: downloadDirectory,
        eventsEnabled: true,
      });
    } catch {
      await devtools.send("Page.setDownloadBehavior", {
        behavior: "allow",
        downloadPath: downloadDirectory,
      }, sessionId);
    }

    const evaluate = async (expression) => {
      const result = await devtools.send("Runtime.evaluate", {
        awaitPromise: true,
        expression,
        returnByValue: true,
        userGesture: true,
      }, sessionId);
      if (result.exceptionDetails) {
        throw new Error(
          result.exceptionDetails.exception?.description
          ?? result.exceptionDetails.text
          ?? "browser evaluation failed",
        );
      }
      return result.result?.value;
    };
    const navigate = async (pathname) => {
      const result = await devtools.send("Page.navigate", {
        url: `${fixture.origin}${pathname}`,
      }, sessionId);
      if (result.errorText) throw new Error(`navigation failed: ${result.errorText}`);
    };
    const hasLabel = (label) => evaluate(
      `document.querySelector('[aria-label=${JSON.stringify(label)}]') !== null`,
    );
    const labelEnabled = (label) => evaluate(
      `(() => {
        const element = document.querySelector('[aria-label=${JSON.stringify(label)}]');
        return Boolean(
          element
          && !element.disabled
          && element.getAttribute('aria-disabled') !== 'true'
        );
      })()`,
    );
    const clickLabel = async (label) => {
      const result = await evaluate(
        `(() => {
          const element = document.querySelector('[aria-label=${JSON.stringify(label)}]');
          if (!element) return 'missing';
          if (element.disabled || element.getAttribute('aria-disabled') === 'true') {
            return 'disabled';
          }
          element.click();
          return 'clicked';
        })()`,
      );
      assert.equal(result, "clicked", `${label} was not clickable`);
    };
    await navigate("/settings");
    await waitFor("zero-entry capability connection", async () => {
      const text = await evaluate("document.body.innerText");
      return text.includes("Tailscale app capability")
        && text.includes(reviewerId)
        && text.includes(fixture.origin);
    });
    for (const removedLabel of [
      "Administrator token",
      "Reviewer ID",
      "QA app URL scheme",
      "Save and connect",
    ]) {
      assert.equal(
        await hasLabel(removedLabel),
        false,
        `${removedLabel} unexpectedly survived in the zero-entry web reviewer`,
      );
    }
    assert.equal(
      await evaluate("Object.keys(sessionStorage).filter((key) => key.startsWith('tacua.')).length"),
      0,
      "the zero-entry web reviewer persisted Tacua configuration",
    );

    await evaluate(`(() => {
      for (const key of ${JSON.stringify(obsoleteConfigurationKeys)}) {
        sessionStorage.setItem(key, "legacy-administrator-secret");
      }
    })()`);
    await navigate("/settings");
    await waitFor("legacy browser secret cleanup", async () => (
      await evaluate(
        `${JSON.stringify(obsoleteConfigurationKeys)}.every((key) => sessionStorage.getItem(key) === null)`,
      )
    ));
    await waitFor("capability reconnection after cleanup", async () => (
      (await evaluate("document.body.innerText")).includes("Tailscale app capability")
    ));

    fixture.usePairedSession();
    const cookieResult = await devtools.send("Network.setCookie", {
      name: "__Host-tacua-reviewer",
      value: reviewerSessionCookieValue,
      url: fixture.origin,
      path: "/",
      secure: true,
      httpOnly: true,
      sameSite: "Strict",
    }, sessionId);
    assert.notEqual(cookieResult.success, false, "Chrome rejected the scoped reviewer cookie");
    await navigate("/settings");
    await waitFor("the paired reviewer controls", () => labelEnabled("Disconnect paired reviewer"));
    const deletesBeforeModal = fixture.requests.filter(
      (entry) => entry === "DELETE /v1/reviewer/session",
    ).length;
    await clickLabel("Disconnect paired reviewer");
    await waitFor("the disconnect confirmation", () => hasLabel("Disconnect this reviewer?"));
    await clickLabel("Cancel");
    await waitFor("the cancelled modal to close", async () => (
      !(await hasLabel("Disconnect this reviewer?"))
    ));
    assert.equal(
      fixture.requests.filter(
        (entry) => entry === "DELETE /v1/reviewer/session",
      ).length,
      deletesBeforeModal,
      "cancelling the modal revoked the reviewer session",
    );

    await clickLabel("Disconnect paired reviewer");
    await waitFor("the second disconnect confirmation", () => hasLabel("Disconnect this reviewer?"));
    await clickLabel("Disconnect");
    await waitFor("the CSRF-bound reviewer revocation", () => (
      fixture.requests.filter(
        (entry) => entry === "DELETE /v1/reviewer/session",
      ).length === deletesBeforeModal + 1
    ));
    await waitFor("capability reconnection after revocation", async () => (
      (await evaluate("document.body.innerText")).includes("Tailscale app capability")
    ));

    await navigate(
      `/candidates/${encodeURIComponent(fixture.candidate.candidate_id)}`,
    );
    await waitFor(
      "the approved candidate handoff action",
      () => labelEnabled("Export JSON handoff"),
    );
    await waitFor("the bound candidate evidence", async () => {
      const text = await evaluate("document.body.innerText");
      return text.includes("Evidence sources")
        && text.includes("No candidate-scoped SDK events were retained.");
    });
    await clickLabel("Export JSON handoff");

    const expectedDownload = path.join(
      downloadDirectory,
      `tacua-handoff-${fixture.candidate.candidate_id}-v${fixture.candidate.candidate_version}.json`,
    );
    await waitFor("the approved handoff download", () => (
      existsSync(expectedDownload)
      && statSync(expectedDownload).size === fixture.handoffBytes.byteLength
    ));
    assert.deepEqual(
      readFileSync(expectedDownload),
      fixture.handoffBytes,
      "the browser download differs from the validated handoff bytes",
    );
    await waitFor("the handoff verification receipt", async () => (
      (await evaluate("document.body.innerText"))
        .includes(`Handoff: ${fixture.handoff.handoff_digest}`)
    ));
    await delay(250);
    assert.deepEqual(
      fixture.protocolErrors,
      [],
      "the reviewer escaped the bounded same-origin scoped protocol",
    );
    assert.ok(
      fixture.requests.includes("GET /v1/reviewer/session"),
      "the real reviewer did not discover its scoped reviewer session",
    );
    assert.ok(
      fixture.requests.includes("GET /v1/reviewer/bootstrap"),
      "the real reviewer did not load its authoritative bootstrap identity",
    );
    assert.equal(
      fixture.requests.some((entry) => entry.includes("/v1/admin/")),
      false,
      "the real reviewer called a legacy administrator route",
    );
    assert.ok(
      fixture.requests.includes(
        `GET /v1/reviewer/candidates/${fixture.candidate.candidate_id}/versions/${fixture.candidate.candidate_version}/evidence`,
      ),
      "the real reviewer did not load its bound candidate evidence",
    );
    assert.ok(
      fixture.requests.includes(
        `GET /v1/reviewer/candidates/${fixture.candidate.candidate_id}/versions/${fixture.candidate.candidate_version}/handoff.json`,
      ),
      "the real reviewer did not request the approved JSON handoff",
    );
    assert.deepEqual(
      browserErrors,
      [],
      `the production reviewer emitted startup/runtime errors:\n${browserErrors.join("\n")}`,
    );
  } catch (error) {
    if (stderr.trim()) {
      error.message = `${error.message}\nChrome stderr:\n${stderr.trim()}`;
    }
    throw error;
  } finally {
    unsubscribe();
    if (sessionId === undefined) {
      child.kill("SIGTERM");
    } else {
      try {
        await devtools.send("Browser.close");
      } catch {
        child.kill("SIGTERM");
      }
    }
    await Promise.race([
      new Promise((resolve) => child.once("exit", resolve)),
      delay(2_000).then(() => child.kill("SIGKILL")),
    ]);
  }
}

export async function runWithBrowserStartupRetry(runAttempt) {
  for (let attempt = 1; attempt <= maximumBrowserStartupAttempts; attempt += 1) {
    try {
      return await runAttempt(attempt);
    } catch (error) {
      if (
        !(error instanceof RetryableBrowserStartupError)
        || attempt === maximumBrowserStartupAttempts
      ) {
        throw error;
      }
      await delay(250);
    }
  }
  throw new Error("The bounded browser startup retry became unreachable.");
}

async function runBrowserSmoke(browser, fixture, temporaryDirectory) {
  await runWithBrowserStartupRetry((attempt) =>
    runBrowserSmokeAttempt(browser, fixture, temporaryDirectory, attempt)
  );
}

export async function main() {
  const browser = findBrowser();
  if (!browser) {
    const message =
      "Chrome/Chromium is unavailable; set TACUA_BROWSER_BINARY to run the reviewer browser smoke.";
    if (process.env.CI) throw new Error(message);
    process.stdout.write(`${JSON.stringify({ status: "skipped", reason: message })}\n`);
    return;
  }

  const temporaryDirectory = mkdtempSync(
    path.join(tmpdir(), "tacua-reviewer-browser-smoke-"),
  );
  let fixture;
  try {
    fixture = await createFixtureServer(temporaryDirectory);
    await runBrowserSmoke(browser, fixture, temporaryDirectory);
    process.stdout.write(`${JSON.stringify({
      status: "ok",
      browser,
      checks: [
        "startup-errors",
        "zero-entry-capability",
        "legacy-secret-cleanup",
        "scoped-session-bootstrap",
        "modal-cancel",
        "csrf-modal-confirm",
        "approved-handoff-download",
      ],
    })}\n`);
  } finally {
    await fixture?.close();
    rmSync(temporaryDirectory, { force: true, recursive: true });
  }
}

if (
  process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error) => {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  });
}
