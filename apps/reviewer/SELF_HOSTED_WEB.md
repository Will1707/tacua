# Self-hosted browser reviewer

The Expo reviewer can produce a static browser bundle, but that bundle is only
one input to a safe deployment. It must not be published directly or given a
second origin.

## Required topology

Keep the current Tailscale-only HTTPS boundary and use one exact origin:

```text
tailnet browser or QA iPhone
  -> Tailscale Serve HTTPS
  -> loopback-only ingress
     -> /healthz, /version, /v1/*: Tacua backend
     -> every other path: static reviewer container
```

The static container must join only the internal ingress network. It must not
publish a host port, mount the administrator secret, backend configuration,
state volume, Docker socket, or source checkout, and it must run read-only as a
non-root user with all capabilities dropped. Pin its runtime image by digest
and copy only a clean, reproducibly generated `dist` directory into it.

The checked-in private-pilot ingress and verifier implement and attest this
path routing. The reviewer image-input validator closes the Docker build
context around the generated export and static server; the container verifier
tests the authority-free runtime; and the backend container verifier exercises
the complete same-origin Compose topology. Do not deploy a hand-written
override that bypasses these checks.

## Why there is no CORS mode

The backend intentionally has no `OPTIONS` handler or
`Access-Control-Allow-Origin` response. The browser reviewer sends a shared
administrator bearer plus non-simple integrity and idempotency headers. A
second origin would therefore need a broad, security-sensitive CORS policy and
would increase the credential-exfiltration surface.

Same-origin routing needs no CORS. The browser build also rejects a configured
backend origin that differs from `window.location.origin`. Keep redirects
disabled and preserve the client's response-origin checks.

## Browser credential boundary

Native builds keep the atomic endpoint-and-credential document in device-only,
when-unlocked secure storage. Browsers cannot provide that guarantee. The web
build uses `sessionStorage`, never `localStorage`, so configuration is scoped
to one browser tab session. The administrator bearer is still readable by
JavaScript in that origin while the tab is open. Saving configuration and
activating a stored client each require the backend's authenticated,
non-mutating reviewer-binding status check; stale reviewer IDs are not exposed
to transition code, and the check returns no configured identity.

For the single-owner private pilot:

- admit only the owner's test devices through the tailnet policy;
- keep Tailscale Funnel disabled;
- load no scripts, fonts, analytics, or other runtime resources from a
  third-party origin; the self-contained bundle still includes the
  third-party open-source packages listed in its generated notices;
- send a response-header Content Security Policy equivalent to
  `default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'
  blob: data:; style-src 'self' 'unsafe-inline'; font-src 'self'; object-src
  'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`;
  React Native Web currently needs inline styles, but not inline scripts;
- set `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy: camera=(), geolocation=()`, and
  `Cache-Control: no-store` on the SPA shell;
- clear the reviewer configuration before handing the browser/device to
  another person.

A multi-user or public deployment needs per-human authentication and a
backend-for-frontend session design. It must not reuse this shared bearer in
browser storage.

## Device-launch limitation

The first-run `QA app URL scheme` setting must exactly match the dedicated
`launchScheme` installed by the Tacua config plugin in the SDK-enabled QA
build. It is intentionally blank rather than prefilled with a plausible
generic value: the browser cannot derive or verify scheme ownership from a
bundle identifier. Correcting this setting clears any retained one-time grant;
create a new launch after saving the correction.

The release that introduced this requirement also increments the browser and
native configuration storage contracts without migrating earlier values. Every
existing reviewer must reconnect once and explicitly enter the exact scheme;
Tacua does not special-case the old placeholder because another self-hoster may
legitimately own that scheme.

Ticket inspection, editing, approval, and handoff download work from a desktop
browser. When starting a review from a desktop, the reviewer renders the QA
app's custom-scheme launch link as a QR code for the test iPhone. The QR is
generated locally in the tab without a third-party service and contains only
the fixed custom-scheme route plus the one-use, short-lived launch code: never
the backend origin, administrator credential, or recording data. It is still a
bearer until use or expiry, and custom URL schemes are not exclusive to one
installed handler, so do not screenshot, copy, or share it. While a grant is
live, the reviewer disables creation of another one rather than leave multiple
valid QRs in circulation. Changing
reviewer configuration or reaching the stated expiry or five-minute local
retention cap removes the retained grant and QR from the UI.

On an iPhone, creating a grant and opening the custom scheme are deliberately
two taps. The authenticated request is asynchronous, and browsers commonly
block a custom-scheme popup after the first tap's transient user activation has
ended; the ready state's second tap performs the open synchronously. Browser
device detection is only a convenience: the ready state always exposes an
explicit same-device action as an accessible alternative to scanning. The
recovery control still opens the QA app on the same device as the reviewer; use
the web reviewer on the test iPhone for interrupted-session recovery.

## Build validation

From a clean checkout with the pinned Node version:

```sh
cd apps/reviewer
test ! -e node_modules
test ! -e dist
test ! -e generated
npm ci --ignore-scripts --no-audit --no-fund
node ../../.github/scripts/generate-reviewer-third-party-notices.mjs
npm test
npm run typecheck
npm run export:web -- --output-dir dist --clear
cd ../..
```

Treat `dist` and the generated third-party notice as release inputs. The
validator proves the shell has no externally loaded runtime resource, binds
the content-addressed entry filename to its exact bytes, rejects real backend
origins, administrator bearers, source maps, and unexpected files, and checks
the notice against the exact package lock. It does not reject harmless URL
text in library diagnostics or comments.

```sh
node .github/scripts/validate-reviewer-web-image-inputs.mjs
node .github/scripts/smoke-reviewer-web-browser.mjs
PYTHONWARNINGS=error python3 -B -m unittest discover \
  -s services/reviewer-web/tests -v
bash .github/scripts/verify-reviewer-web-container.sh
bash .github/scripts/verify-backend-container.sh
```

The package-dependency-free browser smoke drives the production export through
Chrome or Chromium and uses OpenSSL for an ephemeral loopback certificate. It
fails CI when no browser is available; on an operator workstation without a
browser it reports an explicit skip. It permits one fresh-Chrome retry only
when initial DevTools target creation exceeds its fixed startup bound;
application, protocol, assertion, and post-startup browser failures are never
retried.

The final command runs authenticated backend and static-shell smoke tests
through the exact same-origin ingress.
