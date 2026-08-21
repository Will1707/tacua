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
`Access-Control-Allow-Origin` response. Unsafe reviewer operations use a
same-origin `HttpOnly` session cookie (or a Serve-injected capability), exact
`Origin`, and a scoped CSRF header. A second origin would therefore need a
broad, security-sensitive CORS policy and would increase the authentication
surface.

Same-origin routing needs no CORS. The browser client derives its only backend
origin from `window.location.origin`; it has no alternate-origin setting. Keep
redirects disabled and preserve the client's response-origin checks.

## Browser credential boundary

The web reviewer derives the backend from `window.location.origin` and stores
no endpoint, bearer, reviewer identity, or launch scheme in browser storage. It
also deletes superseded session-storage configuration left by older builds.
Tailscale capability access needs no pairing. Otherwise, the reviewer creates
a ten-minute pairing request, keeps its opaque exchange token only in memory,
and displays the short human approval code. Successful exchange installs a
`__Host-tacua-reviewer` `Secure`, `HttpOnly`, `SameSite=Strict` cookie;
JavaScript never receives the credential. The app then binds the authenticated
reviewer principal to the exact bootstrap 1.0 compatibility identity before
exposing any operational client. The bootstrap field must match the principal,
is otherwise rejected, and is used only as a consistency assertion rather than
as browser configuration.

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
- revoke any paired reviewer session before handing the browser/device to
  another person; capability access is removed in the tailnet policy.

A multi-user or public deployment needs a stronger per-human identity and
authorization design. This remains a single-owner private-pilot profile.

## Device-launch limitation

Transport policy 1.2 seals the dedicated QA `launch_scheme` into the SDK build
profile. The backend returns a versioned bootstrap binding and atomically
creates the complete custom-scheme URL through `/v1/reviewer/launch-links`.
The reviewer checks that URL against the selected build and grant, then opens
or renders those exact server bytes; it never accepts a manually entered scheme
or composes a launch URL. Transport 1.1 deployments remain readable but launch
and recovery controls stay disabled until the backend and QA binary are
resealed for 1.2.

Ticket inspection, editing, approval, and handoff download work from a desktop
browser. When starting a review from a desktop, the reviewer renders the QA
app's custom-scheme launch link as a QR code for the test iPhone. The QR is
generated locally in the tab without a third-party service and contains only
the server-issued custom-scheme route plus the one-use, short-lived launch
code: never the backend origin, reviewer credential, or recording data. It is
still a bearer until use or expiry, and custom URL schemes are not exclusive to
one installed handler, so do not screenshot, copy, or share it. While a grant is
live, the reviewer disables creation of another one rather than leave multiple
valid QRs in circulation. Changing the authenticated reviewer/build binding or
reaching the stated expiry or five-minute local
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
