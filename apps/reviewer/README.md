# Tacua reviewer app

This is the iOS-first reviewer surface for the self-hosted Tacua V1 boundary.
It does not record another application. It creates/observes backend sessions,
launches an authorized QA build, shows uploaded evidence and processing state,
and requires a human to review an exact candidate version before approval.

The current scaffold can connect to the pilot backend's session/job endpoints.
Its ticket UI is typed against the standalone `tacua.ticket-candidate@1.0.0`
contract and shows grounded behavior, reproduction, scope, uncertainty, visual
clarification choices, and the exact candidate/evidence digests being approved.
The reviewer can atomically split one exact current source into two through
sixteen drafts or merge two through sixteen exact current sources into one
draft. It shows the complete resulting content before confirmation, removes
superseded sources from the active queue, and keeps their immutable history and
evidence available without treating replacement as approval.
An approved version exposes its immutable `tacua.approved-handoff@1.1.0`
Markdown and JSON files through the native share sheet. Before sharing, the app
hashes the exact bounded response bytes, validates canonical JSON and the
embedded exact source candidate, then writes a uniquely named file in a
dedicated share cache. The cache keeps at most ten files, removes entries older
than one hour on route mount and before sharing, and retains a just-shared file
long enough for the receiving app to consume it. These are structural exports;
execution additionally requires current authenticated registry trust, a
short-lived exact-scope execution assertion, and the registry-current signed
revocation list. This app neither issues that authority nor launches Codex. A
failed candidate or handoff request is intentionally not treated as an empty
approval.

## Local development

Install the pinned Expo SDK 56 dependencies, then use Expo Go first:

```sh
cd apps/reviewer
npm install
npm run typecheck
npm start
```

The app accepts an HTTPS backend origin. Loopback HTTP is allowed only in a
development build. The complete endpoint-and-credential configuration is
committed as one `expo-secure-store` value with this-device-only, when-unlocked
accessibility, preventing a partial settings write from pairing an old token
with a new origin. Authenticated requests use the native Expo fetch boundary,
omit cookies, reject redirects, and verify the response origin before parsing
bounded JSON. Never commit a real endpoint, credential, recording, or private
pilot identifier.

The reviewer also has a browser export for a private, same-origin self-hosted
deployment:

```sh
npm run export:web -- --output-dir dist
```

The web reviewer must be served from the backend's exact HTTPS origin. Its
administrator configuration is kept only in that tab's `sessionStorage`, not
in native secure storage or persistent `localStorage`, and approved handoffs
download as verified files. The browser build deliberately rejects a different
backend origin. The backend deliberately has no CORS surface, so do not add a
wildcard origin or host the reviewer on a second origin. See
[SELF_HOSTED_WEB.md](SELF_HOSTED_WEB.md) before packaging the export in Docker.

The default bundle identifiers and QA target scheme are development
placeholders for the repository owner and must remain configurable for other
self-hosters.

The app uses the adaptive palette and accessibility rules in the
[visual-direction guide](../../docs/design/visual-direction.md).

This directory is covered by the repository-level Apache-2.0 license.
