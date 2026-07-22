# Tacua reviewer app

This is the iOS-first reviewer surface for the self-hosted Tacua V1 boundary.
It does not record another application. It creates/observes backend sessions,
launches an authorized QA build, shows uploaded evidence and processing state,
and requires a human to review an exact candidate version before approval.

The current scaffold can connect to the pilot backend's session/job endpoints.
Its ticket UI is typed against the standalone `tacua.ticket-candidate@1.0.0`
contract and shows grounded behavior, reproduction, scope, uncertainty, visual
clarification choices, and the exact candidate/evidence digests being approved.
An approved version exposes its immutable `tacua.approved-handoff@1.1.0`
Markdown and JSON files through the native share sheet. Before sharing, the app
hashes the exact bounded response bytes, validates canonical JSON and the
embedded exact source candidate, then writes a uniquely named file in a
dedicated share cache. The cache keeps at most ten files, removes entries older
than one hour on route mount and before sharing, and retains a just-shared file
long enough for the receiving app to consume it. These are structural exports;
execution trust remains a separate authenticated registry decision. A failed
candidate or handoff request is intentionally not treated as an empty approval.

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

The default bundle identifiers and QA target scheme are development
placeholders for the repository owner and must remain configurable for other
self-hosters.

The app uses the adaptive palette and accessibility rules in the
[visual-direction guide](../../docs/design/visual-direction.md).

This directory is covered by the repository-level Apache-2.0 license.
