# Tacua reviewer app

This is the iOS-first reviewer surface for the self-hosted Tacua V1 boundary.
It does not record another application. It creates/observes backend sessions,
launches an authorized QA build, shows uploaded evidence and processing state,
and requires a human to review an exact candidate version before approval.

The current scaffold can connect to the pilot backend's session/job endpoints.
Candidate endpoints and launch-code orchestration are typed but remain blocked
until the SDK/backend protocol and reviewer transition API are implemented. A
failed candidate request is intentionally not treated as an empty approval.

## Local development

Install the pinned Expo SDK 56 dependencies, then use Expo Go first:

```sh
cd apps/reviewer
npm install
npm run typecheck
npm start
```

The app accepts an HTTPS backend origin. Loopback HTTP is allowed only in a
development build. The administrator token is kept in `expo-secure-store` with
this-device-only, when-unlocked accessibility. Never commit a real endpoint,
credential, recording, or private pilot identifier.

The default bundle identifiers and QA target scheme are development
placeholders for the repository owner and must remain configurable for other
self-hosters.

The app uses the adaptive palette and accessibility rules in the
[visual-direction guide](../../docs/design/visual-direction.md).

This directory is covered by the repository-level Apache-2.0 license.
