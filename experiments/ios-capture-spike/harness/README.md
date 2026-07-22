# Tacua physical-iPhone capture harness

This is a removable Expo development client for `EXP-001`. It links the local
`@tacua/mobile-sdk` package and provides a deliberately small UI for
consent, ReplayKit start/mark/stop, recovery discovery, and local deletion.

The harness is not a production reviewer app and does not upload anything.
Use only synthetic or explicitly approved QA content. Never commit recordings,
device identifiers, signing material, or raw test evidence.

## Local verification

Use Node 22 and an Xcode environment configured for physical-device signing:

```sh
npm install
npm run typecheck
npx expo run:ios --device
```

Start with a short recording. Confirm microphone narration and at least one
verified segment before running interruption, recovery, or 30-minute tests.
The test operator must handle iOS consent prompts and physical lock/background
actions. Delete local sessions after evidence has been minimized and recorded.

Sanitized experiment observations live in
[`../PHYSICAL-DEVICE-RESULTS.md`](../PHYSICAL-DEVICE-RESULTS.md). Raw media and
stable device identifiers must never be added to that file or committed.

The deterministic low-storage, writer-finalization, and ReplayKit-stop campaign
uses a separate compile-time QA variant. Follow
[`../FAULT-INJECTION-RUNBOOK.md`](../FAULT-INJECTION-RUNBOOK.md); never simulate
low storage by filling the phone, and never leave the double-stop-timeout plan
without performing its required live cleanup stop. A Start attempt consumes the
process's one-shot lease and disables further starts until relaunch. For the two
writer-finalization plans, the harness calls Stop once automatically after
segment 0 commits.
