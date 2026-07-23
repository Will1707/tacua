# Tacua

Tacua is an open-source project for a planned, self-hosted narrated mobile QA system that will turn an iOS app walkthrough into evidence-backed tickets a coding agent can reproduce and implement.

Canonical repository: [`Will1707/tacua`](https://github.com/Will1707/tacua).

The planned V1 consists of:

- an iOS-first reviewer app with a same-origin self-hosted browser build;
- a development-build SDK embedded in the app under test; and
- a Docker-packaged backend for upload, asynchronous research, candidate review, and approved Markdown/JSON handoff.

Tacua is currently in evidence-driven product and technical de-risking. It is not yet ready for production use. This public repository contains sanitized contracts, technical experiments, and a non-production vertical foundation; founder interviews, private pilot details, recordings, and raw environment evidence are intentionally excluded.

See [the V1 product boundary](docs/PRODUCT.md) for the sanitized workflow,
privacy boundary, approval model, and explicit non-goals.
See [release readiness](docs/RELEASE-READINESS.md) for the exact distinction
between implemented foundations, verified evidence, owner decisions, and the
remaining device, integration, and production gates.
See [V1 requirements traceability](docs/V1-TRACEABILITY.md) for a direct map
from each fixed product requirement to code, tests, proof limits, and external
gates.
See the [V1 security model](docs/SECURITY-MODEL.md) for the completed
repository-owned source/design threat review, implemented controls and residual
risks, and the deployment-specific review that remains required.

The repository now contains a non-production vertical foundation spanning the
mobile SDK, backend, and reviewer app. It is not a released V1 or safe for
Internet-facing production use.

`@tacua/mobile-sdk` is intended for source and GitHub Release tarball
distribution; npm registry publication remains disabled and the name is not a
claim that any public package-registry scope is owned or available. Schema
identifiers use the reserved `.invalid` top-level domain for the same reason.

## V1 boundary

The first pilot targets an authorized private Expo/React Native iOS app. The V1 design limits capture to the tested app, requires explicit consent, and permits the SDK only in QA/development builds. The raw-media retention default is 30 days. Android, whole-device capture, Linear synchronization, and autonomous ticket execution are deferred.

## What is here today

- [`experiments/ios-capture-spike`](experiments/ios-capture-spike/package/README.md): a removable, first-party Expo/ReplayKit SDK candidate with segmented local recovery, plus a local-only [physical-iPhone development harness](experiments/ios-capture-spike/harness/README.md). `EXP-001` completed its original physical candidate gates on one iPhone using synthetic QA data, including foreground narration, static-screen segmentation, interruption and recovery choices, scoped deletion, the 30-minute limit, lock recovery, and the deterministic [fault-injection campaign](experiments/ios-capture-spike/FAULT-INJECTION-RUNBOOK.md). A later schema-4, synthetic-narration physical run also passed the [ADR-018](docs/decisions/ADR-018-v1-app-audio-acceptance.md) machine gate with exact source-manifest binding; this closes the narrow app-audio accounting gate, not the physical capture-to-ticket pilot or a supported-device matrix. A sealed QA-build profile now drives native START/RESUME plans; explicit stopped-capture admission verifies media and diagnostics before a crash-safe queue uploads them, completes the backend session, and retires local payloads only after a validated receipt. The SDK also enforces the immutable server raw-media deadline across its recoverable capture, journals, credentials, and queue, with crash-safe sweeping when relaunch discovery or another lifecycle boundary runs. A reboot before that deadline blocks raw-data use until authenticated RESUME refreshes the server-time anchor; at or after the deadline, a valid system wall-time observation is deletion authority. Authenticated backend deletion is also implemented. Upload remains a foreground, process-bound operation with exact replay after relaunch; `stop()` itself never transmits evidence.
- [`experiments/eval-harness`](experiments/eval-harness/README.md): a synthetic multi-issue corpus, scorer and reporter-time protocol. Its fixtures are not product-quality evidence.
- [`experiments/security-harness`](experiments/security-harness/README.md): deterministic, synthetic default-deny, authorization, retention and deletion contract checks. Runtime security remains unverified.
- [`experiments/docker-topology-probe`](experiments/docker-topology-probe/README.md): a non-production container lifecycle probe. It does not select or implement the backend topology.
- [`contracts/approved-handoff`](contracts/approved-handoff/README.md): a strict candidate Markdown/JSON agent-handoff contract that separates offline structure from externally authenticated execution trust. [ADR-017](docs/decisions/ADR-017-codex-execution-trust.md) accepts the single-host private-pilot Codex assertion/revocation subset; the broader remote-production trust decision in [ADR-011](docs/decisions/ADR-011-approved-handoff.md) remains proposed, and no trusted real-consumer trial has passed.
- [`contracts/runtime`](contracts/runtime/README.md): strict candidate contracts for the capture/upload manifest, sanitized SDK diagnostics, asynchronous processing jobs, and editable ticket lifecycle. Structural validation does not authorize capture, egress, or agent execution.
- [`contracts/local-processing`](contracts/local-processing/README.md): canonical synthetic adapter-1.0/1.1 and isolated-wrapper-1.0 conformance fixtures with a dependency-free, content-free validator. They freeze dormant wire compatibility without selecting or activating a processor.
- [`contracts/ticket-candidate`](contracts/ticket-candidate/README.md): the standalone production draft/review contract for immutable candidate versions, evidence-manifest binding, visual clarification choices, atomic split/merge replacement, and exact human approval before approved-handoff export.
- [`contracts/sdk-backend-protocol`](contracts/sdk-backend-protocol/README.md): the exact retry-safe SDK wire contract for scoped Keychain credentials, media and diagnostic receipts, idempotent completion, local cleanup authority, and deletion.
- [`apps/reviewer`](apps/reviewer/README.md): an iOS-first Expo reviewer app with a same-origin, authority-free browser image; secure self-hosted configuration; QA-build launch orchestration; session/evidence/job views; clarification choices; atomic split/merge replacement; exact-version human approval; and verified Markdown/JSON sharing.
- [`services/backend`](services/backend/README.md): a dependency-free, Docker-packaged upload boundary with fixed deployment scope, integrity-checked segment and diagnostic persistence, contract-valid processing jobs, immutable evidence-linked candidate review and replacement, atomic approved-handoff persistence, durable deletion, operator backup/restore tooling, an opt-in provider-neutral local processing command adapter, and a separate host-side isolated private-pilot processor gate. The checked-in Compose deployment keeps the backend and reviewer on an egress-denied network and routes both through one loopback ingress; selecting and authorizing a real transcription/research implementation remains operator work.
- [`services/backend/TAILNET_PRIVATE_PILOT.md`](services/backend/TAILNET_PRIVATE_PILOT.md): a checked, single-owner Tailscale HTTPS-to-loopback test profile that avoids public hosting while explicitly remaining outside the production reverse-proxy gate.
- [`docs/design/visual-direction.md`](docs/design/visual-direction.md): the adaptive, cicada-derived light and dark colour system used by the reviewer app.

## Local verification

The contract and synthetic harnesses have no network dependency:

```sh
python3 -B -m unittest discover -s contracts/approved-handoff/tests -v
python3 -B contracts/runtime/scripts/validate.py bundle contracts/runtime/fixtures/positive
python3 -B -m unittest discover -s contracts/runtime/tests -v
python3 -B contracts/local-processing/scripts/regenerate_fixtures.py --check
python3 -B contracts/local-processing/scripts/validate.py fixtures contracts/local-processing/fixtures
PYTHONWARNINGS=error python3 -B -m unittest discover -s contracts/local-processing/tests -v
PYTHONWARNINGS=error python3 -B -m unittest discover -s contracts/ticket-candidate/tests -v
PYTHONWARNINGS=error python3 -B -m unittest discover -s contracts/sdk-backend-protocol/tests -v
PYTHONWARNINGS=error python3 -B -m unittest discover -s services/backend/tests -v
python3 -B -m unittest discover -s experiments/eval-harness/tests -v
node --test experiments/security-harness/test/harness.test.mjs
sh experiments/ios-capture-spike/package/tests/run-core-tests.sh
npm --prefix apps/reviewer ci --ignore-scripts --no-audit --no-fund
node .github/scripts/generate-reviewer-third-party-notices.mjs
npm --prefix apps/reviewer test
npm --prefix apps/reviewer run typecheck
npm --prefix apps/reviewer run export:ios
npm --prefix apps/reviewer run export:web -- --output-dir dist --clear
node --test .github/scripts/validate-reviewer-web-image-inputs.test.mjs
node .github/scripts/validate-reviewer-web-image-inputs.mjs
node .github/scripts/smoke-reviewer-web-browser.mjs
PYTHONWARNINGS=error python3 -B -m unittest discover \
  -s services/reviewer-web/tests -v
node --test .github/scripts/check-markdown-links.test.mjs
node .github/scripts/check-markdown-links.mjs
```

The security harness and repository checks require Node 22 or newer. On an
isolated Docker host, `bash .github/scripts/verify-backend-container.sh` runs the
same hardened backend and reviewer images, same-origin routing, single-writer,
smoke, backup, restore, and restored-start gate as CI. It refuses to replace
colliding Docker resources and removes only the uniquely named resources it
creates. The older Docker topology probe is a separate experiment; read its
runbook before running it.

## Safety boundary

Use only synthetic or explicitly approved QA data. Never commit recordings, credentials, private source, production telemetry, personal data or stable device identifiers. Tacua's current experiments do not authorize external model egress, production capture, or agent writes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and DCO requirements and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

Copyright 2026 Tacua contributors.

Licensed under the [Apache License 2.0](LICENSE).
