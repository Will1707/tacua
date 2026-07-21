# Tacua

Tacua is an open-source project for a planned, self-hosted narrated mobile QA system that will turn an iOS app walkthrough into evidence-backed tickets a coding agent can reproduce and implement.

Canonical repository: [`Will1707/tacua`](https://github.com/Will1707/tacua).

The planned V1 consists of:

- an iOS reviewer app;
- a development-build SDK embedded in the app under test; and
- a Docker-packaged backend for upload, asynchronous research, candidate review, and approved Markdown/JSON handoff.

Tacua is currently in evidence-driven product and technical de-risking. It is not yet ready for production use. This public repository contains sanitized contracts, technical experiments, and a non-production vertical foundation; founder interviews, private pilot details, recordings, and raw environment evidence are intentionally excluded.

See [the V1 product boundary](docs/PRODUCT.md) for the sanitized workflow,
privacy boundary, approval model, and explicit non-goals.

The repository now contains a non-production backend pilot and reviewer-app
scaffold. Neither is a released V1 or safe for Internet-facing production use.

Names under the local `@tacua` package scope are unpublished experiment identifiers, not a claim that any public package-registry scope is owned or available. Schema identifiers use the reserved `.invalid` top-level domain for the same reason.

## V1 boundary

The first pilot targets an authorized private Expo/React Native iOS app. The V1 design limits capture to the tested app, requires explicit consent, and permits the SDK only in QA/development builds. The planned raw-media retention default is 30 days. Android, whole-device capture, Linear synchronization, and autonomous ticket execution are deferred.

## What is here today

- [`experiments/ios-capture-spike`](experiments/ios-capture-spike/package/README.md): a removable, first-party Expo/ReplayKit package candidate with segmented local recovery, plus a local-only [physical-iPhone development harness](experiments/ios-capture-spike/harness/README.md). `EXP-001` completed its physical candidate gates on one iPhone using synthetic QA data, including foreground narration, static-screen segmentation, interruption and recovery choices, scoped deletion, the 30-minute limit, lock recovery, and the deterministic [fault-injection campaign](experiments/ios-capture-spike/FAULT-INJECTION-RUNBOOK.md). The package now also contains a build-pinned, redirect-rejecting SDK/backend client, Keychain credential boundary, crash-safe replay queue, and START-only session coordinator. The stopped-capture-to-protocol adapter and upload/completion/deletion orchestration remain unimplemented, so stopping a capture does not yet upload it.
- [`experiments/eval-harness`](experiments/eval-harness/README.md): a synthetic multi-issue corpus, scorer and reporter-time protocol. Its fixtures are not product-quality evidence.
- [`experiments/security-harness`](experiments/security-harness/README.md): deterministic, synthetic default-deny, authorization, retention and deletion contract checks. Runtime security remains unverified.
- [`experiments/docker-topology-probe`](experiments/docker-topology-probe/README.md): a non-production container lifecycle probe. It does not select or implement the backend topology.
- [`contracts/approved-handoff`](contracts/approved-handoff/README.md): a strict candidate Markdown/JSON agent-handoff contract that separates offline structure from externally authenticated execution trust. [ADR-011](docs/decisions/ADR-011-approved-handoff.md) remains unaccepted until a trusted real-consumer trial passes.
- [`contracts/runtime`](contracts/runtime/README.md): strict candidate contracts for the capture/upload manifest, sanitized SDK diagnostics, asynchronous processing jobs, and editable ticket lifecycle. Structural validation does not authorize capture, egress, or agent execution.
- [`contracts/ticket-candidate`](contracts/ticket-candidate/README.md): the standalone production draft/review contract for immutable candidate versions, evidence-manifest binding, visual clarification choices, and exact human approval before approved-handoff export.
- [`contracts/sdk-backend-protocol`](contracts/sdk-backend-protocol/README.md): the exact retry-safe SDK wire contract for scoped Keychain credentials, media and diagnostic receipts, idempotent completion, local cleanup authority, and deletion.
- [`apps/reviewer`](apps/reviewer/README.md): an iOS-first Expo reviewer app with secure self-hosted configuration, QA-build launch orchestration, session/evidence/job views, clarification choices, exact-version human approval, and verified Markdown/JSON file sharing.
- [`services/backend`](services/backend/README.md): a dependency-free, Docker-packaged upload boundary with fixed deployment scope, integrity-checked segment and diagnostic persistence, contract-valid processing jobs, immutable evidence-linked candidate review, atomic approved-handoff persistence, and durable deletion. Its documented production blockers remain release work.
- [`docs/design/visual-direction.md`](docs/design/visual-direction.md): the adaptive, cicada-derived light and dark colour system used by the reviewer app.

## Local verification

The contract and synthetic harnesses have no network dependency:

```sh
python3 -B -m unittest discover -s contracts/approved-handoff/tests -v
python3 -B contracts/runtime/scripts/validate.py bundle contracts/runtime/fixtures/positive
python3 -B -m unittest discover -s contracts/runtime/tests -v
PYTHONWARNINGS=error python3 -B -m unittest discover -s contracts/ticket-candidate/tests -v
PYTHONWARNINGS=error python3 -B -m unittest discover -s contracts/sdk-backend-protocol/tests -v
PYTHONWARNINGS=error python3 -B -m unittest discover -s services/backend/tests -v
python3 -B -m unittest discover -s experiments/eval-harness/tests -v
node --test experiments/security-harness/test/harness.test.mjs
sh experiments/ios-capture-spike/package/tests/run-core-tests.sh
npm --prefix apps/reviewer ci --ignore-scripts --no-audit --no-fund
npm --prefix apps/reviewer run typecheck
```

The security harness requires Node 22 or newer. The Docker probe additionally requires a local Docker engine and creates only labelled experiment resources; read its runbook before execution.

## Safety boundary

Use only synthetic or explicitly approved QA data. Never commit recordings, credentials, private source, production telemetry, personal data or stable device identifiers. Tacua's current experiments do not authorize external model egress, production capture, or agent writes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and DCO requirements and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

Copyright 2026 Tacua contributors.

Licensed under the [Apache License 2.0](LICENSE).
