# Tacua

Tacua is an open-source project for a planned, self-hosted narrated mobile QA system that will turn an iOS app walkthrough into evidence-backed tickets a coding agent can reproduce and implement.

Canonical repository: [`Will1707/tacua`](https://github.com/Will1707/tacua).

The planned V1 consists of:

- an iOS reviewer app;
- a development-build SDK embedded in the app under test; and
- a Docker-packaged backend for upload, asynchronous research, candidate review, and approved Markdown/JSON handoff.

Tacua is currently in evidence-driven product and technical de-risking. It is not yet ready for production use. This public repository contains only sanitized contracts and technical experiments; founder interviews, private pilot details, recordings, and raw environment evidence are intentionally excluded.

See [the V1 product boundary](docs/PRODUCT.md) for the sanitized workflow,
privacy boundary, approval model, and explicit non-goals.

No Tacua backend or reviewer app is released yet. The repository currently contains executable risk-reduction work, not a production service.

Names under the local `@tacua` package scope are unpublished experiment identifiers, not a claim that any public package-registry scope is owned or available. Schema identifiers use the reserved `.invalid` top-level domain for the same reason.

## V1 boundary

The first pilot targets an authorized private Expo/React Native iOS app. The V1 design limits capture to the tested app, requires explicit consent, and permits the SDK only in QA/development builds. The planned raw-media retention default is 30 days. Android, whole-device capture, Linear synchronization, and autonomous ticket execution are deferred.

## What is here today

- [`experiments/ios-capture-spike`](experiments/ios-capture-spike/package/README.md): a removable, first-party Expo/ReplayKit package candidate with segmented local recovery, plus a local-only [physical-iPhone development harness](experiments/ios-capture-spike/harness/README.md). Physical runs now cover foreground narration, static-screen segmentation, interruption and recovery choices, scoped deletion, the 30-minute limit, and lock recovery. Deterministic [fault-injection checks](experiments/ios-capture-spike/FAULT-INJECTION-RUNBOOK.md) remain before the experiment closes.
- [`experiments/eval-harness`](experiments/eval-harness/README.md): a synthetic multi-issue corpus, scorer and reporter-time protocol. Its fixtures are not product-quality evidence.
- [`experiments/security-harness`](experiments/security-harness/README.md): deterministic, synthetic default-deny, authorization, retention and deletion contract checks. Runtime security remains unverified.
- [`experiments/docker-topology-probe`](experiments/docker-topology-probe/README.md): a non-production container lifecycle probe. It does not select or implement the backend topology.
- [`contracts/approved-handoff`](contracts/approved-handoff/README.md): a strict candidate Markdown/JSON agent-handoff contract that separates offline structure from externally authenticated execution trust. [ADR-011](docs/decisions/ADR-011-approved-handoff.md) remains unaccepted until a trusted real-consumer trial passes.

## Local verification

The contract and synthetic harnesses have no network dependency:

```sh
python3 -B -m unittest discover -s contracts/approved-handoff/tests -v
python3 -B -m unittest discover -s experiments/eval-harness/tests -v
node --test experiments/security-harness/test/harness.test.mjs
```

The security harness requires Node 22 or newer. The Docker probe additionally requires a local Docker engine and creates only labelled experiment resources; read its runbook before execution.

## Safety boundary

Use only synthetic or explicitly approved QA data. Never commit recordings, credentials, private source, production telemetry, personal data or stable device identifiers. Tacua's current experiments do not authorize external model egress, production capture, or agent writes.

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and DCO requirements and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

Copyright 2026 Tacua contributors.

Licensed under the [Apache License 2.0](LICENSE).
