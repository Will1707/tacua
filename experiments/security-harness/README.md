# Tacua EXP-004 local security harness

This is a deterministic, zero-runtime-dependency harness for the synthetic, pre-implementation phase of `EXP-004`. It exercises product-policy contracts only. It does not make network calls, load environment secrets, inspect production data, invoke models, or claim that unbuilt Tacua runtime controls are secure.

## What it tests

- The versioned default-deny policy and all `DATA-001`–`DATA-012` field/destination cells.
- Unknown field, destination, operation and data-class failures with stable reason codes.
- Synthetic secret/PII/raw-payload canary denial or irreversible transformation before simulated sinks.
- Immutable provenance and project/reviewer approval requirements.
- Structural approval remains non-executable; synthetic-key cases exercise the
  strict trust-artifact shapes, exact evidence-source/repository/build scope,
  exclusive expiry windows, current revocation revision, and Codex-only runtime
  profile, rejecting `danger-full-access`, network-enabled, stale, malformed,
  source-incomplete and missing-assertion cases.
- One-organization, project/member, object-key, job, evidence-reference, ticket-version, connector-query and export authorization.
- Read-only/revocable/bounded connector behavior under malicious content.
- Deterministic Markdown/JSON output from one approved ticket version, including hostile text and stale/cross-project rejection.
- Raw, derived, cache, ticket-reference, audit, backup and provider-copy deletion lineage with visible partial failure.
- The fixed 30-day raw-media default, permitted shortening and rejected silent lengthening.
- Content-free audit records and scans of every generated result artifact.

The corpus represents pixels/OCR, speech/audio, transcripts, keyframes, logs, network records, app/provider state, source, connector output, prompts, model output, tickets, Markdown, JSON, filenames, audit, caches and deletion indexes as typed synthetic envelopes. Execution cases consume only the checked-in synthetic approved-handoff keys and artifacts; they never authenticate a real invocation. Actual binary OCR/audio/media redaction and a real nonce-consuming launcher with controlled effective Codex configuration and single-invocation credential isolation remain unverified until exercised in the selected runtime.

The harness checks the supplied signed revocation revision; it has no online
registry or monotonic revision store and cannot prove that a newer revision does
not exist. That freshness and rollback check belongs to the real launcher.

## Run exactly

From the repository root, with Node 22 or newer:

```sh
node --check experiments/security-harness/src/harness.mjs
node --check experiments/security-harness/scripts/run.mjs
node --check experiments/security-harness/scripts/verify-artifacts.mjs
node --check experiments/security-harness/test/harness.test.mjs
node --test experiments/security-harness/test/*.test.mjs
node experiments/security-harness/scripts/run.mjs artifacts/security-harness/EXP-004
node experiments/security-harness/scripts/verify-artifacts.mjs artifacts/security-harness/EXP-004
```

No install step is needed. The scripts use only Node built-ins. They write three deterministic machine-readable files into the ignored local `artifacts/security-harness/EXP-004` directory: `run-results.json`, `egress-matrix.json`, and `coverage.json`.

## Source layout

- `policy/v1.policy.json`: compact policy source for two fields per current data class and eleven destination classes.
- `schemas/egress-decision.schema.json`: normative output shape for individual egress decisions.
- `fixtures/canaries.json`: obviously synthetic, non-authenticating canary catalogue.
- `fixtures/corpus.json`: table-driven modality/operation/egress cases.
- `fixtures/auth-cases.json`: project/member and boundary authorization cases.
- `fixtures/export-case.json`: approved immutable ticket with hostile Markdown content.
- `fixtures/deletion-graph.json`: governed lineage and partial-failure cases.
- `src/harness.mjs`: policy, authorization, export, retention, deletion, scan and reporting functions.
- `test/harness.test.mjs`: local contract and property tests.

## Safety boundary

All fixture values are prefixed synthetic test data or use the reserved `.invalid` domain. Runtime output contains case IDs, data-class IDs, destinations, decisions/reasons, hashes, byte counts and simulated timings, never fixture payloads. The first-party harness is Apache-2.0 under the repository license and includes no third-party code or fixture assets.
