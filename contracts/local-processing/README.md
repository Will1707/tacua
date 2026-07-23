<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tacua local-processing conformance contracts

This package freezes the provider-neutral JSON boundary between Tacua's trusted
backend adapter and an explicitly selected processor. It is a synthetic,
structural conformance aid only. Validation does not select or run a processor,
authorize evidence access or egress, claim a job, or enable the dormant artifact
pipeline.

The checked-in versions are:

| Layer | Versions | Boundary |
| --- | --- | --- |
| Local command | `tacua.local-processing-command@1.0.0`, `@1.1.0` | Same closed five-field, shell-free command shape. Version 1.1 is the explicit artifact-pipeline opt-in. |
| Local input/result | `tacua.local-processing-input@1.0.0`, `tacua.local-processing-result@1.0.0`; separate `@1.1.0` input/result | Version 1.0 remains exact. Version 1.1 is checkpoint-only for `transcribe` and `align`. |
| Stage artifact | `tacua.processing-stage-artifact@1.0.0`, containing `tacua.transcript@1.0.0` | One immutable transcript produced by `transcribe` and consumed by exact ID/digest at `align`. |
| Isolated transport wrapper | `tacua.isolated-processing-input@1.0.0`, `tacua.isolated-processing-output@1.0.0` | The ADR-016 wrapper stays 1.0 while carrying a nested local input/result. |

The isolated positive fixture deliberately demonstrates wrapper 1.0 carrying a
nested adapter 1.1 alignment exchange. It includes the original canonical local
input so the bundle validator can prove its digest before applying the runner's
only permitted mutation: a common-root, contiguous rewrite of evidence paths.
The rewritten wrapper alone cannot recompute that pre-rewrite digest; its
validity is inherited from the trusted runner's original-input pre-check. At
this commit the host runner still admits only nested adapter input 1.0, so input
pass-through remains the separately reviewed isolated-runner follow-up. The
fixture is not a claim that this dormant path is production-active.

## What validation covers

The dependency-free validator uses Python's standard library and directly calls
the repository's existing pure SDK/runtime validators for the embedded build
identity, capture manifest, and processing-job head. It independently enforces:

- strict canonical UTF-8 JSON, duplicate-key rejection, NFC strings, integer-only
  JSON, safe integers, and bounded structure;
- exact closed adapter and isolated-wrapper field sets and explicit version
  allowlists;
- command placeholders, argument and process limits without executing the
  command or requiring its non-executable arguments to exist;
- command/input version compatibility and the configured stdout byte limit;
- input, artifact, isolated-input, and isolated-output digest bindings;
- job, build, session, stage, manifest, evidence descriptor, and retention
  cross-bindings, including exact running-head and retry chronology;
- exact version-1.1 transcript/artifact cardinality and the alignment stage's
  consumed `{artifact_id, artifact_digest}` echo, including historical artifact
  reuse on an alignment retry;
- the prospective sealed transcript artifact's four-MiB bound; and
- exact local preview descriptors plus isolated preview/result digest and
  exact-reference rules.

The adapter's authoritative backend transaction still validates persisted
artifact identity, lease ownership, retries, retention, consumption receipts,
candidate/evidence contracts, and terminal publication. This package does not
replace those checks. In particular, descriptor conformance does not validate a
preview's image signature or authorize a candidate; the positive preview is a
valid synthetic PNG and the fixture generator validates its candidate/evidence
documents through the existing pure authoring validators.

All CLI success and failure reports are small canonical JSON documents that
contain only a stable code, status, and `synthetic_contract_only` authority
label. They never echo a path, transcript, processor output, or rejected value.

## Fixtures

`fixtures/positive` contains these six exact canonical bundles:

- `adapter-v1.0-checkpoint`, an unchanged adapter-1.0 checkpoint;
- `adapter-v1.0-terminal-preview`, a terminal candidate with one digest-bound body;
- `adapter-v1.1-transcribe`, adapter-1.1 transcription;
- `adapter-v1.1-align`, alignment with one full immutable transcript artifact;
- `adapter-v1.1-align-retry`, a reclaim that reuses its historical transcript; and
- `isolated-v1.0-adapter-v1.1-align`, wrapper 1.0 carrying adapter-1.1 data.

`fixtures/negative` contains canonical semantic failures for extra fields,
unknown versions, digest tampering, missing artifacts, changed private transcript
content, cross-job result substitution, command/input version drift, incorrect
consumption and producer-time bindings, malformed preview descriptors, and
isolated-envelope provenance/path/preview/digest mismatches. Every case pins its
intended content-free failure code, and the corpus rejects undeclared files,
directories, or symlinks. All fixture text is synthetic and must never be
promoted as product evidence.

## Run locally

```sh
python3 -B contracts/local-processing/scripts/regenerate_fixtures.py --check
python3 -B contracts/local-processing/scripts/validate.py \
  fixtures contracts/local-processing/fixtures
PYTHONWARNINGS=error python3 -B -m unittest discover \
  -s contracts/local-processing/tests -v
PYTHONWARNINGS=error python3 -B -m unittest discover \
  -s services/backend/tests \
  -p 'test_local_processing_contract_compatibility.py' -v
```

Validate an individual document or paired exchange with `artifact`, `exchange`,
or `bundle`. `isolated-exchange` requires the original adapter input, rewritten
isolated input, and isolated output so it can prove source provenance as well as
post-rewrite self-consistency. Run `--help` for exact arguments. Regeneration is
deterministic and emits canonical JSON with no trailing newline plus the one
exact synthetic PNG body.

## Deliberate non-goals

This package adds no runtime dependency, database or job schema, production
pipeline switch, processor image, model, connector, credential, network access,
Compose default, HTTP route, SDK/reviewer field, or later-stage artifact. The
post-alignment pause from ADR-019 remains exact. `correlate`, `research`, and
ticket-generation semantics require their own accepted design.
