<!-- SPDX-License-Identifier: Apache-2.0 -->

# Candidate approved-ticket handoff contract

This directory is a repository-contained, implementation-candidate package for the broader handoff decision tracked as [ADR-011](../../docs/decisions/ADR-011-approved-handoff.md). It uses the sibling `ticket-candidate` package as the authoritative validator for its embedded source candidate. It does **not** accept or change ADR-011. The local/private-pilot execution subset is separately accepted by [ADR-017](../../docs/decisions/ADR-017-codex-execution-trust.md); a real consumer trial and remote-production trust design remain outstanding.

The `tacua.*` contract names are candidate identifiers only. Schema `$id` values use the reserved `.invalid` top-level domain and do not imply control of a public DNS or package-registry namespace.

The package defines eight versioned schemas/artifacts, including one reusable evidence-item schema:

| Artifact | Contract version | Media type | Limit |
|---|---|---|---:|
| Build identity | `tacua.build-identity@1.0.0` | `application/vnd.tacua.build-identity+json;version=1.0.0` | Included in handoff limit |
| Evidence item | `tacua.evidence-item@1.0.0` | Embedded in manifest only | 100 MiB referenced-object metadata ceiling; no payload |
| Evidence manifest | `tacua.evidence-manifest@1.0.0` | `application/vnd.tacua.evidence-manifest+json;version=1.0.0` | 100 items |
| Approved handoff | `tacua.approved-handoff@1.1.0` | `application/vnd.tacua.approved-handoff+json;version=1.1.0` | 1 MiB canonical JSON |
| Agent trial | `tacua.agent-trial@1.0.0` | `application/vnd.tacua.agent-trial+json;version=1.0.0` | Included validation fields only |
| Registry assertion | `tacua.registry-assertion@1.0.0` | `application/vnd.tacua.registry-assertion+json;version=1.0.0` | At most 24 hours; authorizes one local execution issuer and revocation revision |
| Execution assertion | `tacua.execution-assertion@1.0.0` | `application/vnd.tacua.execution-assertion+json;version=1.0.0` | At most 15 minutes; OpenAI Codex only |
| Execution revocations | `tacua.execution-revocations@1.0.0` | `application/vnd.tacua.execution-revocations+json;version=1.0.0` | At most 24 hours; exact registry-current revision |

The deterministic Markdown view is UTF-8 `text/markdown` and is limited to 2 MiB. It contains an HTML-escaped, complete canonical JSON representation and an explicit warning that the file is not execution authorization. Exact re-render comparison is the cross-format equivalence rule.

## Security and integrity rules

- Structural validation and execution authorization are separate operations. An offline digest proves internal consistency only; it never proves who approved a ticket or whether it is still current.
- An agent-ready handoff is one immutable, explicitly approved ticket version. Its required `source_candidate.canonical_json` is the exact Tacua Canonical JSON for that approved `tacua.ticket-candidate@1.0.0` snapshot, with no trailing newline. The mirrored source ID, version, snapshot digest, and content digest must match the parsed candidate exactly.
- The embedded source is validated by the authoritative sibling ticket-candidate validator and must be approved, duplicate-key-free, NFC-normalized, safe-integer-only, secret-clean, and internally sealed. The handoff cross-binds its organization, project, build, session, manifest, authorized evidence set, approval, and deterministic convenience-ticket projection to that exact source.
- The approval binds the full source wrapper, projected ticket, build snapshot, evidence-manifest digest, and authority through `ticket_content_digest`; therefore even a change to a valid source field omitted by the convenience projection changes both the approved-content and handoff digests. It is still structural and non-executable. Executable validation additionally requires a current registry assertion and a separately signed, short-lived execution assertion obtained outside the handoff.
- `handoff_digest`, nested object digests, referenced-content digests, JSON artifact digest, Markdown artifact digest, and trial digest use SHA-256.
- Tacua Canonical JSON v1 is UTF-8 JSON with NFC strings, sorted keys, no insignificant whitespace, no floats, `ensure_ascii=false`, and a single trailing newline only for a JSON artifact. Object digests exclude only their own digest field and do not include that artifact newline.
- Available evidence contains only an internal `tacua-evidence` locator, content metadata/digest, provenance, and an immutable handoff-authorization decision. Raw media, logs, source, SaaS results, headers, bodies, credentials, and signed URLs are not embedded.
- Missing evidence is explicit and typed. It is never represented by an invented empty payload.
- Organization, project, session, evidence locator, approval, tested repository revision, trusted source registry, and agent-trial scopes must agree.
- An executable handoff must be the registry-current approved version and the consumer must be `openai_codex`. The local execution assertion binds the exact organization, project, ticket version, repository revisions, build ID/digest, handoff digest, evidence manifest and every evidence-item digest, allowed action set, expiry, nonce, signing key ID, revocation list ID and registry-current revocation revision. Expiry is exclusive: an artifact is invalid at its exact `expires_at` instant. Superseded exports, forged or expired assertions, nonces present in the supplied signed revocation list, revoked assertions/keys, untrusted evidence, and any scope mismatch are rejected. The nonce makes replay identifiable, but this offline validator has no nonce-consumption store; a real launcher must atomically consume or revoke it before starting the invocation.
- Summary, actual behavior, expected behavior, and every reproduction step link to typed claims/evidence. Claims distinguish direct, inferred, and unknown support and carry confidence explicitly.
- Blocking clarifications must be resolved before export. External writes, merge, and deployment are not authorized by this V1 handoff.
- `ticket_version` preserves the immutable backend candidate version. The first approved export may therefore be greater than one after draft and review transitions; supersession is expressed only by `supersedes_handoff_digest`, never inferred from the version number.
- Strict schemas reject unknown properties. The semantic validator additionally rejects tampering, duplicate JSON keys (including inside the embedded source), non-canonical executable artifact bytes, a non-canonical or newline-terminated source string, secret-like values/fields, cross-project references, unsupported source/evidence combinations, ungrounded claims, impossible chronology, unsafe integers, false fixed-trial outcomes, and stale handoffs. Version 1.0 handoffs are rejected rather than interpreted lossily.

The handoff's supersession block is an untrusted export-time observation. `validate-executable` requires a separately supplied current registry assertion, the locally issued execution assertion, the registry-current signed revocation list, and both external verification keys. Artifact signatures plus the local clock do not prove that no newer registry/revocation revision exists: a real launcher must retrieve the current pair through an authenticated path or use a trusted monotonic revision store and reject rollback, rather than accepting arbitrary cached files. HMAC-SHA256 is the dependency-free V1 local/private-pilot assertion mechanism; operators must issue keys outside the repository, give the registry and execution authorities distinct key IDs and distinct key material, rotate them, and publish each new revocation revision through the registry assertion. Validation and issuance fail closed on either kind of reuse. A future remotely distributed or multi-host production trust root still requires the asymmetric key-distribution decision in `ADR-011`. Every checked-in key and assertion is synthetic and fixture-only.

The built-in credential patterns catch obvious bearer tokens, common provider tokens, credential-bearing database URLs and common signed-URL parameters. They are defense in depth, not a complete DLP boundary. A real backend must apply policy filtering and secret scanning before rendering, audit the export, and resolve each evidence locator through project authorization without exposing credentials or signed URLs.

Likewise, an `agent-trial` digest proves internal consistency, not that an owner really accepted a fix. In the runtime system, acceptance/reopen and reporter-intervention events must come from the authenticated ticket/audit store; the synthetic fixture only exercises the shape and invariants.

## Offline commands

No third-party package or network access is required.

```sh
python3 scripts/handoff.py validate fixtures/positive/approved-handoff.json \
  --markdown fixtures/positive/approved-handoff.md
python3 scripts/handoff.py validate-executable-fixture
python3 scripts/handoff.py verify \
  fixtures/positive/approved-handoff.json \
  fixtures/positive/approved-handoff.md
python3 scripts/handoff.py validate-trial \
  fixtures/positive/agent-trial.json \
  fixtures/positive/approved-handoff.json \
  fixtures/positive/approved-handoff.md \
  --registry-assertion fixtures/positive/registry-assertion.json \
  --registry-key-file fixtures/positive/registry-key.synthetic.hex \
  --execution-assertion fixtures/positive/execution-assertion.json \
  --execution-revocations fixtures/positive/execution-revocations.json \
  --execution-key-file fixtures/positive/execution-key.synthetic.hex
python3 -m unittest discover -s tests -v
```

`validate` is deliberately structural and prints that it is not execution trust. `verify` also requires the downloaded JSON bytes to be canonical and checks exact Markdown equivalence. `validate-executable` is the only real-time CLI path that authorizes execution. It always uses current UTC, has no clock-override argument, and requires live external trust inputs:

```sh
python3 scripts/handoff.py validate-executable HANDOFF.json \
  --markdown HANDOFF.md \
  --registry-assertion LIVE-REGISTRY-ASSERTION.json \
  --registry-key-file /trusted/runtime/path/registry-key.hex \
  --execution-assertion LIVE-EXECUTION-ASSERTION.json \
  --execution-revocations LIVE-EXECUTION-REVOCATIONS.json \
  --execution-key-file /trusted/runtime/path/execution-key.hex

```

The checked-in assertions deliberately expire. `validate-executable-fixture` remains reproducible by using one fixed test instant only after requiring the exact checked-in synthetic organization, project, app, registry/execution assertions, revocations, issuers, key IDs, key bytes and key filenames. It accepts no paths or clock arguments and prints that it never grants production authority. This fixture-only branch cannot be selected through `validate-executable`. Trial validation is historical: it binds the digests of all three trust artifacts and verifies that the trial started and completed inside both authenticated assertion windows.

`issue-execution` constructs authority; it does not launch Codex, acquire or
expose Codex authentication, consume the nonce, or bypass a sandbox/approval.
A real launcher is a separate integration gate. Before launch it must verify
and atomically consume the nonce, compare the effective command and configuration
to the assertion's exact non-interactive
`codex exec --ephemeral --sandbox workspace-write`, network-off,
`--output-schema` profile, and scope authentication to only that invocation
without placing it in repository-controlled code. A controlled Codex state and
configuration must disable web search plus every unapproved MCP/app/hook, prove
command networking is off, and expose only exact-revision authorized repository
checkouts; user or project configuration cannot be allowed to widen the profile.
It must obtain the registry/revocation pair through an authenticated current
lookup or trusted monotonic revision state and reject rollback. Any mismatch
must fail closed.

The durable CI command is:

```sh
python3 scripts/handoff.py validate-executable-fixture && python3 -m unittest discover -s tests -v
```

`seal` and `seal-trial` print canonical JSON with recomputed digests. They are fixture/authoring helpers, not an approval mechanism: sealing an unapproved or unsafe document does not make it trusted or executable.

## Compatibility rule

Consumers must require an exact supported `contract_version` and media type. Unknown major/minor versions are rejected; there is no silent field dropping or fallback. A future compatible change requires a new schema/version and migration/conformance fixtures. This candidate deliberately makes optional evidence unavailable states explicit instead of widening schemas through unknown properties.

## Candidate acceptance work still required

The synthetic fixtures prove local contract behavior only. Before a remotely distributed or multi-host production trust path is accepted, run the agent-trial schema against a real, safely authorized mobile-app ticket; measure owner acceptance/reopen state and reporter intervention; test registry freshness and revocation publication against the actual backend registry/evidence resolver; choose and review the asymmetric production key policy; run cross-language canonicalization conformance; validate runtime DLP; and obtain the required owner plus security/AI review.

All files in this directory are licensed under Apache-2.0. Source files carry SPDX identifiers; JSON Schemas use `$comment` because JSON has no comments.
