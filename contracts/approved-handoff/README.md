<!-- SPDX-License-Identifier: Apache-2.0 -->

# Candidate approved-ticket handoff contract

This directory is a self-contained, implementation-candidate package for the decision tracked as [ADR-011](../../docs/decisions/ADR-011-approved-handoff.md). It does **not** accept or change that decision. It exists so the proposed boundary can be exercised by a real coding-agent trial before owner approval.

The `tacua.*` contract names are candidate identifiers only. Schema `$id` values use the reserved `.invalid` top-level domain and do not imply control of a public DNS or package-registry namespace.

The package defines five versioned artifacts and one reusable evidence-item schema:

| Artifact | Contract version | Media type | Limit |
|---|---|---|---:|
| Build identity | `tacua.build-identity@1.0.0` | `application/vnd.tacua.build-identity+json;version=1.0.0` | Included in handoff limit |
| Evidence item | `tacua.evidence-item@1.0.0` | Embedded in manifest only | 100 MiB referenced-object metadata ceiling; no payload |
| Evidence manifest | `tacua.evidence-manifest@1.0.0` | `application/vnd.tacua.evidence-manifest+json;version=1.0.0` | 100 items |
| Approved handoff | `tacua.approved-handoff@1.0.0` | `application/vnd.tacua.approved-handoff+json;version=1.0.0` | 1 MiB canonical JSON |
| Agent trial | `tacua.agent-trial@1.0.0` | `application/vnd.tacua.agent-trial+json;version=1.0.0` | Included validation fields only |
| Registry assertion | `tacua.registry-assertion@1.0.0` | `application/vnd.tacua.registry-assertion+json;version=1.0.0` | Short-lived candidate trust input |

The deterministic Markdown view is UTF-8 `text/markdown` and is limited to 2 MiB. It contains an HTML-escaped, complete canonical JSON representation. Exact re-render comparison is the cross-format equivalence rule.

## Security and integrity rules

- Structural validation and execution authorization are separate operations. An offline digest proves internal consistency only; it never proves who approved a ticket or whether it is still current.
- An agent-ready handoff is one immutable, explicitly approved ticket version. The approval binds the ticket, build snapshot, evidence-manifest digest, and authority through `ticket_content_digest`; executable validation additionally requires an authenticated registry assertion obtained outside the handoff.
- `handoff_digest`, nested object digests, referenced-content digests, JSON artifact digest, Markdown artifact digest, and trial digest use SHA-256.
- Tacua Canonical JSON v1 is UTF-8 JSON with NFC strings, sorted keys, no insignificant whitespace, no floats, `ensure_ascii=false`, and a single trailing newline only for a JSON artifact. Object digests exclude only their own digest field and do not include that artifact newline.
- Available evidence contains only an internal `tacua-evidence` locator, content metadata/digest, provenance, and an immutable handoff-authorization decision. Raw media, logs, source, SaaS results, headers, bodies, credentials, and signed URLs are not embedded.
- Missing evidence is explicit and typed. It is never represented by an invented empty payload.
- Organization, project, session, evidence locator, approval, tested repository revision, trusted source registry, and agent-trial scopes must agree.
- An executable handoff must be the registry-current approved version. A superseded export, forged assertion, expired assertion, untrusted evidence source, or digest that differs from the authenticated registry assertion is rejected.
- Summary, actual behavior, expected behavior, and every reproduction step link to typed claims/evidence. Claims distinguish direct, inferred, and unknown support and carry confidence explicitly.
- Blocking clarifications must be resolved before export. External writes, merge, and deployment are not authorized by this V1 handoff.
- Strict schemas reject unknown properties. The semantic validator additionally rejects tampering, duplicate JSON keys, non-canonical executable artifact bytes, secret-like values/fields, cross-project references, unsupported source/evidence combinations, ungrounded claims, impossible chronology, unsafe integers, false fixed-trial outcomes, and stale handoffs.

The handoff's supersession block is an untrusted export-time observation. `validate-executable` requires a separately supplied, current registry assertion plus an external verification key. The bundled HMAC assertion is a dependency-free candidate trust adapter, not an accepted signature policy; production key distribution, asymmetric signatures, rotation and revocation remain `ADR-011` decisions. The checked-in key and assertion are synthetic fixtures only.

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
  --registry-key-file fixtures/positive/registry-key.synthetic.hex
python3 -m unittest discover -s tests -v
```

`validate` is deliberately structural and prints that it is not execution trust. `verify` also requires the downloaded JSON bytes to be canonical and checks exact Markdown equivalence. `validate-executable` is the only real-time CLI path that authorizes execution. It always uses current UTC, has no clock-override argument, and requires live external trust inputs:

```sh
python3 scripts/handoff.py validate-executable HANDOFF.json \
  --markdown HANDOFF.md \
  --registry-assertion LIVE-REGISTRY-ASSERTION.json \
  --registry-key-file /trusted/runtime/path/registry-key.hex

```

The checked-in assertion deliberately expires. `validate-executable-fixture` remains reproducible by using one fixed test instant only after requiring the exact checked-in synthetic organization, project, app, assertion, issuer, key ID, key bytes and key filename. It accepts no paths or clock arguments and prints that it never grants production authority. This fixture-only branch cannot be selected through `validate-executable`. Trial validation is historical: it verifies that the trial started and completed inside the authenticated assertion window, so the checked-in synthetic trial remains reproducible after that window closes without authorizing a new execution.

The durable CI command is:

```sh
python3 scripts/handoff.py validate-executable-fixture && python3 -m unittest discover -s tests -v
```

`seal` and `seal-trial` print canonical JSON with recomputed digests. They are fixture/authoring helpers, not an approval mechanism: sealing an unapproved or unsafe document does not make it trusted or executable.

## Compatibility rule

Consumers must require an exact supported `contract_version` and media type. Unknown major/minor versions are rejected; there is no silent field dropping or fallback. A future compatible change requires a new schema/version and migration/conformance fixtures. This candidate deliberately makes optional evidence unavailable states explicit instead of widening schemas through unknown properties.

## Candidate acceptance work still required

The synthetic fixtures prove local contract behavior only. Before `ADR-011` can be accepted, run the agent-trial schema against a real, safely authorized mobile-app ticket; measure owner acceptance/reopen state and reporter intervention; test authorization against the actual backend registry/evidence resolver; choose and review the production signature/key policy; run cross-language canonicalization conformance; validate runtime DLP; and obtain the required owner plus security/AI review.

All files in this directory are licensed under Apache-2.0. Source files carry SPDX identifiers; JSON Schemas use `$comment` because JSON has no comments.
