# ADR-011: approved agent-handoff candidate

- Status: proposed
- Date: 2026-07-20
- Scope: `contracts/approved-handoff`

## Context

Tacua must hand an approved ticket to coding agents without confusing a valid
document with permission to execute. Markdown is useful to people and agents,
while canonical JSON is useful to policy and automation. Either representation
can be stale, tampered with, cross-project, or structurally valid but
unauthorized.

## Candidate decision

V1 will expose both canonical Markdown and JSON for the same immutable approved
ticket version. The candidate contract keeps two checks separate:

1. Structural validation proves schema, canonical bytes, matching render,
   evidence grounding, and internal scope consistency.
2. Executable validation additionally requires a current externally issued
   registry assertion bound to the exact organization, project, repositories,
   build, evidence, handoff digest, and expiry.

A reviewer approval changes candidate state; it does not mint execution trust.
Implementations must not treat an offline fixture key, `structural_only` result,
or the presence of an `approved` string as authority to modify a repository.

## Consequences

- Consumers can reject stale or altered handoffs before acting.
- Human-readable and machine-readable outputs cannot drift silently.
- Authentication, key distribution, revocation, DLP, and agent-runtime policy
  remain outside the local candidate and must be supplied by the deployment.
- The contract remains proposed until an independent real consumer validates it
  against a trusted registry and the owner accepts the operational policy.

## Current evidence

The repository contains deterministic positive and adversarial fixtures plus a
synthetic external-HMAC registry assertion. These validate candidate behavior
only; they are not production credentials or evidence that a real agent is safe
to execute.
