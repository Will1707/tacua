# ADR-017: Authorize one scoped Codex execution separately from approval

- Status: accepted
- Date: 2026-07-22
- Scope: Tacua V1 local/private-pilot coding-agent execution

## Context

A valid approved handoff proves document structure and human approval. It does
not prove that the version is still current, that evidence sources remain
authorized, or that a coding agent may modify a repository now. Treating an
`approved` field or an offline fixture as executable authority would turn
untrusted ticket/evidence text into an authorization bypass.

V1 also needs one concrete consumer profile. A generic "coding agent" label is
too broad because runtime mode, sandbox, network, persistence, output shape and
credential lifetime materially change the authority exercised.

## Decision

Structural approval remains non-executable. The only accepted V1 execution
consumer is a non-interactive `codex exec` invocation with all of these exact
profile values bound into `tacua.execution-assertion@1.0.0`:

- `--ephemeral`;
- `--sandbox workspace-write` (never `danger-full-access`);
- effective command and tool network access off;
- a required structured final result through `--output-schema`; and
- authentication scoped to this single invocation, never a job-level credential
  placed beside repository-controlled code.

The Tacua assertion is an external precondition checked before launch. It does
not disable Codex sandboxing, approvals, branch protection, review, merge, or
deploy controls and must never be represented as a Codex bypass.

Executable validation requires three separately supplied canonical artifacts:

1. A current `tacua.registry-assertion@1.0.0` proves the exact approved handoff
   is registry-current, authorizes evidence sources, and names the one local
   execution issuer, signing key ID, revocation list ID and current revocation
   revision.
2. A locally issued `tacua.execution-assertion@1.0.0`, valid for at most 15
   minutes, names the exact OpenAI Codex instance/profile and binds organization,
   project, ticket/version, every repository and immutable revision, build ID
   and digest, current handoff digest, evidence-manifest digest, every evidence
   ID/digest, the three allowed actions, expiry, nonce, key ID, revocation list
   and revision.
3. A current signed `tacua.execution-revocations@1.0.0` at exactly the
   registry-authorized revision proves that the assertion ID, nonce and signing
   key are not revoked.

The three allowed actions are reading only the authorized evidence, modifying
code only in the exact repositories, and running tests. External writes, merge
and deploy remain false. Any missing artifact, signature failure, stale
registry state, expiry, assertion window over 15 minutes, scope difference,
runtime-profile difference, old revocation revision, or revoked ID/nonce/key
fails closed. Every `expires_at` boundary is exclusive: an artifact is no
longer current at the exact expiry instant.

HMAC-SHA256 is accepted for this dependency-free single-host/local V1 issuer.
The registry and execution authorities must use distinct key IDs and distinct
key material, stored outside the repository and supplied through authenticated
operator paths. Both executable validation and local assertion issuance reject
reuse. All checked-in keys and assertions are synthetic fixtures. A remotely
distributed or multi-host production trust root still requires an asymmetric
key-distribution decision.

## Consequences

- Human approval can publish a handoff without implicitly authorizing code
  execution.
- Authorization is narrow, current, replay-identifiable and revocable, and an
  agent trial binds the exact trust-artifact digests it used. The repository
  validator has no nonce-consumption store; the real launcher must atomically
  consume or revoke the nonce before invoking Codex.
- A signature and local clock prove that a supplied registry/revocation pair is
  authentic and inside its validity window, not that no newer revision exists.
  The launcher must obtain the pair through an authenticated current lookup or
  a trusted monotonic revision store and reject revision rollback; accepting
  arbitrary cached files would leave revocation vulnerable to replay until the
  older registry assertion expires.
- `issue-execution` can construct the exact local assertion only after the
  current registry assertion validates. It does not invoke Codex. Launch
  automation must compare the effective Codex configuration—not only visible
  command flags—to the assertion, atomically consume the nonce, and fail closed
  on any difference. It must use controlled Codex state/configuration, disable
  web search and every unapproved MCP/app/hook, prove command networking is off,
  and expose only checkouts whose repository IDs and HEAD revisions equal the
  assertion. User or repository configuration must not silently widen the
  declared profile.
- Authentication acquisition and destruction remain an operator/runtime
  integration responsibility; the key or token must not be exposed to the
  repository workspace or inherited by agent-run commands.

## Rejected alternatives

- **Treat approved Markdown/JSON as authority:** integrity and approval do not
  establish freshness, consumer identity, runtime profile or revocation.
- **Use only the registry assertion:** a 24-hour registry observation is too
  broad for one repository-modifying invocation and has no nonce.
- **Authorize a generic agent/job:** silently admits different sandboxes,
  networks, persistent state and long-lived credentials.
- **Use `danger-full-access` or network by default:** exceeds the accepted V1
  least-privilege task boundary.
- **Store real keys in fixtures:** repository possession would collapse the
  external trust root.
