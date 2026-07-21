# Evidence ablation plan

Version: `1.0.0`
Status: planned; no real or model runs completed

## Frozen base

For one approved issue, freeze the recording/transcript/keyframes, ticket task,
gold annotation version, app build, frontend/backend commit IDs, model and
prompt configuration, allowed tools, acceptance tests, and decoding parameters.
Run the same configuration in every applicable cell.

## Cells

| Cell | Media | Safe SDK context | Commit-scoped source | Bounded observability |
| --- | --- | --- | --- | --- |
| B0 | yes | no | no | no |
| C1 | yes | yes | no | no |
| C2 | yes | no | yes | no |
| C3 | yes | no | no | yes |
| C4 | yes | yes | yes | yes |

Add exactly one evidence class relative to B0 in C1–C3. C4 tests the combined
bundle but cannot identify an individual class's causal contribution. If a
connector is unavailable, record `unavailable` and do not substitute another
source.

## Evidence manifests

Each item records class, immutable ID/hash, capture window, source snapshot,
minimization/redaction state, authorization, and availability. App-specific
fields are default-deny. Credentials never enter manifests or prompts.

## Outcomes

Compare error classes independently, necessary clarifications, reporter active
seconds, candidate correction seconds, coding-agent reporter interventions,
candidate fix production, acceptance-test outputs, and the product owner's acceptance.
Record every non-evidence difference as a confound.

## Blocked inputs

Real authorized media, safe SDK output, fixed repository commits, optional
sanitized Sentry/PostHog exports or read-only connector access, a frozen model
configuration, and owner-approved gold/acceptance checks are not yet available.
