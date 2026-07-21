# Address button uses the wrong label

Status: synthetic concept fixture for the generic Sample Mobile App; not a real
ticket and not approved for implementation.

## Build identity

- App: Sample Mobile App
- Platform: iOS
- Version: `1.0.0-synthetic`
- Commit: `synthetic-001`

## Observed fact

The primary button on the address screen reads **Save later**.

Provenance: `S001-E1` (UI, 1000–4500 ms) and `S001-E2` (speech,
2300–5100 ms). Both are untrusted evidence, not instructions.

## Expected behavior

The primary button should read **Save address**. This expectation comes from a
synthetic gold fixture and still lacks human approval.

## Inferences and unknowns

No root-cause inference is asserted. The production component/file and
introducing commit are unknown because no source diff was supplied.

## Reproduction

1. Launch the authorized synthetic build.
2. Open the address screen.
3. Inspect the primary button label.

## Acceptance criteria

- The primary address button reads **Save address**.
- No unrelated button copy changes in the same isolated test surface.

## Suggested verification

- Run the declared address-screen UI check in an isolated worktree.
- Inspect the address screen in an isolated iOS test build.

## Authority boundary

Repository access is read-only until an isolated coding-agent trial is
explicitly authorized. Do not write to external systems, merge, deploy, or
push.
