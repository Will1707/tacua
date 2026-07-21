# CONCIERGE-001: three-condition comparison protocol

Version: `1.0.0`
Status: frozen for synthetic preparation; blocked for real sessions

## Question

Does a narrated recording, and then a policy-minimized evidence bundle, reduce
the reviewer's active handoff and correction time while preserving or improving
ticket correctness and coding-agent autonomy?

## Eligibility and unit of analysis

An eligible task is a real mobile-app QA review performed against an authorized,
commit-identified build with a non-sensitive test account and dataset. A
session is excluded before analysis if consent, build identity, safe retention,
or repository authorization is missing. The unit of analysis is an approved
issue ticket; no-issue sessions are retained for false-positive measurement.

No sample size or numeric threshold is predeclared here. Every eligible session
the authorized reviewer supplies is included and its selection limits are reported.

## Conditions

1. **A — current manual workflow:** screenshots, written notes, manually
   authored ticket, and the normal coding-agent handoff.
2. **B — recording-only concierge:** recording, transcript, and keyframes;
   no SDK context, source, or observability evidence.
3. **C — evidence-bundle concierge:** condition B plus only the approved,
   minimized evidence classes in the run manifest.

No production Tacua system is implied. A researcher may assemble B and C by
hand. Evidence unavailable in a condition is marked unavailable and is never
silently replaced.

## Assignment and order

- Freeze the task, build, test data, acceptance check, timing rules, and
  evidence policy before viewing comparative outcomes.
- Do not reuse an already-understood bug across conditions. Assign comparable
  fresh tasks in rotating order `ABC`, `BCA`, `CAB`; record task difficulty and
  any order/learning confound.
- With only one eligible session for a condition, report it as a case study and
  do not infer a distribution or market-level effect.
- Condition C ablations follow the separate ablation protocol and never alter
  the repository snapshot or ticket task.

## Active-time measurement

Use `active-time-logging-v1.0.0.md`. Count only time when the reporter is
actively reviewing, narrating, authoring, correcting, answering a question, or
accepting/rejecting a ticket or fix. Do not count upload, transcription, model,
queue, build, or coding-agent wait time. Record each clarification interaction,
the evidence gap that caused it, and whether it prevented a downstream error.

## Output and correction rules

- Source evidence is immutable. Corrections append versioned events.
- One session may yield zero, one, or many issue candidates.
- The authorized reviewer may split, merge, reject, edit, or approve candidates.
- Observed fact, expected behavior, inference, unknown, and external evidence
  remain separate fields.
- A question should offer small, evidence-grounded choices when possible. It is
  judged by active time and corrected outcome, not by question count alone.
- Gold boundaries and actual/expected behavior require the authorized reviewer's approval before
  real results can be scored.

## Metrics

Report raw values per condition and session:

- active reviewer seconds per approved ticket;
- total correction seconds and correction event count;
- reporter interactions after ticket approval;
- first-pass fix acceptance;
- coding-agent autonomous completion by evidence class;
- unsupported and invented assertions, merges, misses, unnecessary splits,
  extras, and no-issue accuracy as separate counts and denominators.

Wall-clock agent time may be recorded operationally, but it is not a value
metric for this comparison.

## Coding-agent trial

After the authorized reviewer approves a ticket, freeze its JSON/Markdown handoff, evidence bundle,
repository commit, allowed tools, and acceptance tests. Use an isolated
worktree. The agent may propose a change and run declared checks but may not
merge, deploy, publish, or push. Record reporter questions, cited evidence,
candidate patch, actual test outputs, and the reviewer's acceptance decision. Never use
the agent's self-report as acceptance evidence.

## Disposition

The final memo may recommend proceed, simplify to recorder/exporter, revise, or
stop. Numeric value or AI thresholds are proposals until the product owner accepts them.

## Known single-reviewer confounds

Single-user familiarity, learning/order effects, task difficulty, changing app
commits, manual concierge skill, synthetic fixtures, and incomplete provider
evidence are recorded rather than averaged away.
