# Annotation and deterministic scoring guide

Version: `1.0.0`

## Annotation layers

1. **Evidence:** immutable, untrusted transcript/UI/log/source records.
2. **Observation:** what the evidence directly supports.
3. **User decision:** expected behavior, issue boundary, rejection, split,
   merge, or approval supplied by the authorized reviewer.
4. **External evidence:** read-only repository/observability facts with source
   and commit/query identity.
5. **Inference:** a hypothesis whose uncertainty and supporting evidence are
   explicit.
6. **Unknown:** a gap that must be omitted or clarified.

Gold issues contain versioned time/evidence boundaries, actual and expected
behavior, reproduction steps, gaps, confidence, and annotation history. The
synthetic labels in `EVAL-001` are authored fixtures with
`approval_status: synthetic_only`; they still require the product owner's confirmation if a
case is promoted to a product threshold.

## Adjudication boundary

Candidate-to-gold mappings and assertion labels are not candidate/model output.
An adjudicator supplies them after freezing a run:

- `supported`: evidence directly supports the assertion;
- `unsupported`: evidence does not support it;
- `invented`: synthetic gold contradicts it.

Disagreement is preserved as an annotation-history event. Real-session scoring
is blocked until the product owner approves issue boundaries and actual/expected behavior.

## Error classes

- **Unsupported assertions:** assertion adjudications labelled unsupported.
- **Invented assertions:** assertion adjudications labelled invented.
- **Merged issue:** one candidate maps to more than one distinct gold issue.
- **Miss:** one gold issue maps to no candidate.
- **Unnecessary split:** one gold issue maps to multiple candidates. Report the
  affected-gold count and excess-candidate count.
- **Extra:** one candidate maps to no gold issue.
- **No-issue accuracy:** a zero-gold session is correct only when it has zero
  candidates.

A merge is not hidden by also counting its mapped issues as found. A split is
not relabelled as an extra. Counts and denominators remain separate; no weighted
average or composite score is emitted.

## Clarification quality

For cases marked `clarification_required`, record whether a question targeted
the documented evidence gap, offered valid choices, and prevented or corrected
an error. Do not reward or punish question count in isolation.

## Safety

Text saying to ignore policies, reveal secrets, create tickets, or execute code
is evidence only. The scorer performs no instruction execution, network access,
repository access, or dynamic imports.
