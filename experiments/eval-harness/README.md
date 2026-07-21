# Tacua synthetic evaluation harness

This directory contains the safe, local preparation for `EXP-002` and
`EXP-003`. It is deliberately usable without a model, network access, package
manager, or third-party Python dependency.

The checked-in `EVAL-001` corpus is synthetic. Its labels are useful for
exercising the contracts and scorer, but they are **not** evidence that Tacua
works on any real app. Real-session collection, an authorized reviewer's
gold-label confirmation, model runs, coding-agent fix trials, and numeric
go/no-go thresholds remain blocked.

## Frozen versions

- corpus: `EVAL-001@1.0.0`
- candidate fixture: `FIXED-SYNTHETIC-CANDIDATES@1.0.0`
- annotation contract: `tacua.annotation@1.0.0`
- candidate contract: `tacua.candidate-run@1.0.0`
- evaluator: `tacua-evaluator@1.0.0`
- protocol: `CONCIERGE-001@1.0.0`

## Run locally

```sh
python3 src/validate_contracts.py
python3 src/evaluate.py \
  --corpus corpus/EVAL-001.v1.0.0.json \
  --candidates fixtures/candidates/FIXED-SYNTHETIC-CANDIDATES.v1.0.0.json \
  --compare fixtures/baselines/SYNTHETIC-BASELINE.v1.0.0.json
python3 -m unittest discover -s tests -v
```

The evaluator prints canonical JSON. It derives each error class separately:

- unsupported assertions (no valid supporting evidence);
- invented assertions (contradicted by the synthetic gold adjudication);
- merged distinct gold issues;
- missed gold issues;
- unnecessary splits of one gold issue;
- extra candidates that match no gold issue; and
- no-issue session accuracy.

Candidate-to-gold mappings and assertion support labels are adjudication data,
not model-visible input. A future model adapter must write candidate output
without these labels; a human then supplies a separately versioned
adjudication before scoring.

## Layout

- `schemas/`: JSON Schema 2020-12 contracts.
- `corpus/`: minimized synthetic evidence and provisional synthetic gold.
- `fixtures/candidates/`: a fixed, intentionally imperfect candidate run.
- `fixtures/baselines/`: the deterministic synthetic scorer regression baseline.
- `fixtures/handoff/`: one Markdown/JSON coding-agent handoff example.
- `fixtures/timing/`: example active-time event log.
- `protocols/`: frozen concierge, timing, ablation, and annotation methods.
- `src/`: standard-library-only validator, scorer, and timing summarizer.
- `tests/`: deterministic regression tests.

All screen, speech, log, and source strings are untrusted evidence. They must
never be interpreted as instructions by an evaluator or downstream agent.
