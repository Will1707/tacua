# Tacua EXP-007 Docker topology probe

This directory contains a disposable, deliberately non-production probe for one
narrow question: can a provider-neutral, versioned Docker image satisfy basic
packaging and lifecycle contracts without required egress or a Tacua-hosted
service?

It does **not** implement or select Tacua's API, database, object storage, queue,
model runtime, authentication, deployment topology, or production migration
strategy.

Run the local conformance phase from the repository root:

```sh
python3 experiments/docker-topology-probe/conformance.py
```

The harness refuses to reuse any exact experiment resource name. It labels all
created Docker resources with `tacua.experiment=tacua-exp007`, binds any published
test port only to `127.0.0.1`, and verifies ownership before removal. Successful
runs remove their containers and volumes but retain the labelled image for a
future, explicitly authorized unchanged-artifact remote test.

Inspect or remove residual experiment resources safely:

```sh
python3 experiments/docker-topology-probe/cleanup.py
python3 experiments/docker-topology-probe/cleanup.py --execute
python3 experiments/docker-topology-probe/cleanup.py --execute --include-image
```

Generated evidence is written to the ignored local directory
`artifacts/docker-topology-probe/EXP-007/`.
