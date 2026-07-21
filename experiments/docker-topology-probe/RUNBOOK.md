# EXP-007 local packaging-probe runbook

This runbook operates only the disposable `tacua-exp007` probe. It is not a
Tacua deployment guide and must not be used with real data or credentials.

## Preconditions

- Run from the Tacua repository root with Python 3 and a reachable Docker
  daemon.
- Permit the public `python:3.13-alpine` pull. No registry push, public port,
  paid resource, remote host, model API, or Tacua service is used.
- Confirm the exact experiment inventory is empty before a fresh build:

  ```sh
  python3 experiments/docker-topology-probe/cleanup.py
  ```

  Expected: an empty `resources` array. If the retained labelled probe image is
  listed, either preserve it for an unchanged-artifact remote test or remove it
  explicitly with the final cleanup command below before rebuilding.

## Build and execute the local phase

Run the repeatable conformance harness:

```sh
python3 experiments/docker-topology-probe/conformance.py
```

Expected: exit code `0`. The harness is intentionally quiet on success and
writes evidence to the ignored local directory
`artifacts/docker-topology-probe/EXP-007/`.
Verify the terminal result:

```sh
jq '{outcome, error, tests: [.tests[] | {case_id, status}], remote_portability}' \
  artifacts/docker-topology-probe/EXP-007/run-manifest.json
```

Expected local outcome: `local-phase-passed`, every listed case `passed`, and
remote portability `blocked`. The full, exact Docker command sequence is in the
same manifest.

The harness performs these lifecycle operations automatically:

1. checks every fixed experiment container, volume, and image name is absent;
2. pulls the base, builds one non-production image, and records its content
   digest, portable archive checksum, labels, history, runtime user, and package
   metadata;
3. starts with `--network none`, a read-only root filesystem, a runtime-mounted
   synthetic configuration file, and labelled persistent volumes;
4. verifies `/healthz`, `/version`, UID/GID `65532:65532`, restart persistence,
   recreation persistence, structured shutdown, and an idle resource sample;
5. creates a pre-migration backup, migrates schema 1 to 2, proves a deliberate
   migration failure is atomic, and restores the pre-migration checksum;
6. creates another backup, removes only the labelled source state volume,
   restores into a new volume, and proves state checksums match;
7. rejects corrupt and incompatible backups without mutating restored state;
8. checks missing/invalid configuration, read-only volume permissions, a 4 KiB
   quota failure, and a loopback-only port conflict;
9. verifies the image content digest did not change; and
10. inventories, verifies, and removes all run-created containers and volumes.

The image `tacua-exp007-probe:0.1.0` is deliberately retained. The public base
image is not experiment-labelled and is never removed automatically.

## Failure recovery

The harness catches failures, writes a partial manifest, and attempts labelled
cleanup. If it is interrupted or cleanup reports an error:

```sh
python3 experiments/docker-topology-probe/cleanup.py
```

Review every listed name and label. Execute cleanup only when every target has
`tacua.experiment=tacua-exp007`:

```sh
python3 experiments/docker-topology-probe/cleanup.py --execute
```

The cleanup program refuses an unexpected label. Never replace its fixed names
with a wildcard, label-wide prune, or unrelated Docker resource.

To remove the retained probe image as well:

```sh
python3 experiments/docker-topology-probe/cleanup.py --execute --include-image
```

This does not remove the pinned `python:3.13-alpine` base because it is a shared, unlabelled
dependency and may predate the experiment.

## Future remote phase — blocked, do not execute yet

After a generic Linux/container host and secure artifact transport are
explicitly authorized, save the retained image once, record the archive SHA-256,
load that archive on the remote host, and verify the loaded image ID against the
local manifest before running the identical conformance cases. A rebuild on the
remote host fails the unchanged-artifact claim. Do not expose the probe publicly;
use no published port or bind only to a private/loopback interface.
