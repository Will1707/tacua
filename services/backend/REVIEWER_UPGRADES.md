# Reviewer-only upgrades

This runbook covers the guarded path for changing the Tacua reviewer while
preserving the existing backend, ingress, networks, state volume, and sealed
deployment authority. It builds on the rootless deployment model in
[RECONCILIATION.md](./RECONCILIATION.md). It is not a general deployment or
rollback tool.

The upgrade commands emit bounded, path-free canonical JSON. The private evidence
they create contains host paths and runtime identities. Never paste a source
manifest, preparation receipt, candidate Compose file, transaction plan,
progress file, backup receipt, rendered unit, or unfiltered command log into a
ticket or chat.

## Architecture and mutation boundary

The workflow has two separately invoked stages:

1. `reviewer_upgrade_candidate_build.py` prepares and verifies a retained
   release. It reads a clean Git lineage worktree and the sealed running state,
   clones the requested commit into an isolated checkout, checks the restricted
   diff, runs the backend and reviewer verification suite, builds and verifies
   a uniquely tagged reviewer image, and publishes a content-addressed release.
2. `reviewer_upgrade_launcher.py launch` is the live mutation boundary. It
   re-proves the release, installs or updates the stable recovery units under
   one serial lock, publishes the durable transaction, and returns after the
   processing inhibitor has reached `quiescing`. The armed path unit then runs
   the transaction asynchronously.

Preparation never invokes the live Compose project, systemd, Tailscale, the
reconciler, or the launcher. It is not network- or Docker-free: it clones from
the canonical HTTPS GitHub URL derived from the repository identity, builds
images, and runs isolated container
verification. The verified reviewer image is deliberately retained for the
live stage. Preparation therefore must use the same rootless Docker image
store that the live stage will inspect, but it does not replace a live
container or change Serve.

The producer keeps its own evidence, logs, and scratch roots under an
owner-private `0077` creation mask and explicit private modes. Every bounded
child process receives a deterministic `0022` mask so the isolated Git
checkout and generated exports have the `0755` directory and `0644` file modes
required after root-owned files are copied into non-root container images.
Those child-created files remain below the attempt's `0700` ancestor, logs are
created explicitly as `0600`, and each command's child mask is recorded in the
verification evidence. The child mask does not change the producer's process
mask.

The candidate diff is intentionally narrow. Reviewer application and web code,
the checked-in reviewer-upgrade boundary, its tests and systemd templates, and
documentation are allowed. Backend package code, protocol contracts, mobile
SDKs, ingress, Compose files, Dockerfiles, and unrelated CI are rejected. The
candidate Compose document is derived from the sealed source Compose document;
its only semantic changes are the verified reviewer image and, when present,
relocation of the backend/reviewer build contexts and ingress file authority to
the retained source tree. On the first managed upgrade, that current source
authority is the clean installed worktree. On every later upgrade, it is the
exact, fully revalidated `source/` tree of the previous retained release. The
Git lineage worktree and current Compose source authority are deliberately
separate after the first upgrade.

The original self-hosted pilot baseline at commit
`1735e1ee25629e2f218225f3560ba75d5d43f068` predates this boundary. Its first
managed upgrade has a commit-bound, path-exact exception for the already
reviewed pilot diagnostics, CI verification, and processing-bridge files that
landed with the reconciliation machinery. No prefix is opened by that bridge:
an unlisted sibling path, the same path from any other installed commit, and
all normally forbidden runtime surfaces still fail closed.

The asynchronous transaction advances monotonically through:

```text
prepared -> quiescing -> maintenance -> backing_up -> backup_ready
-> replacing -> reviewer_ready -> sealing -> sealed_maintenance
-> promoting -> scheduled_maintenance -> activating -> complete
```

It first publishes a durable processing inhibitor, transitions the source
reconciler to maintenance, and proves Serve empty. The backup phase stops the
exact existing backend container, archives and independently verifies the
bound state volume plus config and secret evidence, then restarts the same
backend container and requires health and loopback smoke even when backup
creation fails. Only after `backup_ready` may the transaction run
`docker compose up -d --no-deps --no-build --pull never reviewer`. The backend
and ingress projections, project resources, and candidate image ID must remain
exact throughout.

After reviewer health and loopback smoke succeed, the transaction seals a new
maintenance reconciliation generation, promotes and verifies the target
reconciliation units, activates the target to `running` while the processing
gate is still held, removes the gate, proves a later reconciliation is
scheduled, writes an immutable completion receipt, and removes the active
selector. The old sealed state, transaction journal, and verified backup are
retained.

## Prepared-release contract

Preparation publishes this exact layout below the owner-private preparations
parent:

```text
releases/<64-lowercase-hex-generation>/
  source/
  source-manifest.json
  candidate-compose.json
  preparation-receipt.json
```

The generation name is the SHA-256 digest of a canonical release binding: the
complete source-tree digest, installed and candidate commits, repository
identity, exact source Compose path and digest, and exact tool bindings. This
keeps a later reviewed revert to an earlier full tree distinct from the older
retained release. The release directory is mode `0500`; source directories are
`0555`; source files are `0444` or `0555` according to their Git executable
bit; the manifest and receipt are `0400`; and candidate Compose is `0600`. The
manifest covers the complete exact tree and runtime closure. The receipt binds
the source Compose bytes, candidate Compose bytes, installed and candidate
commits, repository identity, reviewer image reference and ID, verification
command digest, and the exact Git, Python, Node, npm, Docker, and Bash binaries.

The pure candidate loader re-reads all of that evidence, the receipt-bound
source Compose file, and the receipt-bound tools. Extra files, symlinks,
special files, changed modes, changed inodes where bound, changed bytes, a
rebound tool, a missing old sealed source Compose document, or any Compose
delta outside the reviewer transition invalidates the release. The stable
resumer is rendered against `source/`, not a mutable Git checkout, so the
retained release must remain mounted at the same canonical absolute path for
the entire transaction and across reboot. It must also be retained for the
next upgrade because the next producer revalidates it as the current Compose
source authority.

## Prerequisites

Complete [the reconciliation installation and host acceptance
checks](./RECONCILIATION.md#install-the-user-timer) first. In particular:

- the current sealed reconciliation generation is healthy, settled
  `running`, and has no activation marker;
- its reconciliation service and timer are installed and proven, and the user
  manager has linger enabled for no-login boot recovery;
- rootless Docker and the user systemd manager are healthy;
- the clean Git lineage worktree supplied as `installed_repository` is at the
  currently deployed commit and
  has one exact canonical origin for the repository identity:
  `https://github.com/OWNER/REPOSITORY.git`,
  `git@github.com:OWNER/REPOSITORY.git`, or
  `ssh://git@github.com/OWNER/REPOSITORY.git`;
- the candidate is the exact commit fetched from `origin/main`, is a descendant
  of the installed commit, and has at least one permitted changed path;
- Node is exactly `v22.22.2` and npm is exactly `10.9.4`;
- there is enough private disk space for an isolated clone, logs, a complete
  retained source tree, verified images, and up to three backup attempts;
- every supplied path is canonical and absolute, with no symlink component;
  the source state directory and preparations parent already exist, are owned
  by the effective user, and are mode `0700`;
- the selected tools are absolute regular files owned by root or the effective
  user, not group- or world-writable, and the trusted command path resolves
  `bash`, `docker`, `node`, and `python3` to the supplied binaries; and
- the config file, administrator secret, operation directory, project name,
  and current state directory are the exact values in the sealed source
  manifest.

Resolve the logind runtime directory rather than guessing it. Keep all path
values in shell variables and do not enable shell tracing or print them:

```sh
set +x
umask 077

test -n "$XDG_RUNTIME_DIR"
test -d "$XDG_RUNTIME_DIR"
test "$(stat -c '%u' -- "$XDG_RUNTIME_DIR")" = "$(id -u)"
```

The commands below assume these private variables are already set:

- `producer_repository`, `installed_repository`, `installed_commit`,
  `candidate_commit`,
  `source_state_directory`, `state_parent`, `preparations_parent`, and
  `repository_identity`;
- `git_binary`, `python_binary`, `node_binary`, `npm_cli`, `docker_binary`,
  `bash_binary`, and `trusted_command_path`;
- `unit_directory`, `operation_directory`, `config_file`,
  `admin_secret_file`, `systemctl_binary`, `systemd_analyze_binary`,
  `journalctl_binary`, `home_directory`, `xdg_runtime_directory`, and
  `project`.

`state_parent` must be the direct parent of `source_state_directory`.
`processing_lock_file` must be exactly
`/tmp/tacua-compose-processing-$project.lock`, and `serial_lock_file` must be
exactly `$state_parent/reviewer-upgrade.lock`. Do not substitute stable
symlinks for any generation or release path.

## Stage 1: bootstrap the producer, prepare, and verify

The currently installed commit may predate this upgrade machinery, so never
assume its worktree contains the producer. For each candidate, create a
separate owner-private producer checkout from the canonical HTTPS origin and
prove that it is clean, exactly at the requested `origin/main` commit, and
descends from the installed commit. `producer_repository` must name a new
canonical absolute path whose parent is already owner-private:

```sh
repository_url="https://github.com/$repository_identity.git"

test ! -e "$producer_repository"
"$git_binary" clone --no-checkout -- \
  "$repository_url" "$producer_repository"
"$git_binary" -C "$producer_repository" fetch --force --prune origin main

fetched_candidate="$(
  "$git_binary" -C "$producer_repository" \
    rev-parse --verify 'FETCH_HEAD^{commit}'
)"
test "$fetched_candidate" = "$candidate_commit"
"$git_binary" -C "$producer_repository" checkout --detach "$candidate_commit"

test "$(
  "$git_binary" -C "$producer_repository" rev-parse --show-toplevel
)" = "$producer_repository"
test "$(
  "$git_binary" -C "$producer_repository" rev-parse --verify HEAD
)" = "$candidate_commit"
test "$(
  "$git_binary" -C "$producer_repository" remote
)" = 'origin'
test "$(
  "$git_binary" -C "$producer_repository" remote get-url --all origin
)" = "$repository_url"
"$git_binary" -C "$producer_repository" \
  merge-base --is-ancestor "$installed_commit" "$candidate_commit"
test -z "$(
  "$git_binary" -C "$producer_repository" \
    status --porcelain=v1 --untracked-files=all
)"
```

Do not reuse a checkout that fails any proof and do not run a producer copied
out of an unproved tree. The producer independently fetches and re-proves the
same candidate and lineage before publishing a release.

Invoke the proven producer with all tools named explicitly. The
`--installed-repository` argument still names the separate clean Git lineage
worktree at `installed_commit`; it does not name `producer_repository`:

```sh
"$python_binary" -B \
  "$producer_repository/services/backend/scripts/reviewer_upgrade_candidate_build.py" \
  --installed-repository "$installed_repository" \
  --installed-commit "$installed_commit" \
  --candidate-commit "$candidate_commit" \
  --source-state-directory "$source_state_directory" \
  --preparations-parent "$preparations_parent" \
  --repository-identity "$repository_identity" \
  --git "$git_binary" \
  --python "$python_binary" \
  --node "$node_binary" \
  --npm-cli "$npm_cli" \
  --docker "$docker_binary" \
  --bash "$bash_binary" \
  --command-path "$trusted_command_path"
```

Success exits zero and emits one canonical JSON object with
`code=REVIEWER_UPGRADE_CANDIDATE_BUILT` and `status=succeeded`. Its remaining
fields are the candidate commit, generation ID, receipt digest, source
manifest digest, and reviewer image reference and ID; none is a host path or
credential. Invalid CLI input exits `2`. Other preparation failures exit `1`
and emit only `{"code":"...","status":"failed"}` on stderr.

Record the `generation_id` from the success object without printing private
variables, then derive the exact retained paths:

```sh
generation_id='<64-lowercase-hex value from the success object>'
release_root="$preparations_parent/releases/$generation_id"
candidate_repository="$release_root/source"
candidate_compose="$release_root/candidate-compose.json"
```

Do not copy, chmod, edit, or add anything to the published release. A repeated
preparation for the same tree revalidates the existing release and image; it
does not silently replace conflicting evidence.

For a later managed upgrade, advance or recreate the clean Git lineage
worktree so `installed_repository` is exactly at the currently deployed commit
before selecting its descendant candidate. Do not repoint the sealed state or
edit its Compose file: the producer derives the current source authority from
that sealed Compose document and accepts only
`$preparations_parent/releases/<generation>/source`, fully validated as the
previous release for the same repository and installed commit. An unrelated
checkout, a missing prior release, or stale or tampered prior evidence fails
closed. Retain the prior release, its receipt-bound source Compose state, and
its bound tool binaries until the following upgrade has completed.

## Stage 2: launch the live transaction

Use `current_units=absent` only for the first installation of the three stable
reviewer-upgrade units. Use `current_units=managed` after a successful stable
unit installation. This describes the stable reviewer-upgrade units, not the
Compose containers. Do not change the value to bypass a classification error;
an exact rerun with `absent` can recover the documented interrupted
first-install state.

```sh
processing_lock_file="/tmp/tacua-compose-processing-$project.lock"
serial_lock_file="$state_parent/reviewer-upgrade.lock"
current_units='absent'

"$python_binary" -B \
  "$candidate_repository/services/backend/scripts/reviewer_upgrade_launcher.py" \
  launch \
  --release-root "$release_root" \
  --repository "$candidate_repository" \
  --state-directory "$source_state_directory" \
  --candidate-compose "$candidate_compose" \
  --unit-directory "$unit_directory" \
  --lock-file "$processing_lock_file" \
  --operation-directory "$operation_directory" \
  --serial-lock-file "$serial_lock_file" \
  --config-file "$config_file" \
  --admin-secret-file "$admin_secret_file" \
  --python "$python_binary" \
  --systemctl "$systemctl_binary" \
  --systemd-analyze "$systemd_analyze_binary" \
  --home "$home_directory" \
  --xdg-runtime-directory "$xdg_runtime_directory" \
  --project "$project" \
  --current-units "$current_units" \
  --path-deadline-seconds 15
```

A fresh success exits zero and emits
`code=REVIEWER_UPGRADE_LAUNCHED`, the generated `operation_id`, the current
phase/status (normally `quiescing`), and only digest evidence. Record the
operation ID. The launcher has already published the durable selector and
processing inhibitor at this point; it is not permission to issue manual
Docker, Compose, reconciler, or Tailscale commands. An exact rerun recovers a
recognized partial bootstrap or already-prepared launch and otherwise fails
closed on conflicting evidence.

Do not call `reviewer_upgrade_transaction.py prepare` directly for normal
operations. The launcher is what binds the retained release, stable unit
snapshot, bootstrap receipt, and transaction publication under the same
serial lock.

## Asynchronous and reboot recovery

The stable `tacua-reviewer-upgrade-resume.path` watches only for
`$state_parent/upgrades/active.json`. The launcher proves that path unit is
enabled, active, and waiting before it publishes the transaction. Once the
launcher releases the serial lock, the path unit starts
`tacua-reviewer-upgrade-resume.service` against the retained candidate
repository.

Each resumer invocation has `TimeoutStartSec=45min` and `RuntimeMaxSec=45min`.
This is a per-invocation bound, not a promise that the whole upgrade finishes
within 45 minutes. Exit status `1` is a deliberately classified retryable
failure; systemd restarts after five seconds with no start-limit interval.
Exit status `78` is fatal and is listed in `RestartPreventExitStatus`, so it
stops the hot retry loop for operator inspection. A timeout is also a service
failure and is eligible for restart.

The plan, candidate Compose copy, phase checkpoints, backup ledger, sealed
state attempts, completion receipt, and active selector are durable. After a
real reboot, the stable lock prerequisite recreates or validates the lost
`/tmp` processing-lock inode, and the transaction records a new boot-scoped
lock epoch before resuming. The enabled path unit sees the still-present
active selector and continues from the latest validated checkpoint. This
no-login behavior depends on the user manager being started at boot, so linger
is mandatory and must be physically reboot-tested; unit tests alone do not
prove host scheduling.

## Safe status and outcome inspection

The transaction status command is read-only and prints no host path:

```sh
"$python_binary" -B \
  "$candidate_repository/services/backend/scripts/reviewer_upgrade_transaction.py" \
  status \
  --state-parent "$state_parent"
```

While active it returns
`code=REVIEWER_UPGRADE_STATUS`, the operation ID, phase, sequence, and status.
After completion and active-selector removal it returns exactly
`{"code":"REVIEWER_UPGRADE_IDLE","status":"idle"}`. Idle alone does not prove
that a particular operation completed, so retain the launch output and verify
its receipt as shown below.

Inspect only non-sensitive systemd properties:

```sh
env XDG_RUNTIME_DIR="$xdg_runtime_directory" \
  "$systemctl_binary" --user show tacua-reviewer-upgrade-resume.service \
  --property=ActiveState \
  --property=SubState \
  --property=Result \
  --property=ExecMainStatus

env XDG_RUNTIME_DIR="$xdg_runtime_directory" \
  "$systemctl_binary" --user is-enabled --quiet \
  tacua-reviewer-upgrade-resume.path
env XDG_RUNTIME_DIR="$xdg_runtime_directory" \
  "$systemctl_binary" --user is-active --quiet \
  tacua-reviewer-upgrade-resume.path
```

When the service is failed with `Result=exit-code`, `ExecMainStatus=78`
identifies a fatal stop. A retryable exit uses status `1` and normally moves
back into an automatic restart. To retrieve only the path-free application
failure object from the current boot's user journal, use a strict message
filter; do not dump the whole journal:

```sh
env XDG_RUNTIME_DIR="$xdg_runtime_directory" \
  "$journalctl_binary" --user \
  --boot \
  --unit=tacua-reviewer-upgrade-resume.service \
  --output=cat \
  --no-pager \
  --grep='^\{"code":"[A-Z0-9_]+","status":"failed"\}$'
```

For exact completion proof, use the operation ID captured from the launcher.
The following loads and validates the immutable plan, terminal progress, and
receipt, then prints only non-sensitive receipt fields:

```sh
transaction_directory="$state_parent/upgrades/$operation_id"

PYTHONPATH="$candidate_repository/services/backend/scripts" \
  "$python_binary" -B - "$transaction_directory" <<'PY'
import json
from pathlib import Path
import sys

import reviewer_upgrade_journal as journal

transaction = Path(sys.argv[1])
plan = journal.load_plan(transaction)
progress = journal.load_progress(transaction, plan)
receipt = journal.load_receipt(transaction, plan)
if progress is None or progress["phase"] != "complete" or receipt is None:
    raise SystemExit(1)
print(json.dumps({
    "phase": receipt["phase"],
    "receipt_digest": receipt["receipt_digest"],
    "sequence": receipt["sequence"],
    "status": "complete",
}, separators=(",", ":"), sort_keys=True))
PY
```

Finally prove the promoted reconciliation generation reports `running`; do not
print its path:

```sh
target_state_directory="$transaction_directory/sealed-state"

"$python_binary" -B \
  "$candidate_repository/services/backend/scripts/reconcile_compose_deployment.py" \
  status \
  --state-directory "$target_state_directory"
```

Require `{"code":"RECONCILE_STATUS","status":"running"}`, the terminal
receipt proof above, `REVIEWER_UPGRADE_IDLE`, an enabled and active reviewer
upgrade path unit, and the normal reconciliation timer checks from
[RECONCILIATION.md](./RECONCILIATION.md#install-the-user-timer) before declaring
success.

## Failure, recovery, rollback, and cleanup

- A preparation failure is pre-live. Fix the reported stable code and rerun the
  exact preparation. Failed attempts and their owner-private logs are retained
  for local diagnosis; only a successful publish or exact existing-release
  revalidation removes the named scratch checkout, staging, iOS export, and
  runtime directories. A stopped preparation can also leave its unique
  test-tagged Docker artifacts. Never use a broad Docker prune as recovery;
  retain the verified reviewer image and remove an isolated artifact only
  after proving its exact test identity is not receipt-bound. A timed-out or
  over-output command receives `SIGTERM` as one process group while its output
  is drained without exceeding the private log cap; it has up to 30 seconds to
  run its exact cleanup trap before the producer sends `SIGKILL` to that group.
- A launcher interruption may leave stable units and generation-scoped
  evidence installed before transaction publication. Rerun the exact launch
  command with the same release and `current-units` value. The launcher
  recognizes only its documented pending/current evidence and fails closed on
  anything else.
- A retryable resumer failure is already scheduled for retry. Do not race it
  with a hand-run resumer. For a fatal status `78`, inspect the stable code and
  current phase and correct only the external precondition. Then restart the
  exact stable service, without hand-typing a different transaction invocation
  or changing its arguments:

  ```sh
  env XDG_RUNTIME_DIR="$xdg_runtime_directory" \
    "$systemctl_binary" --user restart \
    tacua-reviewer-upgrade-resume.service
  ```
- There is no automated rollback command. The verified backup and old sealed
  generation are recovery evidence, not authorization to improvise a restore.
  Never delete `active.json`, edit JSON, remove the inhibitor, run Compose
  removal commands, change Serve manually, or replace units while a
  transaction is active. A rollback requires a separately reviewed restore
  and deployment procedure bound to the retained backup and generations.
- Do not prune the verified reviewer image, prepared release, old sealed state,
  transaction directory, backup attempts, stable unit snapshots, or
  preparation evidence during an active or failed transaction. The current
  implementation has no garbage-collection command. Even after exact success,
  retain them until an explicit retention procedure proves that no installed
  unit, active selector, transaction plan, or recovery requirement references
  them.

## Privacy rules

- Never pass credentials or launch tokens on these command lines. The producer
  disables interactive Git prompting and accepts only the repository identity,
  commits, paths, and explicit tool binaries.
- Never run these procedures with `set -x`, print the private shell variables,
  or paste process listings.
- Never `cat` preparation evidence, candidate Compose, transaction JSON,
  backup evidence, rendered units, or raw logs. They contain host paths,
  runtime bindings, container/image identities, and may contain diagnostic
  output.
- Use only the producer, launcher, transaction-status, strict receipt-summary,
  filtered failure-journal, and reconciliation-status outputs shown above for
  remote reporting. Replace even their commit, generation, operation, digest,
  and image values with placeholders when they are not needed for diagnosis.
- Keep the preparations parent, attempts, releases, state parent, operation
  directory, and backup trees owner-private. Do not move evidence through a
  world-readable temporary directory.
