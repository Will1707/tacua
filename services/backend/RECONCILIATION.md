# Rootless deployment reconciliation

The checked-in reconciler restores one already-created Tacua Compose
deployment after a rootless Docker daemon interruption. It is deliberately not
a deployment tool: it never runs `up`, `create`, `run`, `pull`, `restart`, or
any removal command. A missing or replaced container, volume, network, image,
mount, label, port, security setting, healthcheck, or restart policy is drift
that requires an operator-controlled restore or deployment.

The V1 deployment keeps `restart: unless-stopped`. This lets a deliberate
maintenance stop remain stopped while the user timer handles daemon loss.

## Safety model

`seal` writes a private desired-state record and one immutable generation below
an existing owner-only directory. The desired record is canonical JSON,
digest-sealed, mode `0600`, and atomically replaced with file and directory
`fsync`. Its generation manifest binds:

- the exact resolved Compose bytes and SHA-256;
- the project and generation names;
- the exact three existing container IDs and their images, labels, users,
  mounts, networks, port bindings, security controls, healthchecks, log
  settings, and live `unless-stopped` restart policies;
- the exact project networks and state volume;
- the rootless Docker socket, daemon ID/root directory, cgroup-v2/systemd
  driver, and built-in seccomp/rootless security facts;
- content digests and paths for the public config and administrator secret;
- the processing-operation parent, rootless Docker user unit, and absolute
  Docker, systemd, and Tailscale executables.

The manifest is private because it contains host paths. Neither command output
nor systemd journal output includes those paths, IDs, origins, Docker/Tailscale
stderr, HTTP bodies, or credentials.

The user-systemd path adds a boot-scoped host-ownership attestation. Its small
`tacua-reconcile-lock.service` prerequisite deliberately runs without a
filesystem or user namespace so it can prove the host's real ownership and
directory ancestry. While holding the exact, non-replaced processing lock, it
publishes an owner-private anchor directly below logind's validated runtime
directory. The anchor binds the current boot and effective user to the exact
home, state, operation, generation, manifest, runtime, lock, public-config, and
administrator-secret identities. After validating the runtime parent through
a pinned directory descriptor, the prerequisite publishes a pending,
deliberately invalid record before it creates or validates the lock and before
it publishes the complete binding. An interrupted refresh therefore cannot
leave an earlier trusted anchor at the validated runtime path.

The main reconciler remains in its hardened filesystem namespace. It accepts
only that exact boot's anchor, pins the anchor, operation directory, public
config, administrator secret, and reconciler source read-only, and keeps only
the sealed state directory and shared lock writable. This allows the main unit
to verify host ownership even when a user service's mount namespace represents
host ancestors with an overflow identity; it does not broaden accepted owners
or make the prerequisite a deployment authority.

For this user-unit path, the sealed state and processing-operation directories
must be strict descendants of the effective user's passwd home, and every path
component below that home must be effective-user-owned. The public config and
administrator secret may be elsewhere, but every directory in each of their
host paths must be root- or effective-user-owned and must not be group- or
world-writable (apart from a root-owned sticky shared directory); each file's
immediate parent must be effective-user-owned. The config and secret files
themselves must be owned by the effective user and must retain the exact
identities sealed in the selected generation. These user-unit requirements are
stricter than the generic `seal` command's support for root-owned inputs.

For `running`, the timer reads and validates state, takes the exact processing
bridge lock, then re-reads state. It refuses any surviving durable processing
operation directory. It starts only the sealed user Docker unit when inactive,
attests the existing deployment, and uses only `docker compose start` against
the sealed snapshot. Container IDs must remain identical.

Tailscale Serve is part of that transaction. The current Serve state must be
either the exact Tacua listener or empty. Before Docker or container recovery,
the reconciler disables an active listener and proves Serve is exactly `{}`.
It restores Serve only after all three same-ID containers are healthy and both
backend and reviewer loopback smokes pass. It then repeats exact tailnet/Serve
validation and backend/reviewer HTTPS smokes. Any later failure disables Serve
again and proves it empty; failure to prove that emits only
`RECONCILE_PUBLIC_PATH_CRITICAL` and requires immediate operator attention.
An unknown or additional Serve configuration is never mutated and blocks
recovery.

## Seal an existing healthy deployment

Run this only after the normal deployment preflight and initial authenticated
loopback and tailnet HTTPS smokes have passed. Use the exact resolved Compose
JSON that created the live containers. The input must be a mode-`0600` regular
file; the reconciler copies it into the sealed generation.

```sh
install -d -m 0700 "$HOME/.local/state/tacua-reconcile"
install -d -m 0700 "$HOME/.local/state/tacua"

python3 -B services/backend/scripts/reconcile_compose_deployment.py seal \
  --state-directory "$HOME/.local/state/tacua-reconcile" \
  --generation 'generation-YYYYMMDDTHHMMSSZ' \
  --project tacua \
  --compose-json /absolute/private/resolved-compose.json \
  --config-file /absolute/private/config.json \
  --admin-secret-file /absolute/private/admin-secret \
  --operation-directory "$HOME/.local/state/tacua"
```

`--allow-mutable-image` exists only for the documented local private pilot. A
production seal requires immutable backend and reviewer image references.
`seal` refuses an existing desired-state record or generation; generation
promotion is an explicit maintenance/deployment operation, not a timer action.

## Install the user timer

First resolve the existing logind runtime directory as shown below. The anchor
path is exactly its direct child `tacua-reconcile.anchor.json`; it is
boot-scoped and must never be placed under persistent home state.

Render the eight absolute placeholders in
`systemd/tacua-reconcile.service.in` into
`$HOME/.config/systemd/user/tacua-reconcile.service`; do not use a shell
wrapper in `ExecStart`. They are the selected Python executable, this
checked-out reconciler, the sealed state directory, the boot-scoped anchor, the
exact shared lock, the sealed processing-operation directory, the public
config, and the administrator secret. The operation, config, and secret paths
must exactly match the selected sealed generation.

Render the four absolute placeholders in
`systemd/tacua-reconcile-lock.service.in` beside it, and copy
`systemd/tacua-reconcile.timer` beside both services. The
lock service receives the same Python, reconciler, state, and anchor paths. The
exact shared bridge lock remains
`/tmp/tacua-compose-processing-<project>.lock`; it is derived from the sealed
project rather than supplied to the prerequisite. The prerequisite creates or
validates that one file after boot without replacing it. This is necessary
because `/tmp` does not survive reboot.

The prerequisite intentionally omits `PrivateDevices`, `ProtectHome`,
`ProtectSystem`, and the other filesystem-namespace-generating directives so
its ownership proof describes the host rather than a transformed mount view.
It retains `UMask=0077`, `NoNewPrivileges`, `PrivateTmp=no`,
`RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, and a bounded
oneshot lifetime. The main service retains the full sandbox.
`ProtectSystem=strict` makes the rest of `/tmp` read-only to the main unit,
while the exact state and lock `ReadWritePaths` exceptions preserve only the
required mutable identities. Its `ReadOnlyPaths` pins the exact anchor,
operation, config, secret, and reconciler paths. Keep all units
owner-controlled and inspect the rendered services before enabling them.

Noninteractive SSH sessions may omit `XDG_RUNTIME_DIR` even when logind has an
existing runtime directory and the user manager is healthy. Resolve that
directory from logind, validate it instead of guessing or creating
`/run/user/<uid>`, and scope it only to the user-systemd commands:

```sh
tacua_user_runtime_directory="$(
  loginctl show-user "$(id -u)" --property=RuntimePath --value
)"
test -n "$tacua_user_runtime_directory"
test -d "$tacua_user_runtime_directory"
test "$(stat -c '%u' -- "$tacua_user_runtime_directory")" = "$(id -u)"
tacua_anchor_file="$tacua_user_runtime_directory/tacua-reconcile.anchor.json"

env XDG_RUNTIME_DIR="$tacua_user_runtime_directory" \
  python3 -B services/backend/scripts/reconcile_compose_deployment.py \
  prepare-lock \
  --state-directory "$HOME/.local/state/tacua-reconcile" \
  --anchor-file "$tacua_anchor_file"
env XDG_RUNTIME_DIR="$tacua_user_runtime_directory" \
  systemd-analyze --user verify "$HOME/.config/systemd/user/tacua-reconcile-lock.service"
env XDG_RUNTIME_DIR="$tacua_user_runtime_directory" \
  systemd-analyze --user verify "$HOME/.config/systemd/user/tacua-reconcile.service"
env XDG_RUNTIME_DIR="$tacua_user_runtime_directory" \
  systemd-analyze --user verify "$HOME/.config/systemd/user/tacua-reconcile.timer"
env XDG_RUNTIME_DIR="$tacua_user_runtime_directory" \
  systemctl --user daemon-reload
env XDG_RUNTIME_DIR="$tacua_user_runtime_directory" \
  systemctl --user start tacua-reconcile.service
env XDG_RUNTIME_DIR="$tacua_user_runtime_directory" \
  systemctl --user status tacua-reconcile.service
env XDG_RUNTIME_DIR="$tacua_user_runtime_directory" \
  systemctl --user enable --now tacua-reconcile.timer
```

The explicit one-shot run must succeed before enabling the timer. Its
`Requires=`/`After=` dependency ensures the host-view prerequisite has
succeeded and proves that the rendered main unit can consume the freshly
published anchor.
On later boots, the same dependency recreates the missing runtime anchor before
the main unit starts. Never render a durable path for `@ANCHOR_FILE@`, and do
not enable the timer if the manual run fails.

The service intentionally has no `Wants=` or `Requires=` dependency on Docker:
maintenance must not activate it. `PrivateTmp=no` is also intentional because
the processing bridge and reconciler must contend on the same `/tmp` lock.

Enable lingering once as a host administrator, then verify it. Without linger,
the user boot timer is not a no-login recovery mechanism.

```sh
loginctl enable-linger "$USER"
loginctl show-user "$USER" -p Linger
```

After installation, perform the daemon-loss acceptance test from the physical
host console: leave desired state `running` and the exact Serve listener
active, stop the rootless Docker user service without using
`docker compose stop`, and verify within the
bounded timer window that the same three container IDs return healthy and the
exact Serve listener is restored. Also reboot without logging in and repeat
the same-ID, health, loopback, tailnet, and HTTPS checks. Do not claim reboot
recovery from unit tests alone.

## Maintenance protocol

Every controlled processing, backup, restore, deployment, or shutdown workflow
must enter maintenance before stopping a container. The command durably marks
the transition, atomically publishes desired `maintenance`, disables and proves
the exact Serve listener empty, and only then retires the transition marker:

```sh
python3 -B services/backend/scripts/reconcile_compose_deployment.py maintenance \
  --state-directory "$HOME/.local/state/tacua-reconcile"
```

In settled maintenance, timer reconciliation validates the sealed records and
exits successfully without invoking systemd, Docker, or Tailscale. If the
maintenance command or host dies mid-transition, the timer resumes the durable
transition and disables/proves-empty Serve; it never starts Docker or a
container for a maintenance intent. Existing backup and processing recovery
rules still apply; this state does not authorize skipping offline verification
or clearing a durable processing journal.

After the operation has recovered the original deployment, use `running`.
While the desired state is still maintenance, this command takes the bridge
lock and publishes a private, digest-bound activation marker. It then refuses
a recovery journal, starts only the same existing containers if needed, and
performs the guarded Serve transaction and all local/public gates. Only then
does it atomically publish `running` and remove the marker. If the process or
host dies after Serve activation but before the state write, the timer sees the
durable marker and resumes the guarded transaction instead of taking the
maintenance no-op:

```sh
python3 -B services/backend/scripts/reconcile_compose_deployment.py running \
  --state-directory "$HOME/.local/state/tacua-reconcile"
```

If this command fails, desired state remains maintenance but its durable
activation marker remains a running intent; the timer will retry the guarded
transaction. After fixing the underlying backup/processing/deployment
obligation, it may therefore recover without another manual command. To cancel
that intent, use the guarded cancellation below. It first durably changes the
marker intent to `canceling`, then accepts only an exact Tacua Serve listener
or empty Serve, disables and proves an exact listener empty, and removes the
marker. If cancellation is interrupted after disable, the timer resumes the
canceling transaction and cannot reactivate Serve. Unknown Serve state leaves
the canceling marker intact and requires inspection.

```sh
python3 -B services/backend/scripts/reconcile_compose_deployment.py \
  cancel-activation \
  --state-directory "$HOME/.local/state/tacua-reconcile"
```

Never edit the JSON records by hand and never change to `running` merely
because `docker compose start` returned success.

## Stable outcomes

Success is one canonical, content-free JSON object with `healthy`, `recovered`,
or `maintenance`. `RECONCILE_HEALTHY` is mutation-free: enabling Serve or
finishing a durable activation is reported as `RECONCILE_RECOVERED`. Failure is
one stable code on stderr. In particular:

- `RECONCILE_DEFERRED`: the processing bridge owns the project lock;
- `RECONCILE_RECOVERY_REQUIRED`: a durable bridge operation must be recovered;
- `RECONCILE_CONTAINER_DRIFT` or `RECONCILE_RESOURCE_DRIFT`: exact live state
  differs from the seal;
- `RECONCILE_PUBLIC_PATH_CRITICAL`: Serve could not be proven empty after a
  failure.

Repeated failure is not authorization to recreate resources. Inspect the code,
recover from the retained generation/backup records, and keep Serve disabled
until every gate succeeds.
