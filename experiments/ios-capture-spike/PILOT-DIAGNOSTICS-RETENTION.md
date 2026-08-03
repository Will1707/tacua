# Host-side physical-pilot diagnostics retention

Physical-device automation can leave logs, filtered test receipts, device-tool
output, and other sensitive diagnostics on the Mac that drives the pilot.
Those files are separate from SDK media on the phone and from backend session
retention. They need their own bounded, enforceable lifecycle.

The repository-owned
[`manage_pilot_diagnostics.py`](scripts/manage_pilot_diagnostics.py) tool
provides that boundary without knowing an app name, device identifier, backend
origin, or private pilot path. It manages only direct children of one explicit,
canonical, owner-owned mode-`0700` operations directory. Never place the
operations directory in the repository, and never commit its contents.
Every ancestor must be owned by the invoking user or root and must not be
group/world writable, except for a root-owned sticky shared directory such as
the platform temporary directory.

## Managed operation contract

Each managed operation has an exact
`tacua-physical-pilot.<six alphanumeric characters>` name, mode `0700`, and a
mode-`0600` `retention.env` containing exactly:

```text
artifact_class=physical_pilot_diagnostics
created_at=<UTC timestamp>
delete_after=<UTC timestamp exactly seven days later>
```

Every descendant directory must be mode `0700`; every descendant regular file
must be mode `0600`, owned by the invoking user, and have exactly one hard
link. Symlinks, nested mount points, and special files are forbidden. An
operation that fails any check is left untouched for manual inspection.

Create the parent explicitly, then let the tool create operation directories:

```sh
operations_root='/absolute/private/path/tacua-pilot-operations'
install -d -m 0700 "$operations_root"

/usr/bin/python3 \
  experiments/ios-capture-spike/scripts/manage_pilot_diagnostics.py \
  create --operations-root "$operations_root"
```

The command returns only the random operation name. Automation should put all
host-side diagnostics under that operation and preserve the marker. The tool
sets an owner-only umask and uses an owner-private staging directory plus
atomic rename, file and directory `fsync`, and exclusive marker creation.

## Migrate legacy diagnostics without deleting them

Migration is dry-run by default. The legacy root must itself be canonical,
owner-owned, and mode `0700`. Name each direct child explicitly; paths,
recursive discovery, symlinks, nested mount points, special files, and
multiply linked files are rejected.

```sh
legacy_root='/absolute/private/path/legacy-pilot-harness'
tool='experiments/ios-capture-spike/scripts/manage_pilot_diagnostics.py'

/usr/bin/python3 "$tool" migrate \
  --operations-root "$operations_root" \
  --legacy-root "$legacy_root" \
  --entry 'one-private-log' \
  --entry 'one-diagnostics-directory'

# After inspecting the content-free count, repeat with explicit mutation:
/usr/bin/python3 "$tool" migrate \
  --operations-root "$operations_root" \
  --legacy-root "$legacy_root" \
  --entry 'one-private-log' \
  --entry 'one-diagnostics-directory' \
  --apply
```

`--apply` hardens every selected source before moving it on the same filesystem
into a managed operation. A crash or validation error never deletes or rolls
back evidence: any partial result remains inside an owner-private hidden
`.incomplete` directory that the scavenger deliberately ignores. Inspect and
reconcile that directory manually before retrying.

Migration begins a new seven-day host-diagnostics period. It does not claim
that already-old material previously met retention, and it does not alter or
delete backend evidence.

## Dry-run and apply the scoped scavenger

Run a dry pass before enabling deletion:

```sh
/usr/bin/python3 "$tool" sweep --operations-root "$operations_root"
/usr/bin/python3 "$tool" sweep --operations-root "$operations_root" --apply
```

The summary contains counts only. The sweep considers exact direct-child names
and exact seven-day markers, revalidates device/inode/owner/mode immediately
before removal, and deletes through directory-relative descriptors. It does
not follow links, cross filesystems, scan legacy locations, infer age from file
timestamps, or remove ambiguous entries.

## Enforce the deadline daily on macOS

A later pilot run is not a retention mechanism. Render and load the checked-in
daily `launchd` job from a stable, trusted checkout:

```sh
tool_path="$(pwd -P)/experiments/ios-capture-spike/scripts/manage_pilot_diagnostics.py"
launch_agents="${HOME}/Library/LaunchAgents"
schedule="$launch_agents/ai.tacua.pilot-diagnostics-retention.plist"

/usr/bin/python3 "$tool_path" render-launchd \
  --operations-root "$operations_root" \
  --tool-path "$tool_path" \
  --python-path /usr/bin/python3 \
  --output "$schedule"

plutil -lint "$schedule"
launchctl bootstrap "gui/$(id -u)" "$schedule"
launchctl kickstart -k "gui/$(id -u)/ai.tacua.pilot-diagnostics-retention"
```

The renderer writes a new mode-`0600` plist and refuses replacement. It embeds
no shell, validates that the interpreter and tool are canonical regular files
not writable by another user, runs once when loaded and every day at 03:17,
uses umask `077`, and invokes only the scoped `sweep --apply --quiet` command.
Standard output and error go to `/dev/null`, so the schedule cannot create its
own indefinitely retained logs. A deletion error or any ignored exact-name
operation produces a nonzero job exit; inspect `launchctl print` and run the
non-quiet dry sweep manually to obtain content-free counts.

Loading the plist is an operator action; rendering it does not modify the
current `launchd` state. Before moving or replacing the checkout, boot out the
old job, archive its plist, render a new one, validate it, and bootstrap it
again. Monitor the error log and investigate any ignored operations rather
than broadening deletion rules.

## Verification

The tests use synthetic temporary directories only:

```sh
PYTHONWARNINGS=error python3 -B -m unittest discover \
  -s experiments/ios-capture-spike/tests \
  -p 'test_pilot_diagnostics*.py' -v
```

They cover owner-only creation, exact retention metadata, dry-run semantics,
scope confinement, fail-closed handling of unsafe entries, content-preserving
migration, scheduled deletion, and shell-free `launchd` generation.
