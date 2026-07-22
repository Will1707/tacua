# Local processing adapter

Tacua includes an opt-in, provider-neutral command adapter that can advance a
completed session through `transcribe`, `align`, `correlate`, `research`, and
`generate_tickets`. It does not select or install a speech model, LLM, API,
repository connector, or SaaS integration. Normal backend startup does not
load a command, claim a job, or spawn a child process.

The V1 worker is deliberately an **exclusive offline worker**. It acquires the
same lifetime state-volume lock as the HTTP service and operator restore tools.
Stop the HTTP container before running it, then restart the service afterward.
This keeps SDK deletion, retention erasure, and evidence reads from racing a
processor that still has the recording open. A later same-process scheduler
can improve availability without weakening that invariant.

## Command document

Enabling the adapter requires a separate, mode-`0600`, canonical JSON file. It
is not part of public deployment config and has no default value.

```json
{"argv":["/usr/local/bin/python","/opt/tacua-processor/processor.py","--input","{input}","--output-directory","{output_directory}"],"contract_version":"tacua.local-processing-command@1.0.0","max_stderr_bytes":65536,"max_stdout_bytes":4194304,"timeout_seconds":240}
```

The file must contain exactly those five fields. `argv` is executed directly;
there is no shell, interpolation, glob expansion, or command substitution.
`{input}` and `{output_directory}` must each be one complete argument and occur
exactly once. The executable path must be absolute. Arguments containing any
other brace are rejected. Timeout is 1–240 seconds, stdout is 1 KiB–16 MiB,
and stderr is 1 KiB–1 MiB. Exceeding either pipe bound or the timeout kills the
child process group. Stderr and invalid stdout are never copied into job state
or an operator error.

The child receives a fixed minimal environment containing only `LANG`,
`LC_ALL`, and `PATH`. Tacua does not pass or inherit the admin secret, SDK bearer
secret, credential ID, launch code, lease token, API key, or repository token.
If an adapter needs provider or connector authority, the operator must design
and authorize that boundary separately; this V1 package does not invent one.

## Processing input

The `{input}` argument is a read-only `/dev/fd/<n>` path for exact canonical
JSON with this shape:

```json
{
  "contract_version": "tacua.local-processing-input@1.0.0",
  "input_digest": "sha256:<digest of the object without this field>",
  "binding": {
    "organization_id": "...",
    "project_id": "...",
    "session_id": "...",
    "build_id": "...",
    "build_identity_digest": "sha256:...",
    "job_id": "...",
    "job_version": 2,
    "job_digest": "sha256:...",
    "stage_name": "transcribe",
    "worker_id": "worker_local"
  },
  "job": { "...": "the verified lease-owned job head, without its lease" },
  "capture": {
    "build_identity": { "...": "the sealed build identity" },
    "manifest": { "...": "the sealed capture manifest" },
    "session_created_at": "...",
    "session_completed_at": "...",
    "raw_media_expires_at": "...",
    "derived_data_expires_at": "...",
    "segments": [
      {
        "segment_id": "...",
        "sequence": 0,
        "content_type": "video/mp4",
        "size_bytes": 123,
        "content_digest": "sha256:...",
        "sidecar_digest": "sha256:...",
        "received_at": "...",
        "read_only_path": "/dev/fd/<n>"
      }
    ],
    "diagnostics": [
      {
        "envelope_id": "...",
        "envelope_digest": "sha256:...",
        "size_bytes": 123,
        "content_digest": "sha256:...",
        "received_at": "...",
        "read_only_path": "/dev/fd/<n>"
      }
    ]
  }
}
```

Before spawning the child, Tacua revalidates the live stage lease, job head,
completion pair, segment/diagnostic request-receipt pairs, session/build
bindings, canonical envelopes, file ownership, paths, sizes, and SHA-256
digests in one deletion-excluding critical section. Evidence descriptors are
opened `O_RDONLY`, admitted object files are changed to mode `0400`, and only
those descriptors plus the unlinked read-only input descriptor are inherited.
The database, admin secret file, SDK requests containing credential IDs, and
lease token are not inherited. One invocation accepts at most 512 evidence
files, 4 GiB of referenced evidence bytes, and 16 MiB of canonical input
metadata; larger completed sessions fail safely for an explicitly redesigned
processor boundary rather than exhausting descriptors or memory.

The worker retains that deletion exclusion until the child exits, its result
is checked, and all descriptors are closed. A crash may leave only an output
workspace under the backend temporary directory; the next ordinary backend or
worker startup removes that bounded `processing-*` workspace before opening
the service. No copy of raw media is created.

## Processor result

Stdout must contain exactly one canonical JSON object and no trailing newline.
Every stage repeats the input binding:

```json
{"contract_version":"tacua.local-processing-result@1.0.0","disposition":"checkpoint","input_digest":"sha256:...","job_digest":"sha256:...","job_id":"job_...","result":null,"session_id":"session_...","stage_name":"transcribe"}
```

Only the first four stages may return `checkpoint`. `generate_tickets` must
return `disposition: "terminal"` and a result with exactly `disposition`,
`summary`, and `candidates`:

```json
{
  "disposition": "candidates_created",
  "summary": "Bounded human-readable summary",
  "candidates": [
    {
      "candidate": { "...": "sealed tacua.ticket-candidate@1.0.0" },
      "evidence_manifest": { "...": "sealed evidence manifest" },
      "previews": [
        {
          "evidence_id": "evidence_frame",
          "preview_revision_id": "preview_primary",
          "content_type": "image/png",
          "size_bytes": 123,
          "content_digest": "sha256:...",
          "body_file": "preview-primary.png"
        }
      ]
    }
  ]
}
```

Preview files must be direct children of `{output_directory}` with safe names.
Symlinks, hard links, directories, special files, unreferenced files, duplicate
references, digest mismatches, and replaced output directories are rejected.
Each preview is at most 2 MiB; one result may reference at most 512 files and
64 MiB total. Use `no_issue_detected` with an empty `candidates` array for a
successful zero-ticket result.

The adapter only converts this closed document into the existing
`ProcessingResult` and `PublicationCandidate` types. The backend then applies
the authoritative ticket/evidence validators and the atomic publication
transaction from ADR-014. Invalid output records a bounded retryable processor
failure and never exposes a partial candidate.

## Run once or drain

From a source checkout:

```sh
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.processing_worker \
  --config-file /absolute/path/config.json \
  --admin-secret-file /absolute/path/admin-secret \
  --command-file /absolute/path/processor-command.json \
  --worker-id worker_local \
  --run-once
```

`--run-once` processes at most one stage. Use `--drain --max-stages 100` to
continue until the queue is empty or that explicit bound is reached. Output is
one content-free canonical summary containing counts, queue state, and the last
job ID. The worker refuses to start while the server, backup/restore, or another
worker owns the state directory.

For the checked-in Compose deployment, stop `backend`, run an ephemeral
container with `--entrypoint python` and explicit read-only mounts for the
command document and adapter implementation, then start `backend` again. Do
not add either mount to the always-on service unless processing is intentionally
enabled.

## Egress and residual isolation boundary

The checked-in Compose network is `internal: true`; the backend and local
processor therefore retain the V1 default-deny egress posture. Do not attach an
external network or pass provider credentials merely to make a sample work.
Any future network authorization needs an explicit decision, destination allow
list, credential boundary, and corresponding processing-job authorization.

Read-only descriptors, mode-`0400` objects, a minimal environment, closed file
descriptors, private workspaces, exact argv, and no shell prevent accidental
scope expansion. They are **not a complete sandbox for hostile code**: the
child runs as the same service UID, so it may discover or chmod same-UID paths,
walk the mounted filesystem, or consume disk through output files before Tacua
can reject them. Run only trusted adapter code in V1. Strong isolation for an
untrusted model/plugin requires a separate UID/container or sandbox with a
read-only evidence mount, an output quota, seccomp/resource limits, and no
network; this repository cannot guarantee that solely from an unprivileged
Python parent process.
