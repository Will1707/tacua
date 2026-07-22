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
`LC_ALL`, `PATH`, and the non-secret `TACUA_ADAPTER_TIMEOUT_SECONDS` value that
the parent is actually enforcing. Tacua does not pass or inherit the admin
secret, SDK bearer secret, credential ID, launch code, lease token, API key, or
repository token.
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

For schema-4 iOS captures, `capture.manifest.app_audio_accounting` is the
persisted allowlisted projection of verified local sidecars. It contains the
ordered runtime-segment bindings, exact append/drop indexes and closed causes,
reserved high-watermark, and any explicit recovery ranges. Schema-3 manifests
may omit it or set it to `null`. Processors may use this object for autonomous
grounding after receipt-authorized SDK cleanup has removed the local sidecars.
The reviewer currently receives only the processor's derived candidates,
evidence, and SDK timeline; this raw manifest object is not a reviewer panel.

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
scope expansion. They are **not a complete sandbox for hostile code**: a
direct child runs as the same service UID. The direct-child path is retained
only for trusted operator code and contract tests.

## Accepted private-pilot isolation gate

[ADR-016](../../docs/decisions/ADR-016-local-processor-isolation.md) requires a
mini-PC/private-pilot model or plugin to run through
`scripts/run_isolated_processor.py`. Stop the backend, then launch the exclusive
worker from the trusted host so the runner can use the host container runtime.
Do not mount the Docker socket into the backend or processor container. The
runner is trusted Tacua boundary code; the selected processor image is not.

The worker's ordinary `tacua.local-processing-command@1.0.0` document must give
the runner the parent's exact 240-second deadline. The adapter exports that
actual value as `TACUA_ADAPTER_TIMEOUT_SECONDS`; the runner rejects any other
value. An illustrative outer document is:

```json
{"argv":["/usr/bin/python3","/absolute/checkout/services/backend/scripts/run_isolated_processor.py","--command-file","/absolute/operator/path/isolated-command.json","--input","{input}","--output-directory","{output_directory}"],"contract_version":"tacua.local-processing-command@1.0.0","max_stderr_bytes":65536,"max_stdout_bytes":16777216,"timeout_seconds":240}
```

The separately mode-`0600`, operator-owned
`tacua.isolated-processing-command@1.0.0` file has this closed shape:

```json
{
  "contract_version": "tacua.isolated-processing-command@1.0.0",
  "image": "operator.example/processor@sha256:<64 lowercase hex characters>",
  "model_id": "operator-selected-model-id",
  "model_path": "/absolute/operator/path/model-file",
  "model_digest": "sha256:<64 lowercase hex characters>",
  "timeout_seconds": 150,
  "argv": [
    "/absolute/executable/in/image",
    "--input",
    "{input}",
    "--model",
    "{model}"
  ]
}
```

This is an illustrative shape, not a selected image, executable, or model. The
repository downloads none of them and supplies no default. The image must
already be present and identified by a repository digest or an exact local
`sha256:` image ID. The model must be one resolved regular file of at most 8
GiB, explicitly identified and SHA-256 verified by the operator. The runner
reopens it without following the final path component, copies and hashes it,
and rejects any mismatch. Sockets, directories, symlinks, Docker sockets,
secrets, provider credentials and arbitrary host mounts are not admitted.
Before container creation the runner disables image healthchecks and rejects
selected images that declare a health command, implicit writable volumes, or
environment keys beyond locale/PATH, then overwrites those values and adds only
the non-secret model ID. Container-runtime metadata such as the hostname may
still be injected and is not represented as application authority.

The trusted runner first creates a mode-`0700` empty host staging directory and
immediately creates a randomized, labeled local Docker volume plus stopped
carrier and final-processor recovery containers. Only after those recovery
identities exist does it read the adapter's inherited evidence descriptors,
verify the source input digest, rehash every copied evidence file against its
`content_digest`, and create the bundle below the staging root.
The input/model directories and files are mode `0555`/`0444`, but their private
parent prevents every other ordinary host UID from traversing them. The carrier
is never started and has an inert, deliberately nonexistent entrypoint; its
writable root and sole RW volume mount exist only so the trusted archive API can
populate the randomized Docker-managed payload volume. The
final processor mounts that same volume read-only with `volume-nocopy`, also has
a read-only root, and has no host bind. After archive upload, the host payload
is deleted after the carrier and volume are re-inspected to prove the carrier
remained in its exact never-started state. The stopped carrier is then removed
and verified absent before the untrusted final entrypoint starts. The bundle
preserves `source_input_digest`, rewrites only evidence paths, and adds its own
`isolated_input_digest`. There is no output mount. The processor emits one exact
canonical `tacua.isolated-processing-output@1.0.0` JSON envelope on attached
stdout. It contains a result object plus its digest and an ordered preview list;
each preview binds a safe filename, canonical base64 body, decoded size and
SHA-256. Envelope entries must be exactly the unique `body_file` set referenced
by the result's candidate previews—missing and unreferenced bodies are rejected.
The runner caps stdout incrementally at 110 MiB, caps and requires empty
stderr, kills on cap/deadline, and exact-inspects exit/OOM state. It accepts at
most 64 MiB of decoded result/preview bytes, publishes previews atomically only
after complete validation, then emits the canonical result to the existing
adapter.

Before stale discovery or image inspection, the runner requires `docker info`
to prove a rootless daemon, cgroup v2 with the systemd driver, effective CPU
quota/memory/PID controls, and builtin default seccomp. Missing proof aborts
without classifying or mutating a labeled recovery artifact.

V1 processor execution is serialized per host. Before stale discovery, each
runner nonblockingly acquires the fixed
`/tmp/tacua-private-processor-runner.lock`, which must be one mode-`0600`
regular file owned by the runner UID. The crash-released `flock` is held through
container and host-staging cleanup. An overlapping invocation fails with
`PROCESSOR_RUNNER_BUSY` and performs no stale reaping.

The enforced ceiling is:

| Resource | V1 ceiling |
| --- | ---: |
| Network | Docker `none`; no network attachment |
| Identity | dedicated `10002:10002`, distinct from backend `10001:10001` |
| Linux privilege | read-only root, all capabilities dropped, no-new-privileges, default seccomp |
| CPU | 2 CPUs |
| Memory/swap | 4 GiB / 4 GiB |
| PIDs/files | 64 PIDs; 1,024 descriptors |
| Container runtime | 150 seconds maximum, capped again by the remaining whole-runner budget |
| Whole-runner work / cleanup | work stops by 180 seconds; kill/removal and temporary cleanup end by 210 seconds |
| Parent margin | outer adapter is exactly 240 seconds, leaving 30 seconds after the runner hard deadline |
| Scratch disk | 256 MiB noexec tmpfs |
| Output transport | no writable mount; 110 MiB incrementally capped attached stdout; empty bounded stderr |
| Decoded output | 64 MiB result/preview aggregate; 16 MiB canonical result; 512 previews |
| Evidence | 512 files / 4 GiB, read-only |
| Model | one regular file / 8 GiB, digest verified and read-only |
| Payload volume | randomized local Docker volume; only the never-started carrier mounts RW, while the processor mounts RO; content is bounded by evidence/model/metadata ceilings but the local volume driver has no independent quota |

`compose.processor.yaml` is the matching opt-in `private-pilot` topology and has
no runnable defaults. Resolve it only with explicit operator values and verify
the result before use:

```sh
TACUA_PROCESSOR_IMAGE='operator.example/processor@sha256:…' \
TACUA_PROCESSOR_MODEL_ID='operator-selected-model-id' \
TACUA_PROCESSOR_EXECUTABLE='/absolute/executable/in/image' \
docker compose -f services/backend/compose.processor.yaml \
  --profile private-pilot config --format json > /tmp/tacua-processor-compose.json
python3 services/backend/scripts/verify_isolated_processor_profile.py \
  /tmp/tacua-processor-compose.json
```

The Compose profile has no host mounts and documents/gates the final stopped
container topology; it cannot create the randomized carrier/volume transaction
or supply its payload. Direct
`docker compose up` is therefore not an approved processor execution path.
Every actual runner carrier, processor, and payload volume carries the exact
contract, instance, staging, role, and deadline identity. A later authorized
run lists only artifacts with both Tacua contract labels and validates the
exact never-started carrier-RW/final-RO volume relationship plus required
no-network and no-host-bind shape and the final processor's read-only root
before recovery. It kills and confirms
containers stopped, removes and verifies label-bound host staging while at
least one recovery identity still exists, removes carriers and processors, and
removes the sensitive payload volume last. A volume-only partial phase is
recoverable. If staging removal fails, all labeled artifacts are deliberately
retained for the next authorized reaper. Any spoofed or malformed match fails
closed.

Run the checked-in synthetic end-to-end image/model/evidence fixture on a host
whose Docker daemon is rootless, cgroup v2/systemd, has effective CPU/memory/PID
controls, and advertises builtin seccomp. The runner proves those facts before
it discovers or reaps any prior artifact:

```sh
python3 -B services/backend/scripts/run_synthetic_isolated_processor_integration.py
```

The fixture interrupts one running synthetic container with `SIGKILL`, then
proves that the next authorized run performs exact stale recovery and completes
under UID `10002` with a read-only root and RO payload volume after a
never-started RW carrier. It also proves the attached canonical-envelope output
channel. It downloads no real model and selects no production processor. The
real integration covers the final-running interruption; carrier-only,
post-copy, malformed-output, and cleanup interruption phases remain deterministic
unit regressions. The ordinary rootful GitHub-hosted job runs the unit/profile
checks only; the real integration is the separate manually dispatched
`verify-rootless-processor.yml` self-hosted gate.
