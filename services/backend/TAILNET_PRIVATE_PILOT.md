# Tailnet-only private pilot

This profile runs Tacua's single-owner test deployment on one Docker host and
reaches it from the tested iPhone and reviewer app through Tailscale Serve:

```text
iPhone -> tailnet HTTPS :443 -> Tailscale Serve
       -> http://127.0.0.1:8080 -> pinned HAProxy ingress
       -> fixed API paths -> Tacua backend container
       -> every other path -> authority-free reviewer container
```

It needs no public Tacua DNS record, cloud VM, public firewall opening,
Cloudflare Tunnel, or Tacua container registry. The first start must retrieve
the digest-pinned Docker Official HAProxy image unless it is already cached.
Tailscale's control plane, that image registry, and the public certificate
authority used for the `*.ts.net` certificate remain external dependencies.

Require Docker Engine 28.0.0 or newer and Docker Compose 2.24.4 or newer.
Docker documents that [localhost-published ports could be reached by hosts on
the same layer-2 segment before Engine
28](https://docs.docker.com/engine/network/port-publishing/#publishing-ports).
The exact resolved model is tested with Compose 2.30.3 and 5.1.3; the
fail-closed validator may reject another renderer's output until that version
is reviewed. Record both versions before setup:

```sh
docker version --format '{{.Server.Version}}'
docker compose version --short
```

This is a **private-pilot/test profile, not the production ingress described in
[OPERATIONS.md](OPERATIONS.md)**. Tailscale Serve provides private HTTPS and a
loopback proxy, but its documented controls do not prove Tacua's production
request deadlines, concurrency/queue ceilings, rate limits, header bounds, or
logging contract. Do not use this profile as production-promotion evidence.

## Fixed boundary

- The deployment is still one organization, project, application, tested
  build, reviewer, and administrator credential.
- The host's tailnet node name and tailnet DNS suffix are immutable deployment
  inputs. Renaming either changes the HTTPS origin and requires a new empty
  backend deployment, sealed SDK profile, and native QA build.
- Limit the tailnet policy to the owner's test devices and the mini-PC. The
  checked-in verifier can prove the node/Serve configuration, but it cannot
  read or attest the account-level tailnet access policy.
- Keep Tailscale Funnel disabled. Serve is tailnet-only; Funnel is public.
- Tailscale HTTPS certificates place the selected `*.ts.net` hostname in public
  Certificate Transparency logs. Do not put a person, customer, project, or
  other confidential identifier in the node name.
- Compose must continue publishing only the ingress at `127.0.0.1:8080`. The
  backend and reviewer each stay on exactly one `internal: true` network,
  publish no host port, and retain zero egress. Never bind any service directly
  to the LAN or a Tailscale address.
- The pinned non-root ingress receives no Tacua config, secret, state, source,
  or Docker socket. It does see proxied plaintext HTTP and joins one ordinary
  bridge to publish host loopback, so a compromised ingress could egress
  captured traffic.
  That accepted private-pilot risk is not a production network-policy claim.
- [Tailscale Serve injects identity
  headers](https://tailscale.com/docs/features/tailscale-serve#identity-headers)
  containing the tailnet user's login, display name, and profile-picture URL.
  Tacua does not use those headers as authorization. Treat them as transient
  PII visible to Serve, the ingress, and backend request handling; never add
  them to logs, tickets, or evidence. The ingress removes these headers before
  forwarding static reviewer requests.
- The tested app's SDK profile pins the exact HTTPS origin at native build time.
  A TestFlight or preview build cannot switch origins through JavaScript or an
  OTA update. The reviewer app can change its HTTPS origin in Settings without
  rebuilding.

## 1. Verify the candidate before creating live inputs

Run the repository and container boundary checks while
`services/backend/local/config.json` and
`services/backend/local/admin-secret` are still absent. The container verifier
deliberately refuses to replace live deployment inputs:

```sh
set -eu
node --test .github/scripts/validate-backend-image-inputs.test.mjs
node .github/scripts/validate-backend-image-inputs.mjs
cd apps/reviewer
test ! -e node_modules
test ! -e dist
test ! -e generated
npm ci --ignore-scripts --no-audit --no-fund
node ../../.github/scripts/generate-reviewer-third-party-notices.mjs
npm test
npm run typecheck
npm run export:web -- --output-dir dist --clear
cd ../..
node --test .github/scripts/validate-reviewer-web-image-inputs.test.mjs
node .github/scripts/validate-reviewer-web-image-inputs.mjs

if docker image inspect tacua-backend:local >/dev/null 2>&1 ||
  docker image inspect tacua-reviewer-web:local >/dev/null 2>&1; then
  echo 'refusing to replace an existing local Tacua image tag' >&2
  exit 1
fi
TACUA_CONTAINER_TEST_ID=tailnet-pilot \
TACUA_KEEP_VERIFIED_IMAGES=true \
  bash .github/scripts/verify-backend-container.sh
docker tag tacua-backend:tailnet-pilot tacua-backend:local
docker tag tacua-reviewer-web:tailnet-pilot tacua-reviewer-web:local
test "$(docker image inspect --format '{{.Id}}' tacua-backend:local)" = \
  "$(docker image inspect --format '{{.Id}}' tacua-backend:tailnet-pilot)"
test "$(docker image inspect --format '{{.Id}}' tacua-reviewer-web:local)" = \
  "$(docker image inspect --format '{{.Id}}' tacua-reviewer-web:tailnet-pilot)"
```

The full check builds and retains the exact local candidates, then exercises
the Compose topology, loopback same-origin routing,
authority-free reviewer, single-writer state, authenticated smoke, backup,
restore, and restored startup. On a rootless daemon it is also the
deployment-specific rootless test; the hosted CI job currently runs this
boundary on its standard Docker daemon.

## 2. Freeze the origin and prepare live inputs

This section creates a **new empty deployment** named
`tacua-tailnet-pilot`. Run it in Bash. First fail closed if Docker cannot be
queried, any project-labelled resource exists, or the exact state/network names
already exist:

```bash
set -euo pipefail
project='tacua-tailnet-pilot'
state_volume="${project}_tacua-state"
private_network="${project}_tacua-default-deny"
publish_network="${project}_tacua-loopback-publish"

if ! project_containers="$(
  docker ps -aq --filter "label=com.docker.compose.project=$project"
)"; then
  echo 'cannot inspect project containers' >&2
  exit 1
fi
if ! project_volumes="$(
  docker volume ls -q --filter "label=com.docker.compose.project=$project"
)"; then
  echo 'cannot inspect project volumes' >&2
  exit 1
fi
if ! project_networks="$(
  docker network ls -q --filter "label=com.docker.compose.project=$project"
)"; then
  echo 'cannot inspect project networks' >&2
  exit 1
fi
if ! volume_names="$(docker volume ls --format '{{.Name}}')"; then
  echo 'cannot list Docker volumes' >&2
  exit 1
fi
if ! network_names="$(docker network ls --format '{{.Name}}')"; then
  echo 'cannot list Docker networks' >&2
  exit 1
fi
if [ -n "$project_containers$project_volumes$project_networks" ] ||
  printf '%s\n' "$volume_names" | grep -Fqx -- "$state_volume" ||
  printf '%s\n' "$network_names" | grep -Fqx -- "$private_network" ||
  printf '%s\n' "$network_names" | grep -Fqx -- "$publish_network"; then
  echo 'refusing non-empty Tacua Compose project identity' >&2
  exit 1
fi
```

Do not use this path to restart or recover an existing deployment. Preserve its
config, secret, state, and project name, then use the offline state/restore
workflow in [OPERATIONS.md](OPERATIONS.md).

Capture the Tailscale document without printing its peer/user metadata. The
checked projection emits only the HTTPS origin needed for configuration:

```bash
set -euo pipefail
umask 077
runtime_directory="$(mktemp -d "${TMPDIR:-/tmp}/tacua-tailnet.XXXXXX")"
runtime_directory="$(cd "$runtime_directory" && pwd -P)"
chmod 0700 "$runtime_directory"
trap 'rm -rf -- "$runtime_directory"' EXIT HUP INT TERM

tailscale status --json > "$runtime_directory/tailscale-discovery.json"
python3 -B services/backend/scripts/verify_tailnet_private_pilot.py \
  --tailscale-status-json "$runtime_directory/tailscale-discovery.json" \
  --inspect-tailnet-identity
```

Write the exact JSON `origin` value, with no port, path, or trailing slash, into
`backend_origin` in `services/backend/local/config.template.json`. Follow
[CONFIGURATION.md](CONFIGURATION.md) to pin the exact QA build and generate both
public artifacts:

```sh
set -eu
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.config_tool \
  services/backend/local/config.template.json \
  --output services/backend/local/config.json \
  --sdk-profile-output services/backend/local/tacua-sdk-profile.json
```

Create the administrator secret separately if this is a new empty deployment:

```sh
set -eu
chmod go-w . services services/backend
test ! -L services/backend/local
install -d -m 0700 services/backend/local
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  create-admin-secret \
  --destination services/backend/local/admin-secret
```

Preflight walks every resolved ancestor from the private input directory to
the filesystem root. Every non-shared ancestor must be operator- or root-owned
and not group/world writable; a shared writable ancestor is accepted only when
root-owned sticky-directory semantics protect its entries. The three `chmod`
targets above do not repair an unsafe higher ancestor—move the checkout to a
protected path instead.

Do not replace the secret against an existing state volume. Config, secret, and
state form one recovery set.

## 3. Preflight and start the backend

Resolve the exact Compose model and run the mutable-image private-pilot
preflight. Continue in the same shell so the fixed project and owner-only
runtime directory remain available:

```bash
set -euo pipefail
: "${project:?run step 2 in this shell}"
: "${runtime_directory:?run step 2 in this shell}"
test -d "$runtime_directory"

docker compose -p "$project" -f services/backend/compose.yaml \
  config --format json > "$runtime_directory/compose.json"

PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  preflight \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --compose-json "$runtime_directory/compose.json" \
  --allow-mutable-image

if ! project_containers="$(
  docker ps -aq --filter "label=com.docker.compose.project=$project"
)" || ! project_volumes="$(
  docker volume ls -q --filter "label=com.docker.compose.project=$project"
)" || ! project_networks="$(
  docker network ls -q --filter "label=com.docker.compose.project=$project"
)" || ! volume_names="$(docker volume ls --format '{{.Name}}')" ||
  ! network_names="$(docker network ls --format '{{.Name}}')"; then
  echo 'cannot repeat the Docker collision checks' >&2
  exit 1
fi
if [ -n "$project_containers$project_volumes$project_networks" ] ||
  printf '%s\n' "$volume_names" | grep -Fqx -- "$state_volume" ||
  printf '%s\n' "$network_names" | grep -Fqx -- "$private_network" ||
  printf '%s\n' "$network_names" | grep -Fqx -- "$publish_network"; then
  echo 'project identity changed before startup; refusing' >&2
  exit 1
fi

docker compose -p "$project" -f services/backend/compose.yaml \
  up -d --no-build

PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  smoke \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --origin http://127.0.0.1:8080 \
  --allow-loopback-http
```

The local image is acceptable only for this private test. Production promotion
still requires the digest-pinned image override and the complete production
runbook. Do not expose Serve until this host-side loopback smoke passes.

## 4. Configure private HTTPS

Require the runtime directory, capture the current Serve document, prove it is
empty, and only then configure port 443. `set -e` makes the validation a real
control-flow gate:

```bash
set -euo pipefail
: "${runtime_directory:?run steps 2 and 3 in this shell}"
test -d "$runtime_directory"
tailscale status --json > "$runtime_directory/tailscale-status-before.json"
tailscale serve status --json > "$runtime_directory/serve-before.json"
python3 -B services/backend/scripts/verify_tailnet_private_pilot.py \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --compose-json "$runtime_directory/compose.json" \
  --tailscale-status-json "$runtime_directory/tailscale-status-before.json" \
  --serve-status-json "$runtime_directory/serve-before.json" \
  --pre-activation

rollback_serve() {
  if ! tailscale serve --https=443 off; then
    echo 'CRITICAL: failed to remove the newly configured Serve listener' >&2
    return 1
  fi
  if ! tailscale serve status --json \
    > "$runtime_directory/serve-rollback.json"; then
    echo 'CRITICAL: cannot inspect Serve after rollback' >&2
    return 1
  fi
  if ! python3 -B services/backend/scripts/verify_tailnet_private_pilot.py \
    --serve-status-json "$runtime_directory/serve-rollback.json" \
    --expect-empty-serve; then
    echo 'CRITICAL: Serve is not empty after rollback' >&2
    return 1
  fi
}
trap 'rollback_serve' ERR
tailscale serve --bg --yes http://127.0.0.1:8080
tailscale status --json > "$runtime_directory/tailscale-status.json"
tailscale serve status --json > "$runtime_directory/serve-status.json"
python3 -B services/backend/scripts/verify_tailnet_private_pilot.py \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --compose-json "$runtime_directory/compose.json" \
  --tailscale-status-json "$runtime_directory/tailscale-status.json" \
  --serve-status-json "$runtime_directory/serve-status.json"
trap - ERR
unset -f rollback_serve
rm -rf -- "$runtime_directory"
trap - EXIT HUP INT TERM
unset runtime_directory
```

The pre-activation check binds the safe config and secret files to their exact
Compose sources, revalidates the local image/build, sealed origin, live
tailnet identity, certificate domain, and loopback topology, and proves Serve
is empty. If any check fails, the shell exits before mutation. An existing
exact Tacua listener can instead be validated with the final command and left
unchanged; any other listener needs explicit operator review. Do not run
`tailscale funnel` or automate `tailscale serve reset`: either can broaden or
remove host-wide Serve state.

If configuration or exact post-validation fails after the guarded mutation,
the error trap removes the listener, captures the resulting Serve document,
and proves it is empty. A rollback failure emits a visible `CRITICAL` error;
stop and inspect the host rather than assuming the listener was removed.
After successful validation, the block removes the owner-only status directory;
the stop workflow creates a fresh one rather than retaining tailnet metadata.

The final command verifies that the sealed origin, base Compose topology,
Tailscale identity, certificate domain, listener, handler, and loopback target
agree exactly.

The verifier fails closed on Funnel, extra ports or handlers, origin drift,
offline/MagicDNS/certificate drift, a non-loopback target, direct backend
publication, ingress/reviewer image or config drift, leaked container
authority, or weakened Docker network isolation. Its input loader requires
stable, mode-`0600`,
operator-owned regular files inside the mode-`0700` runtime directory and
opens them without following symlinks.

## 5. Prove the path

Run the authenticated exact-origin smoke test on the Docker host. It exercises
the tailnet HTTPS origin while the administrator secret remains in its
host-only directory:

```sh
set -eu
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  smoke \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret
```

Then verify from the physical iPhone:

1. Tailscale is connected.
2. The reviewer saves the exact HTTPS origin and passes its `/version` probe.
3. The reviewer launches the dedicated QA build through its configured custom
   scheme.
4. Consent, capture, stop, foreground upload, completion, recovery, deletion,
   and reviewer evidence access work through the tailnet address.
5. A maximum configured segment uploads successfully through Serve without a
   redirect, whole-request timeout, body transformation, or truncated receipt.

The normal backend smoke is necessary but does not prove Serve's behavior for a
maximum-duration upload. Never copy the administrator secret to the phone;
normal device tests use the launch and SDK credentials issued by the backend.

## Stop and recover

Disable only the exact validated Tacua listener **before** stopping ingress.
This prevents Serve from forwarding trusted HTTPS traffic to an unowned
loopback port. Recapture the live documents, prove the exact binding, turn it
off, and prove that Serve is empty. This standalone block recreates the fixed
project identity and private validation inputs instead of relying on setup-shell
variables:

```bash
set -euo pipefail
project='tacua-tailnet-pilot'
umask 077
runtime_directory="$(mktemp -d "${TMPDIR:-/tmp}/tacua-tailnet-stop.XXXXXX")"
runtime_directory="$(cd "$runtime_directory" && pwd -P)"
chmod 0700 "$runtime_directory"
trap 'rm -rf -- "$runtime_directory"' EXIT HUP INT TERM

docker compose -p "$project" -f services/backend/compose.yaml \
  config --format json > "$runtime_directory/compose.json"
tailscale status --json > "$runtime_directory/tailscale-status-stop.json"
tailscale serve status --json > "$runtime_directory/serve-status-stop.json"
python3 -B services/backend/scripts/verify_tailnet_private_pilot.py \
  --config-file services/backend/local/config.json \
  --admin-secret-file services/backend/local/admin-secret \
  --compose-json "$runtime_directory/compose.json" \
  --tailscale-status-json "$runtime_directory/tailscale-status-stop.json" \
  --serve-status-json "$runtime_directory/serve-status-stop.json"
tailscale serve --https=443 off
tailscale serve status --json > "$runtime_directory/serve-status-off.json"
python3 -B services/backend/scripts/verify_tailnet_private_pilot.py \
  --serve-status-json "$runtime_directory/serve-status-off.json" \
  --expect-empty-serve

docker compose -p "$project" -f services/backend/compose.yaml stop
```

The `off` command removes the host's entire port-443 Serve listener, which is
why the exact validator is mandatory immediately before it. If validation
fails, stop and inspect instead of changing Serve or stopping ingress. Do not
remove the state volume as an ordinary shutdown step. Use the backup,
verification, and restore workflow in [OPERATIONS.md](OPERATIONS.md). If the
host/tailnet name or sealed origin must change, preserve the old recovery set,
create an explicitly empty deployment for the new origin, regenerate the SDK
profile, and build a new native QA binary.

`tailscale serve --bg` is persistent and Tailscale documents that it resumes
after reboot. Compose restarts independently. On this single-owner private
pilot, a crash or reboot can therefore briefly leave Serve targeting an
unowned loopback port before ingress rebinds it. Treat that as an explicit
test-only risk: run no untrusted local processes, validate the exact topology
after every host/Tailscale restart, and do not promote this profile to a
multi-user or production host without a supervisor that enables foreground
Serve only after the loopback smoke passes.

## Deliberately deferred

- Direct Serve is not the bounded production reverse proxy.
- The pinned ingress provides only fixed same-origin routing, not the
  production HTTP concurrency, rate, header, or slow-client boundary.
- No real transcription, repository research, or ticket-generation processor
  is selected by this profile.
- Off-host backup, public availability, multi-user tailnet policy, and
  production monitoring remain later promotion work.
