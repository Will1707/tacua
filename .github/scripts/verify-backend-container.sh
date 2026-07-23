#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

test_id="${TACUA_CONTAINER_TEST_ID:-ci}"
case "$test_id" in
  *[!a-z0-9-]*|''|-*)
    echo "TACUA_CONTAINER_TEST_ID must start with a lowercase letter or digit and contain only lowercase letters, digits, and hyphens" >&2
    exit 2
    ;;
esac
if [ "${#test_id}" -gt 32 ]; then
  echo "TACUA_CONTAINER_TEST_ID must be at most 32 characters" >&2
  exit 2
fi

if [ ! -f services/backend/Dockerfile ] || [ ! -f services/backend/config.example.json ]; then
  echo "run this script from the Tacua repository root" >&2
  exit 2
fi

image="tacua-backend:${test_id}"
container="tacua-backend-${test_id}"
second_container="tacua-backend-${test_id}-second"
restored_container="tacua-backend-${test_id}-restored"
compose_project="tacua-backend-${test_id}-compose"
restore_compose_project="${compose_project}-restore"
compose_container=""
compose_ingress_container=""
restore_compose_container=""
volume="tacua-backend-${test_id}-state"
backup_volume="tacua-backend-${test_id}-backup"
restored_volume="tacua-backend-${test_id}-restored-state"
compose_state_volume="${compose_project}_tacua-state"
runtime_parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
runtime_directory="$(mktemp -d "${runtime_parent%/}/tacua-container-${test_id}.XXXXXX")"
secret="$runtime_directory/admin-secret"
resolved_compose="$runtime_directory/compose.json"
resolved_test_compose="$runtime_directory/compose-test.json"
resolved_production_compose="$runtime_directory/compose-production.json"
test_compose_override="$runtime_directory/compose-test-override.json"
restore_volume_override="$runtime_directory/compose-restore-volume.json"
verified_restored_backup="$runtime_directory/restored-backup.json"
local_config="services/backend/local/config.json"
local_secret="services/backend/local/admin-secret"
local_directory="services/backend/local"
cleanup_local_files=false
created_local_directory=false
docker_cleanup=false
compose_started=false
restore_compose_created=false

cleanup() {
  if [ "$docker_cleanup" = true ]; then
    if [ "$compose_started" = true ]; then
      docker compose \
        -p "$compose_project" \
        -f services/backend/compose.yaml \
        -f "$test_compose_override" \
        down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
    docker rm -f "$container" >/dev/null 2>&1 || true
    docker rm -f "$second_container" >/dev/null 2>&1 || true
    docker rm -f "$restored_container" >/dev/null 2>&1 || true
    if [ "$restore_compose_created" = true ]; then
      docker compose \
        -p "$restore_compose_project" \
        -f services/backend/compose.yaml \
        -f "$test_compose_override" \
        -f "$restore_volume_override" \
        down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
    docker volume rm "$volume" >/dev/null 2>&1 || true
    docker volume rm "$backup_volume" >/dev/null 2>&1 || true
    docker volume rm "$restored_volume" >/dev/null 2>&1 || true
    docker image rm "$image" >/dev/null 2>&1 || true
  fi
  if [ "$cleanup_local_files" = true ]; then
    if [ -d "$local_directory" ] && [ ! -L "$local_directory" ]; then
      rm -f -- "$local_config" "$local_secret"
      if [ "$created_local_directory" = true ]; then
        rmdir -- "$local_directory" >/dev/null 2>&1 || true
      fi
    else
      echo "refusing to clean verification inputs through a changed services/backend/local path" >&2
    fi
  fi
  rm -rf "$runtime_directory"
}
trap cleanup EXIT

validate_local_directory() {
  python3 -B - "$local_directory" <<'PY'
import os
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
metadata = path.lstat()
if (
    not stat.S_ISDIR(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or metadata.st_uid != os.geteuid()
    or stat.S_IMODE(metadata.st_mode) != 0o700
):
    raise SystemExit(
        "services/backend/local must be an operator-owned mode-0700 directory"
    )
PY
}

if [ -L "$local_directory" ] || { [ -e "$local_directory" ] && [ ! -d "$local_directory" ]; }; then
  echo "services/backend/local must be absent or a real directory" >&2
  exit 1
fi
if [ -d "$local_directory" ]; then
  validate_local_directory
fi
if [ -e "$local_config" ] || [ -L "$local_config" ] || [ -e "$local_secret" ] || [ -L "$local_secret" ]; then
  echo "refusing to replace existing services/backend/local verification inputs" >&2
  exit 1
fi

if ! container_names="$(docker container ls -a --format '{{.Names}}')"; then
  echo "cannot list Docker containers safely" >&2
  exit 1
fi
for target in \
  "$container" \
  "$second_container" \
  "$restored_container" \
  "${compose_project}-backend-1" \
  "${compose_project}-ingress-1" \
  "${restore_compose_project}-backend-1"; do
  if printf '%s\n' "$container_names" | grep -Fqx -- "$target"; then
    echo "refusing to replace existing Docker container: $target" >&2
    exit 1
  fi
done
if ! compose_containers="$(
  docker container ls -aq \
    --filter "label=com.docker.compose.project=$compose_project"
)"; then
  echo "cannot inspect Docker Compose project containers safely" >&2
  exit 1
fi
if [ -n "$compose_containers" ]; then
  echo "refusing to replace existing Docker Compose project containers: $compose_project" >&2
  exit 1
fi
if ! restore_compose_containers="$(
  docker container ls -aq \
    --filter "label=com.docker.compose.project=$restore_compose_project"
)"; then
  echo "cannot inspect restore Compose project containers safely" >&2
  exit 1
fi
if [ -n "$restore_compose_containers" ]; then
  echo "refusing to replace existing restore Compose project containers: $restore_compose_project" >&2
  exit 1
fi
if ! volume_names="$(docker volume ls --format '{{.Name}}')"; then
  echo "cannot list Docker volumes safely" >&2
  exit 1
fi
for target in \
  "$volume" \
  "$backup_volume" \
  "$restored_volume" \
  "$compose_state_volume"; do
  if printf '%s\n' "$volume_names" | grep -Fqx -- "$target"; then
    echo "refusing to replace existing Docker volume: $target" >&2
    exit 1
  fi
done
if ! compose_volumes="$(
  docker volume ls -q \
    --filter "label=com.docker.compose.project=$compose_project"
)"; then
  echo "cannot inspect Docker Compose project volumes safely" >&2
  exit 1
fi
if [ -n "$compose_volumes" ]; then
  echo "refusing to replace existing Docker Compose project volumes: $compose_project" >&2
  exit 1
fi
if ! restore_compose_volumes="$(
  docker volume ls -q \
    --filter "label=com.docker.compose.project=$restore_compose_project"
)"; then
  echo "cannot inspect restore Compose project volumes safely" >&2
  exit 1
fi
if [ -n "$restore_compose_volumes" ]; then
  echo "refusing to replace existing restore Compose project volumes: $restore_compose_project" >&2
  exit 1
fi
if ! network_names="$(docker network ls --format '{{.Name}}')"; then
  echo "cannot list Docker networks safely" >&2
  exit 1
fi
for target in \
  "${compose_project}_tacua-default-deny" \
  "${compose_project}_tacua-loopback-publish" \
  "${restore_compose_project}_tacua-default-deny" \
  "${restore_compose_project}_tacua-loopback-publish"; do
  if printf '%s\n' "$network_names" | grep -Fqx -- "$target"; then
    echo "refusing to replace existing Docker network: $target" >&2
    exit 1
  fi
done
if ! compose_networks="$(
  docker network ls -q \
    --filter "label=com.docker.compose.project=$compose_project"
)"; then
  echo "cannot inspect Docker Compose project networks safely" >&2
  exit 1
fi
if [ -n "$compose_networks" ]; then
  echo "refusing to replace existing Docker Compose project networks: $compose_project" >&2
  exit 1
fi
if ! restore_compose_networks="$(
  docker network ls -q \
    --filter "label=com.docker.compose.project=$restore_compose_project"
)"; then
  echo "cannot inspect restore Compose project networks safely" >&2
  exit 1
fi
if [ -n "$restore_compose_networks" ]; then
  echo "refusing to replace existing restore Compose project networks: $restore_compose_project" >&2
  exit 1
fi
if ! image_names="$(docker image ls --format '{{.Repository}}:{{.Tag}}')"; then
  echo "cannot list Docker images safely" >&2
  exit 1
fi
if printf '%s\n' "$image_names" | grep -Fqx -- "$image"; then
  echo "refusing to replace existing Docker image: $image" >&2
  exit 1
fi

printf '%s' 'tacua-ci-admin-secret-0123456789abcdef' > "$secret"
chmod 0444 "$secret"
printf '{"services":{"backend":{"image":"%s"}}}\n' "$image" \
  > "$test_compose_override"
printf '{"volumes":{"tacua-state":{"name":"%s"}}}\n' "$restored_volume" \
  > "$restore_volume_override"
if [ ! -d "$local_directory" ]; then
  mkdir -m 0700 -- "$local_directory"
  created_local_directory=true
fi
if [ -L "$local_directory" ] || [ ! -d "$local_directory" ]; then
  echo "services/backend/local changed before verification inputs were created" >&2
  exit 1
fi
validate_local_directory
cleanup_local_files=true
install -m 0644 services/backend/config.example.json "$local_config"
install -m 0444 "$secret" "$local_secret"

docker compose \
  -f services/backend/compose.yaml \
  config --format json > "$resolved_compose"
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  validate-compose \
  --config-file services/backend/config.example.json \
  --compose-json "$resolved_compose" \
  --allow-mutable-image
docker compose \
  -f services/backend/compose.yaml \
  -f "$test_compose_override" \
  config --format json > "$resolved_test_compose"
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  validate-compose \
  --config-file services/backend/config.example.json \
  --compose-json "$resolved_test_compose" \
  --allow-mutable-image
TACUA_BACKEND_IMAGE="registry.invalid/tacua@sha256:$(printf 'a%.0s' {1..64})" \
  docker compose \
    -f services/backend/compose.yaml \
    -f services/backend/compose.production.yaml \
    config --format json > "$resolved_production_compose"
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  preflight \
  --config-file "$local_config" \
  --admin-secret-file "$local_secret" \
  --compose-json "$resolved_production_compose"

wait_for_healthy() {
  local target="$1"
  local status
  for _ in $(seq 1 30); do
    status="$(docker inspect --format '{{.State.Health.Status}}' "$target")"
    if [ "$status" = healthy ]; then
      return 0
    fi
    if [ "$status" = unhealthy ]; then
      docker logs "$target"
      return 1
    fi
    sleep 1
  done
  docker logs "$target"
  return 1
}

docker_cleanup=true
docker build -f services/backend/Dockerfile -t "$image" .

compose_started=true
docker compose \
  -p "$compose_project" \
  -f services/backend/compose.yaml \
  -f "$test_compose_override" \
  up -d --no-build

compose_container="$(
  docker compose \
    -p "$compose_project" \
    -f services/backend/compose.yaml \
    -f "$test_compose_override" \
    ps -q backend
)"
if [ -z "$compose_container" ] || [ "$(printf '%s\n' "$compose_container" | wc -l)" -ne 1 ]; then
  echo "Compose did not resolve exactly one backend container" >&2
  exit 1
fi
compose_ingress_container="$(
  docker compose \
    -p "$compose_project" \
    -f services/backend/compose.yaml \
    -f "$test_compose_override" \
    ps -q ingress
)"
if [ -z "$compose_ingress_container" ] || [ "$(printf '%s\n' "$compose_ingress_container" | wc -l)" -ne 1 ]; then
  echo "Compose did not resolve exactly one ingress container" >&2
  exit 1
fi
wait_for_healthy "$compose_container"
wait_for_healthy "$compose_ingress_container"
docker exec "$compose_container" sh -c \
  'test "$(stat -c %a /run/secrets/tacua_admin)" = 444 && ! test -w /run/secrets/tacua_admin'
if docker port "$compose_container" 8080/tcp >/dev/null 2>&1; then
  echo "the backend unexpectedly published its internal listener" >&2
  exit 1
fi
if [ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$compose_container")" -ne 1 ]; then
  echo "the backend did not remain on exactly one network" >&2
  exit 1
fi
if [ "$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$compose_ingress_container")" -ne 2 ]; then
  echo "the ingress did not join exactly two networks" >&2
  exit 1
fi
docker exec "$compose_ingress_container" sh -c \
  'test "$(id -u)" = 99 && test ! -e /run/secrets/tacua_admin && test ! -e /run/tacua/config.json && haproxy -c -q -f /usr/local/etc/haproxy/haproxy.cfg'
docker exec "$compose_container" python -m tacua_backend.operator_tool smoke \
  --config-file /run/tacua/config.json \
  --admin-secret-file /run/secrets/tacua_admin \
  --origin http://127.0.0.1:8080 \
  --allow-loopback-http
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool smoke \
  --config-file "$local_config" \
  --admin-secret-file "$local_secret" \
  --origin http://127.0.0.1:8080 \
  --allow-loopback-http

docker stop "$compose_ingress_container" >/dev/null
if python3 -B -c \
  "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=1)" \
  >/dev/null 2>&1; then
  echo "loopback remained reachable after the sole ingress stopped" >&2
  exit 1
fi
if [ "$(docker inspect --format '{{.State.Health.Status}}' "$compose_container")" != healthy ]; then
  echo "stopping ingress unexpectedly changed backend health" >&2
  exit 1
fi
docker start "$compose_ingress_container" >/dev/null
wait_for_healthy "$compose_ingress_container"
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool smoke \
  --config-file "$local_config" \
  --admin-secret-file "$local_secret" \
  --origin http://127.0.0.1:8080 \
  --allow-loopback-http

docker compose \
  -p "$compose_project" \
  -f services/backend/compose.yaml \
  -f "$test_compose_override" \
  down --volumes --remove-orphans
compose_started=false

docker volume create "$volume" >/dev/null
docker volume create "$backup_volume" >/dev/null
docker run -d --name "$container" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$volume:/var/lib/tacua" \
  -v "$PWD/services/backend/config.example.json:/run/tacua/config.json:ro" \
  -v "$secret:/run/secrets/tacua_admin:ro" \
  "$image" >/dev/null

wait_for_healthy "$container"
docker exec "$container" test -r /app/LICENSE
docker exec "$container" test -r /app/NOTICE
docker exec "$container" python -m tacua_backend.operator_tool smoke \
  --config-file /run/tacua/config.json \
  --admin-secret-file /run/secrets/tacua_admin \
  --origin http://127.0.0.1:8080 \
  --allow-loopback-http

if docker run --name "$second_container" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$volume:/var/lib/tacua" \
  -v "$PWD/services/backend/config.example.json:/run/tacua/config.json:ro" \
  -v "$secret:/run/secrets/tacua_admin:ro" \
  "$image"; then
  echo "a second backend unexpectedly acquired the state volume" >&2
  exit 1
fi
docker logs "$second_container" 2>&1 | grep -F \
  "another Tacua backend or operator action owns this state directory"
docker rm "$second_container" >/dev/null

docker stop "$container" >/dev/null
docker run --rm --user 0:0 --entrypoint /bin/sh \
  -v "$backup_volume:/backup" \
  "$image" -c 'chown 10001:10001 /backup && chmod 0700 /backup'
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$volume:/var/lib/tacua" \
  -v "$PWD/services/backend/config.example.json:/run/tacua/config.json:ro" \
  -v "$secret:/run/secrets/tacua_admin:ro" \
  -v "$backup_volume:/backup" \
  --entrypoint python \
  "$image" -m tacua_backend.operator_tool backup \
    --config-file /run/tacua/config.json \
    --admin-secret-file /run/secrets/tacua_admin \
    --output /backup/ci
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$backup_volume:/backup" \
  --entrypoint python \
  "$image" -m tacua_backend.operator_tool restore \
    /backup/ci --destination /backup/restored
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$backup_volume:/backup" \
  --entrypoint python \
  "$image" -m tacua_backend.operator_tool restore \
    /backup/ci --destination /backup/restored --apply
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$backup_volume:/backup" \
  --entrypoint python \
  "$image" -m tacua_backend.operator_tool verify-backup /backup/restored \
  > "$verified_restored_backup"
chmod 0600 "$verified_restored_backup"
expected_backup_digest="$(
  python3 -B -c '
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    digest = json.load(stream).get("backup_digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit("verified backup returned an invalid digest")
print(digest)
' "$verified_restored_backup"
)"

docker run --rm \
  --user 10001:10001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$backup_volume:/backup" \
  --entrypoint python \
  "$image" -m tacua_backend.operator_tool prepare-compose-inputs \
    /backup/restored --destination /backup/compose-inputs
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -v "$backup_volume:/backup:ro" \
  --entrypoint /bin/sh \
  "$image" -c \
    'test "$(stat -c %a /backup/compose-inputs)" = 700 && test "$(stat -c %a /backup/compose-inputs/config.json)" = 644 && test "$(stat -c %a /backup/compose-inputs/admin-secret)" = 444'

restore_compose_created=true
docker compose \
  -p "$restore_compose_project" \
  -f services/backend/compose.yaml \
  -f "$test_compose_override" \
  -f "$restore_volume_override" \
  create --no-build backend
restore_compose_container="$(
  docker compose \
    -p "$restore_compose_project" \
    -f services/backend/compose.yaml \
    -f "$test_compose_override" \
    -f "$restore_volume_override" \
    ps -aq backend
)"
if [ -z "$restore_compose_container" ] || \
  [ "$(printf '%s\n' "$restore_compose_container" | wc -l)" -ne 1 ] || \
  [ "$(docker inspect --format '{{.State.Status}}' "$restore_compose_container")" != created ]; then
  echo "restore Compose project did not create one stopped backend" >&2
  exit 1
fi
if [ "$(
  docker inspect --format \
    '{{range .Mounts}}{{if eq .Destination "/var/lib/tacua"}}{{.Name}}{{end}}{{end}}' \
    "$restore_compose_container"
)" != "$restored_volume" ]; then
  echo "restore Compose backend uses an unexpected state volume" >&2
  exit 1
fi
if [ "$(
  docker volume inspect --format \
    '{{index .Labels "com.docker.compose.project"}}' "$restored_volume"
)" != "$restore_compose_project" ] || [ "$(
  docker volume inspect --format \
    '{{index .Labels "com.docker.compose.volume"}}' "$restored_volume"
)" != tacua-state ]; then
  echo "restore Compose state volume labels are invalid" >&2
  exit 1
fi

docker run --rm \
  --user 0:0 \
  --read-only \
  --network none \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges:true \
  --env "EXPECTED_BACKUP_DIGEST=$expected_backup_digest" \
  --env TMPDIR=/tmp \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=0700 \
  --tmpfs /candidate:rw,nosuid,nodev,noexec,size=33554432,mode=0700 \
  -v "$restored_volume:/candidate/state" \
  -v "$backup_volume:/recovery:ro" \
  --entrypoint /bin/sh \
  "$image" -ceu '
    test -d /candidate/state/tmp
    test ! -L /candidate/state/tmp
    test "$(stat -c %u:%g:%a /candidate/state/tmp)" = 10001:10001:700
    test -z "$(find /candidate/state/tmp -mindepth 1 -print -quit)"
    test -z "$(find /candidate/state -mindepth 1 -maxdepth 1 ! -name tmp -print -quit)"
    rmdir /candidate/state/tmp
    test -z "$(find /candidate/state -mindepth 1 -print -quit)"
    chown 0:0 /candidate/state
    chmod 0700 /candidate/state
    cp -a /recovery/restored/manifest.json /recovery/restored/config.json /recovery/restored/admin-secret /candidate/
    cp -a /recovery/restored/state/. /candidate/state/
    chown -R 0:0 /candidate
    find /candidate -type d -exec chmod 0700 {} +
    find /candidate -type f -exec chmod 0600 {} +
    python -m tacua_backend.operator_tool verify-backup \
      /candidate > /tmp/candidate-backup.json
    python -c '"'"'
import json, os
with open("/tmp/candidate-backup.json", encoding="utf-8") as stream:
    actual = json.load(stream).get("backup_digest")
if actual != os.environ["EXPECTED_BACKUP_DIGEST"]:
    raise SystemExit("reconstructed state does not match the selected backup")
'"'"'
    cmp -s /candidate/config.json /recovery/compose-inputs/config.json
    cmp -s /candidate/admin-secret /recovery/compose-inputs/admin-secret
    chown -R 10001:10001 /candidate/state
    sync -f /candidate/state
  '
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --network none \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=0700,uid=10001,gid=10001 \
  -v "$restored_volume:/var/lib/tacua" \
  -v "$PWD/services/backend/config.example.json:/run/tacua/config.json:ro" \
  --entrypoint python \
  "$image" -m tacua_backend.operator_tool verify-compose-state \
    --config-file /run/tacua/config.json \
    --state-directory /var/lib/tacua
docker run -d --name "$restored_container" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --network none \
  -v "$restored_volume:/var/lib/tacua" \
  -v "$backup_volume:/recovery:ro" \
  "$image" \
    --config-file /recovery/compose-inputs/config.json \
    --admin-secret-file /recovery/compose-inputs/admin-secret >/dev/null
wait_for_healthy "$restored_container"
docker exec "$restored_container" python -m tacua_backend.operator_tool smoke \
  --config-file /recovery/compose-inputs/config.json \
  --admin-secret-file /recovery/compose-inputs/admin-secret \
  --origin http://127.0.0.1:8080 \
  --allow-loopback-http

printf 'Backend container verification passed for %s.\n' "$test_id"
