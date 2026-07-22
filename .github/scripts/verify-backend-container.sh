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
volume="tacua-backend-${test_id}-state"
backup_volume="tacua-backend-${test_id}-backup"
restored_volume="tacua-backend-${test_id}-restored-state"
runtime_parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
runtime_directory="$(mktemp -d "${runtime_parent%/}/tacua-container-${test_id}.XXXXXX")"
secret="$runtime_directory/admin-secret"
resolved_compose="$runtime_directory/compose.json"
resolved_production_compose="$runtime_directory/compose-production.json"
local_config="services/backend/local/config.json"
local_secret="services/backend/local/admin-secret"
local_directory="services/backend/local"
cleanup_local_files=false
created_local_directory=false
docker_cleanup=false

cleanup() {
  if [ "$docker_cleanup" = true ]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
    docker rm -f "$second_container" >/dev/null 2>&1 || true
    docker rm -f "$restored_container" >/dev/null 2>&1 || true
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

if [ -L "$local_directory" ] || { [ -e "$local_directory" ] && [ ! -d "$local_directory" ]; }; then
  echo "services/backend/local must be absent or a real directory" >&2
  exit 1
fi
if [ -e "$local_config" ] || [ -L "$local_config" ] || [ -e "$local_secret" ] || [ -L "$local_secret" ]; then
  echo "refusing to replace existing services/backend/local verification inputs" >&2
  exit 1
fi

for target in "$container" "$second_container" "$restored_container"; do
  if docker container inspect "$target" >/dev/null 2>&1; then
    echo "refusing to replace existing Docker container: $target" >&2
    exit 1
  fi
done
for target in "$volume" "$backup_volume" "$restored_volume"; do
  if docker volume inspect "$target" >/dev/null 2>&1; then
    echo "refusing to replace existing Docker volume: $target" >&2
    exit 1
  fi
done
if docker image inspect "$image" >/dev/null 2>&1; then
  echo "refusing to replace existing Docker image: $image" >&2
  exit 1
fi

printf '%s' 'tacua-ci-admin-secret-0123456789abcdef' > "$secret"
chmod 0444 "$secret"
if [ ! -d "$local_directory" ]; then
  mkdir -- "$local_directory"
  created_local_directory=true
fi
if [ -L "$local_directory" ] || [ ! -d "$local_directory" ]; then
  echo "services/backend/local changed before verification inputs were created" >&2
  exit 1
fi
cleanup_local_files=true
cp services/backend/config.example.json "$local_config"
install -m 0600 "$secret" "$local_secret"

docker compose -f services/backend/compose.yaml config --format json > "$resolved_compose"
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  validate-compose \
  --config-file services/backend/config.example.json \
  --compose-json "$resolved_compose" \
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

docker_cleanup=true
docker build -f services/backend/Dockerfile -t "$image" .
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
  "$image" -m tacua_backend.operator_tool verify-backup /backup/restored

docker volume create "$restored_volume" >/dev/null
docker run --rm --user 0:0 --entrypoint /bin/sh \
  -v "$backup_volume:/backup:ro" \
  -v "$restored_volume:/restored-state" \
  "$image" -c \
    'cp -a /backup/restored/state/. /restored-state/ && chown -R 10001:10001 /restored-state && chmod 0700 /restored-state'
docker run -d --name "$restored_container" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --network none \
  -v "$restored_volume:/var/lib/tacua" \
  -v "$backup_volume:/recovery:ro" \
  "$image" \
    --config-file /recovery/restored/config.json \
    --admin-secret-file /recovery/restored/admin-secret >/dev/null
wait_for_healthy "$restored_container"
docker exec "$restored_container" python -m tacua_backend.operator_tool smoke \
  --config-file /recovery/restored/config.json \
  --admin-secret-file /recovery/restored/admin-secret \
  --origin http://127.0.0.1:8080 \
  --allow-loopback-http

printf 'Backend container verification passed for %s.\n' "$test_id"
