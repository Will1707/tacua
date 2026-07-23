#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [ "$#" -ne 9 ]; then
  echo "usage: verify-compose-processing-bridge.sh PROJECT COMPOSE_JSON CONFIG SECRET BACKEND_CONTAINER STATE_VOLUME PROCESSOR_IMAGE_ID BACKEND_IMAGE_ID HOST_PORT" >&2
  exit 2
fi

project="$1"
compose_json="$2"
config_file="$3"
admin_secret_file="$4"
backend_container="$5"
state_volume="$6"
processor_image_id="$7"
backend_image_id="$8"
host_port="$9"

case "$project" in
  *[!a-z0-9_-]*|''|-*)
    echo "bridge verification project is invalid" >&2
    exit 2
    ;;
esac
if [ "${#project}" -gt 63 ]; then
  echo "bridge verification project is too long" >&2
  exit 2
fi
for image_id in "$processor_image_id" "$backend_image_id"; do
  if ! printf '%s\n' "$image_id" | grep -Eq '^sha256:[a-f0-9]{64}$'; then
    echo "bridge verification image identifier is invalid" >&2
    exit 2
  fi
done
if [ "${#host_port}" -gt 5 ]; then
  echo "bridge verification host port is invalid" >&2
  exit 2
fi
case "$host_port" in
  *[!0-9]*|''|0*)
    echo "bridge verification host port is invalid" >&2
    exit 2
    ;;
esac
if [ "$host_port" -lt 1024 ] || [ "$host_port" -gt 65535 ]; then
  echo "bridge verification host port is invalid" >&2
  exit 2
fi
if [ ! -f .github/scripts/seed-compose-processing-fixture.py ] \
  || [ ! -f services/backend/scripts/run_compose_isolated_processing.py ]; then
  echo "run this script from the Tacua repository root" >&2
  exit 2
fi

repository_root="$(pwd -P)"
python_executable="$(command -v python3)"
case "$python_executable" in
  /*) ;;
  *)
    echo "python3 did not resolve to an absolute executable" >&2
    exit 1
    ;;
esac

resolve_regular_file() {
  python3 -B - "$1" <<'PY'
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
metadata = path.lstat()
resolved = path.resolve(strict=True)
if (
    not stat.S_ISREG(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or metadata.st_nlink != 1
):
    raise SystemExit("bridge verification input is unsafe")
print(resolved)
PY
}

compose_json="$(resolve_regular_file "$compose_json")"
config_file="$(resolve_regular_file "$config_file")"
admin_secret_file="$(resolve_regular_file "$admin_secret_file")"

runtime_parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
operation_parent="$(mktemp -d "/tmp/tb.XXXXXX")"
work_directory="$(mktemp -d "${runtime_parent%/}/tacua-bridge.XXXXXX")"
chmod 0700 "$operation_parent" "$work_directory"
operation_parent="$(cd "$operation_parent" && pwd -P)"
work_directory="$(cd "$work_directory" && pwd -P)"
operation="$operation_parent/tacua-compose-processing-$project"
socket_path="$operation/processing-bridge.sock"
model="$work_directory/model.bin"
isolated_command="$work_directory/isolated-command.json"
bridge_summary="$work_directory/bridge-summary.json"
bridge_diagnostic="$work_directory/bridge-diagnostic"
recovery_output="$work_directory/recovery.json"
recovery_error="$work_directory/recovery-error"
verification_succeeded=false

if [ "${#socket_path}" -gt 103 ]; then
  echo "bridge verification project makes the Unix socket path too long" >&2
  rm -rf -- "$operation_parent" "$work_directory"
  exit 2
fi

bridge_arguments=(
  "$python_executable"
  -B
  "$repository_root/services/backend/scripts/run_compose_isolated_processing.py"
  --project "$project"
  --compose-json "$compose_json"
  --operation-directory "$operation_parent"
  --config-file "$config_file"
  --admin-secret-file "$admin_secret_file"
  --isolated-command-file "$isolated_command"
  --worker-id worker_rootless_gate
  --allow-mutable-image
  --expected-published-port "$host_port"
  --run-once
)

recover_bridge() {
  rm -f -- "$recovery_output" "$recovery_error"
  if ! "$python_executable" -B \
    "$repository_root/services/backend/scripts/run_compose_isolated_processing.py" \
    recover \
    --project "$project" \
    --operation-directory "$operation_parent" \
    --config-file "$config_file" \
    --admin-secret-file "$admin_secret_file" \
    --allow-mutable-image \
    --expected-published-port "$host_port" \
    > "$recovery_output" 2> "$recovery_error"; then
    return 1
  fi
  [ "$(cat "$recovery_output")" = '{"status":"recovered"}' ] \
    && [ ! -s "$recovery_error" ]
}

cleanup() {
  if [ -d "$operation" ]; then
    recover_bridge >/dev/null 2>&1 || true
  fi
  if [ "$verification_succeeded" = true ] || [ ! -d "$operation" ]; then
    rm -rf -- "$operation_parent" "$work_directory"
  else
    echo "bridge verification retained its recovery evidence" >&2
  fi
}
trap cleanup EXIT HUP INT TERM

wait_for_healthy() {
  local target="$1"
  local status
  for _ in $(seq 1 60); do
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

smoke_backend() {
  PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
    smoke \
    --config-file "$config_file" \
    --admin-secret-file "$admin_secret_file" \
    --origin "http://127.0.0.1:$host_port" \
    --allow-loopback-http
}

assert_bridge_clean() {
  local bridge_containers
  local consumers
  if [ -e "$operation" ] || [ -L "$operation" ]; then
    echo "bridge operation directory remained" >&2
    return 1
  fi
  bridge_containers="$(
    docker container ls -aq \
      --no-trunc \
      --filter 'label=com.tacua.compose-processing-bridge=true' \
      --filter "label=com.tacua.compose-processing-project=$project"
  )"
  if [ -n "$bridge_containers" ]; then
    echo "bridge container remained" >&2
    return 1
  fi
  if [ "$(docker inspect --format '{{.Id}}' "$backend_container")" != "$backend_container" ] \
    || [ "$(docker inspect --format '{{.Image}}' "$backend_container")" != "$backend_image_id" ] \
    || [ "$(docker inspect --format '{{.State.Health.Status}}' "$backend_container")" != healthy ]; then
    echo "backend identity or health changed during bridge processing" >&2
    return 1
  fi
  consumers="$(
    docker container ls -aq --no-trunc --filter "volume=$state_volume"
  )"
  if [ "$consumers" != "$backend_container" ]; then
    echo "state volume consumer set differs after bridge processing" >&2
    return 1
  fi
  smoke_backend
}

printf '%s\n' 'synthetic checkpoint model' > "$model"
chmod 0400 "$model"
python3 -B - "$processor_image_id" "$model" "$isolated_command" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

image, model_value, destination_value = sys.argv[1:]
model = Path(model_value)
destination = Path(destination_value)
document = {
    "argv": [
        "/usr/local/bin/tacua-offline-processor",
        "--input",
        "{input}",
        "--model",
        "{model}",
    ],
    "contract_version": "tacua.isolated-processing-command@1.0.0",
    "image": image,
    "model_digest": "sha256:" + hashlib.sha256(model.read_bytes()).hexdigest(),
    "model_id": "synthetic_checkpoint",
    "model_path": str(model),
    "timeout_seconds": 150,
}
destination.write_bytes(
    json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
)
destination.chmod(0o600)
PY

docker stop "$backend_container" >/dev/null
docker run --rm \
  --pull never \
  --network none \
  --read-only \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 128 \
  --mount "type=volume,src=$state_volume,dst=/var/lib/tacua,volume-nocopy" \
  --mount "type=bind,src=$config_file,dst=/run/tacua/config.json,readonly" \
  --mount "type=bind,src=$admin_secret_file,dst=/run/secrets/tacua_admin,readonly" \
  --mount "type=bind,src=$repository_root/.github/scripts/seed-compose-processing-fixture.py,dst=/verify/seed.py,readonly" \
  --mount "type=bind,src=$repository_root/contracts/sdk-backend-protocol/fixtures/positive,dst=/verify/fixtures,readonly" \
  --entrypoint /usr/local/bin/python \
  "$backend_image_id" \
    -B /verify/seed.py \
    --config-file /run/tacua/config.json \
    --admin-secret-file /run/secrets/tacua_admin \
    --fixture-directory /verify/fixtures \
  | grep -Fx '{"status":"ok"}'
docker start "$backend_container" >/dev/null
wait_for_healthy "$backend_container"
smoke_backend

if ! "${bridge_arguments[@]}" > "$bridge_summary" 2> "$bridge_diagnostic"; then
  if [ -s "$bridge_diagnostic" ]; then
    cat "$bridge_diagnostic" >&2
  fi
  failure_phase="pre_journal"
  if [ -f "$operation/operation.json" ] \
    && [ ! -L "$operation/operation.json" ]; then
    failure_phase="$(
      "$python_executable" -B - "$operation/operation.json" <<'PY'
import json
from pathlib import Path
import sys

allowed = {
    "prepared",
    "backend_stopped",
    "baseline_verifier_creating",
    "baseline_verifier_created",
    "baseline_verified",
    "worker_creating",
    "worker_created",
    "worker_starting",
    "worker_exited",
    "post_worker_verifier_creating",
    "post_worker_verifier_created",
    "recovery_verifier_creating",
    "recovery_verifier_created",
    "state_verified",
    "backend_healthy",
}
document = json.loads(Path(sys.argv[1]).read_bytes())
phase = document.get("phase") if isinstance(document, dict) else None
if phase not in allowed:
    raise SystemExit(1)
print(phase)
PY
    )" || failure_phase="invalid_journal"
  fi
  printf 'Compose processing bridge failure phase: %s\n' \
    "$failure_phase" >&2
  echo "Compose processing bridge execution failed" >&2
  exit 1
fi
if [ "$(cat "$bridge_summary")" \
    != '{"claim_retries":0,"mode":"run_once","processed_stages":1,"queue_empty":false,"stage_limit_reached":true,"status":"ok"}' ] \
  || [ -s "$bridge_diagnostic" ]; then
  echo "successful bridge run returned an unexpected result" >&2
  exit 1
fi
assert_bridge_clean

if [ -n "$(
  docker container ls -aq \
    --no-trunc \
    --filter 'label=com.tacua.private-isolated-processor=true'
)" ] || [ -n "$(
  docker volume ls -q \
    --filter 'label=com.tacua.private-isolated-processor=true'
)" ]; then
  echo "isolated processor recovery artifact remained" >&2
  exit 1
fi

docker stop "$backend_container" >/dev/null
docker run --rm \
  --pull never \
  --network none \
  --read-only \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 128 \
  --mount "type=volume,src=$state_volume,dst=/var/lib/tacua,volume-nocopy" \
  --mount "type=bind,src=$config_file,dst=/run/tacua/config.json,readonly" \
  --mount "type=bind,src=$admin_secret_file,dst=/run/secrets/tacua_admin,readonly" \
  --mount "type=bind,src=$repository_root/.github/scripts/seed-compose-processing-fixture.py,dst=/verify/seed.py,readonly" \
  --mount "type=bind,src=$repository_root/contracts/sdk-backend-protocol/fixtures/positive,dst=/verify/fixtures,readonly" \
  --entrypoint /usr/local/bin/python \
  "$backend_image_id" \
    -B /verify/seed.py \
    --config-file /run/tacua/config.json \
    --admin-secret-file /run/secrets/tacua_admin \
    --fixture-directory /verify/fixtures \
    --verify-processed \
  | grep -Fx '{"status":"ok"}'
docker start "$backend_container" >/dev/null
wait_for_healthy "$backend_container"
smoke_backend

verification_succeeded=true
printf 'Compose processing bridge verification passed for %s.\n' "$project"
