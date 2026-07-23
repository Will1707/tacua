#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

keep_verified_images="${TACUA_KEEP_VERIFIED_IMAGES:-false}"
case "$keep_verified_images" in
  true|false) ;;
  *)
    echo "TACUA_KEEP_VERIFIED_IMAGES must be true or false" >&2
    exit 2
    ;;
esac

test_id="${TACUA_REVIEWER_TEST_ID:-ci}"
case "$test_id" in
  *[!a-z0-9-]*|''|-*)
    echo "TACUA_REVIEWER_TEST_ID is invalid" >&2
    exit 2
    ;;
esac
if [ "${#test_id}" -gt 32 ]; then
  echo "TACUA_REVIEWER_TEST_ID is too long" >&2
  exit 2
fi

image="tacua-reviewer-web:${test_id}"
container="tacua-reviewer-web-${test_id}"
cleanup=false
cleanup_container=false
verification_succeeded=false

finish() {
  if [ "$cleanup_container" = true ]; then
    docker container rm --force "$container" >/dev/null 2>&1 || true
  fi
  if [ "$cleanup" = true ] \
    && { [ "$verification_succeeded" != true ] || [ "$keep_verified_images" != true ]; }; then
    docker image rm "$image" >/dev/null 2>&1 || true
  fi
}
trap finish EXIT

if [ ! -f apps/reviewer/dist/index.html ]; then
  echo "generate apps/reviewer/dist before reviewer image verification" >&2
  exit 2
fi
if docker container inspect "$container" >/dev/null 2>&1; then
  echo "refusing to replace an existing reviewer verification container" >&2
  exit 1
fi
if docker image inspect "$image" >/dev/null 2>&1; then
  echo "refusing to replace an existing reviewer verification image" >&2
  exit 1
fi

node .github/scripts/validate-reviewer-web-image-inputs.mjs >/dev/null
docker build --pull=false \
  -f services/reviewer-web/Dockerfile \
  -t "$image" \
  .
cleanup=true

docker run --detach \
  --name "$container" \
  --pull never \
  --network none \
  --read-only \
  --init \
  --user 10002:10002 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --cpus 1.0 \
  --memory 256m \
  --memory-swap 256m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16777216,uid=10002,gid=10002,mode=0700 \
  "$image" >/dev/null
cleanup_container=true

status=""
for _attempt in $(seq 1 30); do
  status="$(docker inspect --format '{{.State.Health.Status}}' "$container")"
  if [ "$status" = healthy ]; then
    break
  fi
  if [ "$status" = unhealthy ]; then
    echo "reviewer verification container became unhealthy" >&2
    exit 1
  fi
  sleep 1
done
if [ "$status" != healthy ]; then
  echo "reviewer verification container did not become healthy" >&2
  exit 1
fi

docker exec --interactive "$container" python -B - \
  < .github/scripts/smoke-reviewer-web-container.py
docker exec "$container" python -B -c \
  'from pathlib import Path; import stat; files=(Path("/licenses/tacua/LICENSE"),Path("/licenses/tacua/NOTICE"),Path("/licenses/reviewer/NOTICE"),Path("/licenses/reviewer/THIRD_PARTY_NOTICES.txt")); assert all(path.is_file() and stat.S_IMODE(path.stat().st_mode)==0o444 for path in files); assert files[0].read_text(encoding="utf-8").lstrip().startswith("Apache License"); assert files[3].read_text(encoding="utf-8").startswith("Tacua reviewer web — third-party notices")'

docker inspect "$container" | python3 -B -c '
import json
import sys

documents = json.load(sys.stdin)
assert isinstance(documents, list) and len(documents) == 1
document = documents[0]
host = document["HostConfig"]
config = document["Config"]
assert document["State"]["Running"] is True
assert document["State"]["Health"]["Status"] == "healthy"
assert host["ReadonlyRootfs"] is True
assert host["NetworkMode"] == "none"
assert host["Privileged"] is False
assert host["CapAdd"] in (None, [])
assert host["CapDrop"] == ["ALL"]
assert host["SecurityOpt"] == ["no-new-privileges:true"]
assert host["PidsLimit"] == 64
assert host["Memory"] == 268435456
assert host["MemorySwap"] == 268435456
assert host["NanoCpus"] == 1000000000
assert host["PortBindings"] in (None, {})
assert config["User"] == "10002:10002"
assert config["Entrypoint"] == ["python", "-B", "/usr/local/bin/tacua-reviewer-web"]
assert config["Cmd"] in (None, [])
assert config["ExposedPorts"] == {"8081/tcp": {}}
assert config.get("Volumes") in (None, {})
'

docker container stop --time 10 "$container" >/dev/null
docker container rm "$container" >/dev/null
cleanup_container=false
reviewer_image_id="$(docker image inspect --format '{{.Id}}' "$image")"
if ! printf '%s\n' "$reviewer_image_id" | grep -Eq '^sha256:[a-f0-9]{64}$'; then
  echo "verified reviewer image identifier is invalid" >&2
  exit 1
fi
verification_succeeded=true
printf 'Reviewer container verification passed for %s.\n' "$test_id"
printf 'Verified reviewer image: %s (%s)\n' "$image" "$reviewer_image_id"
