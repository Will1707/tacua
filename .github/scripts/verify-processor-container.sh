#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

keep_verified_image="${TACUA_KEEP_VERIFIED_IMAGES:-false}"
case "$keep_verified_image" in
  true|false) ;;
  *)
    echo "TACUA_KEEP_VERIFIED_IMAGES must be true or false" >&2
    exit 2
    ;;
esac

test_id="${TACUA_PROCESSOR_TEST_ID:-ci}"
case "$test_id" in
  *[!a-z0-9-]*|''|-*)
    echo "TACUA_PROCESSOR_TEST_ID is invalid" >&2
    exit 2
    ;;
esac
if [ "${#test_id}" -gt 32 ]; then
  echo "TACUA_PROCESSOR_TEST_ID is too long" >&2
  exit 2
fi

if [ ! -f services/processor/Dockerfile ] \
  || [ ! -f contracts/local-processing/fixtures/positive/adapter-v1.0-checkpoint/input.json ]; then
  echo "run this script from the Tacua repository root" >&2
  exit 2
fi

image="tacua-offline-processor:${test_id}"
runtime_parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
runtime_directory="$(
  mktemp -d "${runtime_parent%/}/tacua-processor-container-${test_id}.XXXXXX"
)"
wrapper="$runtime_directory/input.json"
model="$runtime_directory/model.bin"
output="$runtime_directory/output.json"
diagnostic="$runtime_directory/diagnostic"
image_created=false
verification_succeeded=false

cleanup() {
  if [ "$image_created" = true ] \
    && { [ "$verification_succeeded" != true ] || [ "$keep_verified_image" != true ]; }; then
    docker image rm "$image" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$runtime_directory"
}
trap cleanup EXIT HUP INT TERM

if docker image inspect "$image" >/dev/null 2>&1; then
  echo "refusing to replace an existing processor verification image" >&2
  exit 1
fi

node .github/scripts/validate-processor-image-inputs.mjs >/dev/null
python3 -B - "$wrapper" <<'PY'
import importlib.util
import json
from pathlib import Path
import sys

root = Path.cwd()
processor_path = root / "services" / "processor" / "processor.py"
spec = importlib.util.spec_from_file_location("tacua_offline_processor", processor_path)
if spec is None or spec.loader is None:
    raise SystemExit("processor module is unavailable")
processor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(processor)
source_path = (
    root
    / "contracts"
    / "local-processing"
    / "fixtures"
    / "positive"
    / "adapter-v1.0-checkpoint"
    / "input.json"
)
source = json.loads(source_path.read_bytes())
wrapper = {
    "contract_version": processor.ISOLATED_INPUT_CONTRACT,
    "isolated_input_digest": "sha256:" + "0" * 64,
    "source_input": source,
    "source_input_digest": source["input_digest"],
}
wrapper["isolated_input_digest"] = processor.digest_without(
    wrapper,
    "isolated_input_digest",
)
destination = Path(sys.argv[1])
destination.write_bytes(processor.canonical_bytes(wrapper))
destination.chmod(0o444)
PY
printf '%s\n' 'synthetic checkpoint model' > "$model"
chmod 0444 "$model"

docker build --pull=false \
  -f services/processor/Dockerfile \
  -t "$image" \
  .
image_created=true

docker image inspect "$image" | python3 -B -c '
import json
import sys

documents = json.load(sys.stdin)
assert isinstance(documents, list) and len(documents) == 1
config = documents[0]["Config"]
assert config.get("Entrypoint") in (None, [])
assert config.get("Cmd") in (None, [])
assert config.get("User", "") == ""
assert config.get("WorkingDir", "") in ("", "/")
assert config.get("Healthcheck") is None
assert config.get("Volumes") in (None, {})
assert config.get("ExposedPorts") in (None, {})
expected_environment = {
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
}
environment = config.get("Env")
assert isinstance(environment, list)
assert len(environment) == len(expected_environment)
assert set(environment) == expected_environment
'

docker run --rm \
  --pull never \
  --network none \
  --read-only \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --cpus 1.0 \
  --memory 512m \
  --memory-swap 512m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16777216,uid=65532,gid=65532,mode=0700 \
  --entrypoint /bin/sh \
  "$image" -ceu '
    test "$(stat -c %a /usr/share/doc/tacua)" = 555
    test "$(stat -c %a /usr/share/doc/tacua/LICENSE)" = 444
    test "$(stat -c %a /usr/share/doc/tacua/NOTICE)" = 444
    test "$(stat -c %a /usr/share/doc/tacua/THIRD_PARTY_NOTICES.md)" = 444
    test -r /usr/share/doc/whisper.cpp/LICENSE
    test ! -w /usr/share/doc/tacua/LICENSE
    test ! -w /usr/share/doc/tacua/NOTICE
    test ! -w /usr/share/doc/tacua/THIRD_PARTY_NOTICES.md
  '

if ! docker run --rm \
  --pull never \
  --network none \
  --read-only \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --cpus 1.0 \
  --memory 512m \
  --memory-swap 512m \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --env TACUA_PROCESSOR_MODEL_ID=synthetic_checkpoint \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16777216,uid=65532,gid=65532,mode=0700 \
  --mount "type=bind,src=$wrapper,dst=/input/input.json,readonly" \
  --mount "type=bind,src=$model,dst=/input/model.bin,readonly" \
  --entrypoint /usr/local/bin/tacua-offline-processor \
  "$image" \
    --input /input/input.json \
    --model /input/model.bin \
  > "$output" 2> "$diagnostic"; then
  echo "processor checkpoint container failed" >&2
  exit 1
fi
if [ -s "$diagnostic" ]; then
  echo "processor checkpoint wrote to its closed diagnostic stream" >&2
  exit 1
fi

PYTHONPATH=contracts/local-processing/src python3 -B - "$wrapper" "$output" <<'PY'
import json
from pathlib import Path
import sys

import local_processing_contract

wrapper_bytes = Path(sys.argv[1]).read_bytes()
output_bytes = Path(sys.argv[2]).read_bytes()
wrapper = json.loads(wrapper_bytes)
output = json.loads(output_bytes)
local_processing_contract.validate_isolated_output(
    output,
    wrapper["source_input"],
)
if local_processing_contract.canonical_json(output).encode("utf-8") != output_bytes:
    raise SystemExit("processor checkpoint output is not canonical")
if output["previews"] != [] or output["result"]["disposition"] != "checkpoint":
    raise SystemExit("processor checkpoint output has an unexpected disposition")
PY

processor_image_id="$(docker image inspect --format '{{.Id}}' "$image")"
if ! printf '%s\n' "$processor_image_id" \
  | grep -Eq '^sha256:[a-f0-9]{64}$'; then
  echo "verified processor image identifier is invalid" >&2
  exit 1
fi
verification_succeeded=true
printf 'Processor container verification passed for %s.\n' "$test_id"
printf 'Verified processor image: %s (%s)\n' "$image" "$processor_image_id"
