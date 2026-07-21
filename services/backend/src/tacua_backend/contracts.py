"""Load Tacua's frozen dependency-free protocol implementation.

The backend intentionally imports the repository validator instead of carrying
an HTTP-specific fork of canonical JSON, digest, or cross-artifact rules.  The
Docker image copies the same contract tree into its monorepo-relative path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _load_protocol_contract() -> ModuleType:
    repository_root = Path(__file__).resolve().parents[4]
    module_path = (
        repository_root
        / "contracts"
        / "sdk-backend-protocol"
        / "src"
        / "protocol_contract.py"
    )
    if not module_path.is_file():
        raise RuntimeError("Tacua SDK/backend protocol validator is unavailable")
    spec = importlib.util.spec_from_file_location("tacua_sdk_backend_protocol", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Tacua SDK/backend protocol validator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROTOCOL = _load_protocol_contract()
RUNTIME = PROTOCOL.runtime
ContractError = PROTOCOL.ContractError
PROTOCOL_VERSION = PROTOCOL.PROTOCOL_VERSION
canonical_json = PROTOCOL.canonical_json
digest = PROTOCOL.digest
digest_without = PROTOCOL.digest_without
seal = PROTOCOL.seal
validate = PROTOCOL.validate
validate_operation_pair = PROTOCOL.validate_operation_pair
validate_idempotent_replay = PROTOCOL.validate_idempotent_replay
validate_new_upload_authentication = PROTOCOL.validate_new_upload_authentication
validate_authenticated_exact_replay = PROTOCOL.validate_authenticated_exact_replay
runtime_seal = RUNTIME.seal
runtime_validate = RUNTIME.validate
