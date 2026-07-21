"""Load Tacua's dependency-free runtime contract implementation.

The backend deliberately consumes the repository's canonical validator instead
of maintaining a subtly different validation fork.  The Docker image copies the
same contract directory into the matching monorepo-relative location.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _load_runtime_contract() -> ModuleType:
    repository_root = Path(__file__).resolve().parents[4]
    module_path = repository_root / "contracts" / "runtime" / "src" / "runtime_contract.py"
    if not module_path.is_file():
        raise RuntimeError("Tacua runtime contract validator is unavailable")
    spec = importlib.util.spec_from_file_location("tacua_runtime_contract", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Tacua runtime contract validator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNTIME = _load_runtime_contract()
ContractError = RUNTIME.ContractError
seal = RUNTIME.seal
validate = RUNTIME.validate

