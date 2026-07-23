# SPDX-License-Identifier: Apache-2.0

"""Exclusive, opt-in CLI for the local processing adapter."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Sequence

from .config import ConfigError, load_config, load_public_config
from .contracts import canonical_json
from .instance_lock import InstanceLockError, acquire_state_instance_lock
from .processing_adapter import (
    LocalProcessingAdapter,
    ProcessingAdapterError,
    load_local_processor_command,
)
from .processing_bridge import WORKER_ERROR_CODE
from .service import ApiError, PilotBackend


MAX_DRAIN_STAGES = 10_000


class _WorkerArgumentError(RuntimeError):
    pass


class _WorkerArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise _WorkerArgumentError


def _parser() -> argparse.ArgumentParser:
    parser = _WorkerArgumentParser(
        description="Run the opt-in Tacua local processing worker"
    )
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--admin-secret-file", type=Path, required=True)
    parser.add_argument("--command-file", type=Path, required=True)
    parser.add_argument("--worker-id", default="worker_local")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run-once", action="store_true")
    mode.add_argument("--drain", action="store_true")
    parser.add_argument("--max-stages", type=int, default=100)
    return parser


def _run(args: argparse.Namespace) -> dict[str, object]:
    if (
        isinstance(args.max_stages, bool)
        or not 1 <= args.max_stages <= MAX_DRAIN_STAGES
    ):
        raise ProcessingAdapterError(
            "PROCESSOR_DRAIN_LIMIT_INVALID",
            f"max-stages must be from 1 through {MAX_DRAIN_STAGES}",
        )
    public_config = load_public_config(args.config_file)
    with acquire_state_instance_lock(
        public_config.state_directory,
        create_directory=True,
    ):
        config, admin_secret = load_config(
            args.config_file, args.admin_secret_file
        )
        if config != public_config:
            raise ConfigError("config file changed while worker startup acquired state")
        command = load_local_processor_command(args.command_file)
        adapter = LocalProcessingAdapter(command)
        backend = PilotBackend(
            config,
            admin_secret,
            processing_engine=adapter,
        )
        adapter.bind_backend(backend)

        stage_limit = 1 if args.run_once else args.max_stages
        processed = 0
        claim_retries = 0
        last_job_id: str | None = None
        queue_empty = False
        # Expired-lease cleanup intentionally asks the caller to retry one
        # bounded claim. Count that progress separately so drain cannot loop
        # without a caller-visible bound.
        iteration_limit = stage_limit * 2 + 50
        for _iteration in range(iteration_limit):
            if processed >= stage_limit:
                break
            try:
                result = backend.run_processing_once(args.worker_id)
            except ApiError as error:
                if error.code == "PROCESSING_CLAIM_RETRY":
                    claim_retries += 1
                    continue
                raise
            if result is None:
                queue_empty = True
                break
            processed += 1
            last_job_id = result["job_id"]

        return {
            "mode": "run_once" if args.run_once else "drain",
            "processed_stages": processed,
            "claim_retries": claim_retries,
            "queue_empty": queue_empty,
            "stage_limit_reached": processed >= stage_limit and not queue_empty,
            "last_job_id": last_job_id,
        }


def _write_failure(code: str) -> int:
    selected = (
        code
        if isinstance(code, str)
        and WORKER_ERROR_CODE.fullmatch(code) is not None
        else "WORKER_FAILED"
    )
    sys.stderr.write(selected + "\n")
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    try:
        args = _parser().parse_args(argv)
        result = _run(args)
        rendered = canonical_json(result) + "\n"
        sys.stdout.write(rendered)
    except _WorkerArgumentError:
        return _write_failure("WORKER_ARGUMENT_INVALID")
    except ProcessingAdapterError as error:
        return _write_failure(error.code)
    except ApiError as error:
        return _write_failure(
            getattr(error, "worker_code", error.code)
        )
    except ConfigError:
        return _write_failure("WORKER_CONFIG_INVALID")
    except InstanceLockError:
        return _write_failure("WORKER_STATE_LOCK_FAILED")
    except ValueError:
        return _write_failure("WORKER_INPUT_INVALID")
    except Exception:
        return _write_failure("WORKER_FAILED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
