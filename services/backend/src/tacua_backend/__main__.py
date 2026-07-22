# SPDX-License-Identifier: Apache-2.0

"""Command-line entrypoint for the Tacua pilot backend."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal

from .config import ConfigError, load_config
from .http_api import create_server
from .instance_lock import InstanceLockError, acquire_state_instance_lock
from .service import PilotBackend


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Run the self-hosted Tacua backend")
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--admin-secret-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        config, admin_secret = load_config(args.config_file, args.admin_secret_file)
        instance_lock = acquire_state_instance_lock(
            config.state_directory,
            create_directory=True,
        )
        try:
            backend = PilotBackend(config, admin_secret)
        except Exception:
            instance_lock.close()
            raise
    except (ConfigError, InstanceLockError, ValueError) as exc:
        parser.error(str(exc))
    try:
        server = create_server(backend)
    except Exception:
        instance_lock.close()
        raise
    print(
        f"Tacua backend listening on {config.listen_host}:{config.listen_port}",
        flush=True,
    )

    def stop_on_sigterm(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    previous_sigterm = signal.signal(signal.SIGTERM, stop_on_sigterm)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            server.server_close()
        finally:
            instance_lock.close()
            signal.signal(signal.SIGTERM, previous_sigterm)


if __name__ == "__main__":
    main()
