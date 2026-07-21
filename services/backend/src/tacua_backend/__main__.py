"""Command-line entrypoint for the Tacua pilot backend."""

from __future__ import annotations

import argparse
from pathlib import Path

from .config import ConfigError, load_config
from .http_api import create_server
from .service import PilotBackend


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the non-production Tacua pilot backend")
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--admin-secret-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        config, admin_secret = load_config(args.config_file, args.admin_secret_file)
        backend = PilotBackend(config, admin_secret)
    except ConfigError as exc:
        parser.error(str(exc))
    server = create_server(backend)
    print(f"Tacua pilot backend listening on {config.listen_host}:{config.listen_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

