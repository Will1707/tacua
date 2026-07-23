# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[3]
SCRIPT = (
    REPOSITORY
    / ".github"
    / "scripts"
    / "seed-compose-processing-fixture.py"
)
FIXTURES = (
    REPOSITORY
    / "contracts"
    / "sdk-backend-protocol"
    / "fixtures"
    / "positive"
)
BACKEND_SOURCE = REPOSITORY / "services" / "backend" / "src"


class ComposeProcessingFixtureTests(unittest.TestCase):
    def run_fixture(
        self,
        config: Path,
        secret: Path,
        *extra: str,
    ) -> subprocess.CompletedProcess[bytes]:
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(BACKEND_SOURCE),
        }
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPT),
                "--config-file",
                str(config),
                "--admin-secret-file",
                str(secret),
                "--fixture-directory",
                str(FIXTURES),
                *extra,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=REPOSITORY,
            env=environment,
            timeout=20,
            check=False,
        )

    def test_seed_refuses_reuse_and_verifies_one_processed_stage(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="tacua-compose-fixture-"
        ) as directory:
            root = Path(directory)
            config_path = root / "config.json"
            secret_path = root / "secret"
            state = root / "state"
            config = json.loads(
                (
                    REPOSITORY
                    / "services"
                    / "backend"
                    / "config.example.json"
                ).read_bytes()
            )
            config["state_directory"] = str(state)
            config_path.write_text(
                json.dumps(config, indent=2) + "\n",
                encoding="utf-8",
            )
            secret_path.write_bytes(
                b"tacua-ci-admin-secret-0123456789abcdef"
            )
            secret_path.chmod(0o400)

            seeded = self.run_fixture(config_path, secret_path)
            self.assertEqual(0, seeded.returncode, seeded.stderr)
            self.assertEqual(b'{"status":"ok"}\n', seeded.stdout)
            self.assertEqual(b"", seeded.stderr)

            premature_verification = self.run_fixture(
                config_path,
                secret_path,
                "--verify-processed",
            )
            self.assertEqual(1, premature_verification.returncode)
            self.assertEqual(b"", premature_verification.stdout)
            self.assertEqual(
                b"COMPOSE_PROCESSING_FIXTURE_FAILED\n",
                premature_verification.stderr,
            )

            repeated = self.run_fixture(config_path, secret_path)
            self.assertEqual(1, repeated.returncode)
            self.assertEqual(b"", repeated.stdout)
            self.assertEqual(
                b"COMPOSE_PROCESSING_FIXTURE_FAILED\n",
                repeated.stderr,
            )

            sys.path.insert(0, str(BACKEND_SOURCE))
            try:
                from tacua_backend.config import load_config
                from tacua_backend.instance_lock import (
                    acquire_state_instance_lock,
                )
                from tacua_backend.service import PilotBackend
            finally:
                sys.path.pop(0)
            loaded_config, admin_secret = load_config(
                config_path,
                secret_path,
            )
            with acquire_state_instance_lock(
                loaded_config.state_directory,
                create_directory=False,
            ):
                backend = PilotBackend(loaded_config, admin_secret)
                claim = backend.claim_processing_job("worker_fixture_test")
                self.assertIsNotNone(claim)
                assert claim is not None
                backend.checkpoint_processing_stage(
                    claim["job"]["job_id"],
                    claim["lease"]["stage_name"],
                    claim["lease"]["lease_token"],
                    detail="The configured processor completed this stage.",
                )

            verified = self.run_fixture(
                config_path,
                secret_path,
                "--verify-processed",
            )
            self.assertEqual(0, verified.returncode, verified.stderr)
            self.assertEqual(b'{"status":"ok"}\n', verified.stdout)
            self.assertEqual(b"", verified.stderr)


if __name__ == "__main__":
    unittest.main()
