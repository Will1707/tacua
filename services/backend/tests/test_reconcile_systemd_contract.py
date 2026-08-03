# SPDX-License-Identifier: Apache-2.0
"""Static security contract for the rootless reconciliation user units."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SYSTEMD = ROOT / "services" / "backend" / "systemd"


class ReconcileSystemdContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock_service = (
            SYSTEMD / "tacua-reconcile-lock.service.in"
        ).read_text(encoding="utf-8")
        cls.main_service = (
            SYSTEMD / "tacua-reconcile.service.in"
        ).read_text(encoding="utf-8")
        cls.timer = (SYSTEMD / "tacua-reconcile.timer").read_text(
            encoding="utf-8"
        )

    def test_lock_prerequisite_keeps_the_host_ownership_view(self) -> None:
        self.assertIn("host-ownership anchor", self.lock_service)
        self.assertIn("Type=oneshot", self.lock_service)
        self.assertIn("RemainAfterExit=yes", self.lock_service)
        self.assertIn("TimeoutStartSec=30", self.lock_service)
        self.assertIn("UMask=0077", self.lock_service)
        self.assertIn("NoNewPrivileges=yes", self.lock_service)
        self.assertIn("PrivateTmp=no", self.lock_service)
        self.assertIn("RestrictSUIDSGID=yes", self.lock_service)
        self.assertIn("LockPersonality=yes", self.lock_service)
        self.assertIn("MemoryDenyWriteExecute=yes", self.lock_service)
        self.assertIn(
            'prepare-lock --state-directory "@STATE_DIRECTORY@" '
            '--anchor-file "@ANCHOR_FILE@"',
            self.lock_service,
        )

        namespace_directives = (
            "PrivateDevices=",
            "PrivateUsers=",
            "ProtectControlGroups=",
            "ProtectHome=",
            "ProtectKernelModules=",
            "ProtectKernelTunables=",
            "ProtectSystem=",
            "ReadOnlyPaths=",
            "ReadWritePaths=",
            "InaccessiblePaths=",
            "BindPaths=",
            "BindReadOnlyPaths=",
        )
        for directive in namespace_directives:
            with self.subTest(directive=directive):
                self.assertNotIn(directive, self.lock_service)

    def test_main_service_retains_sandbox_and_attested_paths(self) -> None:
        for directive in (
            "NoNewPrivileges=yes",
            "PrivateDevices=yes",
            "PrivateTmp=no",
            "ProtectControlGroups=yes",
            "ProtectHome=read-only",
            "ProtectKernelModules=yes",
            "ProtectKernelTunables=yes",
            "ProtectSystem=strict",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "MemoryDenyWriteExecute=yes",
        ):
            with self.subTest(directive=directive):
                self.assertIn(directive, self.main_service)

        self.assertIn("Requires=tacua-reconcile-lock.service", self.main_service)
        self.assertIn("After=tacua-reconcile-lock.service", self.main_service)
        self.assertIn(
            'reconcile --state-directory "@STATE_DIRECTORY@" '
            '--anchor-file "@ANCHOR_FILE@"',
            self.main_service,
        )
        self.assertIn(
            'ReadWritePaths="@STATE_DIRECTORY@" "@LOCK_FILE@"',
            self.main_service,
        )
        self.assertIn(
            'ReadOnlyPaths="@ANCHOR_FILE@" "@OPERATION_DIRECTORY@" '
            '"@CONFIG_FILE@" "@ADMIN_SECRET_FILE@" "@RECONCILER@"',
            self.main_service,
        )
        self.assertNotIn("ReadWritePaths=/tmp\n", self.main_service)

    def test_timer_declares_activation_and_completion_relative_triggers(
        self,
    ) -> None:
        directives = self.timer.splitlines()
        self.assertEqual(directives.count("OnActiveSec=30s"), 1)
        self.assertEqual(directives.count("OnUnitInactiveSec=30s"), 1)
        self.assertFalse(
            any(line.startswith("OnBootSec=") for line in directives)
        )
        self.assertFalse(
            any(line.startswith("OnStartupSec=") for line in directives)
        )
        self.assertFalse(
            any(line.startswith("OnUnitActiveSec=") for line in directives)
        )
        self.assertFalse(
            any(line.startswith("Persistent=") for line in directives)
        )
        self.assertNotIn("RemainAfterElapse=no", directives)
        self.assertEqual(directives.count("AccuracySec=5s"), 1)
        self.assertEqual(directives.count("Unit=tacua-reconcile.service"), 1)


if __name__ == "__main__":
    unittest.main()
