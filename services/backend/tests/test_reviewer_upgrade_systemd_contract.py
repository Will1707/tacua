# SPDX-License-Identifier: Apache-2.0
"""Static security contract for the durable reviewer-upgrade resumer."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
TEMPLATE = (
    ROOT
    / "services/backend/systemd/tacua-reviewer-upgrade-resume.service.in"
)
LOCK_TEMPLATE = (
    ROOT
    / "services/backend/systemd/tacua-reviewer-upgrade-lock.service.in"
)
PATH_TEMPLATE = (
    ROOT
    / "services/backend/systemd/tacua-reviewer-upgrade-resume.path.in"
)
EXPECTED_PLACEHOLDERS = {
    "@PYTHON@",
    "@UPGRADER@",
    "@STATE_PARENT@",
    "@SERIAL_LOCK_FILE@",
    "@UNIT_DIRECTORY@",
    "@LOCK_FILE@",
    "@OPERATION_DIRECTORY@",
    "@REPOSITORY@",
    "@CONFIG_FILE@",
    "@ADMIN_SECRET_FILE@",
}


class ReviewerUpgradeSystemdContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.service = TEMPLATE.read_text(encoding="utf-8")
        cls.directives = cls.service.splitlines()

    def test_resumer_has_bounded_restartable_oneshot_contract(self) -> None:
        for directive in (
            "Type=oneshot",
            "UMask=0077",
            "TimeoutStartSec=45min",
            "RuntimeMaxSec=45min",
            "Restart=on-failure",
            "RestartSec=5s",
            "RestartPreventExitStatus=78",
            "StartLimitIntervalSec=0",
            "Wants=tacua-reviewer-upgrade-lock.service",
            "After=tacua-reviewer-upgrade-lock.service",
        ):
            with self.subTest(directive=directive):
                self.assertEqual(self.directives.count(directive), 1)
        self.assertNotIn(
            "Requires=tacua-reviewer-upgrade-lock.service",
            self.directives,
        )
        self.assertNotIn("Wants=tacua-reconcile-lock.service", self.directives)
        self.assertNotIn("[Install]", self.directives)
        self.assertFalse(
            any(line.startswith("WantedBy=") for line in self.directives)
        )

    def test_resumer_does_not_order_timer_activation_after_itself(self) -> None:
        self.assertNotIn("Before=tacua-reconcile.timer", self.directives)
        self.assertNotIn("After=tacua-reconcile.timer", self.directives)
        self.assertNotIn("Requires=tacua-reconcile.timer", self.directives)
        self.assertNotIn("Wants=tacua-reconcile.timer", self.directives)

    def test_exec_and_placeholder_surface_is_exact(self) -> None:
        self.assertEqual(
            set(re.findall(r"@[A-Z][A-Z0-9_]*@", self.service)),
            EXPECTED_PLACEHOLDERS,
        )
        self.assertIn(
            'ExecStart=@PYTHON@ -B "@UPGRADER@" resume '
            '--state-parent "@STATE_PARENT@" '
            '--serial-lock-file "@SERIAL_LOCK_FILE@" '
            '--unit-directory "@UNIT_DIRECTORY@" '
            '--lock-file "@LOCK_FILE@" '
            '--operation-directory "@OPERATION_DIRECTORY@"',
            self.service,
        )

    def test_sandbox_writes_only_transaction_units_lock_and_operation_gate(
        self,
    ) -> None:
        self.assertEqual(
            [
                directive
                for directive in self.directives
                if directive.startswith("ReadWritePaths=")
            ],
            [
                'ReadWritePaths="@STATE_PARENT@" "@SERIAL_LOCK_FILE@" '
                '"@UNIT_DIRECTORY@" "@LOCK_FILE@" '
                '"@OPERATION_DIRECTORY@"'
            ],
        )
        self.assertEqual(
            [
                directive
                for directive in self.directives
                if directive.startswith("ReadOnlyPaths=")
            ],
            [
                'ReadOnlyPaths="@UPGRADER@" "@REPOSITORY@" '
                '"@CONFIG_FILE@" "@ADMIN_SECRET_FILE@"'
            ],
        )
        self.assertNotIn("ReadWritePaths=/tmp", self.service)
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
                self.assertEqual(self.directives.count(directive), 1)

    def test_stable_lock_prerequisite_is_outside_the_promoted_bundle(self) -> None:
        service = LOCK_TEMPLATE.read_text(encoding="utf-8")
        directives = service.splitlines()
        self.assertEqual(
            set(re.findall(r"@[A-Z][A-Z0-9_]*@", service)),
            {
                "@PYTHON@",
                "@UPGRADER@",
                "@SERIAL_LOCK_FILE@",
                "@LOCK_FILE@",
                "@PROJECT@",
            },
        )
        for directive in (
            "Type=oneshot",
            "RemainAfterExit=yes",
            "UMask=0077",
            "TimeoutStartSec=30s",
            "PrivateTmp=no",
        ):
            with self.subTest(directive=directive):
                self.assertEqual(directives.count(directive), 1)
        self.assertIn(
            'ExecStart=@PYTHON@ -B "@UPGRADER@" prepare-lock '
            '--serial-lock-file "@SERIAL_LOCK_FILE@" '
            '--lock-file "@LOCK_FILE@" --project "@PROJECT@"',
            service,
        )
        self.assertNotIn("WantedBy=", service)

    def test_path_trigger_closes_prepublication_and_reboot_liveness_gap(
        self,
    ) -> None:
        path_unit = PATH_TEMPLATE.read_text(encoding="utf-8")
        directives = path_unit.splitlines()
        self.assertEqual(
            set(re.findall(r"@[A-Z][A-Z0-9_]*@", path_unit)),
            {"@STATE_PARENT@"},
        )
        for directive in (
            "PathExists=@STATE_PARENT@/upgrades/active.json",
            "Unit=tacua-reviewer-upgrade-resume.service",
            "TriggerLimitIntervalSec=infinity",
            "TriggerLimitBurst=1",
            "WantedBy=default.target",
        ):
            with self.subTest(directive=directive):
                self.assertEqual(directives.count(directive), 1)
        path_section = directives[
            directives.index("[Path]") + 1 : directives.index("[Install]")
        ]
        self.assertIn("TriggerLimitIntervalSec=infinity", path_section)
        self.assertIn("TriggerLimitBurst=1", path_section)
        self.assertNotIn("PathChanged=", path_unit)
        self.assertNotIn(".next", path_unit)


if __name__ == "__main__":
    unittest.main()
