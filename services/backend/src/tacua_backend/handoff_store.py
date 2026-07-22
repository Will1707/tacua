# SPDX-License-Identifier: Apache-2.0
"""Atomic persistence for immutable approved-handoff JSON and Markdown."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import sqlite3
from typing import Any

from .candidate_domain import ContractError as CandidateContractError, TICKET_CONTRACT
from .handoff_export import (
    HANDOFF,
    HandoffArtifacts,
    map_candidate_ticket,
    map_source_candidate,
)


class HandoffStoreError(ValueError):
    """Stable, content-free handoff persistence failure."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class StoredHandoff:
    candidate_id: str
    candidate_version: int
    candidate_digest: str
    handoff_digest: str
    json_digest: str
    markdown_digest: str
    json_bytes: bytes
    markdown_bytes: bytes
    current: bool


def initialize_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS tacua_handoff_schema (
            schema_version INTEGER PRIMARY KEY CHECK (schema_version = 1)
        );
        INSERT OR IGNORE INTO tacua_handoff_schema(schema_version) VALUES (1);

        CREATE TABLE IF NOT EXISTS approved_handoffs (
            candidate_id TEXT NOT NULL,
            candidate_version INTEGER NOT NULL CHECK (candidate_version >= 1),
            candidate_digest TEXT NOT NULL UNIQUE,
            organization_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            handoff_digest TEXT NOT NULL UNIQUE,
            supersedes_handoff_digest TEXT,
            registry_revision TEXT NOT NULL,
            json_digest TEXT NOT NULL UNIQUE,
            markdown_digest TEXT NOT NULL UNIQUE,
            json_bytes BLOB NOT NULL,
            markdown_bytes BLOB NOT NULL,
            created_at TEXT NOT NULL,
            current INTEGER NOT NULL CHECK (current IN (0, 1)),
            PRIMARY KEY (candidate_id, candidate_version),
            FOREIGN KEY (candidate_id, candidate_version)
              REFERENCES candidate_versions(candidate_id, candidate_version)
              ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
        );
        CREATE UNIQUE INDEX IF NOT EXISTS approved_handoffs_current_idx
          ON approved_handoffs(candidate_id) WHERE current = 1;
        CREATE INDEX IF NOT EXISTS approved_handoffs_session_idx
          ON approved_handoffs(organization_id, project_id, session_id);
        """
    )
    versions = connection.execute(
        "SELECT schema_version FROM tacua_handoff_schema ORDER BY schema_version"
    ).fetchall()
    if [tuple(row) for row in versions] != [(1,)]:
        raise HandoffStoreError(
            "HANDOFF_SCHEMA_VERSION_INVALID", "unsupported handoff schema version"
        )


class HandoffStore:
    """Store exact cross-format exports inside the candidate approval transaction."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        organization_id: str,
        project_id: str,
    ):
        self.connection = connection
        self.organization_id = organization_id
        self.project_id = project_id

    @staticmethod
    def _bytes_digest(payload: bytes) -> str:
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _validate(
        self,
        candidate: dict[str, Any],
        artifacts: HandoffArtifacts,
        *,
        require_transaction: bool = True,
    ) -> None:
        if require_transaction and not self.connection.in_transaction:
            raise HandoffStoreError(
                "HANDOFF_TRANSACTION_REQUIRED",
                "handoff persistence requires the active candidate transaction",
            )
        try:
            TICKET_CONTRACT.validate(candidate)
            HANDOFF.validate_handoff(artifacts.handoff, executable=False)
            expected_json = HANDOFF.canonical_json_artifact(artifacts.handoff)
            expected_markdown = HANDOFF.render_markdown(artifacts.handoff).encode(
                "utf-8"
            )
            HANDOFF.validate_markdown(
                artifacts.handoff, artifacts.markdown_bytes.decode("utf-8")
            )
        except CandidateContractError as error:
            raise HandoffStoreError(
                "HANDOFF_CANDIDATE_INVALID",
                "handoff candidate failed contract validation",
            ) from error
        except (HANDOFF.ContractError, UnicodeDecodeError) as error:
            raise HandoffStoreError(
                "HANDOFF_ARTIFACT_INVALID", "handoff artifacts failed validation"
            ) from error
        handoff = artifacts.handoff
        approval = candidate["approval"]
        expected_ticket = map_candidate_ticket(candidate)
        expected_ticket["ticket_content_digest"] = handoff["ticket"][
            "ticket_content_digest"
        ]
        if (
            candidate["state"] != "approved"
            or not isinstance(approval, dict)
            or candidate["organization_id"] != self.organization_id
            or candidate["project_id"] != self.project_id
            or handoff["organization_id"] != self.organization_id
            or handoff["project_id"] != self.project_id
            or handoff["source_candidate"] != map_source_candidate(candidate)
            or handoff["ticket"] != expected_ticket
            or handoff["build_identity"]["build_id"] != candidate["build_id"]
            or handoff["evidence_manifest"]["session_id"]
            != candidate["session_id"]
            or handoff["approval"]["approval_id"] != approval["approval_id"]
            or handoff["approval"]["actor_id"] != approval["actor_id"]
            or handoff["approval"]["approved_at"] != approval["approved_at"]
            or handoff["evidence_manifest"]["manifest_id"]
            != candidate["evidence_manifest"]["manifest_id"]
            or {
                item["evidence_id"]
                for item in handoff["evidence_manifest"]["items"]
            }
            != set(approval["authorized_evidence_ids"])
        ):
            raise HandoffStoreError(
                "HANDOFF_CANDIDATE_MISMATCH",
                "handoff does not identify the exact approved candidate",
            )
        if (
            artifacts.json_bytes != expected_json
            or artifacts.markdown_bytes != expected_markdown
            or artifacts.json_digest != self._bytes_digest(expected_json)
            or artifacts.markdown_digest != self._bytes_digest(expected_markdown)
            or artifacts.handoff["handoff_digest"]
            != HANDOFF.digest_without(artifacts.handoff, "handoff_digest")
        ):
            raise HandoffStoreError(
                "HANDOFF_ARTIFACT_MISMATCH",
                "handoff bytes or digests differ from the sealed document",
            )

    def put(
        self, candidate: dict[str, Any], artifacts: HandoffArtifacts
    ) -> StoredHandoff:
        self._validate(candidate, artifacts)
        handoff = artifacts.handoff
        existing = self.connection.execute(
            """SELECT * FROM approved_handoffs
               WHERE candidate_id = ? AND candidate_version = ?
                 AND organization_id = ? AND project_id = ?""",
            (
                candidate["candidate_id"],
                candidate["candidate_version"],
                self.organization_id,
                self.project_id,
            ),
        ).fetchone()
        if existing is not None:
            linked = self.connection.execute(
                self._select(
                    "handoffs.candidate_id = ? AND handoffs.candidate_version = ? "
                    "AND handoffs.organization_id = ? AND handoffs.project_id = ?"
                ),
                (
                    candidate["candidate_id"],
                    candidate["candidate_version"],
                    self.organization_id,
                    self.project_id,
                ),
            ).fetchone()
            stored = (
                self._verified_input_row(existing, candidate, artifacts)
                if linked is None
                else self._verified_row(linked)
            )
            if (
                stored.candidate_digest != candidate["candidate_digest"]
                or stored.handoff_digest != handoff["handoff_digest"]
                or stored.json_bytes != artifacts.json_bytes
                or stored.markdown_bytes != artifacts.markdown_bytes
            ):
                raise HandoffStoreError(
                    "HANDOFF_VERSION_COLLISION",
                    "immutable candidate version already has another handoff",
                )
            return stored

        current_row = self.connection.execute(
            self._select(
                "handoffs.candidate_id = ? AND handoffs.organization_id = ? "
                "AND handoffs.project_id = ? AND handoffs.current = 1"
            ),
            (candidate["candidate_id"], self.organization_id, self.project_id),
        ).fetchone()
        current = None if current_row is None else self._verified_row(current_row)
        if current is not None and candidate["candidate_version"] <= current.candidate_version:
            raise HandoffStoreError(
                "HANDOFF_SUPERSESSION_MISMATCH",
                "handoff candidate version does not advance the current export",
            )
        expected_supersedes = None if current is None else current.handoff_digest
        if (
            handoff["supersession"]["supersedes_handoff_digest"]
            != expected_supersedes
        ):
            raise HandoffStoreError(
                "HANDOFF_SUPERSESSION_MISMATCH",
                "handoff does not supersede the current stored export",
            )
        savepoint = "tacua_handoff_put"
        self.connection.execute(f"SAVEPOINT {savepoint}")
        try:
            if current is not None:
                self.connection.execute(
                    """UPDATE approved_handoffs SET current = 0
                        WHERE candidate_id = ? AND organization_id = ?
                          AND project_id = ? AND current = 1""",
                    (
                        candidate["candidate_id"],
                        self.organization_id,
                        self.project_id,
                    ),
                )
            self.connection.execute(
                """INSERT INTO approved_handoffs (
                       candidate_id, candidate_version, candidate_digest,
                       organization_id, project_id, session_id,
                       handoff_digest, supersedes_handoff_digest,
                       registry_revision, json_digest, markdown_digest,
                       json_bytes, markdown_bytes, created_at, current
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    candidate["candidate_id"],
                    candidate["candidate_version"],
                    candidate["candidate_digest"],
                    self.organization_id,
                    self.project_id,
                    candidate["session_id"],
                    handoff["handoff_digest"],
                    expected_supersedes,
                    handoff["supersession"]["registry_revision"],
                    artifacts.json_digest,
                    artifacts.markdown_digest,
                    artifacts.json_bytes,
                    artifacts.markdown_bytes,
                    handoff["supersession"]["checked_at"],
                ),
            )
        except sqlite3.IntegrityError as error:
            self.connection.execute(f"ROLLBACK TO {savepoint}")
            self.connection.execute(f"RELEASE {savepoint}")
            raise HandoffStoreError(
                "HANDOFF_STORAGE_CONFLICT", "handoff identity is already in use"
            ) from error
        except BaseException:
            self.connection.execute(f"ROLLBACK TO {savepoint}")
            self.connection.execute(f"RELEASE {savepoint}")
            raise
        else:
            self.connection.execute(f"RELEASE {savepoint}")
        row = self.connection.execute(
            """SELECT * FROM approved_handoffs
               WHERE candidate_id = ? AND candidate_version = ?
                 AND organization_id = ? AND project_id = ?""",
            (
                candidate["candidate_id"],
                candidate["candidate_version"],
                self.organization_id,
                self.project_id,
            ),
        ).fetchone()
        if row is None:  # pragma: no cover - defensive SQLite invariant
            raise HandoffStoreError(
                "HANDOFF_STORAGE_CORRUPT", "stored handoff could not be read back"
            )
        return self._verified_input_row(row, candidate, artifacts)

    def get(
        self, candidate_id: str, candidate_version: int | None = None
    ) -> StoredHandoff:
        if candidate_version is None:
            row = self.connection.execute(
                self._select(
                    "handoffs.candidate_id = ? AND handoffs.organization_id = ? "
                    "AND handoffs.project_id = ? AND handoffs.current = 1"
                ),
                (candidate_id, self.organization_id, self.project_id),
            ).fetchone()
        else:
            row = self.connection.execute(
                self._select(
                    "handoffs.candidate_id = ? AND handoffs.candidate_version = ? "
                    "AND handoffs.organization_id = ? AND handoffs.project_id = ?"
                ),
                (
                    candidate_id,
                    candidate_version,
                    self.organization_id,
                    self.project_id,
                ),
            ).fetchone()
        if row is None:
            raise HandoffStoreError(
                "HANDOFF_NOT_FOUND", "approved handoff was not found"
            )
        return self._verified_row(row)

    @staticmethod
    def _select(where: str) -> str:
        return f"""SELECT handoffs.*, versions.canonical_json AS candidate_json
                     FROM approved_handoffs AS handoffs
                     JOIN candidate_versions AS versions
                       ON versions.candidate_id = handoffs.candidate_id
                      AND versions.candidate_version = handoffs.candidate_version
                    WHERE {where}"""

    def _verified_row(self, row: sqlite3.Row) -> StoredHandoff:
        stored = self._row(row)
        try:
            document = json.loads(stored.json_bytes)
            candidate = json.loads(row["candidate_json"])
            if (
                not isinstance(document, dict)
                or not isinstance(candidate, dict)
                or HANDOFF.canonical_json_artifact(document) != stored.json_bytes
                or TICKET_CONTRACT.canonical_json(candidate) != row["candidate_json"]
            ):
                raise ValueError("stored handoff or candidate JSON is not canonical")
            artifacts = HandoffArtifacts(
                handoff=document,
                json_bytes=stored.json_bytes,
                markdown_bytes=stored.markdown_bytes,
                json_digest=stored.json_digest,
                markdown_digest=stored.markdown_digest,
            )
            self._validate(candidate, artifacts, require_transaction=False)
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValueError,
            HandoffStoreError,
            CandidateContractError,
            HANDOFF.ContractError,
        ) as error:
            raise HandoffStoreError(
                "HANDOFF_STORAGE_CORRUPT", "stored handoff failed validation"
            ) from error
        if (
            self._bytes_digest(stored.json_bytes) != stored.json_digest
            or self._bytes_digest(stored.markdown_bytes) != stored.markdown_digest
            or document["handoff_digest"] != stored.handoff_digest
            or row["candidate_digest"] != candidate["candidate_digest"]
            or row["candidate_digest"]
            != document["source_candidate"]["candidate_digest"]
            or row["candidate_json"]
            != document["source_candidate"]["canonical_json"]
            or row["candidate_id"] != document["ticket"]["ticket_id"]
            or row["candidate_version"] != document["ticket"]["ticket_version"]
            or row["organization_id"] != document["organization_id"]
            or row["project_id"] != document["project_id"]
            or row["session_id"] != document["evidence_manifest"]["session_id"]
            or row["supersedes_handoff_digest"]
            != document["supersession"]["supersedes_handoff_digest"]
            or row["registry_revision"]
            != document["supersession"]["registry_revision"]
            or row["created_at"] != document["supersession"]["checked_at"]
        ):
            raise HandoffStoreError(
                "HANDOFF_STORAGE_CORRUPT", "stored handoff digest verification failed"
            )
        return stored

    def _verified_input_row(
        self,
        row: sqlite3.Row,
        candidate: dict[str, Any],
        artifacts: HandoffArtifacts,
    ) -> StoredHandoff:
        stored = self._row(row)
        handoff = artifacts.handoff
        if (
            stored.candidate_id != candidate["candidate_id"]
            or stored.candidate_version != candidate["candidate_version"]
            or stored.candidate_digest != candidate["candidate_digest"]
            or stored.handoff_digest != handoff["handoff_digest"]
            or stored.json_digest != artifacts.json_digest
            or stored.markdown_digest != artifacts.markdown_digest
            or stored.json_bytes != artifacts.json_bytes
            or stored.markdown_bytes != artifacts.markdown_bytes
            or row["organization_id"] != self.organization_id
            or row["project_id"] != self.project_id
            or row["session_id"] != candidate["session_id"]
            or row["supersedes_handoff_digest"]
            != handoff["supersession"]["supersedes_handoff_digest"]
            or row["registry_revision"]
            != handoff["supersession"]["registry_revision"]
            or row["created_at"] != handoff["supersession"]["checked_at"]
        ):
            raise HandoffStoreError(
                "HANDOFF_STORAGE_CORRUPT",
                "stored handoff metadata differs from its exact input",
            )
        return stored

    def delete_session(self, session_id: str) -> int:
        if not self.connection.in_transaction:
            raise HandoffStoreError(
                "HANDOFF_TRANSACTION_REQUIRED",
                "handoff deletion requires an active transaction",
            )
        return self.connection.execute(
            """DELETE FROM approved_handoffs
               WHERE organization_id = ? AND project_id = ? AND session_id = ?""",
            (self.organization_id, self.project_id, session_id),
        ).rowcount

    @staticmethod
    def _row(row: sqlite3.Row) -> StoredHandoff:
        return StoredHandoff(
            candidate_id=row["candidate_id"],
            candidate_version=row["candidate_version"],
            candidate_digest=row["candidate_digest"],
            handoff_digest=row["handoff_digest"],
            json_digest=row["json_digest"],
            markdown_digest=row["markdown_digest"],
            json_bytes=bytes(row["json_bytes"]),
            markdown_bytes=bytes(row["markdown_bytes"]),
            current=bool(row["current"]),
        )
