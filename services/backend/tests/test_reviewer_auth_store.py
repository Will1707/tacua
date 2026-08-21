# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE = REPOSITORY_ROOT / "services" / "backend" / "src"
sys.path.insert(0, str(SOURCE))

from tacua_backend.reviewer_auth_store import (  # noqa: E402
    PAIRING_TTL,
    REVIEWER_SCOPES,
    SESSION_TTL,
    ReviewerAuthStore,
    ReviewerAuthStoreError,
)


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )


class FakeClock:
    def __init__(self, value: str):
        self._value = parse_time(value)
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self._value

    def set(self, value: str) -> None:
        with self._lock:
            self._value = parse_time(value)


class ReviewerAuthStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "backend.sqlite3"
        self.clock = FakeClock("2026-08-21T09:10:11Z")
        self.verifier_key = b"k" * 32

        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(
                "CREATE TABLE existing_backend_state (value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO existing_backend_state(value) VALUES ('preserved')"
            )

        self.store = self.make_store()
        self.store.initialize_schema()

    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database, timeout=10)

    def make_store(self, **overrides: object) -> ReviewerAuthStore:
        arguments: dict[str, object] = {
            "verifier_key": self.verifier_key,
            "reviewer_id": "reviewer_owner",
            "clock": self.clock,
        }
        arguments.update(overrides)
        return ReviewerAuthStore(self.connect, **arguments)

    def assert_store_error(
        self, status: int, code: str, callback
    ) -> ReviewerAuthStoreError:
        with self.assertRaises(ReviewerAuthStoreError) as caught:
            callback()
        self.assertEqual(status, caught.exception.status)
        self.assertEqual(code, caught.exception.code)
        return caught.exception

    def issue_session(
        self,
        *,
        device_label: str = "Will's browser",
        client_kind: str = "web",
        scopes: tuple[str, ...] = REVIEWER_SCOPES,
    ):
        pairing = self.store.create_pairing(
            device_label=device_label,
            client_kind=client_kind,
        )
        self.store.approve_pairing(pairing.human_code, scopes=scopes)
        return pairing, self.store.exchange_pairing(pairing.pairing_token)

    def test_schema_is_additive_and_has_one_exact_version_marker(self) -> None:
        self.store.initialize_schema()
        with closing(self.connect()) as connection:
            self.assertEqual(
                [("preserved",)],
                connection.execute("SELECT value FROM existing_backend_state").fetchall(),
            )
            self.assertEqual(
                [(1,)],
                connection.execute(
                    "SELECT schema_version FROM tacua_reviewer_auth_schema"
                ).fetchall(),
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
        self.assertIn("reviewer_pairing_requests", tables)
        self.assertIn("reviewer_sessions", tables)
        self.assertIn("tacua_reviewer_auth_time_floor", tables)

    def test_incompatible_schema_marker_fails_closed(self) -> None:
        database = Path(self.temporary.name) / "incompatible.sqlite3"
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute(
                "CREATE TABLE tacua_reviewer_auth_schema "
                "(schema_version INTEGER PRIMARY KEY CHECK (schema_version = 2))"
            )
            connection.execute(
                "INSERT INTO tacua_reviewer_auth_schema(schema_version) VALUES (2)"
            )

        def connect() -> sqlite3.Connection:
            return sqlite3.connect(database, timeout=10)

        store = ReviewerAuthStore(
            connect,
            verifier_key=self.verifier_key,
            reviewer_id="reviewer_owner",
            clock=self.clock,
        )
        error = self.assert_store_error(
            500, "REVIEWER_AUTH_SCHEMA_INVALID", store.initialize_schema
        )
        self.assertNotIn("2", error.message)

    def test_same_columns_with_weakened_constraints_is_not_adopted_or_repaired(
        self,
    ) -> None:
        database = Path(self.temporary.name) / "weakened.sqlite3"

        def connect() -> sqlite3.Connection:
            return sqlite3.connect(database, timeout=10)

        weakened = ReviewerAuthStore(
            connect,
            verifier_key=self.verifier_key,
            reviewer_id="reviewer_owner",
            clock=self.clock,
        )
        weakened.initialize_schema()
        with closing(connect()) as connection, connection:
            connection.executescript(
                """DROP TABLE reviewer_sessions;
                   CREATE TABLE reviewer_sessions (
                       session_id TEXT PRIMARY KEY,
                       session_verifier BLOB NOT NULL,
                       reviewer_id TEXT NOT NULL,
                       device_label TEXT NOT NULL,
                       client_kind TEXT NOT NULL,
                       scopes_json TEXT NOT NULL,
                       created_at TEXT NOT NULL,
                       expires_at TEXT NOT NULL,
                       revoked_at TEXT,
                       originating_pairing_id TEXT NOT NULL
                   );
                   CREATE INDEX reviewer_sessions_reviewer_idx
                     ON reviewer_sessions(reviewer_id, created_at DESC, session_id);"""
            )
        self.assert_store_error(
            500,
            "REVIEWER_AUTH_SCHEMA_INVALID",
            weakened.initialize_schema,
        )
        with closing(connect()) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            session_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' "
                "AND name = 'reviewer_sessions'"
            ).fetchone()[0]
        self.assertEqual(
            {
                "tacua_reviewer_auth_schema",
                "tacua_reviewer_auth_time_floor",
                "reviewer_pairing_requests",
                "reviewer_sessions",
            },
            tables,
        )
        self.assertNotIn("FOREIGN KEY", session_sql)

    def test_schema_rejects_missing_redefined_or_extra_owned_indexes_and_triggers(
        self,
    ) -> None:
        mutations = (
            "DROP INDEX reviewer_sessions_reviewer_idx",
            "DROP INDEX reviewer_sessions_reviewer_idx; "
            "CREATE INDEX reviewer_sessions_reviewer_idx "
            "ON reviewer_sessions(expires_at)",
            "CREATE INDEX reviewer_sessions_extra_idx "
            "ON reviewer_sessions(expires_at)",
            "CREATE TRIGGER reviewer_sessions_extra_trigger "
            "AFTER INSERT ON reviewer_sessions BEGIN SELECT 1; END;",
        )
        for index, mutation in enumerate(mutations):
            database = Path(self.temporary.name) / f"schema-drift-{index}.sqlite3"

            def connect(database: Path = database) -> sqlite3.Connection:
                return sqlite3.connect(database, timeout=10)

            store = ReviewerAuthStore(
                connect,
                verifier_key=self.verifier_key,
                reviewer_id="reviewer_owner",
                clock=self.clock,
            )
            store.initialize_schema()
            with closing(connect()) as connection, connection:
                connection.executescript(mutation)
            with self.subTest(mutation=mutation):
                self.assert_store_error(
                    500,
                    "REVIEWER_AUTH_SCHEMA_INVALID",
                    store.initialize_schema,
                )

    def test_pairing_has_canonical_ten_minute_expiry_and_bounded_metadata(self) -> None:
        pairing = self.store.create_pairing(
            device_label="Will’s iPhone",
            client_kind="native",
        )
        self.assertEqual("2026-08-21T09:10:11Z", pairing.created_at)
        self.assertEqual(
            PAIRING_TTL,
            parse_time(pairing.expires_at) - parse_time(pairing.created_at),
        )
        self.assertEqual("Will’s iPhone", pairing.device_label)
        self.assertEqual("native", pairing.client_kind)
        self.assertNotIn(pairing.pairing_token, repr(pairing))
        self.assertNotIn(pairing.human_code, repr(pairing))

        for label in (
            "",
            " leading",
            "trailing ",
            "e\u0301",
            "a" * 65,
            "hidden\x00value",
        ):
            with self.subTest(label=repr(label)):
                self.assert_store_error(
                    400,
                    "INVALID_PAIRING_REQUEST",
                    lambda label=label: self.store.create_pairing(
                        device_label=label, client_kind="web"
                    ),
                )
        for kind in ("", "Web", "native_ios", "has space", "a" * 33):
            with self.subTest(kind=kind):
                self.assert_store_error(
                    400,
                    "INVALID_PAIRING_REQUEST",
                    lambda kind=kind: self.store.create_pairing(
                        device_label="browser", client_kind=kind
                    ),
                )

    def test_database_never_contains_raw_pairing_or_session_secrets(self) -> None:
        pairing, issued = self.issue_session()
        with closing(self.connect()) as connection:
            connection.text_factory = bytes
            dump_parts: list[bytes] = []
            for table in ("reviewer_pairing_requests", "reviewer_sessions"):
                rows = connection.execute(f"SELECT * FROM {table}").fetchall()
                for row in rows:
                    dump_parts.extend(
                        value if isinstance(value, bytes) else str(value).encode("ascii")
                        for value in row
                        if value is not None
                    )
        persisted = b"\n".join(dump_parts)
        for secret in (
            pairing.pairing_token,
            pairing.pairing_token.split(".", 1)[1],
            pairing.human_code,
            pairing.human_code.replace("-", ""),
            issued.session_token,
            issued.session_token.split(".", 1)[1],
        ):
            self.assertNotIn(secret.encode("ascii"), persisted)
        with closing(self.connect()) as connection:
            pairing_row = connection.execute(
                """SELECT pairing_verifier, human_code_verifier
                     FROM reviewer_pairing_requests"""
            ).fetchone()
            session_row = connection.execute(
                "SELECT session_verifier FROM reviewer_sessions"
            ).fetchone()
        self.assertEqual([32, 32], [len(value) for value in pairing_row])
        self.assertEqual(32, len(session_row[0]))

    def test_pending_quota_is_atomic_and_expiry_releases_capacity(self) -> None:
        store = self.make_store(pending_pairing_limit=2)
        first = store.create_pairing(device_label="one", client_kind="web")
        store.create_pairing(device_label="two", client_kind="web")
        self.assert_store_error(
            429,
            "PAIRING_CAPACITY_REACHED",
            lambda: store.create_pairing(device_label="three", client_kind="web"),
        )
        self.clock.set(first.expires_at)
        third = store.create_pairing(device_label="three", client_kind="web")
        self.assertEqual(first.expires_at, third.created_at)

    def test_sustained_expired_pairing_requests_are_bounded_and_pruned(self) -> None:
        store = self.make_store(pending_pairing_limit=2)
        retained = store.create_pairing(device_label="retained", client_kind="web")
        store.approve_pairing(retained.human_code)
        store.exchange_pairing(retained.pairing_token)

        for generation in range(20):
            first = store.create_pairing(
                device_label=f"generation {generation} first",
                client_kind="web",
            )
            store.create_pairing(
                device_label=f"generation {generation} second",
                client_kind="web",
            )
            store.approve_pairing(first.human_code)
            self.clock.set(first.expires_at)

        survivor = store.create_pairing(device_label="survivor", client_kind="web")
        with closing(self.connect()) as connection:
            rows = connection.execute(
                """SELECT pairing_id, consumed_at, expires_at
                     FROM reviewer_pairing_requests ORDER BY pairing_id"""
            ).fetchall()
        self.assertEqual(2, len(rows))
        self.assertEqual(1, sum(row[1] is not None for row in rows))
        self.assertEqual(
            [(survivor.pairing_id, None, survivor.expires_at)],
            [row for row in rows if row[1] is None],
        )

    def test_approval_uses_human_code_once_and_seals_scopes(self) -> None:
        pairing = self.store.create_pairing(device_label="browser", client_kind="web")
        approved = self.store.approve_pairing(
            pairing.human_code,
            scopes=("reviewer.write", "reviewer.read"),
        )
        self.assertEqual(pairing.pairing_id, approved.pairing_id)
        self.assertEqual(("reviewer.read", "reviewer.write"), approved.scopes)
        replay = self.assert_store_error(
            404,
            "PAIRING_APPROVAL_INVALID",
            lambda: self.store.approve_pairing(pairing.human_code),
        )
        invalid = self.assert_store_error(
            404,
            "PAIRING_APPROVAL_INVALID",
            lambda: self.store.approve_pairing("2222-2222"),
        )
        malformed = self.assert_store_error(
            404,
            "PAIRING_APPROVAL_INVALID",
            lambda: self.store.approve_pairing("not-a-code"),
        )
        self.assertEqual((replay.code, replay.message), (invalid.code, invalid.message))
        self.assertEqual((invalid.code, invalid.message), (malformed.code, malformed.message))

        other = self.store.create_pairing(device_label="other", client_kind="web")
        self.assert_store_error(
            400,
            "INVALID_REVIEWER_SCOPES",
            lambda: self.store.approve_pairing(
                other.human_code,
                scopes=("reviewer.read", "reviewer.read"),
            ),
        )

    def test_pairing_exchange_is_approved_atomic_one_use_and_thirty_days(self) -> None:
        pairing = self.store.create_pairing(device_label="browser", client_kind="web")
        self.assert_store_error(
            409,
            "PAIRING_NOT_APPROVED",
            lambda: self.store.exchange_pairing(pairing.pairing_token),
        )
        self.store.approve_pairing(pairing.human_code)
        issued = self.store.exchange_pairing(pairing.pairing_token)
        self.assertNotIn(issued.session_token, repr(issued))
        self.assertEqual(
            SESSION_TTL,
            parse_time(issued.session.expires_at) - parse_time(issued.session.created_at),
        )
        self.assertEqual(REVIEWER_SCOPES, issued.session.scopes)
        self.assert_store_error(
            401,
            "PAIRING_EXCHANGE_INVALID",
            lambda: self.store.exchange_pairing(pairing.pairing_token),
        )

    def test_client_kind_mismatch_cannot_consume_an_approved_pairing(self) -> None:
        pairing = self.store.create_pairing(device_label="browser", client_kind="web")
        self.store.approve_pairing(pairing.human_code)
        self.assert_store_error(
            401,
            "PAIRING_EXCHANGE_INVALID",
            lambda: self.store.exchange_pairing(
                pairing.pairing_token,
                expected_client_kind="native",
            ),
        )
        issued = self.store.exchange_pairing(
            pairing.pairing_token,
            expected_client_kind="web",
        )
        self.assertEqual("web", issued.session.client_kind)

    def test_pairing_cancellation_is_idempotent_and_removes_pending_request(self) -> None:
        pairing = self.store.create_pairing(device_label="browser", client_kind="web")
        self.store.approve_pairing(pairing.human_code)

        self.store.cancel_pairing(
            pairing.pairing_token,
            expected_client_kind="web",
        )
        self.store.cancel_pairing(
            pairing.pairing_token,
            expected_client_kind="web",
        )
        self.assert_store_error(
            401,
            "PAIRING_EXCHANGE_INVALID",
            lambda: self.store.exchange_pairing(
                pairing.pairing_token,
                expected_client_kind="web",
            ),
        )
        with closing(self.connect()) as connection:
            self.assertEqual(
                [],
                connection.execute(
                    "SELECT pairing_id FROM reviewer_pairing_requests"
                ).fetchall(),
            )

    def test_pairing_cancellation_removes_the_session_issued_from_that_token(self) -> None:
        pairing, issued = self.issue_session(client_kind="native")
        self.assertEqual(
            issued.session.session_id,
            self.store.authenticate_session(issued.session_token).session_id,
        )

        self.store.cancel_pairing(
            pairing.pairing_token,
            expected_client_kind="native",
        )

        self.assert_store_error(
            401,
            "REVIEWER_SESSION_UNAUTHORIZED",
            lambda: self.store.authenticate_session(issued.session_token),
        )
        self.assertEqual((), self.store.list_sessions())
        with closing(self.connect()) as connection:
            self.assertEqual(
                (0, 0),
                (
                    connection.execute(
                        "SELECT COUNT(*) FROM reviewer_pairing_requests"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM reviewer_sessions"
                    ).fetchone()[0],
                ),
            )

    def test_pairing_cancellation_is_content_free_for_unbound_tokens(self) -> None:
        pairing, issued = self.issue_session(client_kind="web")
        replacement = "A" if pairing.pairing_token[-1] != "A" else "B"
        tampered = pairing.pairing_token[:-1] + replacement

        for token, client_kind in (
            ("not-a-token", "web"),
            (tampered, "web"),
            (pairing.pairing_token, "native"),
            ("rpair_" + "0" * 32 + "." + "A" * 43, "web"),
        ):
            self.assertIsNone(
                self.store.cancel_pairing(
                    token,
                    expected_client_kind=client_kind,
                )
            )
            self.assertEqual(
                issued.session.session_id,
                self.store.authenticate_session(issued.session_token).session_id,
            )

        self.store.cancel_pairing(
            pairing.pairing_token,
            expected_client_kind="web",
        )
        self.assert_store_error(
            401,
            "REVIEWER_SESSION_UNAUTHORIZED",
            lambda: self.store.authenticate_session(issued.session_token),
        )

    def test_pairing_cancellation_racing_exchange_leaves_no_live_session(self) -> None:
        pairing = self.store.create_pairing(device_label="phone", client_kind="native")
        self.store.approve_pairing(pairing.human_code)
        start = threading.Barrier(3)
        issued_tokens: list[str] = []
        exchange_errors: list[ReviewerAuthStoreError] = []

        def exchange() -> None:
            start.wait()
            try:
                issued_tokens.append(
                    self.store.exchange_pairing(
                        pairing.pairing_token,
                        expected_client_kind="native",
                    ).session_token
                )
            except ReviewerAuthStoreError as error:
                exchange_errors.append(error)

        def cancel() -> None:
            start.wait()
            self.store.cancel_pairing(
                pairing.pairing_token,
                expected_client_kind="native",
            )

        exchange_thread = threading.Thread(target=exchange)
        cancel_thread = threading.Thread(target=cancel)
        exchange_thread.start()
        cancel_thread.start()
        start.wait()
        exchange_thread.join(timeout=10)
        cancel_thread.join(timeout=10)
        self.assertFalse(exchange_thread.is_alive())
        self.assertFalse(cancel_thread.is_alive())
        self.assertLessEqual(len(issued_tokens), 1)
        self.assertLessEqual(len(exchange_errors), 1)
        if exchange_errors:
            self.assertEqual("PAIRING_EXCHANGE_INVALID", exchange_errors[0].code)
        for session_token in issued_tokens:
            self.assert_store_error(
                401,
                "REVIEWER_SESSION_UNAUTHORIZED",
                lambda token=session_token: self.store.authenticate_session(token),
            )
        self.assertEqual((), self.store.list_sessions())
        with closing(self.connect()) as connection:
            self.assertEqual(
                (0, 0),
                (
                    connection.execute(
                        "SELECT COUNT(*) FROM reviewer_pairing_requests"
                    ).fetchone()[0],
                    connection.execute(
                        "SELECT COUNT(*) FROM reviewer_sessions"
                    ).fetchone()[0],
                ),
            )

    def test_pairing_expiry_and_token_tampering_share_a_content_free_failure(self) -> None:
        expired = self.store.create_pairing(device_label="expired", client_kind="web")
        self.store.approve_pairing(expired.human_code)
        self.clock.set(expired.expires_at)
        expiry_error = self.assert_store_error(
            401,
            "PAIRING_EXCHANGE_INVALID",
            lambda: self.store.exchange_pairing(expired.pairing_token),
        )

        fresh = self.store.create_pairing(device_label="fresh", client_kind="web")
        self.store.approve_pairing(fresh.human_code)
        replacement = "A" if fresh.pairing_token[-1] != "A" else "B"
        tampered_token = fresh.pairing_token[:-1] + replacement
        tamper_error = self.assert_store_error(
            401,
            "PAIRING_EXCHANGE_INVALID",
            lambda: self.store.exchange_pairing(tampered_token),
        )
        unknown = "rpair_" + "0" * 32 + "." + "A" * 43
        unknown_error = self.assert_store_error(
            401,
            "PAIRING_EXCHANGE_INVALID",
            lambda: self.store.exchange_pairing(unknown),
        )
        self.assertEqual(
            (expiry_error.code, expiry_error.message),
            (tamper_error.code, tamper_error.message),
        )
        self.assertEqual(
            (tamper_error.code, tamper_error.message),
            (unknown_error.code, unknown_error.message),
        )

    def test_authentication_checks_scope_and_returns_server_reviewer(self) -> None:
        _, issued = self.issue_session(scopes=("reviewer.read", "reviewer.launch"))
        principal = self.store.authenticate_session(
            issued.session_token,
            required_scope="reviewer.launch",
        )
        self.assertEqual("reviewer_owner", principal.reviewer_id)
        self.assertEqual(issued.session.session_id, principal.session_id)
        self.assertEqual(("reviewer.launch", "reviewer.read"), principal.scopes)
        self.assert_store_error(
            403,
            "REVIEWER_SESSION_FORBIDDEN",
            lambda: self.store.authenticate_session(
                issued.session_token,
                required_scope="reviewer.write",
            ),
        )
        with self.assertRaisesRegex(ValueError, "required_scope is unsupported"):
            self.store.authenticate_session(
                issued.session_token,
                required_scope="administrator",
            )

    def test_session_tamper_unknown_expiry_and_revocation_are_indistinguishable(self) -> None:
        _, issued = self.issue_session()
        replacement = "A" if issued.session_token[-1] != "A" else "B"
        tampered = issued.session_token[:-1] + replacement
        failures = [
            self.assert_store_error(
                401,
                "REVIEWER_SESSION_UNAUTHORIZED",
                lambda: self.store.authenticate_session(tampered),
            ),
            self.assert_store_error(
                401,
                "REVIEWER_SESSION_UNAUTHORIZED",
                lambda: self.store.authenticate_session("malformed"),
            ),
            self.assert_store_error(
                401,
                "REVIEWER_SESSION_UNAUTHORIZED",
                lambda: self.store.authenticate_session(
                    "rsess_" + "0" * 32 + "." + "A" * 43
                ),
            ),
        ]
        _, revoked_issued = self.issue_session(device_label="revoked")
        self.store.revoke_session(revoked_issued.session.session_id)
        failures.append(
            self.assert_store_error(
                401,
                "REVIEWER_SESSION_UNAUTHORIZED",
                lambda: self.store.authenticate_session(revoked_issued.session_token),
            )
        )
        self.clock.set(issued.session.expires_at)
        failures.append(
            self.assert_store_error(
                401,
                "REVIEWER_SESSION_UNAUTHORIZED",
                lambda: self.store.authenticate_session(issued.session_token),
            )
        )
        self.assertEqual(
            {(failure.code, failure.message) for failure in failures},
            {
                (
                    "REVIEWER_SESSION_UNAUTHORIZED",
                    "reviewer session is invalid or unavailable",
                )
            },
        )

    def test_revoke_prunes_the_session_and_list_contains_only_active_sessions(self) -> None:
        _, first = self.issue_session(device_label="first")
        self.clock.set("2026-08-21T09:11:11Z")
        _, second = self.issue_session(device_label="second")
        self.clock.set("2026-08-21T09:12:11Z")
        revoked = self.store.revoke_session(first.session.session_id)
        self.assertEqual("2026-08-21T09:12:11Z", revoked.revoked_at)
        self.assertEqual(
            [second.session.session_id],
            [session.session_id for session in self.store.list_sessions()],
        )
        self.assertIsNone(self.store.list_sessions()[0].revoked_at)
        self.assert_store_error(
            404,
            "REVIEWER_SESSION_NOT_FOUND",
            lambda: self.store.revoke_session(first.session.session_id),
        )
        with closing(self.connect()) as connection:
            self.assertEqual(
                1,
                connection.execute("SELECT COUNT(*) FROM reviewer_sessions").fetchone()[0],
            )
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT COUNT(*) FROM reviewer_pairing_requests"
                ).fetchone()[0],
            )

    def test_active_session_cap_is_atomic_and_released_by_revocation(self) -> None:
        store = self.make_store(active_session_limit=2)

        def issue(label: str):
            pairing = store.create_pairing(device_label=label, client_kind="web")
            store.approve_pairing(pairing.human_code)
            return pairing, store.exchange_pairing(pairing.pairing_token)

        _first_pairing, first = issue("first")
        issue("second")
        pending = store.create_pairing(device_label="pending", client_kind="web")
        store.approve_pairing(pending.human_code)
        self.assert_store_error(
            401,
            "PAIRING_EXCHANGE_INVALID",
            lambda: store.exchange_pairing(
                "rpair_" + "0" * 32 + "." + "A" * 43
            ),
        )
        self.assert_store_error(
            429,
            "REVIEWER_SESSION_CAPACITY_REACHED",
            lambda: store.exchange_pairing(pending.pairing_token),
        )

        store.revoke_session(first.session.session_id)
        issued = store.exchange_pairing(pending.pairing_token)
        self.assertEqual("pending", issued.session.device_label)
        self.assertEqual(2, len(store.list_sessions()))

    def test_sustained_session_issuance_prunes_expired_sessions_and_pairings(self) -> None:
        store = self.make_store(active_session_limit=2)
        for generation in range(80):
            pairing = store.create_pairing(
                device_label=f"generation {generation}",
                client_kind="web",
            )
            store.approve_pairing(pairing.human_code)
            issued = store.exchange_pairing(pairing.pairing_token)
            self.clock.set(issued.session.expires_at)
            self.assertEqual((), store.list_sessions())

        with closing(self.connect()) as connection:
            self.assertEqual(
                0,
                connection.execute("SELECT COUNT(*) FROM reviewer_sessions").fetchone()[0],
            )
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT COUNT(*) FROM reviewer_pairing_requests"
                ).fetchone()[0],
            )

    def test_restart_preserves_sessions_and_a_different_key_cannot_authenticate(self) -> None:
        _, issued = self.issue_session()
        restarted = self.make_store()
        restarted.initialize_schema()
        self.assertEqual(
            issued.session.session_id,
            restarted.authenticate_session(issued.session_token).session_id,
        )
        wrong_key = self.make_store(verifier_key=b"x" * 32)
        self.assert_store_error(
            401,
            "REVIEWER_SESSION_UNAUTHORIZED",
            lambda: wrong_key.authenticate_session(issued.session_token),
        )

    def test_restart_and_clock_rollback_cannot_resurrect_expired_session(self) -> None:
        _, issued = self.issue_session()
        self.clock.set(issued.session.expires_at)
        self.assert_store_error(
            401,
            "REVIEWER_SESSION_UNAUTHORIZED",
            lambda: self.store.authenticate_session(issued.session_token),
        )
        with closing(self.connect()) as connection:
            self.assertEqual(
                [(issued.session.expires_at,)],
                connection.execute(
                    "SELECT observed_at FROM tacua_reviewer_auth_time_floor"
                ).fetchall(),
            )

        self.clock.set("2026-08-21T09:20:00Z")
        restarted = self.make_store()
        restarted.initialize_schema()
        self.assert_store_error(
            401,
            "REVIEWER_SESSION_UNAUTHORIZED",
            lambda: restarted.authenticate_session(issued.session_token),
        )
        pairing = restarted.create_pairing(
            device_label="after rollback",
            client_kind="web",
        )
        self.assertEqual(issued.session.expires_at, pairing.created_at)

    def test_concurrent_pairing_exchange_has_exactly_one_winner(self) -> None:
        pairing = self.store.create_pairing(device_label="browser", client_kind="web")
        self.store.approve_pairing(pairing.human_code)
        barrier = threading.Barrier(3)
        lock = threading.Lock()
        results: list[str] = []

        def exchange() -> None:
            barrier.wait()
            try:
                self.store.exchange_pairing(pairing.pairing_token)
                result = "ok"
            except ReviewerAuthStoreError as error:
                result = error.code
            with lock:
                results.append(result)

        threads = [threading.Thread(target=exchange) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(["PAIRING_EXCHANGE_INVALID", "ok"], sorted(results))
        self.assertEqual(1, len(self.store.list_sessions()))

    def test_concurrent_pending_quota_has_exactly_one_winner(self) -> None:
        store = self.make_store(pending_pairing_limit=1)
        barrier = threading.Barrier(3)
        lock = threading.Lock()
        results: list[str] = []

        def create(index: int) -> None:
            barrier.wait()
            try:
                store.create_pairing(
                    device_label=f"browser {index}", client_kind="web"
                )
                result = "ok"
            except ReviewerAuthStoreError as error:
                result = error.code
            with lock:
                results.append(result)

        threads = [threading.Thread(target=create, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(["PAIRING_CAPACITY_REACHED", "ok"], sorted(results))


if __name__ == "__main__":
    unittest.main()
