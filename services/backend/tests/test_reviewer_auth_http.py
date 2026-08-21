# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
from email.message import Message
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "src"
TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))
sys.path.insert(0, str(TESTS))

from test_backend import BackendHarness, approved_handoff_config, fixture  # noqa: E402
from tacua_backend.config import (  # noqa: E402
    PilotConfig,
    ReviewerAuthConfig,
    TRANSPORT_POLICY_VERSION_1_2,
)
from tacua_backend.contracts import canonical_json, seal  # noqa: E402
from tacua_backend.http_api import PilotRequestHandler  # noqa: E402
from tacua_backend.service import ApiError, PilotBackend  # noqa: E402


class ExplodingReader:
    def read(self, _size: int = -1) -> bytes:
        raise AssertionError("protected body was read before authentication")


class ReviewerAuthHTTPTests(BackendHarness):
    capability = {"qa.example.com/cap/tacua-reviewer": [{}]}

    def use_auth_mode(self, mode: str) -> None:
        capabilities = (
            copy.deepcopy(self.capability)
            if mode == "tailscale_capability_or_pairing"
            else None
        )
        config = PilotConfig(
            **{
                **self.config.__dict__,
                "reviewer_auth": ReviewerAuthConfig(
                    mode=mode,
                    tailscale_app_capabilities=capabilities,
                ),
            }
        )
        self.config = config
        self.backend = PilotBackend(config, self.admin_secret, clock=self.clock)

    def use_sealed_launch_scheme(self) -> None:
        state_directory = Path(self.temporary.name) / "transport_1_2"
        build = copy.deepcopy(self.build)
        draft = PilotConfig(
            **{
                **self.config.__dict__,
                "state_directory": state_directory,
                "transport_policy_version": TRANSPORT_POLICY_VERSION_1_2,
                "launch_scheme": "tacua-synthetic-qa",
            }
        )
        build["transport_configuration_digest"] = draft.transport_configuration_digest
        build = seal(build)
        scope = copy.deepcopy(self.scope)
        scope["build_identity_digest"] = build["build_identity_digest"]
        config = PilotConfig(
            **{
                **draft.__dict__,
                "build_identity": build,
                "approved_handoff": approved_handoff_config(build, scope),
            }
        )
        self.build = build
        self.scope = scope
        self.config = config
        self.backend = PilotBackend(config, self.admin_secret, clock=self.clock)

    def start_current_session(self) -> dict:
        grant = self.backend.create_launch_code(
            {"exchange_kind": "start_session", "build_id": self.config.build_id}
        )
        request = fixture("launch-exchange-request")
        request["launch_code"] = grant["launch_code"]
        request["build_identity"] = copy.deepcopy(self.build)
        scope = copy.deepcopy(self.scope)
        scope["consent"]["granted_at"] = self.clock().strftime("%Y-%m-%dT%H:%M:%SZ")
        request["scope"] = seal(scope)
        request["requested_at"] = scope["consent"]["granted_at"]
        request = seal(request)
        response = self.backend.exchange_launch_code(request)
        self.assertEqual(201, response.status)
        return response.json()

    def handler(
        self,
        path: str,
        *,
        method: str = "GET",
        body: object | None = None,
        raw_body: bytes | None = None,
        authorization: str | None = None,
        cookie: str | None = None,
        origin: str | None = None,
        csrf: str | None = None,
        capability: str | None = None,
    ) -> PilotRequestHandler:
        if body is not None and raw_body is not None:
            raise AssertionError("test must provide one body representation")
        payload = (
            canonical_json(body).encode("utf-8")
            if body is not None
            else (raw_body or b"")
        )
        handler = object.__new__(PilotRequestHandler)
        handler.path = path
        handler.command = method
        handler.server = SimpleNamespace(backend=self.backend)
        handler.headers = Message()
        handler.close_connection = False
        handler.rfile = io.BytesIO(payload)
        handler.wfile = io.BytesIO()
        if authorization is not None:
            handler.headers["Authorization"] = authorization
        if cookie is not None:
            handler.headers["Cookie"] = cookie
        if origin is not None:
            handler.headers["Origin"] = origin
        if csrf is not None:
            handler.headers["Tacua-CSRF-Token"] = csrf
        if capability is not None:
            handler.headers["Tailscale-App-Capabilities"] = capability
        if payload:
            handler.headers["Content-Type"] = "application/json"
            handler.headers["Content-Length"] = str(len(payload))
        return handler

    @staticmethod
    def dispatch_json(
        handler: PilotRequestHandler,
    ) -> tuple[int, dict, dict[str, str]]:
        sent: list[tuple[int, bytes, dict[str, str]]] = []

        def capture(
            status: int,
            payload: bytes,
            _content_type: str = "application/json",
            *,
            headers: dict[str, str] | None = None,
        ) -> None:
            sent.append((status, payload, headers or {}))

        handler._send_bytes = capture
        handler._dispatch()
        if len(sent) != 1:
            raise AssertionError("expected one response")
        status, payload, headers = sent[0]
        return status, json.loads(payload), headers

    def approve(self, human_code: str) -> None:
        status, _, _ = self.dispatch_json(
            self.handler(
                "/v1/admin/reviewer-pairing-approvals",
                method="POST",
                body={"human_code": human_code},
                authorization="Bearer " + self.admin_secret.decode("ascii"),
            )
        )
        self.assertEqual(200, status)

    def pair(self, client_kind: str) -> tuple[dict, dict, dict[str, str]]:
        origin = self.config.backend_origin if client_kind == "web" else None
        request_status, pairing, _ = self.dispatch_json(
            self.handler(
                "/v1/reviewer/pairing-requests",
                method="POST",
                body={"device_label": "Will's reviewer", "client_kind": client_kind},
                origin=origin,
            )
        )
        self.assertEqual(201, request_status)
        self.approve(pairing["human_code"])
        exchange_status, session, headers = self.dispatch_json(
            self.handler(
                "/v1/reviewer/pairing-exchanges",
                method="POST",
                body={
                    "pairing_token": pairing["pairing_token"],
                    "client_kind": client_kind,
                },
                origin=origin,
            )
        )
        self.assertEqual(201, exchange_status)
        return pairing, session, headers

    def cancel_pairing(
        self,
        pairing_token: object,
        client_kind: str,
        *,
        origin: str | None = None,
    ) -> tuple[int, dict, dict[str, str]]:
        return self.dispatch_json(
            self.handler(
                "/v1/reviewer/pairing-cancellations",
                method="POST",
                body={
                    "pairing_token": pairing_token,
                    "client_kind": client_kind,
                },
                origin=origin,
            )
        )

    def test_legacy_admin_reviewer_alias_is_transitional_and_origin_bound(self) -> None:
        authorization = "Bearer " + self.admin_secret.decode("ascii")
        status, bootstrap, _ = self.dispatch_json(
            self.handler(
                "/v1/reviewer/bootstrap",
                authorization=authorization,
            )
        )
        self.assertEqual(200, status)
        self.assertEqual(self.config.reviewer_id, bootstrap["reviewer_id"])

        _, session, _ = self.dispatch_json(
            self.handler("/v1/reviewer/session", authorization=authorization)
        )
        no_origin = self.handler(
            "/v1/reviewer/launch-codes",
            method="POST",
            body={"exchange_kind": "start_session", "build_id": self.config.build_id},
            authorization=authorization,
            csrf=session["csrf_token"],
        )
        with self.assertRaises(ApiError) as captured:
            no_origin._dispatch()
        self.assertEqual("REVIEWER_ORIGIN_FORBIDDEN", captured.exception.code)

        status, _, _ = self.dispatch_json(
            self.handler(
                "/v1/reviewer/launch-codes",
                method="POST",
                body={
                    "exchange_kind": "start_session",
                    "build_id": self.config.build_id,
                },
                authorization=authorization,
                origin=self.config.backend_origin,
                csrf=session["csrf_token"],
            )
        )
        self.assertEqual(201, status)
        with self.backend._connect() as connection:
            audit = connection.execute(
                """SELECT actor_kind FROM audit_events
                     WHERE event_type = 'launch_grant_created'
                     ORDER BY rowid DESC LIMIT 1"""
            ).fetchone()
        self.assertEqual("reviewer", audit["actor_kind"])

    def test_pairing_cancellation_is_content_free_and_invalidates_native_session(self) -> None:
        self.use_auth_mode("pairing")
        pairing, session, _ = self.pair("native")
        token = pairing["pairing_token"]
        session_token = session["session_token"]
        replacement = "A" if token[-1] != "A" else "B"

        for candidate, client_kind in (
            (token[:-1] + replacement, "native"),
            (token, "web"),
            ("not-a-token", "native"),
        ):
            status, document, _ = self.cancel_pairing(
                candidate,
                client_kind,
                origin=(
                    self.config.backend_origin if client_kind == "web" else None
                ),
            )
            self.assertEqual((200, {"status": "canceled"}), (status, document))
            status, principal, _ = self.dispatch_json(
                self.handler(
                    "/v1/reviewer/session",
                    authorization="Bearer " + session_token,
                )
            )
            self.assertEqual(200, status)
            self.assertEqual(session["session_id"], principal["session_id"])

        status, document, headers = self.cancel_pairing(token, "native")
        self.assertEqual((200, {"status": "canceled"}, {}), (status, document, headers))
        status, replay, replay_headers = self.cancel_pairing(token, "native")
        self.assertEqual(
            (200, {"status": "canceled"}, {}),
            (status, replay, replay_headers),
        )
        with self.assertRaises(ApiError) as captured:
            self.handler(
                "/v1/reviewer/session",
                authorization="Bearer " + session_token,
            )._dispatch()
        self.assertEqual("REVIEWER_AUTHENTICATION_FAILED", captured.exception.code)

    def test_web_pairing_cancellation_requires_origin_and_expires_cookie(self) -> None:
        self.use_auth_mode("pairing")
        pairing, _, exchange_headers = self.pair("web")
        cookie = exchange_headers["Set-Cookie"].split(";", 1)[0]

        with self.assertRaises(ApiError) as captured:
            self.cancel_pairing(pairing["pairing_token"], "web")
        self.assertEqual("REVIEWER_ORIGIN_FORBIDDEN", captured.exception.code)

        status, document, headers = self.cancel_pairing(
            pairing["pairing_token"],
            "web",
            origin=self.config.backend_origin,
        )
        self.assertEqual((200, {"status": "canceled"}), (status, document))
        self.assertIn("Set-Cookie", headers)
        self.assertIn("Max-Age=0", headers["Set-Cookie"])
        with self.assertRaises(ApiError) as captured:
            self.handler("/v1/reviewer/session", cookie=cookie)._dispatch()
        self.assertEqual("REVIEWER_AUTHENTICATION_FAILED", captured.exception.code)

    def test_pairing_cancellation_rejects_non_exact_body_and_legacy_mode(self) -> None:
        self.use_auth_mode("pairing")
        with self.assertRaises(ApiError) as captured:
            self.handler(
                "/v1/reviewer/pairing-cancellations",
                method="POST",
                body={
                    "pairing_token": "not-a-token",
                    "client_kind": "native",
                    "extra": True,
                },
            )._dispatch()
        self.assertEqual("INVALID_PAIRING_CANCELLATION", captured.exception.code)

        self.use_auth_mode("legacy_admin")
        with self.assertRaises(ApiError) as captured:
            self.cancel_pairing("not-a-token", "native")
        self.assertEqual("NOT_FOUND", captured.exception.code)

    def test_admin_launch_grant_keeps_admin_audit_attribution(self) -> None:
        status, _, _ = self.dispatch_json(
            self.handler(
                "/v1/admin/launch-codes",
                method="POST",
                body={
                    "exchange_kind": "start_session",
                    "build_id": self.config.build_id,
                },
                authorization="Bearer " + self.admin_secret.decode("ascii"),
            )
        )
        self.assertEqual(201, status)
        with self.backend._connect() as connection:
            audit = connection.execute(
                """SELECT actor_kind FROM audit_events
                     WHERE event_type = 'launch_grant_created'
                     ORDER BY rowid DESC LIMIT 1"""
            ).fetchone()
        self.assertEqual("admin", audit["actor_kind"])

    def test_pairing_web_cookie_lifecycle_and_strict_reviewer_route_matrix(self) -> None:
        self.use_auth_mode("pairing")
        _, session, headers = self.pair("web")
        self.assertNotIn("session_token", session)
        set_cookie = headers["Set-Cookie"]
        self.assertRegex(set_cookie, r"^__Host-tacua-reviewer=[A-Za-z0-9_.-]+;")
        for attribute in (
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Strict",
            "Max-Age=2592000",
        ):
            self.assertIn(attribute, set_cookie)
        self.assertNotIn("Domain=", set_cookie)
        cookie = set_cookie.split(";", 1)[0]

        status, current, _ = self.dispatch_json(
            self.handler("/v1/reviewer/session", cookie=cookie)
        )
        self.assertEqual(200, status)
        self.assertEqual("session", current["auth_kind"])

        protected = self.handler(
            "/v1/reviewer/launch-codes",
            method="POST",
            cookie=cookie,
            csrf=current["csrf_token"],
        )
        protected.headers["Content-Type"] = "application/json"
        protected.headers["Content-Length"] = "10"
        protected.rfile = ExplodingReader()
        with self.assertRaises(ApiError) as captured:
            protected._dispatch()
        self.assertEqual("REVIEWER_ORIGIN_FORBIDDEN", captured.exception.code)

        forbidden_delete = self.handler(
            "/v1/reviewer/sessions/session_synthetic",
            method="DELETE",
            cookie=cookie,
            origin=self.config.backend_origin,
            csrf=current["csrf_token"],
        )
        with self.assertRaises(ApiError) as captured:
            forbidden_delete._dispatch()
        self.assertEqual(404, captured.exception.status)

        revoke_status, revoked, revoke_headers = self.dispatch_json(
            self.handler(
                "/v1/reviewer/session",
                method="DELETE",
                cookie=cookie,
                origin=self.config.backend_origin,
                csrf=current["csrf_token"],
            )
        )
        self.assertEqual(200, revoke_status)
        self.assertIsNotNone(revoked["session"]["revoked_at"])
        self.assertIn("Max-Age=0", revoke_headers["Set-Cookie"])
        with self.assertRaises(ApiError) as captured:
            self.handler("/v1/reviewer/session", cookie=cookie)._dispatch()
        self.assertEqual(401, captured.exception.status)

    def test_pairing_native_returns_bearer_without_requiring_origin(self) -> None:
        self.use_auth_mode("pairing")
        _, session, headers = self.pair("native")
        self.assertEqual({}, headers)
        self.assertRegex(
            session["session_token"],
            r"^rsess_[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$",
        )
        status, current, _ = self.dispatch_json(
            self.handler(
                "/v1/reviewer/session",
                authorization="Bearer " + session["session_token"],
            )
        )
        self.assertEqual(200, status)
        self.assertEqual("native", current["client_kind"])

    def test_restart_restores_auth_floor_before_issuing_protocol_timestamps(self) -> None:
        self.use_auth_mode("pairing")
        durable_floor = "2026-07-21T10:30:00Z"
        self.clock.set(durable_floor)
        self.assert_api_error(
            401,
            "REVIEWER_AUTHENTICATION_FAILED",
            lambda: self.backend.authenticate_reviewer_session(
                "rsess_" + "a" * 32 + "." + "A" * 43,
                required_scope="reviewer.read",
            ),
        )
        with self.backend._connect() as connection:
            self.assertEqual(
                durable_floor,
                connection.execute(
                    "SELECT observed_at FROM tacua_reviewer_auth_time_floor "
                    "WHERE singleton = 1"
                ).fetchone()["observed_at"],
            )

        self.clock.set("2026-07-21T09:57:01Z")
        restarted = PilotBackend(self.config, self.admin_secret, clock=self.clock)
        grant = restarted.create_launch_code(
            {
                "exchange_kind": "start_session",
                "build_id": self.config.build_id,
            }
        )
        request = fixture("launch-exchange-request")
        request["launch_code"] = grant["launch_code"]
        scope = copy.deepcopy(self.scope)
        scope["consent"]["granted_at"] = durable_floor
        request["scope"] = seal(scope)
        request["requested_at"] = durable_floor
        response = restarted.exchange_launch_code(seal(request))

        self.assertEqual(201, response.status)
        self.assertEqual(durable_floor, response.json()["received_at"])
        self.assertEqual(durable_floor, response.json()["issued_at"])

    def test_admin_pairing_approval_authenticates_before_reading_body(self) -> None:
        self.use_auth_mode("pairing")
        handler = self.handler(
            "/v1/admin/reviewer-pairing-approvals",
            method="POST",
        )
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = "10"
        handler.rfile = ExplodingReader()
        with self.assertRaises(ApiError) as captured:
            handler._dispatch()
        self.assertEqual(401, captured.exception.status)

    def test_tailscale_capability_is_exact_and_not_tailnet_presence(self) -> None:
        self.use_auth_mode("tailscale_capability_or_pairing")
        exact = canonical_json(self.capability)
        status, session, _ = self.dispatch_json(
            self.handler(
                "/v1/reviewer/session",
                capability=exact,
            )
        )
        self.assertEqual(200, status)
        self.assertEqual("tailscale_capability", session["auth_kind"])

        identity_only = self.handler("/v1/reviewer/session")
        identity_only.headers["Tailscale-User-Login"] = "will@example.com"
        with self.assertRaises(ApiError) as captured:
            identity_only._dispatch()
        self.assertEqual(401, captured.exception.status)

        for invalid in (
            "{}",
            canonical_json(
                {
                    **self.capability,
                    "qa.example.com/cap/other": [{}],
                }
            ),
            '{"qa.example.com/cap/tacua-reviewer":[{}],'
            '"qa.example.com/cap/tacua-reviewer":[{}]}',
            "é",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ApiError) as captured:
                self.handler(
                    "/v1/reviewer/session",
                    capability=invalid,
                )._dispatch()
            self.assertEqual(401, captured.exception.status)

        mixed = self.handler(
            "/v1/reviewer/session",
            authorization="Bearer invalid",
            cookie="__Host-tacua-reviewer=rsess_" + "a" * 32 + "." + "A" * 43,
            capability=exact,
        )
        with self.assertRaises(ApiError) as captured:
            mixed._dispatch()
        self.assertEqual(401, captured.exception.status)

        stale_cookie = "__Host-tacua-reviewer=rsess_" + "a" * 32 + "." + "A" * 43
        status, principal, _ = self.dispatch_json(
            self.handler(
                "/v1/reviewer/session",
                cookie=stale_cookie,
                capability=exact,
            )
        )
        self.assertEqual(200, status)
        self.assertEqual("tailscale_capability", principal["auth_kind"])

    def test_tailscale_capability_auth_is_pinned_against_config_object_mutation(self) -> None:
        self.use_auth_mode("tailscale_capability_or_pairing")
        startup_value = canonical_json(self.capability)
        configured = self.config.reviewer_auth.tailscale_app_capabilities
        assert configured is not None
        configured["qa.example.com/cap/tacua-reviewer"][0]["mutated"] = True

        status, principal, _ = self.dispatch_json(
            self.handler(
                "/v1/reviewer/session",
                capability=startup_value,
            )
        )
        self.assertEqual(200, status)
        self.assertEqual("tailscale_capability", principal["auth_kind"])
        with self.assertRaises(ApiError) as captured:
            self.handler(
                "/v1/reviewer/session",
                capability=canonical_json(configured),
            )._dispatch()
        self.assertEqual(401, captured.exception.status)

    def test_web_pairing_rejects_wrong_origin_before_body_read(self) -> None:
        self.use_auth_mode("pairing")
        handler = self.handler(
            "/v1/reviewer/pairing-requests",
            method="POST",
            origin="https://attacker.example",
        )
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = "10"
        handler.rfile = ExplodingReader()
        with self.assertRaises(ApiError) as captured:
            handler._dispatch()
        self.assertEqual("REVIEWER_ORIGIN_FORBIDDEN", captured.exception.code)

    def test_reviewer_launch_link_exactly_wraps_start_and_resume_grants(self) -> None:
        self.use_sealed_launch_scheme()
        authorization = "Bearer " + self.admin_secret.decode("ascii")
        _, principal, _ = self.dispatch_json(
            self.handler("/v1/reviewer/session", authorization=authorization)
        )

        start_status, start, _ = self.dispatch_json(
            self.handler(
                "/v1/reviewer/launch-links",
                method="POST",
                body={
                    "exchange_kind": "start_session",
                    "build_id": self.config.build_id,
                },
                authorization=authorization,
                origin=self.config.backend_origin,
                csrf=principal["csrf_token"],
            )
        )
        self.assertEqual(201, start_status)
        self.assertEqual(
            {"contract_version", "launch_url", "grant"},
            set(start),
        )
        self.assertEqual("tacua.reviewer-launch-link@1.0.0", start["contract_version"])
        self.assertEqual(
            {
                "launch_id",
                "launch_code",
                "exchange_kind",
                "session_id",
                "build_identity_digest",
                "expires_at",
                "scope_policy_digest",
            },
            set(start["grant"]),
        )
        self.assertEqual(
            "tacua-synthetic-qa://tacua/start?launch_code="
            + start["grant"]["launch_code"],
            start["launch_url"],
        )
        self.assertIsNone(start["grant"]["session_id"])
        with self.backend._connect() as connection:
            audit = connection.execute(
                """SELECT actor_kind FROM audit_events
                     WHERE event_type = 'launch_grant_created'
                     ORDER BY rowid DESC LIMIT 1"""
            ).fetchone()
        self.assertEqual("reviewer", audit["actor_kind"])

        receipt = self.start_current_session()
        resume_status, resume, _ = self.dispatch_json(
            self.handler(
                "/v1/reviewer/launch-links",
                method="POST",
                body={
                    "exchange_kind": "resume_session",
                    "session_id": receipt["session_id"],
                },
                authorization=authorization,
                origin=self.config.backend_origin,
                csrf=principal["csrf_token"],
            )
        )
        self.assertEqual(201, resume_status)
        self.assertEqual(
            {
                "launch_id",
                "launch_code",
                "exchange_kind",
                "session_id",
                "build_identity_digest",
                "expires_at",
                "scope_digest",
            },
            set(resume["grant"]),
        )
        self.assertEqual(receipt["session_id"], resume["grant"]["session_id"])
        self.assertEqual(
            "tacua-synthetic-qa://tacua/start?launch_code="
            + resume["grant"]["launch_code"]
            + "&session_id="
            + receipt["session_id"],
            resume["launch_url"],
        )
        with self.backend._connect() as connection:
            audit = connection.execute(
                """SELECT actor_kind FROM audit_events
                     WHERE event_type = 'launch_grant_created'
                     ORDER BY rowid DESC LIMIT 1"""
            ).fetchone()
        self.assertEqual("reviewer", audit["actor_kind"])

    def test_reviewer_launch_link_authenticates_before_reading_body(self) -> None:
        self.use_sealed_launch_scheme()
        handler = self.handler("/v1/reviewer/launch-links", method="POST")
        handler.headers["Content-Type"] = "application/json"
        handler.headers["Content-Length"] = "10"
        handler.rfile = ExplodingReader()
        with self.assertRaises(ApiError) as captured:
            handler._dispatch()
        self.assertEqual(401, captured.exception.status)

    def test_reviewer_launch_link_requires_a_sealed_scheme_before_minting(self) -> None:
        authorization = "Bearer " + self.admin_secret.decode("ascii")
        _, principal, _ = self.dispatch_json(
            self.handler("/v1/reviewer/session", authorization=authorization)
        )
        with self.backend._connect() as connection:
            before = connection.execute("SELECT COUNT(*) FROM launch_grants").fetchone()[0]
        handler = self.handler(
            "/v1/reviewer/launch-links",
            method="POST",
            body={
                "exchange_kind": "start_session",
                "build_id": self.config.build_id,
            },
            authorization=authorization,
            origin=self.config.backend_origin,
            csrf=principal["csrf_token"],
        )
        with self.assertRaises(ApiError) as captured:
            handler._dispatch()
        self.assertEqual(409, captured.exception.status)
        self.assertEqual(
            "REVIEWER_LAUNCH_SCHEME_UNAVAILABLE",
            captured.exception.code,
        )
        with self.backend._connect() as connection:
            after = connection.execute("SELECT COUNT(*) FROM launch_grants").fetchone()[0]
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
