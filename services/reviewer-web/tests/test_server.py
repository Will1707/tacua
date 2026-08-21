# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from email.message import Message
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SERVER_PATH = ROOT / "services" / "reviewer-web" / "server.py"
spec = importlib.util.spec_from_file_location("tacua_reviewer_web", SERVER_PATH)
assert spec is not None and spec.loader is not None
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)


class ReviewerWebServerTests(unittest.TestCase):
    def test_sensitive_request_headers_are_closed(self) -> None:
        self.assertEqual(
            {
                "authorization",
                "cookie",
                "idempotency-key",
                "if-match",
                "proxy-authorization",
                "tacua-content-digest",
                "tacua-csrf-token",
                "tacua-credential-id",
                "tacua-evidence-manifest-digest",
                "tacua-intent-digest",
                "tacua-page-cursor",
                "tacua-protocol-version",
                "tacua-requested-at",
                "tacua-reviewer-id",
                "tacua-scope-digest",
                "tacua-sidecar-digest",
                "tailscale-app-capabilities",
                "tailscale-user-login",
                "tailscale-user-name",
                "tailscale-user-profile-pic",
            },
            server.SENSITIVE_REQUEST_HEADERS,
        )

    def test_csrf_header_is_rejected_even_without_the_ingress_scrubber(self) -> None:
        handler = object.__new__(server.ReviewerRequestHandler)
        handler.headers = Message()
        handler.headers["Tacua-CSRF-Token"] = "synthetic"
        handler.wfile = io.BytesIO()
        statuses: list[int] = []
        handler.send_response = statuses.append
        handler._security_headers = lambda _cache_control: None
        handler.send_header = lambda _name, _value: None
        handler.end_headers = lambda: None

        handler._write_response(include_body=True)

        self.assertEqual([400], statuses)
        self.assertEqual(server.ERROR_BODY, handler.wfile.getvalue())

    def test_spa_routes_and_exact_assets_remain_inside_the_document_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            index = root / "index.html"
            index.write_bytes(b"<!doctype html><title>Tacua</title>")
            asset = (
                root
                / "_expo"
                / "static"
                / "js"
                / "web"
                / "entry-0123456789abcdef0123456789abcdef.js"
            )
            asset.parent.mkdir(parents=True)
            asset.write_bytes(b"console.log('synthetic')")
            other_asset = root / "assets" / "synthetic.png"
            other_asset.parent.mkdir()
            other_asset.write_bytes(b"synthetic")

            self.assertEqual((index, False), server.select_resource("/", root))
            self.assertEqual(
                (index, False),
                server.select_resource("/candidates/candidate_synthetic", root),
            )
            self.assertEqual(
                (asset, True),
                server.select_resource(
                    "/_expo/static/js/web/"
                    "entry-0123456789abcdef0123456789abcdef.js",
                    root,
                ),
            )
            self.assertEqual(
                (other_asset, False),
                server.select_resource("/assets/synthetic.png", root),
            )
            self.assertIsNone(server.select_resource("/_expo/%2e%2e/index.html", root))
            self.assertIsNone(server.select_resource("//other.example/asset.js", root))
            self.assertIsNone(server.select_resource("/assets/file.exe", root))

    def test_root_validation_rejects_missing_index_links_and_writable_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(server.ReviewerWebError):
                server.validate_document_root(root)

            index = root / "index.html"
            index.write_text("Tacua", encoding="utf-8")
            index.chmod(0o666)
            with self.assertRaises(server.ReviewerWebError):
                server.validate_document_root(root)

            index.chmod(0o444)
            linked = root / "linked.js"
            linked.symlink_to(index)
            with self.assertRaises(server.ReviewerWebError):
                server.validate_document_root(root)
            linked.unlink()
            server.validate_document_root(root)

    def test_regular_file_reader_rejects_links_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body = root / "entry.js"
            body.write_bytes(b"synthetic")
            body.chmod(0o444)
            self.assertEqual(b"synthetic", server.read_regular_file(body))

            linked = root / "linked.js"
            linked.symlink_to(body)
            self.assertIsNone(server.read_regular_file(linked))


if __name__ == "__main__":
    unittest.main()
