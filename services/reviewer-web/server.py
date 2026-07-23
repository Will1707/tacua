#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serve one validated Tacua reviewer export without dynamic authority."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path, PurePosixPath
import re
import stat
import unicodedata
from urllib.parse import unquote_to_bytes, urlsplit


DOCUMENT_ROOT = Path("/srv/tacua-reviewer")
LISTEN_ADDRESS = ("0.0.0.0", 8081)
MAX_FILES = 1_024
MAX_FILE_BYTES = 16_777_216
MAX_TOTAL_BYTES = 67_108_864
SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9@._-]{1,255}$")
IMMUTABLE_ENTRY_BUNDLE = re.compile(r"^entry-[a-f0-9]{32}\.js$")
CONTENT_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ttf": "font/ttf",
    ".webp": "image/webp",
    ".woff2": "font/woff2",
}
SENSITIVE_REQUEST_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "idempotency-key",
        "if-match",
        "proxy-authorization",
        "tacua-content-digest",
        "tacua-credential-id",
        "tacua-evidence-manifest-digest",
        "tacua-intent-digest",
        "tacua-page-cursor",
        "tacua-protocol-version",
        "tacua-requested-at",
        "tacua-scope-digest",
        "tacua-sidecar-digest",
        "tailscale-user-login",
        "tailscale-user-name",
        "tailscale-user-profile-pic",
    }
)
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; "
    "script-src 'self'; "
    "connect-src 'self'; "
    "img-src 'self' blob: data:; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "manifest-src 'none'; "
    "worker-src 'none'"
)
ERROR_BODY = b"Not found\n"


class ReviewerWebError(RuntimeError):
    """A content-free static-export validation failure."""


def validate_document_root(root: Path = DOCUMENT_ROOT) -> None:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise ReviewerWebError("reviewer document root is unavailable") from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) & 0o022
    ):
        raise ReviewerWebError("reviewer document root is unsafe")

    count = 0
    total = 0
    index_seen = False
    for current, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        directory_names.sort()
        file_names.sort()
        current_path = Path(current)
        for name in directory_names:
            path = current_path / name
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise ReviewerWebError("reviewer export contains an unsafe directory")
        for name in file_names:
            path = current_path / name
            metadata = path.lstat()
            count += 1
            total += metadata.st_size
            if (
                count > MAX_FILES
                or total > MAX_TOTAL_BYTES
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size < 1
                or metadata.st_size > MAX_FILE_BYTES
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise ReviewerWebError("reviewer export contains an unsafe file")
            relative = path.relative_to(root)
            if relative == Path("index.html"):
                index_seen = True
    if not index_seen:
        raise ReviewerWebError("reviewer export has no SPA shell")


def _decoded_path(request_target: str) -> str | None:
    try:
        parsed = urlsplit(request_target)
        if parsed.scheme or parsed.netloc:
            return None
        decoded = unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
    except (UnicodeError, ValueError):
        return None
    if (
        not decoded.startswith("/")
        or "\x00" in decoded
        or unicodedata.normalize("NFC", decoded) != decoded
    ):
        return None
    return decoded


def select_resource(
    request_target: str,
    root: Path = DOCUMENT_ROOT,
) -> tuple[Path, bool] | None:
    decoded = _decoded_path(request_target)
    if decoded is None:
        return None
    if decoded == "/" or (
        not decoded.startswith("/_expo/")
        and not decoded.startswith("/assets/")
        and decoded != "/metadata.json"
    ):
        return root / "index.html", False

    relative = PurePosixPath(decoded.removeprefix("/"))
    if (
        relative.is_absolute()
        or not relative.parts
        or any(
            part in {"", ".", ".."} or SAFE_SEGMENT.fullmatch(part) is None
            for part in relative.parts
        )
        or relative.suffix.lower() not in CONTENT_TYPES
    ):
        return None
    immutable = (
        relative.parts[:4] == ("_expo", "static", "js", "web")
        and len(relative.parts) == 5
        and IMMUTABLE_ENTRY_BUNDLE.fullmatch(relative.name) is not None
    )
    return root.joinpath(*relative.parts), immutable


def read_regular_file(path: Path) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if getattr(os, "O_NOFOLLOW", 0):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_FILE_BYTES
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            return None
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            return None
        return b"".join(chunks)
    finally:
        os.close(descriptor)


class ReviewerRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Tacua"
    sys_version = ""

    def log_message(self, _format: str, *_args: object) -> None:
        # Request targets may contain user-entered text. The static server emits
        # no access log and has no mounted application logger.
        return

    def version_string(self) -> str:
        return "Tacua"

    def _security_headers(self, cache_control: str) -> None:
        self.send_header("Cache-Control", cache_control)
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _write_response(self, *, include_body: bool) -> None:
        if any(name in self.headers for name in SENSITIVE_REQUEST_HEADERS):
            self.send_response(HTTPStatus.BAD_REQUEST)
            self._security_headers("no-store")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(ERROR_BODY)))
            self.end_headers()
            if include_body:
                self.wfile.write(ERROR_BODY)
            return

        selection = select_resource(self.path)
        if selection is None:
            self.send_response(HTTPStatus.NOT_FOUND)
            self._security_headers("no-store")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(ERROR_BODY)))
            self.end_headers()
            if include_body:
                self.wfile.write(ERROR_BODY)
            return

        path, immutable = selection
        body = read_regular_file(path)
        content_type = CONTENT_TYPES.get(path.suffix.lower())
        if body is None or content_type is None:
            self.send_response(HTTPStatus.NOT_FOUND)
            self._security_headers("no-store")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(ERROR_BODY)))
            self.end_headers()
            if include_body:
                self.wfile.write(ERROR_BODY)
            return

        self.send_response(HTTPStatus.OK)
        self._security_headers(
            "public, max-age=31536000, immutable" if immutable else "no-store"
        )
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._write_response(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._write_response(include_body=False)

    def _method_not_allowed(self) -> None:
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self._security_headers("no-store")
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_DELETE = _method_not_allowed  # type: ignore[assignment]  # noqa: N815
    do_OPTIONS = _method_not_allowed  # type: ignore[assignment]  # noqa: N815
    do_PATCH = _method_not_allowed  # type: ignore[assignment]  # noqa: N815
    do_POST = _method_not_allowed  # type: ignore[assignment]  # noqa: N815
    do_PUT = _method_not_allowed  # type: ignore[assignment]  # noqa: N815


def main() -> int:
    validate_document_root()
    server = ThreadingHTTPServer(LISTEN_ADDRESS, ReviewerRequestHandler)
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
