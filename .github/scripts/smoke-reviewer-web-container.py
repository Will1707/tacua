# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from http.client import HTTPConnection
from pathlib import Path
import re
import stat

MAX_FILE_BYTES = 16_777_216


def require_image_path(path: str, *, mode: int, directory: bool) -> Path:
    target = Path(path)
    metadata = target.lstat()
    assert metadata.st_uid == 0 and metadata.st_gid == 0
    assert stat.S_IMODE(metadata.st_mode) == mode
    if directory:
        assert stat.S_ISDIR(metadata.st_mode)
    else:
        assert stat.S_ISREG(metadata.st_mode)
    return target


static_root = require_image_path(
    "/srv/tacua-reviewer",
    mode=0o555,
    directory=True,
)
for entry in static_root.rglob("*"):
    metadata = entry.lstat()
    assert metadata.st_uid == 0 and metadata.st_gid == 0
    assert stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
    expected_mode = 0o555 if stat.S_ISDIR(metadata.st_mode) else 0o444
    assert stat.S_IMODE(metadata.st_mode) == expected_mode

require_image_path(
    "/usr/local/bin/tacua-reviewer-web",
    mode=0o555,
    directory=False,
)
for directory_path in ("/licenses", "/licenses/tacua", "/licenses/reviewer"):
    require_image_path(directory_path, mode=0o555, directory=True)
for license_path in (
    "/licenses/tacua/LICENSE",
    "/licenses/tacua/NOTICE",
    "/licenses/reviewer/NOTICE",
    "/licenses/reviewer/THIRD_PARTY_NOTICES.txt",
):
    require_image_path(license_path, mode=0o444, directory=False)


def request(
    method: str,
    path: str,
    *,
    request_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = HTTPConnection("127.0.0.1", 8081, timeout=3)
    try:
        connection.request(method, path, headers=request_headers or {})
        response = connection.getresponse()
        body = response.read(MAX_FILE_BYTES + 1)
        return response.status, {key.lower(): value for key, value in response.headers.items()}, body
    finally:
        connection.close()


required_headers = {
    "cache-control": "no-store",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}

status, headers, shell = request("GET", "/")
assert status == 200
assert 1 <= len(shell) <= 65_536
assert b'<div id="root"></div>' in shell
assert all(headers.get(key) == value for key, value in required_headers.items())
assert headers.get("content-security-policy", "").startswith("default-src 'none';")
assert headers.get("content-length") == str(len(shell))
assert headers.get("server") == "Tacua"

entry_match = re.search(
    rb'<script src="/(_expo/static/js/web/entry-[a-f0-9]{32}\.js)" defer></script>',
    shell,
)
assert entry_match is not None
status, entry_headers, entry_body = request(
    "GET",
    f"/{entry_match.group(1).decode('ascii')}",
)
assert status == 200
assert 1 <= len(entry_body) <= MAX_FILE_BYTES
assert entry_headers.get("cache-control") == "public, max-age=31536000, immutable"

asset = next(
    path
    for path in sorted(Path("/srv/tacua-reviewer/assets").rglob("*"))
    if path.is_file()
)
asset_target = f"/{asset.relative_to('/srv/tacua-reviewer').as_posix()}"
status, asset_headers, asset_body = request("GET", asset_target)
assert status == 200
assert 1 <= len(asset_body) <= MAX_FILE_BYTES
assert asset_headers.get("cache-control") == "no-store"

status, deep_headers, deep_shell = request(
    "GET",
    "/candidates/candidate_synthetic?ignored=1",
)
assert status == 200
assert deep_shell == shell
assert deep_headers.get("cache-control") == "no-store"

status, traversal_headers, traversal = request(
    "GET",
    "/_expo/%2e%2e/index.html",
)
assert status == 404
assert traversal == b"Not found\n"
assert traversal_headers.get("cache-control") == "no-store"

status, method_headers, method_body = request("POST", "/")
assert status == 405
assert method_headers.get("allow") == "GET, HEAD"
assert method_headers.get("cache-control") == "no-store"
assert method_body == b""

status, sensitive_headers, sensitive_body = request(
    "GET",
    "/",
    request_headers={"Authorization": "Bearer synthetic-never-log"},
)
assert status == 400
assert sensitive_headers.get("cache-control") == "no-store"
assert sensitive_body == b"Not found\n"
