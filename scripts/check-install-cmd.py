#!/usr/bin/env python3
"""Fail unless the committed install.cmd blob is CRLF-only ASCII.

The Windows install downloads this file from raw.githubusercontent.com,
which serves the git blob with no checkout conversion. cmd.exe scans
labels in 512-byte chunks and restarts that count only after CRLF. A
label at column 0 is safe once every line ends in CRLF; marking the
path "text" or "eol=crlf" would store LF and bring the bug back.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def git_blob(spec: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "cat-file", "blob", spec],
            cwd=ROOT,
        )
    except subprocess.CalledProcessError:
        fail(f"could not read git blob {spec}")
        return b""


def check_crlf(data: bytes, what: str) -> None:
    if data.startswith(b"\xef\xbb\xbf"):
        fail(f"{what} must not start with a UTF-8 BOM")
    if not data:
        fail(f"{what} is empty")
    stripped = data.replace(b"\r\n", b"")
    if b"\n" in stripped or b"\r" in stripped:
        fail(f"{what} must use CRLF line endings only")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail(f"{what} must be ASCII")
    for n, line in enumerate(text.split("\r\n"), 1):
        if not line.startswith(":") or line.startswith("::"):
            continue
        token = line.split(" ", 1)[0].split("\t", 1)[0]
        # CRLF restarts the scan at column 0. The label token itself must
        # still fit in one 512-byte chunk.
        if len(token.encode("ascii")) > 511:
            fail(f"{what}:{n} label {token} straddles a 512-byte cmd boundary")


def check_attributes() -> None:
    text = (ROOT / ".gitattributes").read_text(encoding="ascii")
    found = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] != "install.cmd":
            continue
        attrs = parts[1:]
        if "text" in attrs or any(a.startswith("eol=") for a in attrs):
            fail(
                "install.cmd must be marked -text in .gitattributes "
                "(text/eol=crlf stores LF in the blob that curl downloads)"
            )
        if "-text" not in attrs:
            fail(f"unexpected install.cmd attributes: {line}")
        found = True
    if not found:
        fail(".gitattributes must contain: install.cmd -text")


def main() -> None:
    check_attributes()
    blob = git_blob("HEAD:install.cmd")
    work = (ROOT / "install.cmd").read_bytes()
    check_crlf(blob, "git blob HEAD:install.cmd")
    check_crlf(work, "install.cmd")
    lines = blob.count(b"\r\n")
    print(f"install.cmd CRLF ok ({lines} lines)")


if __name__ == "__main__":
    main()
