"""Filesystem helpers."""

from __future__ import annotations

import os
from pathlib import Path


def open_private(path: Path) -> int:
    """Open ``path`` for writing with mode 0600, tightening pre-existing files."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
    except BaseException:
        os.close(fd)
        raise
    return fd


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` (and parents) and force mode 0700 on it.

    ``mkdir(mode=)`` is masked by umask and ignores pre-existing dirs, so chmod explicitly.
    """
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def write_private_bytes(path: Path, data: bytes) -> None:
    with os.fdopen(open_private(path), "wb") as f:
        f.write(data)


def write_private_text(path: Path, text: str) -> None:
    write_private_bytes(path, text.encode("utf-8"))
