"""Filesystem helpers."""

from __future__ import annotations

import os
from pathlib import Path


def open_private(path: Path) -> int:
    """Open ``path`` for writing, creating it atomically with mode 0600."""
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)


def write_private_bytes(path: Path, data: bytes) -> None:
    with os.fdopen(open_private(path), "wb") as f:
        f.write(data)


def write_private_text(path: Path, text: str) -> None:
    write_private_bytes(path, text.encode("utf-8"))
