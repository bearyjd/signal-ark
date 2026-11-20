"""Content-store naming/layout and frame statistics shared by mapper, CLI and TUI."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

from signal_ark.proto.Backup_pb2 import Frame


def media_name(plaintext_hash: bytes, local_key: bytes) -> str:
    """Media name = hex SHA256(plaintextHash || localKey)."""
    return hashlib.sha256(bytes(plaintext_hash) + bytes(local_key)).hexdigest()


def store_path(files_dir: Path, name: str) -> Path:
    """Path of a media file in the sharded content store (files/XX/<name>)."""
    return files_dir / name[:2] / name


def frame_stats(frames: Iterable[Frame]) -> tuple[dict[str, int], list[tuple[str, object]]]:
    """Per-type frame counts and (dateSent, FilePointer) for each standard-message attachment."""
    counts: dict[str, int] = {}
    pointers: list[tuple[str, object]] = []
    for frame in frames:
        item_type = frame.WhichOneof("item") or "unknown"
        counts[item_type] = counts.get(item_type, 0) + 1
        if item_type == "chatItem" and frame.chatItem.HasField("standardMessage"):
            for ma in frame.chatItem.standardMessage.attachments:
                pointers.append((str(frame.chatItem.dateSent), ma.pointer))
    return counts, pointers
