"""Parse Signal v1 backup files into typed frames.

Provides a generator-based streaming parser that yields typed frames
from a v1 .backup file, plus a SQL collector that replays SQL statements
into an in-memory SQLite database.

Reference: Signal-Android FullBackupImporter.java
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import BinaryIO, Iterator

from signal_ark.proto.V1Backup_pb2 import BackupFrame
from signal_ark.v1_decrypt import V1FrameDecryptor, derive_v1_keys


class V1FrameType(Enum):
    HEADER = auto()
    VERSION = auto()
    STATEMENT = auto()
    PREFERENCE = auto()
    ATTACHMENT = auto()
    STICKER = auto()
    AVATAR = auto()
    KEY_VALUE = auto()
    END = auto()


@dataclass(frozen=True)
class V1Header:
    iv: bytes
    salt: bytes | None
    version: int


@dataclass(frozen=True)
class V1ParsedFrame:
    frame_type: V1FrameType
    frame: BackupFrame
    attachment_data: bytes | None = None


@dataclass(frozen=True)
class V1BackupStats:
    total_frames: int = 0
    statements: int = 0
    preferences: int = 0
    attachments: int = 0
    stickers: int = 0
    avatars: int = 0
    key_values: int = 0


def parse_v1_header(stream: BinaryIO) -> tuple[V1Header, BackupFrame]:
    """Read the unencrypted header frame from a v1 backup stream."""
    length_bytes = stream.read(4)
    if len(length_bytes) != 4:
        raise ValueError("Cannot read header length — file too short")
    header_length = int.from_bytes(length_bytes, "big")

    header_data = stream.read(header_length)
    if len(header_data) != header_length:
        raise ValueError(f"Short header: expected {header_length}, got {len(header_data)}")

    frame = BackupFrame()
    frame.ParseFromString(header_data)

    if not frame.HasField("header"):
        raise ValueError("First frame is not a header")

    header = frame.header
    if not header.HasField("iv") or len(header.iv) != 16:
        raise ValueError("Header missing or invalid IV")

    salt = bytes(header.salt) if header.HasField("salt") else None
    version = header.version if header.HasField("version") else 0

    return V1Header(iv=bytes(header.iv), salt=salt, version=version), frame


def parse_v1_backup(path: Path | str, passphrase: str) -> Iterator[V1ParsedFrame]:
    """Stream-parse a v1 backup file, yielding typed frames.

    Attachments, stickers, and avatars include their inline binary data
    in the attachment_data field of the yielded V1ParsedFrame.
    """
    path = Path(path)
    with open(path, "rb") as f:
        yield from parse_v1_stream(f, passphrase)


def parse_v1_stream(stream: BinaryIO, passphrase: str) -> Iterator[V1ParsedFrame]:
    """Stream-parse a v1 backup from an open file handle."""
    header_info, header_frame = parse_v1_header(stream)

    yield V1ParsedFrame(
        frame_type=V1FrameType.HEADER,
        frame=header_frame,
    )

    keys = derive_v1_keys(passphrase, header_info.salt)
    decryptor = V1FrameDecryptor(
        cipher_key=keys.cipher_key,
        mac_key=keys.mac_key,
        iv=header_info.iv,
        version=header_info.version,
    )

    while True:
        try:
            plaintext = decryptor.read_frame(stream)
        except ValueError as e:
            if "Short read" in str(e):
                break  # Clean EOF
            raise

        frame = BackupFrame()
        frame.ParseFromString(plaintext)

        if frame.HasField("end") and frame.end:
            yield V1ParsedFrame(frame_type=V1FrameType.END, frame=frame)
            break

        attachment_data = None

        if frame.HasField("version"):
            yield V1ParsedFrame(frame_type=V1FrameType.VERSION, frame=frame)
        elif frame.HasField("statement"):
            yield V1ParsedFrame(frame_type=V1FrameType.STATEMENT, frame=frame)
        elif frame.HasField("preference"):
            yield V1ParsedFrame(frame_type=V1FrameType.PREFERENCE, frame=frame)
        elif frame.HasField("attachment"):
            attachment_data = decryptor.read_attachment(stream, frame.attachment.length)
            yield V1ParsedFrame(
                frame_type=V1FrameType.ATTACHMENT,
                frame=frame,
                attachment_data=attachment_data,
            )
        elif frame.HasField("sticker"):
            attachment_data = decryptor.read_attachment(stream, frame.sticker.length)
            yield V1ParsedFrame(
                frame_type=V1FrameType.STICKER,
                frame=frame,
                attachment_data=attachment_data,
            )
        elif frame.HasField("avatar"):
            attachment_data = decryptor.read_attachment(stream, frame.avatar.length)
            yield V1ParsedFrame(
                frame_type=V1FrameType.AVATAR,
                frame=frame,
                attachment_data=attachment_data,
            )
        elif frame.HasField("keyValue"):
            yield V1ParsedFrame(frame_type=V1FrameType.KEY_VALUE, frame=frame)
        else:
            pass  # Unknown frame type — skip


def collect_v1_database(frames: Iterator[V1ParsedFrame]) -> tuple[sqlite3.Connection, V1BackupStats]:
    """Replay v1 SQL statements into an in-memory SQLite database.

    Also counts frame types for stats. Attachment data is discarded
    by this function (use parse_v1_backup directly if you need it).
    """
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = OFF")
    stats = {
        "total_frames": 0,
        "statements": 0,
        "preferences": 0,
        "attachments": 0,
        "stickers": 0,
        "avatars": 0,
        "key_values": 0,
    }

    for parsed in frames:
        stats["total_frames"] += 1

        if parsed.frame_type == V1FrameType.STATEMENT:
            stats["statements"] += 1
            stmt = parsed.frame.statement
            if not stmt.HasField("statement"):
                continue
            sql = stmt.statement
            params = _extract_sql_params(stmt)
            try:
                conn.execute(sql, params)
            except Exception:
                pass  # Skip statements that fail (schema mismatches, etc.)
        elif parsed.frame_type == V1FrameType.PREFERENCE:
            stats["preferences"] += 1
        elif parsed.frame_type == V1FrameType.ATTACHMENT:
            stats["attachments"] += 1
        elif parsed.frame_type == V1FrameType.STICKER:
            stats["stickers"] += 1
        elif parsed.frame_type == V1FrameType.AVATAR:
            stats["avatars"] += 1
        elif parsed.frame_type == V1FrameType.KEY_VALUE:
            stats["key_values"] += 1

    conn.commit()
    return conn, V1BackupStats(**stats)


def _extract_sql_params(stmt) -> list:
    """Convert SqlStatement parameters to Python values for sqlite3.execute()."""
    params = []
    for p in stmt.parameters:
        if p.HasField("stringParamter"):
            params.append(p.stringParamter)
        elif p.HasField("integerParameter"):
            params.append(p.integerParameter)
        elif p.HasField("doubleParameter"):
            params.append(p.doubleParameter)
        elif p.HasField("blobParameter"):
            params.append(bytes(p.blobParameter))
        elif p.HasField("nullparameter"):
            params.append(None)
        else:
            params.append(None)
    return params
