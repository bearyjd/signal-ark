"""Decrypt and parse Signal v2 backup main file."""

from __future__ import annotations

import gzip
import io
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from signal_ark.proto.Backup_pb2 import BackupInfo, Frame

MAGIC = b"SBACKUP\x01"
HMAC_SIZE = 32
IV_SIZE = 16
AES_BLOCK_SIZE = 16


@dataclass(frozen=True)
class DecryptedBackup:
    backup_info: BackupInfo
    frames: list[Frame]


def _read_varint(stream: io.BytesIO) -> int | None:
    """Read a protobuf varint from a stream. Returns None at EOF."""
    result = 0
    shift = 0
    while True:
        byte = stream.read(1)
        if not byte:
            return None
        b = byte[0]
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result
        shift += 7
        if shift > 63:
            raise ValueError("Varint too long")


def _write_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def detect_format(data: bytes) -> tuple[bool, int]:
    """Detect if backup uses modern format. Returns (is_modern, offset_to_encrypted_data)."""
    if data[:8] == MAGIC:
        offset = 8
        # Read varint length of FS metadata
        stream = io.BytesIO(data[offset:])
        fs_meta_len = _read_varint(stream)
        if fs_meta_len is None:
            raise ValueError("Failed to read FS metadata length")
        offset += stream.tell() + fs_meta_len
        return True, offset
    return False, 0


def verify_hmac(hmac_key: bytes, iv: bytes, ciphertext: bytes, expected_mac: bytes) -> None:
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(iv)
    h.update(ciphertext)
    h.verify(expected_mac)


def decrypt_main(data: bytes, hmac_key: bytes, aes_key: bytes) -> bytes:
    """Decrypt the main backup file, returning decompressed plaintext frame stream."""
    is_modern, offset = detect_format(data)
    encrypted_payload = data[offset:]

    mac = encrypted_payload[-HMAC_SIZE:]
    iv = encrypted_payload[:IV_SIZE]
    ciphertext = encrypted_payload[IV_SIZE:-HMAC_SIZE]

    verify_hmac(hmac_key, iv, ciphertext, mac)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_compressed = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
    compressed = unpadder.update(padded_compressed) + unpadder.finalize()

    return gzip.decompress(compressed)


def parse_frames(plaintext: bytes) -> DecryptedBackup:
    """Parse varint-delimited protobuf frames from decrypted plaintext."""
    stream = io.BytesIO(plaintext)

    # First frame is BackupInfo
    info_len = _read_varint(stream)
    if info_len is None:
        raise ValueError("Empty backup — no BackupInfo frame")
    info_data = stream.read(info_len)
    if len(info_data) != info_len:
        raise ValueError(f"Truncated BackupInfo: expected {info_len}, got {len(info_data)}")

    backup_info = BackupInfo()
    backup_info.ParseFromString(info_data)

    frames: list[Frame] = []
    while True:
        frame_len = _read_varint(stream)
        if frame_len is None:
            break
        if frame_len == 0:
            continue
        frame_data = stream.read(frame_len)
        if len(frame_data) != frame_len:
            raise ValueError(f"Truncated frame: expected {frame_len}, got {len(frame_data)}")
        frame = Frame()
        frame.ParseFromString(frame_data)
        frames.append(frame)

    return DecryptedBackup(backup_info=backup_info, frames=frames)


def decrypt_files_manifest(data: bytes, hmac_key: bytes, aes_key: bytes) -> bytes:
    """Decrypt the files manifest (same format as main)."""
    return decrypt_main(data, hmac_key, aes_key)


def parse_files_manifest(data: bytes) -> list[str]:
    """Parse the files manifest as raw varint-delimited FilesFrame protobuf."""
    from signal_ark.proto.LocalArchive_pb2 import FilesFrame

    stream = io.BytesIO(data)
    names: list[str] = []
    while True:
        frame_len = _read_varint(stream)
        if frame_len is None:
            break
        frame_data = stream.read(frame_len)
        ff = FilesFrame()
        ff.ParseFromString(frame_data)
        names.append(ff.mediaName)
    return names


def frame_to_dict(frame: Frame) -> dict:
    """Convert a Frame to a JSON-serializable dict."""
    from google.protobuf.json_format import MessageToDict
    return MessageToDict(frame, preserving_proto_field_name=True)


def backup_info_to_dict(info: BackupInfo) -> dict:
    from google.protobuf.json_format import MessageToDict
    return MessageToDict(info, preserving_proto_field_name=True)
