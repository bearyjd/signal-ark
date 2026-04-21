"""Encrypt Signal v2 backup main file and files manifest."""

from __future__ import annotations

import gzip
import io
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from signal_ark.decrypt import _write_varint
from signal_ark.proto.Backup_pb2 import BackupInfo, Frame
from signal_ark.proto.LocalArchive_pb2 import FilesFrame

AES_BLOCK_SIZE = 16
HMAC_SIZE = 32
IV_SIZE = 16


def serialize_frames(backup_info: BackupInfo, frames: list[Frame]) -> bytes:
    """Serialize BackupInfo + Frames as varint-length-delimited protobuf stream."""
    buf = io.BytesIO()

    info_bytes = backup_info.SerializeToString()
    buf.write(_write_varint(len(info_bytes)))
    buf.write(info_bytes)

    for frame in frames:
        frame_bytes = frame.SerializeToString()
        buf.write(_write_varint(len(frame_bytes)))
        buf.write(frame_bytes)

    return buf.getvalue()


def encrypt_main(plaintext: bytes, hmac_key: bytes, aes_key: bytes) -> bytes:
    """Encrypt a plaintext frame stream into a v2 backup main file (legacy format)."""
    compressed = gzip.compress(plaintext)

    padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded = padder.update(compressed) + padder.finalize()

    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(iv)
    h.update(ciphertext)
    mac = h.finalize()

    return iv + ciphertext + mac


def serialize_files_manifest(media_names: list[str]) -> bytes:
    """Serialize media names as varint-delimited FilesFrame protobuf (unencrypted)."""
    buf = io.BytesIO()
    for name in media_names:
        ff = FilesFrame()
        ff.mediaName = name
        data = ff.SerializeToString()
        buf.write(_write_varint(len(data)))
        buf.write(data)
    return buf.getvalue()


def write_backup_directory(
    output_dir: Path,
    backup_info: BackupInfo,
    frames: list[Frame],
    hmac_key: bytes,
    aes_key: bytes,
    backup_key: bytes,
    backup_id: bytes,
    media_names: list[str] | None = None,
    version: int = 1,
) -> None:
    """Write a complete v2 backup directory (main, metadata, files manifest)."""
    from signal_ark.metadata import write_metadata

    output_dir.mkdir(parents=True, exist_ok=True)

    plaintext = serialize_frames(backup_info, frames)
    main_data = encrypt_main(plaintext, hmac_key, aes_key)
    (output_dir / "main").write_bytes(main_data)

    write_metadata(output_dir / "metadata", backup_key, backup_id, version)

    if media_names is not None:
        manifest = serialize_files_manifest(media_names)
        (output_dir / "files").write_bytes(manifest)
