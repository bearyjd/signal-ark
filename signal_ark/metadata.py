"""Parse and write the LocalArchive metadata file."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from signal_ark.kdf import backup_key_to_local_metadata_key
from signal_ark.proto.LocalArchive_pb2 import Metadata


@dataclass(frozen=True)
class BackupMetadata:
    version: int
    backup_id: bytes
    iv: bytes
    encrypted_id: bytes

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "backup_id": self.backup_id.hex(),
            "iv": self.iv.hex(),
            "encrypted_id": self.encrypted_id.hex(),
        }


def parse_metadata(metadata_path: Path) -> Metadata:
    data = metadata_path.read_bytes()
    msg = Metadata()
    msg.ParseFromString(data)
    return msg


def decrypt_metadata(metadata_path: Path, backup_key: bytes) -> BackupMetadata:
    msg = parse_metadata(metadata_path)
    metadata_key = backup_key_to_local_metadata_key(backup_key)

    iv = bytes(msg.backupId.iv)
    encrypted_id = bytes(msg.backupId.encryptedId)

    cipher = Cipher(algorithms.AES(metadata_key), modes.CTR(iv + b"\x00" * 4))
    decryptor = cipher.decryptor()
    backup_id = decryptor.update(encrypted_id) + decryptor.finalize()

    return BackupMetadata(
        version=msg.version,
        backup_id=backup_id,
        iv=iv,
        encrypted_id=encrypted_id,
    )


def write_metadata(output_path: Path, backup_key: bytes, backup_id: bytes, version: int = 1) -> None:
    import os
    metadata_key = backup_key_to_local_metadata_key(backup_key)
    iv = os.urandom(12)

    cipher = Cipher(algorithms.AES(metadata_key), modes.CTR(iv + b"\x00" * 4))
    encryptor = cipher.encryptor()
    encrypted_id = encryptor.update(backup_id) + encryptor.finalize()

    msg = Metadata()
    msg.version = version
    msg.backupId.iv = iv
    msg.backupId.encryptedId = encrypted_id

    output_path.write_bytes(msg.SerializeToString())
