"""Test that decrypt → re-encrypt → decrypt produces identical frames."""

import os

from signal_ark.decrypt import decrypt_main, parse_frames, parse_files_manifest
from signal_ark.encrypt import encrypt_main, serialize_frames, serialize_files_manifest
from signal_ark.proto.Backup_pb2 import BackupInfo, Frame


def test_roundtrip_main() -> None:
    info = BackupInfo()
    info.version = 1
    info.backupTimeMs = 1234567890

    frame1 = Frame()
    frame1.account.givenName = "Test"
    frame1.account.profileKey = os.urandom(32)

    frame2 = Frame()
    frame2.recipient.id = 1
    frame2.recipient.self.avatarColor = 10

    frames = [frame1, frame2]

    hmac_key = os.urandom(32)
    aes_key = os.urandom(32)

    plaintext = serialize_frames(info, frames)
    encrypted = encrypt_main(plaintext, hmac_key, aes_key)
    decrypted = decrypt_main(encrypted, hmac_key, aes_key)

    assert decrypted == plaintext

    result = parse_frames(decrypted)
    assert result.backup_info.version == 1
    assert result.backup_info.backupTimeMs == 1234567890
    assert len(result.frames) == 2
    assert result.frames[0].account.givenName == "Test"
    assert result.frames[1].recipient.id == 1


def test_roundtrip_files_manifest() -> None:
    names = ["abc123", "def456", "deadbeef"]
    data = serialize_files_manifest(names)
    parsed = parse_files_manifest(data)
    assert parsed == names
