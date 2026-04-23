"""Tests for v1 backup parser with synthetic backup builder."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import io
import os
import tempfile
from pathlib import Path

import pytest

from signal_ark.proto.V1Backup_pb2 import (
    BackupFrame,
)
from signal_ark.v1_decrypt import derive_v1_keys
from signal_ark.v1_parser import (
    V1FrameType,
    collect_v1_database,
    parse_v1_backup,
    parse_v1_header,
    parse_v1_stream,
)

TEST_PASSPHRASE = "123456789012345678901234567890"
TEST_SALT = os.urandom(32)
TEST_IV = os.urandom(16)


def _encrypt_frame(cipher_key: bytes, mac_key: bytes, iv: bytearray,
                   counter: int, plaintext: bytes) -> tuple[bytes, int]:
    """Encrypt a single frame for a version-0 backup. Returns (bytes, next_counter)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv[:4] = counter.to_bytes(4, "big")
    counter += 1

    cipher = Cipher(algorithms.AES(cipher_key), modes.CTR(bytes(iv)))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    mac = hmac_mod.new(mac_key, digestmod=hashlib.sha256)
    mac.update(ciphertext)
    truncated_mac = mac.digest()[:10]

    frame_body = ciphertext + truncated_mac
    length_prefix = len(frame_body).to_bytes(4, "big")
    return length_prefix + frame_body, counter


def _encrypt_attachment(cipher_key: bytes, mac_key: bytes, iv: bytearray,
                        counter: int, data: bytes) -> tuple[bytes, int]:
    """Encrypt inline attachment data. Returns (encrypted_data + mac, next_counter)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv[:4] = counter.to_bytes(4, "big")
    counter += 1

    cipher = Cipher(algorithms.AES(cipher_key), modes.CTR(bytes(iv)))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    mac = hmac_mod.new(mac_key, digestmod=hashlib.sha256)
    mac.update(bytes(iv))
    mac.update(ciphertext)
    truncated_mac = mac.digest()[:10]

    return ciphertext + truncated_mac, counter


def build_synthetic_v1_backup(
    passphrase: str = TEST_PASSPHRASE,
    salt: bytes = TEST_SALT,
    iv: bytes = TEST_IV,
    sql_statements: list[tuple[str, list]] | None = None,
    attachment_data: bytes | None = None,
    include_preference: bool = False,
    include_key_value: bool = False,
) -> bytes:
    """Build a complete synthetic v1 backup file."""
    keys = derive_v1_keys(passphrase, salt)
    working_iv = bytearray(iv)
    counter = int.from_bytes(iv[:4], "big")

    buf = io.BytesIO()

    # 1. Unencrypted header frame
    header_frame = BackupFrame()
    header_frame.header.iv = iv
    header_frame.header.salt = salt
    header_frame.header.version = 0
    header_bytes = header_frame.SerializeToString()
    buf.write(len(header_bytes).to_bytes(4, "big"))
    buf.write(header_bytes)

    # 2. Database version frame
    version_frame = BackupFrame()
    version_frame.version.version = 100
    enc, counter = _encrypt_frame(keys.cipher_key, keys.mac_key, working_iv, counter,
                                  version_frame.SerializeToString())
    buf.write(enc)

    # 3. SQL statements
    if sql_statements is None:
        sql_statements = [
            ("CREATE TABLE test_contacts (id INTEGER PRIMARY KEY, name TEXT, phone TEXT)", []),
            ("INSERT INTO test_contacts VALUES (?, ?, ?)", [1, "Alice", "+15551234567"]),
            ("INSERT INTO test_contacts VALUES (?, ?, ?)", [2, "Bob", "+15559876543"]),
        ]

    for sql, params in sql_statements:
        stmt_frame = BackupFrame()
        stmt_frame.statement.statement = sql
        for p in params:
            param = stmt_frame.statement.parameters.add()
            if p is None:
                param.nullparameter = True
            elif isinstance(p, int):
                param.integerParameter = p
            elif isinstance(p, float):
                param.doubleParameter = p
            elif isinstance(p, bytes):
                param.blobParameter = p
            else:
                param.stringParamter = str(p)

        enc, counter = _encrypt_frame(keys.cipher_key, keys.mac_key, working_iv, counter,
                                      stmt_frame.SerializeToString())
        buf.write(enc)

    # 4. Optional preference
    if include_preference:
        pref_frame = BackupFrame()
        pref_frame.preference.file = "prefs"
        pref_frame.preference.key = "theme"
        pref_frame.preference.value = "dark"
        enc, counter = _encrypt_frame(keys.cipher_key, keys.mac_key, working_iv, counter,
                                      pref_frame.SerializeToString())
        buf.write(enc)

    # 5. Optional attachment
    if attachment_data is not None:
        att_frame = BackupFrame()
        att_frame.attachment.rowId = 1
        att_frame.attachment.attachmentId = 100
        att_frame.attachment.length = len(attachment_data)
        enc, counter = _encrypt_frame(keys.cipher_key, keys.mac_key, working_iv, counter,
                                      att_frame.SerializeToString())
        buf.write(enc)

        att_enc, counter = _encrypt_attachment(keys.cipher_key, keys.mac_key, working_iv, counter,
                                              attachment_data)
        buf.write(att_enc)

    # 6. Optional key value
    if include_key_value:
        kv_frame = BackupFrame()
        kv_frame.keyValue.key = "test_key"
        kv_frame.keyValue.stringValue = "test_value"
        enc, counter = _encrypt_frame(keys.cipher_key, keys.mac_key, working_iv, counter,
                                      kv_frame.SerializeToString())
        buf.write(enc)

    # 7. End frame
    end_frame = BackupFrame()
    end_frame.end = True
    enc, counter = _encrypt_frame(keys.cipher_key, keys.mac_key, working_iv, counter,
                                  end_frame.SerializeToString())
    buf.write(enc)

    return buf.getvalue()


# --- Header parsing ---

def test_parse_header() -> None:
    backup = build_synthetic_v1_backup()
    stream = io.BytesIO(backup)
    header, frame = parse_v1_header(stream)

    assert header.iv == TEST_IV
    assert header.salt == TEST_SALT
    assert header.version == 0


def test_parse_header_bad_data() -> None:
    with pytest.raises(ValueError):
        parse_v1_header(io.BytesIO(b"\x00\x00"))


# --- Full parse ---

def test_parse_all_frame_types() -> None:
    attachment_data = b"hello attachment"
    backup = build_synthetic_v1_backup(
        attachment_data=attachment_data,
        include_preference=True,
        include_key_value=True,
    )

    with tempfile.NamedTemporaryFile(suffix=".backup", delete=False) as f:
        f.write(backup)
        f.flush()
        path = Path(f.name)

    try:
        frames = list(parse_v1_backup(path, TEST_PASSPHRASE))
    finally:
        path.unlink()

    types = [f.frame_type for f in frames]
    assert types[0] == V1FrameType.HEADER
    assert types[1] == V1FrameType.VERSION
    assert V1FrameType.STATEMENT in types
    assert V1FrameType.PREFERENCE in types
    assert V1FrameType.ATTACHMENT in types
    assert V1FrameType.KEY_VALUE in types
    assert types[-1] == V1FrameType.END

    att_frames = [f for f in frames if f.frame_type == V1FrameType.ATTACHMENT]
    assert len(att_frames) == 1
    assert att_frames[0].attachment_data == attachment_data


def test_parse_stream_basic() -> None:
    backup = build_synthetic_v1_backup()
    frames = list(parse_v1_stream(io.BytesIO(backup), TEST_PASSPHRASE))

    assert frames[0].frame_type == V1FrameType.HEADER
    assert frames[-1].frame_type == V1FrameType.END
    stmt_count = sum(1 for f in frames if f.frame_type == V1FrameType.STATEMENT)
    assert stmt_count == 3  # CREATE + 2 INSERTs


# --- SQL collector ---

def test_collect_database() -> None:
    backup = build_synthetic_v1_backup()
    frames = parse_v1_stream(io.BytesIO(backup), TEST_PASSPHRASE)
    conn, stats = collect_v1_database(frames)

    rows = conn.execute("SELECT * FROM test_contacts ORDER BY id").fetchall()
    assert len(rows) == 2
    assert rows[0][1] == "Alice"
    assert rows[1][1] == "Bob"

    assert stats.statements == 3
    assert stats.total_frames > 0


def test_collect_database_with_attachment() -> None:
    backup = build_synthetic_v1_backup(attachment_data=b"image data here")
    frames = parse_v1_stream(io.BytesIO(backup), TEST_PASSPHRASE)
    conn, stats = collect_v1_database(frames)

    assert stats.attachments == 1
    assert stats.statements == 3


# --- Edge cases ---

def test_empty_backup_header_and_end() -> None:
    backup = build_synthetic_v1_backup(sql_statements=[])
    frames = list(parse_v1_stream(io.BytesIO(backup), TEST_PASSPHRASE))

    types = [f.frame_type for f in frames]
    assert types[0] == V1FrameType.HEADER
    assert types[1] == V1FrameType.VERSION
    assert types[-1] == V1FrameType.END


def test_wrong_passphrase_raises() -> None:
    backup = build_synthetic_v1_backup()
    wrong_pass = "999999999999999999999999999999"

    frames_gen = parse_v1_stream(io.BytesIO(backup), wrong_pass)
    next(frames_gen)  # Header (unencrypted) should work
    with pytest.raises(ValueError, match="HMAC"):
        next(frames_gen)  # First encrypted frame should fail
