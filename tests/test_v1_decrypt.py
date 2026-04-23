"""Tests for v1 backup KDF and frame decryption."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import io
import os

import pytest

from signal_ark.v1_decrypt import (
    V1FrameDecryptor,
    _get_backup_key,
    derive_v1_keys,
    validate_v1_passphrase,
)

# --- Passphrase validation ---


def test_validate_passphrase_strips_spaces() -> None:
    raw = "123 456 789 012 345 678 901 234 567 890"
    assert validate_v1_passphrase(raw) == "123456789012345678901234567890"


def test_validate_passphrase_no_spaces() -> None:
    assert validate_v1_passphrase("123456789012345678901234567890") == "123456789012345678901234567890"


def test_validate_passphrase_rejects_short() -> None:
    with pytest.raises(ValueError, match="30 digits"):
        validate_v1_passphrase("12345")


def test_validate_passphrase_rejects_letters() -> None:
    with pytest.raises(ValueError, match="only digits"):
        validate_v1_passphrase("12345678901234567890123456789a")


# --- KDF vectors ---

ZERO_PASSPHRASE = "000000000000000000000000000000"


def test_backup_key_no_salt() -> None:
    key = _get_backup_key(ZERO_PASSPHRASE, None)
    assert key.hex() == "6971b4862f91b3d75866480ca272d1a63af736c4f358bb920c5cfe41803b8a92"


def test_backup_key_zero_salt() -> None:
    key = _get_backup_key(ZERO_PASSPHRASE, bytes(32))
    assert key.hex() == "6b8b929a0477e5b5ecb56feb05c711588a17e2ced720ae37602351fe0a86eaca"


def test_derive_v1_keys_no_salt() -> None:
    keys = derive_v1_keys(ZERO_PASSPHRASE, None)
    assert keys.cipher_key.hex() == "b0427a3bda52a2d87e6ade0d73e8c362a247453d900170bf82a8d2f9d89c1f9a"
    assert keys.mac_key.hex() == "0abac2311ca23dec5d113615440a363d67ec66988e30a344e0149e4a557dbad1"


def test_derive_v1_keys_zero_salt() -> None:
    keys = derive_v1_keys(ZERO_PASSPHRASE, bytes(32))
    assert keys.cipher_key.hex() == "ba6590518563c8d2ea080b74f770f7785aae6c1f0862b5ce20a519b39f0b7182"
    assert keys.mac_key.hex() == "e7275571ce5d43c677ec28541f03b24fb221143c178859620183b72638b31025"


def test_v1_keys_is_frozen() -> None:
    keys = derive_v1_keys(ZERO_PASSPHRASE, None)
    with pytest.raises(AttributeError):
        keys.cipher_key = b"x" * 32  # type: ignore[misc]


# --- Frame decryption ---


def _build_encrypted_frame(cipher_key: bytes, mac_key: bytes, iv: bytes,
                           counter: int, plaintext: bytes, version: int = 0) -> tuple[bytes, int]:
    """Build a single encrypted v1 frame, returning (frame_bytes, next_counter).

    frame_bytes includes the 4-byte length prefix.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Bump counter for frame length (version >= 1 encrypts the length)
    frame_iv = bytearray(iv)
    frame_iv[:4] = counter.to_bytes(4, "big")
    counter += 1

    # Encrypt plaintext
    cipher = Cipher(algorithms.AES(cipher_key), modes.CTR(bytes(frame_iv)))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # MAC over ciphertext
    mac = hmac_mod.new(mac_key, digestmod=hashlib.sha256)
    mac.update(ciphertext)
    truncated_mac = mac.digest()[:10]

    frame_body = ciphertext + truncated_mac
    frame_length = len(frame_body)

    if version >= 1:
        # Encrypt the length too
        length_cipher = Cipher(algorithms.AES(cipher_key), modes.CTR(bytes(frame_iv)))
        enc = length_cipher.encryptor()
        encrypted_length = enc.update(frame_length.to_bytes(4, "big")) + enc.finalize()
        # MAC the encrypted length
        length_mac = hmac_mod.new(mac_key, digestmod=hashlib.sha256)
        length_mac.update(encrypted_length)
        # Note: the MAC for length is consumed by the running mac state in the decryptor,
        # but in our test helper we just prepend the encrypted length bytes
        return encrypted_length + frame_body, counter
    else:
        return frame_length.to_bytes(4, "big") + frame_body, counter


def test_decrypt_single_frame_v0() -> None:
    cipher_key = os.urandom(32)
    mac_key = os.urandom(32)
    iv = os.urandom(16)
    counter = int.from_bytes(iv[:4], "big")

    plaintext = b"hello v1 backup frame"
    frame_bytes, _ = _build_encrypted_frame(cipher_key, mac_key, iv, counter, plaintext, version=0)

    stream = io.BytesIO(frame_bytes)
    decryptor = V1FrameDecryptor(cipher_key, mac_key, iv, version=0)
    result = decryptor.read_frame(stream)
    assert result == plaintext


def test_decrypt_multiple_frames_v0() -> None:
    cipher_key = os.urandom(32)
    mac_key = os.urandom(32)
    iv = os.urandom(16)
    counter = int.from_bytes(iv[:4], "big")

    messages = [b"frame one", b"frame two", b"frame three"]
    buf = io.BytesIO()
    for msg in messages:
        frame_bytes, counter = _build_encrypted_frame(cipher_key, mac_key, iv, counter, msg, version=0)
        # Update IV for next frame (mirror counter progression)
        iv_mut = bytearray(iv)
        iv_mut[:4] = counter.to_bytes(4, "big")
        buf.write(frame_bytes)

    buf.seek(0)
    decryptor = V1FrameDecryptor(cipher_key, mac_key, iv, version=0)
    for expected in messages:
        result = decryptor.read_frame(buf)
        assert result == expected


def test_decrypt_bad_mac_raises() -> None:
    cipher_key = os.urandom(32)
    mac_key = os.urandom(32)
    iv = os.urandom(16)
    counter = int.from_bytes(iv[:4], "big")

    frame_bytes, _ = _build_encrypted_frame(cipher_key, mac_key, iv, counter, b"test", version=0)
    # Corrupt the MAC (last 10 bytes of the frame body, after the 4-byte length)
    corrupted = bytearray(frame_bytes)
    corrupted[-1] ^= 0xFF

    stream = io.BytesIO(bytes(corrupted))
    decryptor = V1FrameDecryptor(cipher_key, mac_key, iv, version=0)
    with pytest.raises(ValueError, match="HMAC verification failed"):
        decryptor.read_frame(stream)


def test_decrypt_attachment() -> None:
    cipher_key = os.urandom(32)
    mac_key = os.urandom(32)
    iv = os.urandom(16)
    counter = int.from_bytes(iv[:4], "big")

    attachment_data = os.urandom(1234)

    # Build encrypted attachment (mirrors readAttachmentTo)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    att_iv = bytearray(iv)
    att_iv[:4] = counter.to_bytes(4, "big")
    cipher = Cipher(algorithms.AES(cipher_key), modes.CTR(bytes(att_iv)))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(attachment_data) + encryptor.finalize()

    mac = hmac_mod.new(mac_key, digestmod=hashlib.sha256)
    mac.update(bytes(att_iv))  # Attachments MAC the IV
    mac.update(ciphertext)
    truncated_mac = mac.digest()[:10]

    stream = io.BytesIO(ciphertext + truncated_mac)
    decryptor = V1FrameDecryptor(cipher_key, mac_key, iv, version=0)
    result = decryptor.read_attachment(stream, len(attachment_data))
    assert result == attachment_data


def test_short_read_raises() -> None:
    cipher_key = os.urandom(32)
    mac_key = os.urandom(32)
    iv = os.urandom(16)

    stream = io.BytesIO(b"\x00\x00")  # Too short for frame length
    decryptor = V1FrameDecryptor(cipher_key, mac_key, iv, version=0)
    with pytest.raises(ValueError, match="Short read"):
        decryptor.read_frame(stream)
