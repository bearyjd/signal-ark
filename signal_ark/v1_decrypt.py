"""Decrypt Signal v1 backup files.

Implements the v1 KDF chain (SHA-512 250K rounds + HKDF) and streaming
per-frame AES-256-CTR decryption with truncated HMAC-SHA256 verification.

Reference: Signal-Android BackupRecordInputStream.java, FullBackupBase.java
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

DIGEST_ROUNDS = 250_000
HKDF_INFO = b"Backup Export"
HMAC_TRUNCATED_SIZE = 10


@dataclass(frozen=True)
class V1Keys:
    cipher_key: bytes  # 32 bytes, AES-256
    mac_key: bytes     # 32 bytes, HMAC-SHA256


def validate_v1_passphrase(passphrase: str) -> str:
    """Strip spaces and validate a v1 30-digit passphrase."""
    stripped = passphrase.replace(" ", "")
    if len(stripped) != 30:
        raise ValueError(f"v1 passphrase must be 30 digits, got {len(stripped)}")
    if not stripped.isdigit():
        raise ValueError("v1 passphrase must contain only digits [0-9]")
    return stripped


def _get_backup_key(passphrase: str, salt: bytes | None) -> bytes:
    """SHA-512 iterated 250K times, returns first 32 bytes.

    Mirrors FullBackupBase.BackupStream.getBackupKey() exactly.
    """
    inp = passphrase.encode("utf-8")
    h = inp

    for i in range(DIGEST_ROUNDS):
        digest = hashlib.sha512()
        if i == 0 and salt is not None:
            digest.update(salt)
        digest.update(h)
        digest.update(inp)
        h = digest.digest()

    return h[:32]


def derive_v1_keys(passphrase: str, salt: bytes | None) -> V1Keys:
    """Full v1 KDF: passphrase → SHA-512 rounds → HKDF → (cipher_key, mac_key)."""
    passphrase = validate_v1_passphrase(passphrase)
    backup_key = _get_backup_key(passphrase, salt)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=HKDF_INFO,
    )
    derived = hkdf.derive(backup_key)

    return V1Keys(cipher_key=derived[:32], mac_key=derived[32:64])


class V1FrameDecryptor:
    """Stateful decryptor for v1 backup frame stream.

    Manages the counter that increments per frame/attachment and
    provides methods to decrypt frames and inline attachment data.
    """

    def __init__(self, cipher_key: bytes, mac_key: bytes, iv: bytes, version: int = 0) -> None:
        if len(iv) != 16:
            raise ValueError(f"IV must be 16 bytes, got {len(iv)}")
        self._cipher_key = cipher_key
        self._mac_key = mac_key
        self._iv = bytearray(iv)
        self._counter = int.from_bytes(iv[:4], "big")
        self._version = version

    def _bump_counter(self) -> bytes:
        """Increment counter and write it into IV[0:4]. Returns updated IV."""
        self._iv[:4] = self._counter.to_bytes(4, "big")
        self._counter += 1
        return bytes(self._iv)

    def _make_cipher(self) -> Cipher:
        iv = self._bump_counter()
        return Cipher(algorithms.AES(self._cipher_key), modes.CTR(iv))

    def _verify_mac(self, data: bytes, expected: bytes) -> None:
        mac = hmac_mod.new(self._mac_key, digestmod=hashlib.sha256)
        mac.update(data)
        our_mac = mac.digest()[:HMAC_TRUNCATED_SIZE]
        if not hmac_mod.compare_digest(our_mac, expected):
            raise ValueError("HMAC verification failed — wrong passphrase or corrupt data")

    def read_frame(self, stream: BinaryIO) -> bytes:
        """Read and decrypt one frame from the stream. Returns plaintext protobuf bytes."""
        frame_length = self._read_frame_length(stream)
        if frame_length <= 0:
            raise ValueError(f"Invalid frame length: {frame_length}")

        frame_data = _read_fully(stream, frame_length)

        their_mac = frame_data[-HMAC_TRUNCATED_SIZE:]
        encrypted = frame_data[:-HMAC_TRUNCATED_SIZE]

        self._verify_mac(encrypted, their_mac)

        cipher = Cipher(algorithms.AES(self._cipher_key), modes.CTR(bytes(self._iv)))
        # Don't bump again — _read_frame_length already bumped
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(encrypted) + decryptor.finalize()

        return plaintext

    def _read_frame_length(self, stream: BinaryIO) -> int:
        """Read 4-byte frame length, decrypting if version >= 1."""
        length_bytes = _read_fully(stream, 4)
        cipher = self._make_cipher()

        if self._version >= 1:
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(length_bytes) + decryptor.finalize()
            return int.from_bytes(decrypted, "big")
        else:
            return int.from_bytes(length_bytes, "big")

    def read_attachment(self, stream: BinaryIO, length: int) -> bytes:
        """Read and decrypt inline attachment data from the stream."""
        cipher = self._make_cipher()
        decryptor = cipher.decryptor()

        mac = hmac_mod.new(self._mac_key, digestmod=hashlib.sha256)
        mac.update(bytes(self._iv))  # Attachments MAC the IV

        buf = bytearray()
        remaining = length
        while remaining > 0:
            chunk_size = min(8192, remaining)
            chunk = _read_fully(stream, chunk_size)
            mac.update(chunk)
            plaintext = decryptor.update(chunk)
            if plaintext:
                buf.extend(plaintext)
            remaining -= len(chunk)

        final = decryptor.finalize()
        if final:
            buf.extend(final)

        our_mac = mac.digest()[:HMAC_TRUNCATED_SIZE]
        their_mac = _read_fully(stream, HMAC_TRUNCATED_SIZE)
        if not hmac_mod.compare_digest(our_mac, their_mac):
            raise ValueError("Attachment HMAC verification failed")

        return bytes(buf)


def _read_fully(stream: BinaryIO, n: int) -> bytes:
    """Read exactly n bytes from stream, raising on short read."""
    data = stream.read(n)
    if data is None or len(data) != n:
        raise ValueError(f"Short read: expected {n} bytes, got {len(data) if data else 0}")
    return data
