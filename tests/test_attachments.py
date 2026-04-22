"""Test the attachment encrypt/decrypt pipeline."""

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from signal_ark.mapper import decrypt_desktop_attachment, encrypt_attachment


def _make_desktop_encrypted_file(
    plaintext: bytes, local_key: bytes, pad_to_boundary: int = 1024
) -> bytes:
    """Simulate Desktop's at-rest encryption: zero-pad + AES-CBC + HMAC."""
    padded_pt = plaintext + b"\x00" * (pad_to_boundary - len(plaintext) % pad_to_boundary)

    aes_key = local_key[:32]
    hmac_key = local_key[32:]
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    pkcs_padded = padder.update(padded_pt) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(pkcs_padded) + enc.finalize()

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(iv)
    h.update(ct)
    mac = h.finalize()

    return iv + ct + mac


def test_decrypt_desktop_attachment() -> None:
    original = os.urandom(5000)
    desktop_key = os.urandom(64)

    encrypted = _make_desktop_encrypted_file(original, desktop_key)
    decrypted = decrypt_desktop_attachment(encrypted, desktop_key, len(original))

    assert decrypted == original


def test_encrypt_attachment_with_desktop_decryption(tmp_path: Path) -> None:
    """Full pipeline: Desktop-encrypted file → decrypt → re-encrypt → verify."""
    original = b"\xff\xd8\xff\xe0" + os.urandom(4096)
    desktop_key = os.urandom(64)
    plaintext_hash = hashlib.sha256(original).hexdigest()

    encrypted_on_disk = _make_desktop_encrypted_file(original, desktop_key)
    src = tmp_path / "af" / "somefile"
    src.parent.mkdir()
    src.write_bytes(encrypted_on_disk)

    output_dir = tmp_path / "backup_files"
    result = encrypt_attachment(
        src,
        output_dir,
        db_plaintext_hash=plaintext_hash,
        desktop_local_key=desktop_key,
        plaintext_size=len(original),
    )

    assert result is not None
    local_key_b64, media_name = result

    import base64
    backup_key = base64.b64decode(local_key_b64)
    aes_key = backup_key[:32]
    hmac_key = backup_key[32:]

    shard = media_name[:2]
    enc_file = output_dir / shard / media_name
    assert enc_file.exists()

    enc_data = enc_file.read_bytes()
    iv = enc_data[:16]
    mac = enc_data[-32:]
    ct = enc_data[16:-32]

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(iv)
    h.update(ct)
    h.verify(mac)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    recovered = unpadder.update(padded) + unpadder.finalize()

    assert recovered == original
    assert hashlib.sha256(recovered).hexdigest() == plaintext_hash


def test_encrypt_attachment_plaintext_file(tmp_path: Path) -> None:
    """Older Desktop versions with plaintext files on disk (no desktop_local_key)."""
    original = os.urandom(3000)
    src = tmp_path / "plainfile"
    src.write_bytes(original)

    output_dir = tmp_path / "backup_files"
    result = encrypt_attachment(src, output_dir)

    assert result is not None
    local_key_b64, media_name = result

    expected_hash = hashlib.sha256(original).digest()
    import base64
    backup_key = base64.b64decode(local_key_b64)
    expected_media = hashlib.sha256(expected_hash + backup_key).hexdigest()
    assert media_name == expected_media
