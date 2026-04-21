"""Key derivation functions for Signal v2 backup format.

Implements the KDF chain from libsignal:
  AccountEntropyPool → BackupKey → BackupId → MessageBackupKey
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes
import hashlib
import hmac as _hmac

AEP_LENGTH = 64
AEP_CHARSET = set("0123456789abcdefghijklmnopqrstuvwxyz")

BACKUP_KEY_INFO = b"20240801_SIGNAL_BACKUP_KEY"
BACKUP_ID_INFO_PREFIX = b"20241024_SIGNAL_BACKUP_ID:"
MESSAGE_BACKUP_KEY_INFO_PREFIX = b"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"
MESSAGE_BACKUP_KEY_FS_INFO_PREFIX = b"20250708_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"
LOCAL_METADATA_KEY_INFO = b"20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY"
MEDIA_ID_INFO_PREFIX = b"20241007_SIGNAL_BACKUP_MEDIA_ID:"
MEDIA_ENCRYPTION_KEY_INFO_PREFIX = b"20241007_SIGNAL_BACKUP_ENCRYPT_MEDIA:"


def _hkdf_expand(ikm: bytes, info: bytes, length: int, salt: bytes | None = None) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def validate_aep(aep: str) -> str:
    aep = aep.lower().strip()
    if len(aep) != AEP_LENGTH:
        raise ValueError(f"AEP must be {AEP_LENGTH} characters, got {len(aep)}")
    if not all(c in AEP_CHARSET for c in aep):
        raise ValueError("AEP must contain only [0-9a-z]")
    return aep


def aep_to_backup_key(aep: str) -> bytes:
    aep = validate_aep(aep)
    return _hkdf_expand(aep.encode("utf-8"), BACKUP_KEY_INFO, 32)


def aci_to_service_id_binary(aci_hex: str) -> bytes:
    """Convert ACI UUID to variable-width service ID binary (raw 16 UUID bytes, no prefix)."""
    aci_hex = aci_hex.replace("-", "")
    if len(aci_hex) != 32:
        raise ValueError(f"ACI must be 16 bytes (32 hex chars), got {len(aci_hex)}")
    return bytes.fromhex(aci_hex)


def backup_key_to_backup_id(backup_key: bytes, aci: str) -> bytes:
    aci_binary = aci_to_service_id_binary(aci)
    info = BACKUP_ID_INFO_PREFIX + aci_binary
    return _hkdf_expand(backup_key, info, 16)


def backup_key_to_message_backup_key(
    backup_key: bytes,
    backup_id: bytes,
    forward_secrecy_token: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Derive MessageBackupKey (hmac_key, aes_key) from BackupKey + BackupId.

    Returns (hmac_key: 32 bytes, aes_key: 32 bytes).
    """
    if forward_secrecy_token is not None:
        info = MESSAGE_BACKUP_KEY_FS_INFO_PREFIX + backup_id
        salt = forward_secrecy_token
    else:
        info = MESSAGE_BACKUP_KEY_INFO_PREFIX + backup_id
        salt = None

    derived = _hkdf_expand(backup_key, info, 64, salt=salt)
    return derived[:32], derived[32:]


def backup_key_to_local_metadata_key(backup_key: bytes) -> bytes:
    return _hkdf_expand(backup_key, LOCAL_METADATA_KEY_INFO, 32)


def backup_key_to_media_id(backup_key: bytes, media_name: str) -> bytes:
    info = MEDIA_ID_INFO_PREFIX + media_name.encode("utf-8")
    return _hkdf_expand(backup_key, info, 15)


def backup_key_to_media_encryption_key(backup_key: bytes, media_id: bytes) -> tuple[bytes, bytes]:
    info = MEDIA_ENCRYPTION_KEY_INFO_PREFIX + media_id
    derived = _hkdf_expand(backup_key, info, 64)
    return derived[:32], derived[32:]
