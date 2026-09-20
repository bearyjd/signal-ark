"""Desktop attachment decryption, backup content-store encryption, and FilePointer wiring."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import NamedTuple

from signal_ark.mapping.chats import _map_reactions
from signal_ark.mapping.ids import IdAllocator
from signal_ark.mapping.util import (
    LONG_TEXT_CONTENT_TYPE,
    MAX_BODY_BYTES_WITH_LONG_TEXT,
    _b64_to_bytes,
    _to_int,
    _trim_utf8,
)
from signal_ark.proto.Backup_pb2 import (
    FilePointer,
    Frame,
    MessageAttachment,
    StandardMessage,
)

_REMOTE_ATTACHMENT_KEY_SIZE = 64


def _resolve_attachment_source(attachments_dir: Path, rel_path: str | None) -> Path | None:
    """Resolve a DB-supplied attachment path, refusing anything that escapes
    attachments_dir (absolute paths, `..` traversal, symlinks pointing out)."""
    if not rel_path or Path(rel_path).is_absolute():
        return None
    root = attachments_dir.resolve()
    candidate = (attachments_dir / rel_path).resolve()
    if not candidate.is_relative_to(root):
        return None
    return candidate


def _is_long_text(att: dict) -> bool:
    return att.get("contentType") == LONG_TEXT_CONTENT_TYPE


def _has_text_body(frame: Frame) -> bool:
    item = frame.chatItem
    return item.HasField("standardMessage") and item.standardMessage.HasField("text")


def _encrypt_attachment_row(
    att: dict, src_path: Path, output_files_dir: Path
) -> EncryptedAttachment | None:
    """Encrypt one collected attachment row; a localKey that is present but
    undecodable is a failure, not a plaintext file."""
    local_key_b64 = att.get("localKey")
    desktop_key = _b64_to_bytes(local_key_b64) or None
    plaintext_size = _to_int(att.get("size")) or None
    if local_key_b64 and (desktop_key is None or plaintext_size is None):
        return None
    return encrypt_attachment(
        src_path,
        output_files_dir,
        db_plaintext_hash=att.get("plaintextHash"),
        desktop_local_key=desktop_key,
        plaintext_size=plaintext_size,
    )


def _process_attachments(
    attachments: list[dict],
    attachments_dir: Path,
    output_files_dir: Path,
    frames: list[Frame],
    frame_index: dict[str, int],
    ids: IdAllocator,
    stats: dict[str, int],
) -> list[str]:
    """Encrypt every attachment that binds to an emitted ChatItem and attach
    its FilePointer; returns the mediaNames written to output_files_dir."""
    media_names: list[str] = []
    for att in attachments:
        target = _find_attachment_target(frames, att, frame_index)
        if target is None:
            stats["attachments_orphaned"] += 1
            continue
        if _is_long_text(att) and not _has_text_body(target):
            stats["long_text_without_body"] += 1
            continue
        src_path = _resolve_attachment_source(attachments_dir, att.get("path"))
        if src_path is None:
            stats["attachments_rejected_path"] += 1
            continue
        if not src_path.exists():
            stats["attachments_missing_file"] += 1
            continue

        result = _encrypt_attachment_row(att, src_path, output_files_dir)
        if result is None:
            stats["attachment_failures"] += 1
            continue

        media_names.append(result.media_name)
        stats["attachments"] += 1
        if result.plaintext_hash_mismatch:
            stats["plaintext_hash_mismatch"] += 1
        _attach_file_pointer_to_message(
            target, att, result.local_key_b64, ids, plaintext_hash=result.plaintext_hash
        )
    return media_names


def decrypt_desktop_attachment(
    encrypted_bytes: bytes,
    desktop_local_key: bytes,
    plaintext_size: int,
) -> bytes:
    """Decrypt a Desktop attachment encrypted at rest.

    Desktop encrypts with [IV 16][AES-256-CBC, PKCS7][HMAC-SHA256 32] and
    zero-pads plaintext to a block boundary. Truncate to plaintext_size to
    recover the original file.
    """
    from cryptography.hazmat.primitives import hashes, hmac, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv = encrypted_bytes[:16]
    mac = encrypted_bytes[-32:]
    ct = encrypted_bytes[16:-32]

    aes_key = desktop_local_key[:32]
    hmac_key = desktop_local_key[32:]

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(iv)
    h.update(ct)
    h.verify(mac)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext[:plaintext_size]


class EncryptedAttachment(NamedTuple):
    local_key_b64: str
    media_name: str
    plaintext_hash: bytes
    plaintext_hash_mismatch: bool


def _db_hash_disagrees(db_plaintext_hash: str | None, computed: bytes) -> bool:
    """True when Desktop's recorded plaintextHash is absent-but-set, malformed,
    or differs from the hash of the bytes actually read. The computed hash
    always wins: it is what mediaName and the FilePointer must agree on."""
    if not db_plaintext_hash:
        return False
    try:
        return bytes.fromhex(db_plaintext_hash) != computed
    except ValueError:
        return True


def encrypt_attachment(
    src_path: Path,
    output_files_dir: Path,
    db_plaintext_hash: str | None = None,
    desktop_local_key: bytes | None = None,
    plaintext_size: int | None = None,
) -> EncryptedAttachment | None:
    """Encrypt an attachment file for the backup content store.

    If desktop_local_key and plaintext_size are provided, the file is first
    decrypted (Desktop stores attachments encrypted at rest) before
    re-encrypting for the backup.

    Returns the backup localKey, the mediaName, the plaintextHash the
    mediaName was derived from (the FilePointer must carry the same hash),
    and whether Desktop's recorded plaintextHash disagreed with it; or None
    on failure.
    """
    from cryptography.hazmat.primitives import hashes, hmac, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    try:
        file_bytes = src_path.read_bytes()
    except OSError:
        return None

    if desktop_local_key is not None and plaintext_size is not None:
        try:
            file_bytes = decrypt_desktop_attachment(
                file_bytes, desktop_local_key, plaintext_size
            )
        except Exception:
            return None

    plaintext_hash = hashlib.sha256(file_bytes).digest()
    hash_mismatch = _db_hash_disagrees(db_plaintext_hash, plaintext_hash)

    # Generate random 64-byte local key (32 AES + 32 HMAC)
    local_key = os.urandom(64)
    aes_key = local_key[:32]
    hmac_key = local_key[32:]

    # Encrypt: IV + AES-256-CBC(plaintext) + HMAC-SHA256
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(file_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(iv)
    h.update(ciphertext)
    mac = h.finalize()

    encrypted = iv + ciphertext + mac

    # Media name = SHA256(plaintextHash || localKey)
    media_name = hashlib.sha256(plaintext_hash + local_key).hexdigest()

    # Write to sharded directory
    shard = media_name[:2]
    shard_dir = output_files_dir / shard
    shard_dir.mkdir(parents=True, exist_ok=True)
    (shard_dir / media_name).write_bytes(encrypted)

    local_key_b64 = base64.b64encode(local_key).decode()
    return EncryptedAttachment(local_key_b64, media_name, plaintext_hash, hash_mismatch)


def _is_attachable_chat_item(frame: Frame) -> bool:
    return (
        frame.HasField("chatItem")
        and frame.chatItem.WhichOneof("item") in (None, "standardMessage")
    )


def _find_attachment_target(
    frames: list[Frame],
    att: dict,
    frame_index: dict[str, int],
) -> Frame | None:
    """Locate the ChatItem an attachment belongs to by exact message id.

    Rows whose message was never emitted (group chats, dropped messages)
    return None: binding by dateSent could attach them to the wrong item.
    """
    message_id = att.get("messageId")
    if message_id is None:
        return None
    idx = frame_index.get(message_id)
    if idx is None or not _is_attachable_chat_item(frames[idx]):
        return None
    return frames[idx]


def _remote_attachment_key(desktop_key_b64: str | None) -> bytes:
    """Desktop's remote attachment key if it is well-formed and 64 bytes,
    otherwise a fresh one (as Signal generates for a never-uploaded file)."""
    key = _b64_to_bytes(desktop_key_b64)
    if len(key) == _REMOTE_ATTACHMENT_KEY_SIZE:
        return key
    return os.urandom(_REMOTE_ATTACHMENT_KEY_SIZE)


def _build_file_pointer(att: dict, local_key_b64: str, plaintext_hash: bytes) -> FilePointer:
    """Build a FilePointer whose LocatorInfo libsignal accepts.

    A LocatorInfo with a plaintextHash must also carry the 64-byte remote
    attachment key (libsignal `LocatorError::MissingKey`); Desktop stores it
    as base64 `key`, and a fresh one is generated when Desktop has none, as
    Signal does for a never-uploaded attachment.
    """
    fp = FilePointer()

    if att.get("contentType"):
        fp.contentType = att["contentType"]
    if att.get("fileName"):
        fp.fileName = att["fileName"]
    width = _to_int(att.get("width"))
    if width:
        fp.width = width
    height = _to_int(att.get("height"))
    if height:
        fp.height = height
    if att.get("caption"):
        fp.caption = att["caption"]
    if att.get("blurHash"):
        fp.blurHash = att["blurHash"]
    size = _to_int(att.get("size"))
    if size:
        fp.locatorInfo.size = size

    fp.locatorInfo.plaintextHash = plaintext_hash
    fp.locatorInfo.key = _remote_attachment_key(att.get("key"))
    fp.locatorInfo.localKey = _b64_to_bytes(local_key_b64)
    return fp


def _build_message_attachment(
    att: dict, local_key_b64: str, plaintext_hash: bytes
) -> MessageAttachment:
    ma = MessageAttachment()
    ma.pointer.CopyFrom(_build_file_pointer(att, local_key_b64, plaintext_hash))
    ma.wasDownloaded = True
    return ma


def _attach_long_text(
    std_msg: StandardMessage, att: dict, local_key_b64: str, plaintext_hash: bytes
) -> None:
    """Route a text/x-signal-plain attachment to StandardMessage.longText and
    shorten the inline body to what libsignal allows alongside it."""
    std_msg.longText.CopyFrom(_build_file_pointer(att, local_key_b64, plaintext_hash))
    std_msg.text.body = _trim_utf8(std_msg.text.body, MAX_BODY_BYTES_WITH_LONG_TEXT)


def _attach_file_pointer_to_message(
    frame: Frame,
    att: dict,
    local_key_b64: str,
    ids: IdAllocator,
    *,
    plaintext_hash: bytes,
) -> None:
    """Add this attachment's FilePointer to the ChatItem frame it belongs to.

    Long-text attachments need an existing text body and are otherwise
    ignored. When the target has no StandardMessage yet (body-less message),
    one is created carrying the message's reactions, which build_chat_item
    had to leave out.
    """
    item = frame.chatItem
    if _is_long_text(att):
        if _has_text_body(frame):
            _attach_long_text(item.standardMessage, att, local_key_b64, plaintext_hash)
        return

    if not item.HasField("standardMessage"):
        std_msg = StandardMessage()
        std_msg.reactions.extend(_map_reactions(json.loads(att.get("json") or "{}"), ids))
        item.standardMessage.CopyFrom(std_msg)

    item.standardMessage.attachments.append(
        _build_message_attachment(att, local_key_b64, plaintext_hash)
    )
