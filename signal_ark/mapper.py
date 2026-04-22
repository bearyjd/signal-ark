"""Map Signal Desktop SQLite data to v2 backup archive frames.

Reference: signalbackup-tools/signalbackup/importfromdesktop.cc
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from signal_ark.proto.Backup_pb2 import (
    AccountData,
    BackupInfo,
    Chat,
    ChatItem,
    Contact,
    Frame,
    Group,
    Recipient,
    Self as SelfRecipient,
    StandardMessage,
    Text,
    FilePointer,
    MessageAttachment,
    SendStatus,
)


@dataclass
class IdAllocator:
    """Allocates unique IDs for recipients and chats."""
    _next_recipient_id: int = 1
    _next_chat_id: int = 1
    # Desktop conversation ID → our recipient ID
    conversation_to_recipient: dict[str, int] = field(default_factory=dict)
    # Desktop conversation ID → our chat ID
    conversation_to_chat: dict[str, int] = field(default_factory=dict)
    # serviceId (ACI) → recipient ID
    service_id_to_recipient: dict[str, int] = field(default_factory=dict)

    def alloc_recipient(self, conversation_id: str, service_id: str | None = None) -> int:
        rid = self._next_recipient_id
        self._next_recipient_id += 1
        self.conversation_to_recipient[conversation_id] = rid
        if service_id:
            self.service_id_to_recipient[service_id] = rid
        return rid

    def alloc_chat(self, conversation_id: str) -> int:
        cid = self._next_chat_id
        self._next_chat_id += 1
        self.conversation_to_chat[conversation_id] = cid
        return cid


def _uuid_str_to_bytes(uuid_str: str) -> bytes:
    """Convert UUID string to 16 raw bytes."""
    return bytes.fromhex(uuid_str.replace("-", ""))


def _b64_to_bytes(b64: str | None) -> bytes:
    if not b64:
        return b""
    return base64.b64decode(b64)


def build_account_frame(seed_account: AccountData) -> Frame:
    """Use the seed backup's AccountData as-is (has correct registration info)."""
    frame = Frame()
    frame.account.CopyFrom(seed_account)
    return frame


def build_self_recipient(ids: IdAllocator, self_conversation_id: str) -> Frame:
    """Build the Self recipient frame."""
    rid = ids.alloc_recipient(self_conversation_id, service_id="__self__")
    frame = Frame()
    frame.recipient.id = rid
    frame.recipient.self.CopyFrom(SelfRecipient())
    return frame


def build_contact_recipient(
    ids: IdAllocator,
    conv: dict,
    conv_id: str,
) -> Frame | None:
    """Build a Contact recipient frame from a Desktop conversation row."""
    service_id = conv.get("serviceId")
    if not service_id:
        return None

    rid = ids.alloc_recipient(conv_id, service_id=service_id)

    frame = Frame()
    frame.recipient.id = rid

    contact = frame.recipient.contact

    # ACI
    aci_str = service_id
    if aci_str and not aci_str.startswith("PNI:"):
        try:
            contact.aci = _uuid_str_to_bytes(aci_str)
        except ValueError:
            pass

    # PNI
    pni_str = conv.get("pni")
    if pni_str:
        if pni_str.startswith("PNI:"):
            pni_str = pni_str[4:]
        try:
            contact.pni = _uuid_str_to_bytes(pni_str)
        except ValueError:
            pass

    # E164
    e164 = conv.get("e164")
    if e164:
        e164_num = e164.replace("+", "")
        if e164_num.isdigit():
            contact.e164 = int(e164_num)

    # Profile
    profile_key = conv.get("profileKey")
    if profile_key:
        contact.profileKey = _b64_to_bytes(profile_key)

    contact.profileSharing = bool(conv.get("profileSharing"))
    contact.profileGivenName = conv.get("profileName") or ""
    contact.profileFamilyName = conv.get("profileFamilyName") or ""
    contact.systemGivenName = conv.get("systemGivenName") or ""
    contact.systemFamilyName = conv.get("systemFamilyName") or ""

    # Identity key
    identity_key = conv.get("identityKey")
    if identity_key:
        contact.identityKey = _b64_to_bytes(identity_key)

    # Registration status
    contact.registered.CopyFrom(Contact.Registered())

    # Blocked
    contact.blocked = bool(conv.get("isBlocked"))

    return frame


def _map_story_send_mode(mode_str: str | None) -> int:
    if mode_str == "Never":
        return 1  # DISABLED
    if mode_str == "Always":
        return 2  # ENABLED
    return 0  # DEFAULT


def build_group_recipient(
    ids: IdAllocator,
    conv: dict,
    conv_id: str,
) -> Frame | None:
    """Build a Group recipient frame from a Desktop group conversation."""
    master_key_b64 = conv.get("masterKey")
    if not master_key_b64:
        return None

    rid = ids.alloc_recipient(conv_id)

    frame = Frame()
    frame.recipient.id = rid

    group = frame.recipient.group
    group.masterKey = _b64_to_bytes(master_key_b64)
    group.whitelisted = bool(conv.get("profileSharing"))
    group.hideStory = bool(conv.get("hideStory"))
    group.storySendMode = _map_story_send_mode(conv.get("storySendMode"))
    group.blocked = bool(conv.get("isBlocked"))

    snapshot = group.snapshot
    snapshot.version = int(conv.get("revision") or 0)
    snapshot.announcements_only = bool(conv.get("announcementsOnly"))

    # Title
    name = conv.get("name")
    if name:
        snapshot.title.title = name

    # Disappearing messages timer
    expire_timer = conv.get("expireTimer")
    if expire_timer:
        snapshot.disappearingMessagesTimer.disappearingMessagesDuration = int(expire_timer)

    # Access control
    ac = conv.get("accessControl")
    if ac:
        snapshot.accessControl.attributes = int(ac.get("attributes", 0))
        snapshot.accessControl.members = int(ac.get("members", 0))
        snapshot.accessControl.addFromInviteLink = int(ac.get("addFromInviteLink", 0))

    # Members
    for m in conv.get("membersV2") or []:
        aci = m.get("aci")
        if not aci:
            continue
        member = snapshot.members.add()
        member.userId = _uuid_str_to_bytes(aci)
        member.role = int(m.get("role", 1))
        member.joinedAtVersion = int(m.get("joinedAtVersion", 0))

    return frame


def build_chat(ids: IdAllocator, conv_id: str, conv: dict) -> Frame | None:
    """Build a Chat frame from a Desktop conversation."""
    recipient_id = ids.conversation_to_recipient.get(conv_id)
    if recipient_id is None:
        return None

    chat_id = ids.alloc_chat(conv_id)

    frame = Frame()
    frame.chat.id = chat_id
    frame.chat.recipientId = recipient_id

    if conv.get("isArchived"):
        frame.chat.archived = True
    if conv.get("markedUnread"):
        frame.chat.markedUnread = True
    if conv.get("expireTimer"):
        frame.chat.expirationTimerMs = int(conv["expireTimer"]) * 1000
    if conv.get("expireTimerVersion"):
        frame.chat.expireTimerVersion = int(conv["expireTimerVersion"])
    if conv.get("muteExpiresAt"):
        frame.chat.muteUntilMs = int(conv["muteExpiresAt"])

    return frame


def build_chat_item(
    ids: IdAllocator,
    msg_row: dict,
    msg_json: dict,
) -> Frame | None:
    """Build a ChatItem frame from a Desktop message row."""
    conv_id = msg_row["conversationId"]
    chat_id = ids.conversation_to_chat.get(conv_id)
    if chat_id is None:
        return None

    msg_type = msg_row["type"]
    if msg_type not in ("incoming", "outgoing"):
        return None

    frame = Frame()
    item = frame.chatItem
    item.chatId = chat_id
    item.dateSent = msg_row.get("sent_at") or msg_row.get("timestamp") or 0

    if msg_type == "incoming":
        source_sid = msg_row.get("sourceServiceId")
        author_rid = ids.service_id_to_recipient.get(source_sid) if source_sid else None
        if author_rid is None:
            # Try to find by conversation
            author_rid = ids.conversation_to_recipient.get(conv_id, 0)
        item.authorId = author_rid

        incoming = item.incoming
        incoming.dateReceived = msg_row.get("received_at_ms") or msg_row.get("received_at") or 0
        server_ts = msg_row.get("serverTimestamp")
        if server_ts:
            incoming.dateServerSent = server_ts
        incoming.read = (msg_row.get("readStatus") or 0) >= 1
        incoming.sealedSender = bool(msg_row.get("unidentifiedDeliveryReceived"))

    elif msg_type == "outgoing":
        self_rid = ids.service_id_to_recipient.get("__self__", 0)
        item.authorId = self_rid

        outgoing = item.outgoing
        outgoing.dateReceived = msg_row.get("received_at_ms") or msg_row.get("received_at") or 0

        send_state = msg_json.get("sendStateByConversationId", {})
        for dest_conv_id, state in send_state.items():
            dest_rid = ids.conversation_to_recipient.get(dest_conv_id)
            if dest_rid is None:
                continue
            ss = SendStatus()
            ss.recipientId = dest_rid
            ss.timestamp = state.get("updatedAt", 0)
            status_str = state.get("status", "Sent")
            if status_str == "Delivered":
                ss.delivered.sealedSender = True
            elif status_str == "Read":
                ss.read.sealedSender = True
            elif status_str == "Viewed":
                ss.viewed.sealedSender = True
            elif status_str == "Sent":
                ss.sent.sealedSender = True
            else:
                ss.sent.sealedSender = False
            outgoing.sendStatus.append(ss)

    # Message body
    body = msg_row.get("body")
    if body:
        std_msg = StandardMessage()
        std_msg.text.body = body
        item.standardMessage.CopyFrom(std_msg)

    # Expiration
    expire_timer = msg_row.get("expireTimer")
    if expire_timer:
        item.expiresInMs = int(expire_timer) * 1000
    expire_start = msg_row.get("expirationStartTimestamp")
    if expire_start:
        item.expireStartDate = int(expire_start)

    return frame


@dataclass
class MappingResult:
    backup_info: BackupInfo
    frames: list[Frame]
    media_names: list[str]
    stats: dict[str, int]


def map_desktop_to_frames(
    db_path: Path,
    attachments_dir: Path,
    seed_backup_info: BackupInfo,
    seed_account_frame: Frame,
    seed_frames: list[Frame],
    self_aci: str,
    output_files_dir: Path | None = None,
    progress_callback: Callable[[str, int, int], None] | None = None,
) -> MappingResult:
    """Map Signal Desktop data to v2 backup frames.

    Args:
        db_path: Path to decrypted Desktop SQLite database
        attachments_dir: Path to Desktop's attachments.noindex/ directory
        seed_backup_info: BackupInfo from the seed backup
        seed_account_frame: AccountData frame from the seed backup
        seed_frames: All frames from the seed backup (for carrying over required frames)
        self_aci: Our own ACI UUID string
        output_files_dir: If provided, encrypt attachments here
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    ids = IdAllocator()
    frames: list[Frame] = []
    media_names: list[str] = []
    stats: dict[str, int] = {
        "recipients": 0,
        "chats": 0,
        "messages": 0,
        "attachments": 0,
        "skipped_messages": 0,
    }

    # 1. AccountData (from seed — has correct registration)
    frames.append(build_account_frame(seed_account_frame.account))

    # 2. Find self conversation and build Self recipient
    self_conv = conn.execute(
        "SELECT id FROM conversations WHERE serviceId = ? OR type = 'private' AND e164 IS NULL AND serviceId IS NULL",
        (self_aci,),
    ).fetchone()

    # Also check for "Note to Self" pattern
    if not self_conv:
        self_conv = conn.execute(
            "SELECT id FROM conversations WHERE type = 'private' AND serviceId = ?",
            (self_aci,),
        ).fetchone()

    self_conv_id = self_conv["id"] if self_conv else "__self_placeholder__"
    frames.append(build_self_recipient(ids, self_conv_id))

    # 2b. Carry over required seed frames (distribution lists, release notes, sticker packs)
    seed_chat_folders: list[Frame] = []
    for sf in seed_frames:
        item_type = sf.WhichOneof("item")
        if item_type == "recipient":
            dest = sf.recipient.WhichOneof("destination")
            if dest == "distributionList":
                frames.append(sf)
            elif dest == "releaseNotes":
                frames.append(sf)
        elif item_type == "stickerPack":
            frames.append(sf)
        elif item_type == "chatFolder":
            seed_chat_folders.append(sf)

    # 3. Build group recipients (prevents StorageSyncJob placeholder crash)
    group_conversations = conn.execute("""
        SELECT id, json
        FROM conversations
        WHERE type = 'group'
        ORDER BY active_at DESC
    """).fetchall()

    for conv_row in group_conversations:
        conv_json = json.loads(conv_row["json"])
        conv_id = conv_row["id"]
        group_frame = build_group_recipient(ids, conv_json, conv_id)
        if group_frame:
            frames.append(group_frame)
            stats["recipients"] += 1

    # 4. Build contact recipients from private conversations
    conversations = conn.execute("""
        SELECT id, json, active_at, type, e164, serviceId, profileName, profileFamilyName
        FROM conversations
        WHERE type = 'private' AND serviceId IS NOT NULL AND serviceId != ?
        ORDER BY active_at DESC
    """, (self_aci,)).fetchall()

    for conv_row in conversations:
        conv_json = json.loads(conv_row["json"])
        conv_id = conv_row["id"]
        recipient_frame = build_contact_recipient(ids, conv_json, conv_id)
        if recipient_frame:
            frames.append(recipient_frame)
            stats["recipients"] += 1

    # 5. Build chats for conversations that have messages
    active_conversations = conn.execute("""
        SELECT DISTINCT c.id, c.json
        FROM conversations c
        INNER JOIN messages m ON m.conversationId = c.id
        WHERE c.type = 'private' AND (c.serviceId IS NOT NULL OR c.id = ?)
        AND m.type IN ('incoming', 'outgoing')
    """, (self_conv_id,)).fetchall()

    for conv_row in active_conversations:
        conv_id = conv_row["id"]
        conv_json = json.loads(conv_row["json"])
        chat_frame = build_chat(ids, conv_id, conv_json)
        if chat_frame:
            frames.append(chat_frame)
            stats["chats"] += 1

    # 6. Build chat items from messages (ordered by received timestamp)
    messages = conn.execute("""
        SELECT m.id, m.body, m.type, m.sent_at, m.received_at, m.received_at_ms,
               m.timestamp, m.conversationId, m.sourceServiceId, m.serverTimestamp,
               m.readStatus, m.unidentifiedDeliveryReceived, m.expireTimer,
               m.expirationStartTimestamp, m.json
        FROM messages m
        WHERE m.type IN ('incoming', 'outgoing')
        ORDER BY m.received_at ASC, m.sent_at ASC
    """).fetchall()

    for msg_row in messages:
        msg_dict = dict(msg_row)
        msg_json = json.loads(msg_dict.get("json") or "{}")

        chat_item_frame = build_chat_item(ids, msg_dict, msg_json)
        if chat_item_frame:
            frames.append(chat_item_frame)
            stats["messages"] += 1
        else:
            stats["skipped_messages"] += 1

    # 7. Handle attachments (if output dir provided)
    if output_files_dir:
        output_files_dir.mkdir(parents=True, exist_ok=True)
        attachments = conn.execute("""
            SELECT ma.messageId, ma.contentType, ma.path, ma.size,
                   ma.width, ma.height, ma.fileName, ma.plaintextHash,
                   ma.blurHash, ma.caption, ma.localKey, m.sent_at
            FROM message_attachments ma
            JOIN messages m ON m.id = ma.messageId
            WHERE ma.path IS NOT NULL
            AND m.type IN ('incoming', 'outgoing')
            ORDER BY m.sent_at ASC
        """).fetchall()

        for att_row in attachments:
            att = dict(att_row)
            src_path = attachments_dir / att["path"]
            if not src_path.exists():
                continue

            desktop_key = _b64_to_bytes(att.get("localKey")) or None
            pt_size = int(att["size"]) if att.get("size") else None

            result = encrypt_attachment(
                src_path,
                output_files_dir,
                db_plaintext_hash=att.get("plaintextHash"),
                desktop_local_key=desktop_key,
                plaintext_size=pt_size,
            )
            if result:
                local_key_b64, media_name = result
                media_names.append(media_name)
                stats["attachments"] += 1

                _attach_file_pointer_to_message(
                    frames, att, local_key_b64, media_name, ids
                )

    conn.close()

    # 8. Append chat folders at the end (must come after recipients and chats)
    frames.extend(seed_chat_folders)

    # Use seed's BackupInfo with updated timestamp
    import time
    info = BackupInfo()
    info.CopyFrom(seed_backup_info)
    info.backupTimeMs = int(time.time() * 1000)

    return MappingResult(
        backup_info=info,
        frames=frames,
        media_names=media_names,
        stats=stats,
    )


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


def encrypt_attachment(
    src_path: Path,
    output_files_dir: Path,
    db_plaintext_hash: str | None = None,
    desktop_local_key: bytes | None = None,
    plaintext_size: int | None = None,
) -> tuple[str, str] | None:
    """Encrypt an attachment file for the backup content store.

    If desktop_local_key and plaintext_size are provided, the file is first
    decrypted (Desktop stores attachments encrypted at rest) before
    re-encrypting for the backup.

    Returns (localKey_base64, mediaName) or None on failure.
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
    if db_plaintext_hash:
        expected = bytes.fromhex(db_plaintext_hash)
        if plaintext_hash != expected:
            plaintext_hash = expected

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
    return local_key_b64, media_name


def _attach_file_pointer_to_message(
    frames: list[Frame],
    att: dict,
    local_key_b64: str,
    media_name: str,
    ids: IdAllocator,
) -> None:
    """Find the ChatItem frame for this attachment's message and add the FilePointer."""
    msg_sent_at = att.get("sent_at")
    if not msg_sent_at:
        return

    for frame in frames:
        if not frame.HasField("chatItem"):
            continue
        if frame.chatItem.dateSent != msg_sent_at:
            continue

        # Ensure it has a standardMessage
        if not frame.chatItem.HasField("standardMessage"):
            frame.chatItem.standardMessage.CopyFrom(StandardMessage())

        ma = MessageAttachment()
        fp = ma.pointer

        if att.get("contentType"):
            fp.contentType = att["contentType"]
        if att.get("fileName"):
            fp.fileName = att["fileName"]
        if att.get("width"):
            fp.width = int(att["width"])
        if att.get("height"):
            fp.height = int(att["height"])
        if att.get("caption"):
            fp.caption = att["caption"]
        if att.get("blurHash"):
            fp.blurHash = att["blurHash"]
        if att.get("size"):
            fp.locatorInfo.size = int(att["size"])
        if att.get("plaintextHash"):
            fp.locatorInfo.plaintextHash = bytes.fromhex(att["plaintextHash"])

        fp.locatorInfo.localKey = _b64_to_bytes(local_key_b64)

        ma.wasDownloaded = True

        frame.chatItem.standardMessage.attachments.append(ma)
        break
