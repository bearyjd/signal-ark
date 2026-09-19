"""Map Signal Desktop SQLite data to v2 backup archive frames.

Reference: signalbackup-tools/signalbackup/importfromdesktop.cc
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from signal_ark.proto.Backup_pb2 import (
    AccountData,
    BackupInfo,
    ChatItem,
    Contact,
    FilePointer,
    Frame,
    Group,
    GroupCall,
    IndividualCall,
    MessageAttachment,
    Quote,
    Reaction,
    Self as SelfRecipient,
    SendStatus,
    StandardMessage,
)

# Body limits enforced by libsignal (message-backup/src/backup/chat/text.rs)
MAX_BODY_BYTES = 128 * 1024
MAX_BODY_BYTES_WITH_LONG_TEXT = 2 * 1024
MAX_QUOTE_BODY_BYTES = 2 * 1024
LONG_TEXT_CONTENT_TYPE = "text/x-signal-plain"

_KNOWN_TABLES = frozenset({"conversations", "messages", "message_attachments", "callsHistory"})


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

    def alias_service_id(self, service_id: str, rid: int) -> None:
        self.service_id_to_recipient[service_id] = rid

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
    try:
        return base64.b64decode(b64)
    except (binascii.Error, ValueError):
        return b""


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return default


def _trim_utf8(text: str, max_bytes: int) -> str:
    """Trim text to at most max_bytes of UTF-8 without splitting a codepoint."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _resolve_recipient_id(ids: IdAllocator, identifier: str | None) -> int:
    """Resolve a Desktop identifier to a backup recipient ID."""
    if not identifier:
        return 0
    return (
        ids.service_id_to_recipient.get(identifier)
        or ids.conversation_to_recipient.get(identifier)
        or 0
    )


def _map_reactions(msg_json: dict, ids: IdAllocator) -> list[Reaction]:
    """Extract reactions from Desktop message JSON."""
    reactions_data = msg_json.get("reactions")
    if not reactions_data:
        return []

    result = []
    for r in reactions_data:
        emoji = r.get("emoji")
        author_id = _resolve_recipient_id(ids, r.get("fromId"))
        if not emoji or not author_id:
            continue
        reaction = Reaction()
        reaction.emoji = emoji
        reaction.authorId = author_id
        sent_ts = r.get("timestamp") or 0
        reaction.sentTimestamp = sent_ts
        reaction.sortOrder = r.get("receivedAtDate") or sent_ts
        result.append(reaction)

    return result


def _map_quote(msg_json: dict, ids: IdAllocator) -> Quote | None:
    """Extract quote from Desktop message JSON.

    Drops the quote when the author cannot be resolved or when it carries
    neither text nor attachments (both are rejected by the backup validator).
    """
    quote_data = msg_json.get("quote")
    if not quote_data:
        return None

    author_id = _resolve_recipient_id(
        ids, quote_data.get("authorAci") or quote_data.get("authorUuid")
    )
    if not author_id:
        return None

    quote = Quote()
    quote.authorId = author_id

    target_ts = _to_int(quote_data.get("id"))
    if target_ts and not quote_data.get("referencedMessageNotFound"):
        quote.targetSentTimestamp = target_ts

    text = quote_data.get("text")
    if text:
        quote.text.body = _trim_utf8(text, MAX_QUOTE_BODY_BYTES)

    for att in quote_data.get("attachments") or []:
        quoted = quote.attachments.add()
        if att.get("contentType"):
            quoted.contentType = att["contentType"]
        if att.get("fileName"):
            quoted.fileName = att["fileName"]

    if not quote.HasField("text") and not quote.attachments:
        return None

    quote.type = Quote.Type.NORMAL
    return quote


def build_account_frame(seed_account: AccountData) -> Frame:
    """Use the seed backup's AccountData as-is (has correct registration info)."""
    frame = Frame()
    frame.account.CopyFrom(seed_account)
    return frame


def build_self_recipient(
    ids: IdAllocator,
    self_conversation_id: str,
    self_aci: str | None = None,
) -> Frame:
    """Build the Self recipient frame.

    Registers the recipient under both the "__self__" placeholder and the
    real ACI so quotes/reactions authored by us resolve to this recipient.
    """
    rid = ids.alloc_recipient(self_conversation_id, service_id="__self__")
    if self_aci:
        ids.alias_service_id(self_aci, rid)
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
    profile_key = _b64_to_bytes(conv.get("profileKey"))
    if profile_key:
        contact.profileKey = profile_key

    contact.profileSharing = bool(conv.get("profileSharing"))
    contact.profileGivenName = conv.get("profileName") or ""
    contact.profileFamilyName = conv.get("profileFamilyName") or ""
    contact.systemGivenName = conv.get("systemGivenName") or ""
    contact.systemFamilyName = conv.get("systemFamilyName") or ""

    # Identity key
    identity_key = _b64_to_bytes(conv.get("identityKey"))
    if identity_key:
        contact.identityKey = identity_key

    # Registration status
    contact.registered.CopyFrom(Contact.Registered())

    # Blocked
    contact.blocked = bool(conv.get("isBlocked"))

    return frame


def _map_story_send_mode(mode_str: str | None) -> int:
    if mode_str == "Never":
        return Group.StorySendMode.DISABLED
    if mode_str == "Always":
        return Group.StorySendMode.ENABLED
    return Group.StorySendMode.DEFAULT


def build_group_recipient(
    ids: IdAllocator,
    conv: dict,
    conv_id: str,
) -> Frame | None:
    """Build a Group recipient frame from a Desktop group conversation."""
    master_key = _b64_to_bytes(conv.get("masterKey"))
    if not master_key:
        return None

    rid = ids.alloc_recipient(conv_id)

    frame = Frame()
    frame.recipient.id = rid

    group = frame.recipient.group
    group.masterKey = master_key
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

    # Message body, reactions, and quote. Reactions alone don't make a valid
    # StandardMessage; attachments may still be added later.
    body = msg_row.get("body")
    quote = _map_quote(msg_json, ids)

    if body or quote:
        std_msg = StandardMessage()
        if body:
            std_msg.text.body = _trim_utf8(body, MAX_BODY_BYTES)
        if quote:
            std_msg.quote.CopyFrom(quote)
        std_msg.reactions.extend(_map_reactions(msg_json, ids))
        item.standardMessage.CopyFrom(std_msg)

    # Expiration
    expire_timer = msg_row.get("expireTimer")
    if expire_timer:
        item.expiresInMs = int(expire_timer) * 1000
    expire_start = msg_row.get("expirationStartTimestamp")
    if expire_start:
        item.expireStartDate = int(expire_start)

    return frame


_CALL_TYPES = {
    "Audio": IndividualCall.Type.AUDIO_CALL,
    "Video": IndividualCall.Type.VIDEO_CALL,
}
_CALL_DIRECTIONS = {
    "Incoming": IndividualCall.Direction.INCOMING,
    "Outgoing": IndividualCall.Direction.OUTGOING,
}
_INDIVIDUAL_CALL_STATES = {
    "Accepted": IndividualCall.State.ACCEPTED,
    "Declined": IndividualCall.State.NOT_ACCEPTED,
    "Missed": IndividualCall.State.MISSED,
    "MissedNotificationProfile": IndividualCall.State.MISSED_NOTIFICATION_PROFILE,
}
_GROUP_CALL_STATES = {
    "GenericGroupCall": GroupCall.State.GENERIC,
    "Joined": GroupCall.State.JOINED,
    "Ringing": GroupCall.State.RINGING,
    "Accepted": GroupCall.State.ACCEPTED,
    "Declined": GroupCall.State.DECLINED,
    "Missed": GroupCall.State.MISSED,
    "MissedNotificationProfile": GroupCall.State.MISSED_NOTIFICATION_PROFILE,
    "OutgoingRing": GroupCall.State.OUTGOING_RING,
}
_CALL_STATUS_DELETED = "Deleted"
_REMOTE_ATTACHMENT_KEY_SIZE = 64


def _normalize_legacy_call(details: dict, msg_row: dict | None) -> dict:
    """Convert pre-callsHistory ``callHistoryDetails`` JSON into the modern
    callsHistory row shape (mirrors Desktop migration 89-call-history)."""
    sent_at = (msg_row or {}).get("sent_at") or (msg_row or {}).get("timestamp") or 0

    if details.get("callMode") == "Group" or "startedTime" in details:
        return {
            "callId": details.get("callId"),
            "mode": "Group",
            "direction": "Incoming",
            "status": "GenericGroupCall",
            "timestamp": details.get("startedTime") or sent_at,
            "ringerId": details.get("creatorUuid"),
        }

    accepted_time = details.get("acceptedTime")
    if accepted_time is not None:
        status = "Accepted"
    elif details.get("wasDeclined"):
        status = "Declined"
    else:
        status = "Missed"

    return {
        "callId": details.get("callId"),
        "mode": "Direct",
        "type": "Video" if details.get("wasVideoCall") else "Audio",
        "direction": "Incoming" if details.get("wasIncoming") else "Outgoing",
        "status": status,
        "timestamp": accepted_time or details.get("endedTime") or sent_at,
        "ringerId": None,
    }


def _get_call_info(
    msg_json: dict,
    conn: sqlite3.Connection,
    has_calls_table: bool,
    msg_row: dict | None = None,
) -> dict | None:
    """Look up call details from callsHistory table or message JSON fallback."""
    call_id = msg_json.get("callId")
    if call_id and has_calls_table:
        row = conn.execute(
            "SELECT callId, peerId, ringerId, mode, type, direction, status, timestamp"
            " FROM callsHistory WHERE callId = ?",
            (str(call_id),),
        ).fetchone()
        if row:
            return dict(row)

    details = msg_json.get("callHistoryDetails")
    if not details:
        return None
    return _normalize_legacy_call(details, msg_row)


def _individual_call_state(status: str | None, direction: str | None) -> int:
    if status == "Pending":
        if direction == "Incoming":
            return IndividualCall.State.MISSED
        return IndividualCall.State.NOT_ACCEPTED
    return _INDIVIDUAL_CALL_STATES.get(status or "", IndividualCall.State.UNKNOWN_STATE)


def _set_call_id(call: IndividualCall | GroupCall, call_id: object) -> None:
    if call_id is None or call_id == "":
        return
    try:
        call.callId = int(call_id)
    except (ValueError, TypeError):
        pass


def _build_individual_call(call_info: dict) -> IndividualCall | None:
    direction = call_info.get("direction")
    call_type = _CALL_TYPES.get(call_info.get("type") or "", IndividualCall.Type.UNKNOWN_TYPE)
    call_direction = _CALL_DIRECTIONS.get(
        direction or "", IndividualCall.Direction.UNKNOWN_DIRECTION
    )
    state = _individual_call_state(call_info.get("status"), direction)
    # libsignal's validator rejects UNKNOWN_* on all three fields
    if not (call_type and call_direction and state):
        return None
    call = IndividualCall()
    _set_call_id(call, call_info.get("callId"))
    call.type = call_type
    call.direction = call_direction
    call.state = state
    call.startedCallTimestamp = _to_int(call_info.get("timestamp"))
    call.read = True
    return call


def _build_group_call(call_info: dict, ids: IdAllocator) -> GroupCall | None:
    state = _GROUP_CALL_STATES.get(call_info.get("status") or "", GroupCall.State.UNKNOWN_STATE)
    if not state:
        return None
    call = GroupCall()
    _set_call_id(call, call_info.get("callId"))
    call.state = state
    call.startedCallTimestamp = _to_int(call_info.get("timestamp"))
    ringer_rid = _resolve_recipient_id(ids, call_info.get("ringerId"))
    if ringer_rid:
        call.ringerRecipientId = ringer_rid
    call.read = True
    return call


def build_call_item(
    ids: IdAllocator,
    msg_row: dict,
    msg_json: dict,
    conn: sqlite3.Connection,
    has_calls_table: bool,
) -> Frame | None:
    """Build a ChatItem frame for a call-history message."""
    conv_id = msg_row["conversationId"]
    chat_id = ids.conversation_to_chat.get(conv_id)
    if chat_id is None:
        return None

    call_info = _get_call_info(msg_json, conn, has_calls_table, msg_row)
    if not call_info or call_info.get("status") == _CALL_STATUS_DELETED:
        return None

    mode = call_info.get("mode")
    if mode not in ("Direct", "Group"):
        return None

    call = (
        _build_individual_call(call_info)
        if mode == "Direct"
        else _build_group_call(call_info, ids)
    )
    if call is None:
        return None

    frame = Frame()
    item = frame.chatItem
    item.chatId = chat_id
    item.dateSent = msg_row.get("sent_at") or msg_row.get("timestamp") or 0
    item.authorId = ids.service_id_to_recipient.get("__self__", 0)
    item.directionless.CopyFrom(ChatItem.DirectionlessMessageDetails())

    if mode == "Direct":
        item.updateMessage.individualCall.CopyFrom(call)
    else:
        item.updateMessage.groupCall.CopyFrom(call)

    return frame


def _has_table(conn: sqlite3.Connection, table_name: str) -> bool:
    """Check if a table exists in the SQLite database."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _has_column(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    """Check if a column exists on a table (Desktop schemas vary by version)."""
    if table_name not in _KNOWN_TABLES:
        raise ValueError(f"unknown table {table_name!r}")
    columns = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(col[1] == column_name for col in columns)


def _collect_modern_attachments(conn: sqlite3.Connection) -> list[dict]:
    """Read attachment rows from the message_attachments table (newer Desktop)."""
    key_column = "ma.key" if _has_column(conn, "message_attachments", "key") else "NULL AS key"
    rows = conn.execute(f"""
        SELECT ma.messageId, ma.contentType, ma.path, ma.size,
               ma.width, ma.height, ma.fileName, ma.plaintextHash,
               ma.blurHash, ma.caption, ma.localKey, {key_column}, m.sent_at, m.json
        FROM message_attachments ma
        JOIN messages m ON m.id = ma.messageId
        WHERE ma.path IS NOT NULL
        AND m.type IN ('incoming', 'outgoing')
        ORDER BY m.sent_at ASC
    """).fetchall()
    return [dict(r) for r in rows]


def _collect_legacy_attachments(conn: sqlite3.Connection) -> list[dict]:
    """Parse attachment info from message JSON for older Desktop versions."""
    messages = conn.execute("""
        SELECT m.id, m.sent_at, m.json
        FROM messages m
        WHERE m.type IN ('incoming', 'outgoing')
        AND m.json LIKE '%"attachments"%'
        ORDER BY m.sent_at ASC
    """).fetchall()

    result = []
    for msg in messages:
        msg_json = json.loads(msg["json"] or "{}")
        for att in msg_json.get("attachments") or []:
            path = att.get("path")
            if not path:
                continue
            result.append({
                "messageId": msg["id"],
                "contentType": att.get("contentType"),
                "path": path,
                "size": att.get("size"),
                "width": att.get("width"),
                "height": att.get("height"),
                "fileName": att.get("fileName"),
                "plaintextHash": att.get("plaintextHash"),
                "blurHash": att.get("blurHash"),
                "caption": att.get("caption"),
                "localKey": att.get("localKey"),
                "key": att.get("key"),
                "sent_at": msg["sent_at"],
                "json": msg["json"],
            })

    return result


def _drop_empty_chat_items(frames: list[Frame]) -> tuple[list[Frame], int]:
    """Return frames without item-less ChatItems, plus how many were dropped."""
    kept = [
        f for f in frames
        if not (f.HasField("chatItem") and f.chatItem.WhichOneof("item") is None)
    ]
    return kept, len(frames) - len(kept)


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
        "plaintext_hash_mismatch": 0,
        "attachments_rejected_path": 0,
        "attachments_missing_file": 0,
        "attachments_orphaned": 0,
        "attachment_failures": 0,
        "long_text_without_body": 0,
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
    frames.append(build_self_recipient(ids, self_conv_id, self_aci))

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
        AND m.type IN ('incoming', 'outgoing', 'call-history')
    """, (self_conv_id,)).fetchall()

    for conv_row in active_conversations:
        conv_id = conv_row["id"]
        conv_json = json.loads(conv_row["json"])
        chat_frame = build_chat(ids, conv_id, conv_json)
        if chat_frame:
            frames.append(chat_frame)
            stats["chats"] += 1

    # 6. Build chat items from messages (ordered by received timestamp)
    has_calls_table = _has_table(conn, "callsHistory")

    messages = conn.execute("""
        SELECT m.id, m.body, m.type, m.sent_at, m.received_at, m.received_at_ms,
               m.timestamp, m.conversationId, m.sourceServiceId, m.serverTimestamp,
               m.readStatus, m.unidentifiedDeliveryReceived, m.expireTimer,
               m.expirationStartTimestamp, m.json
        FROM messages m
        WHERE m.type IN ('incoming', 'outgoing', 'call-history')
        ORDER BY m.received_at ASC, m.sent_at ASC
    """).fetchall()

    message_frame_index: dict[str, int] = {}
    for msg_row in messages:
        msg_dict = dict(msg_row)
        msg_json = json.loads(msg_dict.get("json") or "{}")

        if msg_dict.get("type") == "call-history":
            result_frame = build_call_item(ids, msg_dict, msg_json, conn, has_calls_table)
        else:
            result_frame = build_chat_item(ids, msg_dict, msg_json)

        if result_frame:
            message_frame_index[msg_dict["id"]] = len(frames)
            frames.append(result_frame)
            stats["messages"] += 1
        else:
            stats["skipped_messages"] += 1

    # 7. Handle attachments (if output dir provided)
    if output_files_dir:
        output_files_dir.mkdir(parents=True, exist_ok=True)

        if _has_table(conn, "message_attachments"):
            attachments = _collect_modern_attachments(conn)
        else:
            attachments = _collect_legacy_attachments(conn)

        media_names = _process_attachments(
            attachments,
            attachments_dir,
            output_files_dir,
            frames,
            message_frame_index,
            ids,
            stats,
        )

    conn.close()

    # 8. Drop ChatItems that ended up with no content (no body, no quote,
    # no attachment on disk) — an item-less ChatItem fails validation.
    frames, dropped = _drop_empty_chat_items(frames)
    stats["messages"] -= dropped
    stats["skipped_messages"] += dropped

    # 9. Append chat folders at the end (must come after recipients and chats)
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
