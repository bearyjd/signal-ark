"""Convert a v1 backup to v2 backup frames.

Parses a v1 .backup file, replays the SQL into an in-memory SQLite DB,
maps recipients/chats/messages to v2 Frame protobufs, and re-encrypts
attachments for the v2 content store.

Reference: Signal-Android FullBackupImporter.java, mapper.py
"""

from __future__ import annotations

import logging
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from signal_ark.mapper import IdAllocator, encrypt_attachment
from signal_ark.proto.Backup_pb2 import (
    BackupInfo,
    Contact,
    Frame,
    Self as SelfRecipient,
    SendStatus,
    StandardMessage,
)
from signal_ark.v1_parser import (
    V1FrameType,
    parse_v1_backup,
)

log = logging.getLogger(__name__)

# v1 message type bitmask (from Signal Android MmsSmsColumns)
BASE_TYPE_MASK = 0x1F
INCOMING_MESSAGE_TYPE = 1  # received
OUTGOING_MESSAGE_TYPE = 2  # sent (various sub-types 21-26, but base is 2)


@dataclass(frozen=True)
class V1ImportResult:
    backup_info: BackupInfo
    frames: list[Frame]
    media_names: list[str]
    stats: dict[str, int]


def convert_v1_to_v2(
    v1_path: Path | str,
    v1_passphrase: str,
    seed_backup_info: BackupInfo,
    seed_account_frame: Frame,
    self_aci: str,
    output_files_dir: Path | None = None,
    progress_callback: Callable[[str, int, int], None] | None = None,
) -> V1ImportResult:
    """Convert a v1 backup to v2 frames.

    Requires a seed backup's BackupInfo and AccountData (for registration info
    that doesn't exist in v1 backups).
    """
    v1_path = Path(v1_path)
    frames_iter = parse_v1_backup(v1_path, v1_passphrase)

    # Collect attachments separately while building the DB
    attachment_index: dict[tuple[int, int], bytes] = {}  # (rowId, attachmentId) -> data
    avatar_data: dict[str, bytes] = {}  # recipientId/name -> data

    conn, parse_stats = _collect_with_attachments(frames_iter, attachment_index, avatar_data)

    if progress_callback:
        progress_callback("v1 parsed", parse_stats.total_frames, 0)

    ids = IdAllocator()
    frames: list[Frame] = []
    media_names: list[str] = []
    stats: dict[str, int] = {
        "recipients": 0,
        "chats": 0,
        "messages": 0,
        "attachments": 0,
        "skipped_messages": 0,
        "v1_sql_statements": parse_stats.statements,
        "v1_attachments": parse_stats.attachments,
    }

    # 1. AccountData from seed
    account_frame = Frame()
    account_frame.account.CopyFrom(seed_account_frame.account)
    frames.append(account_frame)

    # 2. Self recipient
    self_rid = ids.alloc_recipient("__self__", service_id="__self__")
    self_frame = Frame()
    self_frame.recipient.id = self_rid
    self_frame.recipient.self.CopyFrom(SelfRecipient())
    frames.append(self_frame)

    # 3. Map recipients
    _map_recipients(conn, ids, frames, stats)

    if progress_callback:
        progress_callback("recipients mapped", stats["recipients"], 0)

    # 4. Map chats (threads)
    _map_chats(conn, ids, frames, stats)

    # 5. Map messages (sms + mms)
    _map_messages(conn, ids, frames, stats, attachment_index, output_files_dir, media_names)

    if progress_callback:
        progress_callback("messages mapped", stats["messages"], stats["skipped_messages"])

    conn.close()

    # Build BackupInfo
    info = BackupInfo()
    info.CopyFrom(seed_backup_info)
    info.backupTimeMs = int(time.time() * 1000)

    return V1ImportResult(
        backup_info=info,
        frames=frames,
        media_names=media_names,
        stats=stats,
    )


def _collect_with_attachments(
    frames_iter,
    attachment_index: dict[tuple[int, int], bytes],
    avatar_data: dict[str, bytes],
):
    """Replay SQL statements and collect attachment data."""
    from signal_ark.v1_parser import V1BackupStats

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = OFF")
    stats_dict = {
        "total_frames": 0,
        "statements": 0,
        "preferences": 0,
        "attachments": 0,
        "stickers": 0,
        "avatars": 0,
        "key_values": 0,
    }

    for parsed in frames_iter:
        stats_dict["total_frames"] += 1

        if parsed.frame_type == V1FrameType.STATEMENT:
            stats_dict["statements"] += 1
            stmt = parsed.frame.statement
            if not stmt.HasField("statement"):
                continue
            sql = stmt.statement
            params = _extract_sql_params(stmt)
            try:
                conn.execute(sql, params)
            except Exception:
                pass
        elif parsed.frame_type == V1FrameType.ATTACHMENT:
            stats_dict["attachments"] += 1
            att = parsed.frame.attachment
            if parsed.attachment_data and att.HasField("rowId"):
                att_id = att.attachmentId if att.HasField("attachmentId") else 0
                attachment_index[(att.rowId, att_id)] = parsed.attachment_data
        elif parsed.frame_type == V1FrameType.AVATAR:
            stats_dict["avatars"] += 1
            av = parsed.frame.avatar
            if parsed.attachment_data:
                key = av.recipientId if av.HasField("recipientId") else av.name
                avatar_data[key] = parsed.attachment_data
        elif parsed.frame_type == V1FrameType.STICKER:
            stats_dict["stickers"] += 1
        elif parsed.frame_type == V1FrameType.PREFERENCE:
            stats_dict["preferences"] += 1
        elif parsed.frame_type == V1FrameType.KEY_VALUE:
            stats_dict["key_values"] += 1

    conn.commit()
    return conn, V1BackupStats(**stats_dict)


def _extract_sql_params(stmt) -> list:
    params = []
    for p in stmt.parameters:
        if p.HasField("stringParamter"):
            params.append(p.stringParamter)
        elif p.HasField("integerParameter"):
            params.append(p.integerParameter)
        elif p.HasField("doubleParameter"):
            params.append(p.doubleParameter)
        elif p.HasField("blobParameter"):
            params.append(bytes(p.blobParameter))
        elif p.HasField("nullparameter"):
            params.append(None)
        else:
            params.append(None)
    return params


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row[0] > 0


def _get_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        cursor = conn.execute(f"PRAGMA table_info({table})")
        return {row[1] for row in cursor.fetchall()}
    except Exception:
        return set()


def _map_recipients(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
) -> None:
    """Map v1 recipients to v2 Recipient frames."""
    if _table_exists(conn, "recipient"):
        _map_recipients_modern(conn, ids, frames, stats)
    elif _table_exists(conn, "recipient_preferences"):
        _map_recipients_legacy(conn, ids, frames, stats)
    else:
        log.warning("No recipient table found in v1 backup")


def _map_recipients_modern(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
) -> None:
    columns = _get_columns(conn, "recipient")

    id_col = "_id" if "_id" in columns else "id"
    has_aci = "aci" in columns or "uuid" in columns
    aci_col = "aci" if "aci" in columns else "uuid"
    has_e164 = "e164" in columns or "phone" in columns
    e164_col = "e164" if "e164" in columns else "phone"
    has_profile_key = "profile_key" in columns or "profileKey" in columns
    profile_key_col = "profile_key" if "profile_key" in columns else "profileKey"
    has_blocked = "blocked" in columns
    has_group_id = "group_id" in columns
    has_group_type = "group_type" in columns

    try:
        rows = conn.execute("SELECT * FROM recipient").fetchall()
    except Exception:
        return

    col_names = [desc[0] for desc in conn.execute("SELECT * FROM recipient LIMIT 0").description]

    for row in rows:
        r = dict(zip(col_names, row))
        v1_id = str(r.get(id_col, ""))
        if not v1_id:
            continue

        aci = r.get(aci_col) if has_aci else None
        e164 = r.get(e164_col) if has_e164 else None

        # Skip group recipients (handled separately if needed)
        if has_group_id and r.get("group_id"):
            group_type = r.get("group_type", 0) if has_group_type else 0
            if group_type and int(group_type) > 0:
                continue

        if not aci and not e164:
            continue

        rid = ids.alloc_recipient(v1_id, service_id=aci)

        frame = Frame()
        frame.recipient.id = rid

        contact = frame.recipient.contact

        if aci:
            try:
                contact.aci = bytes.fromhex(aci.replace("-", ""))
            except ValueError:
                pass

        if e164:
            e164_clean = e164.replace("+", "")
            if e164_clean.isdigit():
                contact.e164 = int(e164_clean)

        if has_profile_key and r.get(profile_key_col):
            import base64
            try:
                contact.profileKey = base64.b64decode(r[profile_key_col])
            except Exception:
                pass

        profile_name = r.get("profile_joined_name") or r.get("signal_profile_name") or ""
        if profile_name:
            contact.profileGivenName = profile_name

        contact.registered.CopyFrom(Contact.Registered())

        if has_blocked and r.get("blocked"):
            contact.blocked = bool(r["blocked"])

        frames.append(frame)
        stats["recipients"] += 1


def _map_recipients_legacy(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
) -> None:
    """Fallback for older schemas with recipient_preferences table."""
    try:
        rows = conn.execute("SELECT * FROM recipient_preferences").fetchall()
    except Exception:
        return

    col_names = [desc[0] for desc in conn.execute("SELECT * FROM recipient_preferences LIMIT 0").description]

    for row in rows:
        r = dict(zip(col_names, row))
        address = r.get("recipient_ids") or r.get("address") or ""
        if not address:
            continue

        rid = ids.alloc_recipient(address)

        frame = Frame()
        frame.recipient.id = rid

        contact = frame.recipient.contact

        if "+" in address and address.replace("+", "").replace("-", "").isdigit():
            e164_clean = address.replace("+", "").replace("-", "")
            contact.e164 = int(e164_clean)

        contact.registered.CopyFrom(Contact.Registered())

        if r.get("block"):
            contact.blocked = bool(r["block"])

        frames.append(frame)
        stats["recipients"] += 1


def _map_chats(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
) -> None:
    """Map v1 threads to v2 Chat frames."""
    if not _table_exists(conn, "thread"):
        return

    columns = _get_columns(conn, "thread")
    recipient_col = "recipient_id" if "recipient_id" in columns else "thread_recipient_id"
    has_recipient = recipient_col in columns

    # Fallback: use address-based matching
    has_address = "address" in columns or "recipient_ids" in columns

    try:
        rows = conn.execute("SELECT * FROM thread").fetchall()
    except Exception:
        return

    col_names = [desc[0] for desc in conn.execute("SELECT * FROM thread LIMIT 0").description]

    for row in rows:
        t = dict(zip(col_names, row))
        thread_id = str(t.get("_id", ""))

        # Find the recipient ID for this thread
        v1_recipient_id = None
        if has_recipient:
            v1_recipient_id = str(t.get(recipient_col, ""))
        elif has_address:
            v1_recipient_id = t.get("address") or t.get("recipient_ids")

        if not v1_recipient_id:
            continue

        recipient_id = ids.conversation_to_recipient.get(v1_recipient_id)
        if recipient_id is None:
            continue

        chat_id = ids.alloc_chat(thread_id)
        ids.conversation_to_recipient[thread_id] = recipient_id

        frame = Frame()
        frame.chat.id = chat_id
        frame.chat.recipientId = recipient_id

        if t.get("archived"):
            frame.chat.archived = bool(t["archived"])

        if t.get("expires_in") or t.get("message_expiry"):
            expire = t.get("expires_in") or t.get("message_expiry")
            if expire:
                frame.chat.expirationTimerMs = int(expire)

        frames.append(frame)
        stats["chats"] += 1


def _map_messages(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
    attachment_index: dict[tuple[int, int], bytes],
    output_files_dir: Path | None,
    media_names: list[str],
) -> None:
    """Map v1 sms + mms messages to v2 ChatItem frames."""
    if _table_exists(conn, "sms"):
        _map_sms_messages(conn, ids, frames, stats)
    if _table_exists(conn, "mms"):
        _map_mms_messages(conn, ids, frames, stats, attachment_index, output_files_dir, media_names)
    elif _table_exists(conn, "message"):
        _map_mms_messages(conn, ids, frames, stats, attachment_index, output_files_dir, media_names,
                          table="message")


def _map_sms_messages(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
) -> None:
    columns = _get_columns(conn, "sms")
    thread_col = "thread_id" if "thread_id" in columns else "address"

    try:
        rows = conn.execute(
            "SELECT * FROM sms ORDER BY date_received ASC, date ASC"
        ).fetchall()
    except Exception:
        try:
            rows = conn.execute("SELECT * FROM sms ORDER BY date ASC").fetchall()
        except Exception:
            return

    col_names = [desc[0] for desc in conn.execute("SELECT * FROM sms LIMIT 0").description]

    for row in rows:
        m = dict(zip(col_names, row))
        frame = _build_chat_item_from_v1(m, ids, thread_col)
        if frame:
            frames.append(frame)
            stats["messages"] += 1
        else:
            stats["skipped_messages"] += 1


def _map_mms_messages(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
    attachment_index: dict[tuple[int, int], bytes],
    output_files_dir: Path | None,
    media_names: list[str],
    table: str = "mms",
) -> None:
    columns = _get_columns(conn, table)
    thread_col = "thread_id" if "thread_id" in columns else "address"

    try:
        rows = conn.execute(
            f"SELECT * FROM {table} ORDER BY date_received ASC, date ASC"
        ).fetchall()
    except Exception:
        try:
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY date ASC").fetchall()
        except Exception:
            return

    col_names = [desc[0] for desc in conn.execute(f"SELECT * FROM {table} LIMIT 0").description]

    # Build attachment lookup: mms_id -> list of (rowId, attachmentId)
    att_lookup: dict[int, list[tuple[int, int]]] = {}
    if _table_exists(conn, "part"):
        try:
            parts = conn.execute("SELECT _id, mid, unique_id FROM part ORDER BY _id").fetchall()
            for p in parts:
                mid = p[1]
                att_lookup.setdefault(mid, []).append((p[0], p[2] if p[2] else 0))
        except Exception:
            pass

    for row in rows:
        m = dict(zip(col_names, row))
        frame = _build_chat_item_from_v1(m, ids, thread_col)
        if not frame:
            stats["skipped_messages"] += 1
            continue

        # Attach inline attachment data if available
        mms_id = m.get("_id")
        if mms_id and output_files_dir and mms_id in att_lookup:
            for row_id, att_id in att_lookup[mms_id]:
                att_data = attachment_index.get((row_id, att_id))
                if not att_data:
                    continue

                import tempfile
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(att_data)
                    tmp_path = Path(tmp.name)

                try:
                    result = encrypt_attachment(tmp_path, output_files_dir)
                    if result:
                        _, media_name = result
                        media_names.append(media_name)
                        stats["attachments"] += 1
                finally:
                    tmp_path.unlink(missing_ok=True)

        frames.append(frame)
        stats["messages"] += 1


def _build_chat_item_from_v1(
    msg: dict,
    ids: IdAllocator,
    thread_col: str,
) -> Frame | None:
    """Build a v2 ChatItem from a v1 sms/mms row."""
    thread_id = str(msg.get(thread_col, ""))
    chat_id = ids.conversation_to_chat.get(thread_id)
    if chat_id is None:
        return None

    msg_type = msg.get("type", 0)
    try:
        msg_type = int(msg_type)
    except (TypeError, ValueError):
        return None

    base_type = msg_type & BASE_TYPE_MASK
    is_outgoing = base_type in (2, 21, 22, 23, 24, 25, 26)
    is_incoming = base_type == 1 or base_type in (20,)

    if not is_outgoing and not is_incoming:
        return None

    date_sent = msg.get("date") or msg.get("date_sent") or 0
    date_received = msg.get("date_received") or msg.get("date") or 0

    frame = Frame()
    item = frame.chatItem
    item.chatId = chat_id
    item.dateSent = int(date_sent)

    if is_incoming:
        # Try to resolve author from address/recipient_id
        address = msg.get("address") or msg.get("recipient_id")
        author_rid = ids.conversation_to_recipient.get(str(address)) if address else None
        item.authorId = author_rid or 0

        incoming = item.incoming
        incoming.dateReceived = int(date_received)
        incoming.read = bool(msg.get("read", 0))
    else:
        self_rid = ids.service_id_to_recipient.get("__self__", 0)
        item.authorId = self_rid

        outgoing = item.outgoing
        outgoing.dateReceived = int(date_received)
        ss = SendStatus()
        ss.recipientId = ids.conversation_to_recipient.get(thread_id, 0)
        ss.sent.sealedSender = False
        outgoing.sendStatus.append(ss)

    body = msg.get("body")
    if body:
        std_msg = StandardMessage()
        std_msg.text.body = str(body)
        item.standardMessage.CopyFrom(std_msg)

    expire_timer = msg.get("expires_in")
    if expire_timer:
        item.expiresInMs = int(expire_timer)

    return frame
