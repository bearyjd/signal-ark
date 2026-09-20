"""Orchestrate the Desktop-DB → v2 frame stream mapping, one helper per pipeline step."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from signal_ark.mapping.attachments import _process_attachments
from signal_ark.mapping.calls import build_call_item
from signal_ark.mapping.chats import _drop_empty_chat_items, build_chat, build_chat_item
from signal_ark.mapping.desktop_db import (
    _collect_legacy_attachments,
    _collect_modern_attachments,
    _find_self_conversation,
    _has_table,
    _load_active_conversations,
    _load_contact_conversations,
    _load_group_conversations,
    _load_group_sender_acis,
    _load_messages,
)
from signal_ark.mapping.ids import IdAllocator
from signal_ark.mapping.recipients import (
    build_account_frame,
    build_contact_recipient,
    build_group_recipient,
    build_member_recipient,
    build_self_recipient,
)
from signal_ark.mapping.util import _normalize_aci
from signal_ark.proto.Backup_pb2 import BackupInfo, Frame


@dataclass
class MappingResult:
    backup_info: BackupInfo
    frames: list[Frame]
    media_names: list[str]
    stats: dict[str, int]


def _emit_account(frames: list[Frame], seed_account_frame: Frame) -> None:
    # 1. AccountData (from seed — has correct registration)
    frames.append(build_account_frame(seed_account_frame.account))


def _emit_self_recipient(
    conn: sqlite3.Connection, ids: IdAllocator, frames: list[Frame], self_aci: str
) -> str:
    # 2. Find self conversation and build Self recipient
    self_conv = _find_self_conversation(conn, self_aci)

    self_conv_id = self_conv["id"] if self_conv else "__self_placeholder__"
    frames.append(build_self_recipient(ids, self_conv_id, self_aci))
    return self_conv_id


def _emit_seed_frames(frames: list[Frame], seed_frames: list[Frame]) -> list[Frame]:
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
    return seed_chat_folders


def _emit_group_recipients(
    conn: sqlite3.Connection, ids: IdAllocator, frames: list[Frame], stats: dict[str, int]
) -> None:
    # 3. Build group recipients (prevents StorageSyncJob placeholder crash)
    group_conversations = _load_group_conversations(conn)

    for conv_row in group_conversations:
        conv_json = json.loads(conv_row["json"])
        conv_id = conv_row["id"]
        group_frame = build_group_recipient(ids, conv_json, conv_id)
        if group_frame:
            frames.append(group_frame)
            stats["recipients"] += 1


def _emit_contact_recipients(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
    self_aci: str,
) -> None:
    # 4. Build contact recipients from private conversations
    conversations = _load_contact_conversations(conn, self_aci)

    for conv_row in conversations:
        conv_json = json.loads(conv_row["json"])
        conv_id = conv_row["id"]
        recipient_frame = build_contact_recipient(ids, conv_json, conv_id)
        if recipient_frame:
            frames.append(recipient_frame)
            stats["recipients"] += 1


def _emit_member_if_unknown(
    ids: IdAllocator, frames: list[Frame], stats: dict[str, int], aci: str | None, self_aci: str
) -> None:
    canonical = _normalize_aci(aci)
    if canonical is None or canonical == _normalize_aci(self_aci):
        return
    if ids.resolve_service_id(canonical) is not None:
        return
    member_frame = build_member_recipient(ids, canonical)
    if member_frame:
        frames.append(member_frame)
        stats["recipients"] += 1
        stats["group_member_recipients"] += 1


def _emit_group_member_recipients(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
    self_aci: str,
) -> None:
    # 4b. Minimal contacts for group members that have no conversation of their own,
    # so incoming group messages always have a Contact author
    for conv_row in _load_group_conversations(conn):
        if conv_row["id"] not in ids.conversation_to_recipient:
            continue
        for member in json.loads(conv_row["json"]).get("membersV2") or []:
            _emit_member_if_unknown(ids, frames, stats, member.get("aci"), self_aci)


def _emit_group_sender_recipients(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
    self_aci: str,
) -> None:
    # 4c. Same for senders that have since left the group (not in membersV2)
    for conv_id, source_sid in _load_group_sender_acis(conn):
        if conv_id in ids.conversation_to_recipient:
            _emit_member_if_unknown(ids, frames, stats, source_sid, self_aci)


def _emit_chats(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
    self_conv_id: str,
) -> None:
    # 5. Build chats for conversations that have messages and a recipient
    # (a group without a masterKey has neither a recipient nor a chat)
    active_conversations = _load_active_conversations(conn, self_conv_id)

    for conv_row in active_conversations:
        conv_id = conv_row["id"]
        if conv_id not in ids.conversation_to_recipient:
            stats["chats_without_recipient"] += 1
            continue
        conv_json = json.loads(conv_row["json"])
        chat_frame = build_chat(ids, conv_id, conv_json)
        if chat_frame:
            frames.append(chat_frame)
            stats["chats"] += 1


def _emit_chat_items(
    conn: sqlite3.Connection, ids: IdAllocator, frames: list[Frame], stats: dict[str, int]
) -> dict[str, int]:
    # 6. Build chat items from messages (ordered by received timestamp)
    has_calls_table = _has_table(conn, "callsHistory")

    messages = _load_messages(conn)

    message_frame_index: dict[str, int] = {}
    for msg_row in messages:
        msg_dict = dict(msg_row)
        msg_json = json.loads(msg_dict.get("json") or "{}")

        if msg_dict.get("type") == "call-history":
            result_frame = build_call_item(ids, msg_dict, msg_json, conn, has_calls_table)
        else:
            result_frame = build_chat_item(ids, msg_dict, msg_json, stats)

        if result_frame:
            message_frame_index[msg_dict["id"]] = len(frames)
            frames.append(result_frame)
            stats["messages"] += 1
        else:
            stats["skipped_messages"] += 1
    return message_frame_index


def _emit_attachments(
    conn: sqlite3.Connection,
    ids: IdAllocator,
    frames: list[Frame],
    stats: dict[str, int],
    attachments_dir: Path,
    output_files_dir: Path,
    message_frame_index: dict[str, int],
) -> list[str]:
    # 7. Handle attachments (if output dir provided)
    output_files_dir.mkdir(parents=True, exist_ok=True)

    if _has_table(conn, "message_attachments"):
        attachments = _collect_modern_attachments(conn)
    else:
        attachments = _collect_legacy_attachments(conn)

    return _process_attachments(
        attachments,
        attachments_dir,
        output_files_dir,
        frames,
        message_frame_index,
        ids,
        stats,
    )


def _finalize(
    frames: list[Frame],
    stats: dict[str, int],
    media_names: list[str],
    seed_chat_folders: list[Frame],
    seed_backup_info: BackupInfo,
) -> MappingResult:
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
        "group_member_recipients": 0,
        "chats": 0,
        "chats_without_recipient": 0,
        "messages": 0,
        "attachments": 0,
        "skipped_messages": 0,
        "skipped_unresolved_author": 0,
        "plaintext_hash_mismatch": 0,
        "attachments_rejected_path": 0,
        "attachments_missing_file": 0,
        "attachments_orphaned": 0,
        "attachment_failures": 0,
        "long_text_without_body": 0,
    }

    _emit_account(frames, seed_account_frame)
    self_conv_id = _emit_self_recipient(conn, ids, frames, self_aci)
    seed_chat_folders = _emit_seed_frames(frames, seed_frames)
    _emit_group_recipients(conn, ids, frames, stats)
    _emit_contact_recipients(conn, ids, frames, stats, self_aci)
    _emit_group_member_recipients(conn, ids, frames, stats, self_aci)
    _emit_group_sender_recipients(conn, ids, frames, stats, self_aci)
    _emit_chats(conn, ids, frames, stats, self_conv_id)
    message_frame_index = _emit_chat_items(conn, ids, frames, stats)

    if output_files_dir:
        media_names = _emit_attachments(
            conn, ids, frames, stats, attachments_dir, output_files_dir, message_frame_index
        )

    conn.close()

    return _finalize(frames, stats, media_names, seed_chat_folders, seed_backup_info)
