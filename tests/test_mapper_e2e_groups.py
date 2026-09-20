"""End-to-end coverage for group chats in the Desktop → v2 build path:
group Chat, member recipients, author resolution, group calls, attachments."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from signal_ark.mapping import MappingResult, map_desktop_to_frames
from signal_ark.mapping.util import _uuid_str_to_bytes
from signal_ark.proto.Backup_pb2 import Frame, GroupCall
from signal_ark.validate import ValidationResult

from tests.test_mapper_e2e import (
    ALICE_ACI,
    BOB_ACI,
    SELF_ACI,
    _assert_validates,
    _find_chat_items,
    _find_frames_by_type,
    _seed_account_frame,
    _seed_backup_info,
)

GHOST_ACI = "dddddddd-1111-2222-3333-444444444444"
MASTER_KEY_B64 = base64.b64encode(b"g" * 32).decode()
MESSAGE_COLUMNS = "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?"


def _create_group_desktop_db(db_path: Path, *, with_master_key: bool = True) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE conversations (
            id TEXT PRIMARY KEY, json TEXT, active_at INTEGER, type TEXT,
            e164 TEXT, serviceId TEXT, profileName TEXT, profileFamilyName TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE messages (
            id TEXT PRIMARY KEY, body TEXT, type TEXT, sent_at INTEGER,
            received_at INTEGER, received_at_ms INTEGER, timestamp INTEGER,
            conversationId TEXT, sourceServiceId TEXT, serverTimestamp INTEGER,
            readStatus INTEGER, unidentifiedDeliveryReceived INTEGER,
            expireTimer INTEGER, expirationStartTimestamp INTEGER, json TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE message_attachments (
            messageId TEXT, contentType TEXT, path TEXT, size INTEGER,
            width INTEGER, height INTEGER, fileName TEXT, plaintextHash TEXT,
            blurHash TEXT, caption TEXT, localKey TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE callsHistory (
            callId TEXT, peerId TEXT, ringerId TEXT,
            mode TEXT, type TEXT, direction TEXT, status TEXT, timestamp INTEGER
        )
    """)

    conn.execute(
        "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
        ("conv-self", json.dumps({"serviceId": SELF_ACI}), 1000, "private", None, SELF_ACI, "Test", "User"),
    )
    alice_json = json.dumps({"serviceId": ALICE_ACI, "profileName": "Alice", "profileSharing": True})
    conn.execute(
        "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
        ("conv-alice", alice_json, 2000, "private", None, ALICE_ACI, "Alice", ""),
    )
    group_json: dict = {
        "name": "Test Group",
        "membersV2": [
            {"aci": SELF_ACI, "role": 2, "joinedAtVersion": 0},
            {"aci": ALICE_ACI.upper(), "role": 1, "joinedAtVersion": 0},
            {"aci": BOB_ACI, "role": 1, "joinedAtVersion": 1},
        ],
        "revision": 1,
    }
    if with_master_key:
        group_json["masterKey"] = MASTER_KEY_B64
    conn.execute(
        "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
        ("conv-group", json.dumps(group_json), 3000, "group", None, None, None, None),
    )

    def insert(msg_id: str, body: str | None, msg_type: str, ts: int, source: str | None, msg_json: dict) -> None:
        conn.execute(
            f"INSERT INTO messages VALUES ({MESSAGE_COLUMNS})",
            (msg_id, body, msg_type, ts, ts, ts, ts, "conv-group", source,
             None, 1, 0, None, None, json.dumps(msg_json)),
        )

    insert("msg-alice", "Hi from Alice", "incoming", 1000, ALICE_ACI, {})
    insert("msg-bob", "Hi from Bob", "incoming", 2000, BOB_ACI, {})
    insert("msg-ghost", "Who am I", "incoming", 3000, GHOST_ACI, {})
    insert("msg-nosource", "No sender", "incoming", 3500, None, {})
    insert("msg-out", "Hello everyone", "outgoing", 4000, None, {
        "sendStateByConversationId": {
            "conv-alice": {"status": "Read", "updatedAt": 4100},
            "conv-group": {"status": "Sent", "updatedAt": 4100},
        },
    })
    insert("msg-call", None, "call-history", 5000, None, {"callId": "gcall-1"})

    conn.execute(
        "INSERT INTO callsHistory VALUES (?,?,?,?,?,?,?,?)",
        ("gcall-1", "group-id", ALICE_ACI, "Group", "Group", "Incoming", "Joined", 5000),
    )
    conn.execute(
        "INSERT INTO message_attachments (messageId, contentType, path, size, fileName)"
        " VALUES (?,?,?,?,?)",
        ("msg-alice", "image/jpeg", "ab/group.jpg", 16, "group.jpg"),
    )
    conn.commit()
    conn.close()


def _recipient_by_aci(frames: list[Frame], aci: str) -> Frame:
    aci_bytes = _uuid_str_to_bytes(aci)
    return next(
        f for f in _find_frames_by_type(frames, "recipient")
        if f.recipient.HasField("contact") and f.recipient.contact.aci == aci_bytes
    )


def _chat_item_at(frames: list[Frame], sent_at: int) -> Frame | None:
    return next((f for f in _find_chat_items(frames) if f.chatItem.dateSent == sent_at), None)


class TestMapDesktopGroupChats:
    @pytest.fixture(autouse=True)
    def _workspace(self, tmp_path: Path) -> None:
        self.db_path = tmp_path / "desktop.sqlite"
        self.attachments_dir = tmp_path / "attachments"
        self.output_dir = tmp_path / "output_files"
        att_path = self.attachments_dir / "ab" / "group.jpg"
        att_path.parent.mkdir(parents=True)
        att_path.write_bytes(b"group jpeg bytes")
        _create_group_desktop_db(self.db_path)
        self.result = self._map()
        self.frames = self.result.frames
        self.stats = self.result.stats

    def _map(self) -> MappingResult:
        return map_desktop_to_frames(
            db_path=self.db_path,
            attachments_dir=self.attachments_dir,
            seed_backup_info=_seed_backup_info(),
            seed_account_frame=_seed_account_frame(),
            seed_frames=[],
            self_aci=SELF_ACI,
            output_files_dir=self.output_dir,
        )

    def _group_recipient(self) -> Frame:
        return next(
            f for f in _find_frames_by_type(self.frames, "recipient") if f.recipient.HasField("group")
        )

    def _self_recipient_id(self) -> int:
        return next(
            f.recipient.id for f in _find_frames_by_type(self.frames, "recipient")
            if f.recipient.HasField("self")
        )

    @pytest.mark.validator
    def test_frames_pass_libsignal_validator(
        self, validator: Callable[..., ValidationResult]
    ) -> None:
        _assert_validates(validator, self.result)

    def test_one_chat_references_group_recipient(self) -> None:
        chats = _find_frames_by_type(self.frames, "chat")
        assert len(chats) == 1
        assert chats[0].chat.recipientId == self._group_recipient().recipient.id
        assert self.stats["chats"] == 1
        assert self.stats["chats_without_recipient"] == 0

    def test_bob_gets_minimal_member_recipient(self) -> None:
        bob = _recipient_by_aci(self.frames, BOB_ACI).recipient.contact
        assert bob.HasField("registered")
        assert bob.profileGivenName == ""
        assert self.stats["group_member_recipients"] == 2

    def test_former_member_sender_gets_member_recipient_and_message(self) -> None:
        ghost_item = _chat_item_at(self.frames, 3000)
        assert ghost_item is not None
        ghost_rid = _recipient_by_aci(self.frames, GHOST_ACI).recipient.id
        assert ghost_item.chatItem.authorId == ghost_rid
        assert ghost_rid != 0
        assert ghost_rid != self._group_recipient().recipient.id

    def test_alice_is_not_duplicated_as_member_recipient(self) -> None:
        alice_bytes = _uuid_str_to_bytes(ALICE_ACI)
        alice_frames = [
            f for f in _find_frames_by_type(self.frames, "recipient")
            if f.recipient.HasField("contact") and f.recipient.contact.aci == alice_bytes
        ]
        assert len(alice_frames) == 1
        assert alice_frames[0].recipient.contact.profileGivenName == "Alice"

    def test_incoming_authors_resolve_to_member_recipients(self) -> None:
        alice_item = _chat_item_at(self.frames, 1000)
        bob_item = _chat_item_at(self.frames, 2000)
        assert alice_item is not None and bob_item is not None
        assert alice_item.chatItem.authorId == _recipient_by_aci(self.frames, ALICE_ACI).recipient.id
        assert bob_item.chatItem.authorId == _recipient_by_aci(self.frames, BOB_ACI).recipient.id

    def test_no_chat_item_is_authored_by_the_group(self) -> None:
        group_rid = self._group_recipient().recipient.id
        assert all(f.chatItem.authorId != group_rid for f in _find_chat_items(self.frames))

    def test_sourceless_group_message_is_skipped(self) -> None:
        assert _chat_item_at(self.frames, 3500) is None
        assert self.stats["skipped_unresolved_author"] == 1
        assert self.stats["skipped_messages"] == 1
        assert self.stats["messages"] == 5

    def test_outgoing_send_status_targets_alice_only(self) -> None:
        item = _chat_item_at(self.frames, 4000)
        assert item is not None
        assert item.chatItem.authorId == self._self_recipient_id()
        recipients = [ss.recipientId for ss in item.chatItem.outgoing.sendStatus]
        assert recipients == [_recipient_by_aci(self.frames, ALICE_ACI).recipient.id]

    def test_group_call_item_has_alice_as_ringer(self) -> None:
        item = _chat_item_at(self.frames, 5000)
        assert item is not None
        call = item.chatItem.updateMessage.groupCall
        assert call.state == GroupCall.State.JOINED
        assert call.ringerRecipientId == _recipient_by_aci(self.frames, ALICE_ACI).recipient.id
        assert item.chatItem.HasField("directionless")

    def test_attachment_binds_to_alice_message(self) -> None:
        item = _chat_item_at(self.frames, 1000)
        assert item is not None
        attachments = item.chatItem.standardMessage.attachments
        assert len(attachments) == 1
        loc = attachments[0].pointer.locatorInfo
        media_name = hashlib.sha256(loc.plaintextHash + loc.localKey).hexdigest()
        assert self.result.media_names == [media_name]
        assert (self.output_dir / media_name[:2] / media_name).is_file()
        assert self.stats["attachments"] == 1
        assert self.stats["attachments_orphaned"] == 0

    def test_media_names_match_every_file_pointer_exactly(self) -> None:
        expected = {
            hashlib.sha256(loc.plaintextHash + loc.localKey).hexdigest()
            for f in _find_chat_items(self.frames)
            for loc in [a.pointer.locatorInfo for a in f.chatItem.standardMessage.attachments]
        }
        assert expected
        assert set(self.result.media_names) == expected


class TestMapDesktopGroupWithoutMasterKey:
    @pytest.fixture(autouse=True)
    def _workspace(self, tmp_path: Path) -> None:
        self.db_path = tmp_path / "desktop.sqlite"
        self.attachments_dir = tmp_path / "attachments"
        self.attachments_dir.mkdir()
        _create_group_desktop_db(self.db_path, with_master_key=False)
        self.result = map_desktop_to_frames(
            db_path=self.db_path,
            attachments_dir=self.attachments_dir,
            seed_backup_info=_seed_backup_info(),
            seed_account_frame=_seed_account_frame(),
            seed_frames=[],
            self_aci=SELF_ACI,
            output_files_dir=tmp_path / "output_files",
        )

    def test_group_without_master_key_gets_no_chat_and_no_items(self) -> None:
        assert _find_frames_by_type(self.result.frames, "chat") == []
        assert _find_chat_items(self.result.frames) == []
        assert self.result.stats["chats"] == 0
        assert self.result.stats["chats_without_recipient"] == 1
        assert self.result.stats["group_member_recipients"] == 0

    @pytest.mark.validator
    def test_frames_pass_libsignal_validator(
        self, validator: Callable[..., ValidationResult]
    ) -> None:
        _assert_validates(validator, self.result)
