"""End-to-end test for map_desktop_to_frames with a synthetic Desktop DB.

Exercises the full mapping pipeline: recipients, chats, text messages,
reactions, quotes, call history (individual + group), and legacy attachments.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from signal_ark.encrypt import serialize_frames
from signal_ark.mapper import MappingResult, map_desktop_to_frames
from signal_ark.proto.Backup_pb2 import BackupInfo, Frame, IndividualCall
from signal_ark.validate import ValidationResult

from tests.helpers.synthetic_seed import default_account_frame, default_backup_info

SELF_ACI = "aaaaaaaa-1111-2222-3333-444444444444"
ALICE_ACI = "bbbbbbbb-1111-2222-3333-444444444444"
BOB_ACI = "cccccccc-1111-2222-3333-444444444444"


def _seed_backup_info() -> BackupInfo:
    return default_backup_info(backup_time_ms=1000000)


def _seed_account_frame() -> Frame:
    return default_account_frame(givenName="Test", familyName="User")


def _assert_validates(validator: Callable[..., ValidationResult], result: MappingResult) -> None:
    outcome = validator(serialize_frames(result.backup_info, result.frames))
    assert outcome.ok, f"libsignal validator rejected mapper output: {outcome.error}"
    assert outcome.frames == len(result.frames)


def _create_desktop_db(db_path: Path, *, include_calls_table: bool = True) -> None:
    conn = sqlite3.connect(str(db_path))

    conn.execute("""
        CREATE TABLE conversations (
            id TEXT PRIMARY KEY,
            json TEXT,
            active_at INTEGER,
            type TEXT,
            e164 TEXT,
            serviceId TEXT,
            profileName TEXT,
            profileFamilyName TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            body TEXT,
            type TEXT,
            sent_at INTEGER,
            received_at INTEGER,
            received_at_ms INTEGER,
            timestamp INTEGER,
            conversationId TEXT,
            sourceServiceId TEXT,
            serverTimestamp INTEGER,
            readStatus INTEGER,
            unidentifiedDeliveryReceived INTEGER,
            expireTimer INTEGER,
            expirationStartTimestamp INTEGER,
            json TEXT
        )
    """)

    # Self conversation
    conn.execute(
        "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
        ("conv-self", json.dumps({"serviceId": SELF_ACI}), 1000, "private", None, SELF_ACI, "Test", "User"),
    )

    # Alice conversation
    alice_json = json.dumps({
        "serviceId": ALICE_ACI,
        "profileName": "Alice",
        "profileFamilyName": "Smith",
        "profileSharing": True,
    })
    conn.execute(
        "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
        ("conv-alice", alice_json, 2000, "private", "+15551234567", ALICE_ACI, "Alice", "Smith"),
    )

    # Bob conversation
    bob_json = json.dumps({
        "serviceId": BOB_ACI,
        "profileName": "Bob",
        "profileFamilyName": "Jones",
        "profileSharing": True,
    })
    conn.execute(
        "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
        ("conv-bob", bob_json, 3000, "private", "+15559876543", BOB_ACI, "Bob", "Jones"),
    )

    # --- Messages ---

    # 1. Incoming text from Alice with reactions
    msg1_json = json.dumps({
        "reactions": [
            {"emoji": "\U0001f44d", "fromId": "conv-alice", "timestamp": 1100},
            {"emoji": "❤️", "fromId": "conv-self", "timestamp": 1200, "receivedAtDate": 1250},
        ],
    })
    conn.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("msg-1", "Hello from Alice", "incoming", 1000, 1000, 1000, 1000,
         "conv-alice", ALICE_ACI, None, 1, 0, None, None, msg1_json),
    )

    # 2. Outgoing text to Alice with a quote
    msg2_json = json.dumps({
        "quote": {
            "id": 1000,
            "authorAci": ALICE_ACI,
            "text": "Hello from Alice",
        },
        "sendStateByConversationId": {
            "conv-alice": {"status": "Read", "updatedAt": 2100},
        },
    })
    conn.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("msg-2", "Replying to you", "outgoing", 2000, 2000, 2000, 2000,
         "conv-alice", None, None, 1, 0, None, None, msg2_json),
    )

    # 3. Incoming from Bob — body only, no reactions/quotes
    conn.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("msg-3", "Hey there", "incoming", 3000, 3000, 3000, 3000,
         "conv-bob", BOB_ACI, None, 1, 0, None, None, "{}"),
    )

    # 4. Call history — individual audio call with Alice
    msg4_json = json.dumps({"callId": "call-1"})
    conn.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("msg-4", None, "call-history", 4000, 4000, 4000, 4000,
         "conv-alice", None, None, 1, 0, None, None, msg4_json),
    )

    # 5. Call history — individual video call with Bob (missed)
    msg5_json = json.dumps({"callId": "call-2"})
    conn.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("msg-5", None, "call-history", 5000, 5000, 5000, 5000,
         "conv-bob", None, None, 1, 0, None, None, msg5_json),
    )

    # 6. Outgoing with both reactions and quote
    msg6_json = json.dumps({
        "reactions": [
            {"emoji": "\U0001f389", "fromId": "conv-bob", "timestamp": 6100},
        ],
        "quote": {
            "id": 3000,
            "authorUuid": BOB_ACI,
            "text": "Hey there",
        },
        "sendStateByConversationId": {
            "conv-bob": {"status": "Delivered", "updatedAt": 6050},
        },
    })
    conn.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("msg-6", "Quoting you Bob", "outgoing", 6000, 6000, 6000, 6000,
         "conv-bob", None, None, 1, 0, None, None, msg6_json),
    )

    # 7. Outgoing quoting our own earlier message
    msg7_json = json.dumps({
        "quote": {"id": 2000, "authorAci": SELF_ACI, "text": "Replying to you"},
        "sendStateByConversationId": {
            "conv-alice": {"status": "Sent", "updatedAt": 7050},
        },
    })
    conn.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("msg-7", "Quoting myself", "outgoing", 7000, 7000, 7000, 7000,
         "conv-alice", None, None, 1, 0, None, None, msg7_json),
    )

    # 8. Reaction-only message with no body and no attachments (must be dropped)
    msg8_json = json.dumps({
        "reactions": [{"emoji": "\U0001f525", "fromId": "conv-alice", "timestamp": 8100}],
    })
    conn.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("msg-8", None, "incoming", 8000, 8000, 8000, 8000,
         "conv-alice", ALICE_ACI, None, 1, 0, None, None, msg8_json),
    )

    # callsHistory table
    if include_calls_table:
        conn.execute("""
            CREATE TABLE callsHistory (
                callId TEXT, peerId TEXT, ringerId TEXT,
                mode TEXT, type TEXT, direction TEXT, status TEXT, timestamp INTEGER
            )
        """)
        conn.execute(
            "INSERT INTO callsHistory VALUES (?,?,?,?,?,?,?,?)",
            ("call-1", "conv-alice", None, "Direct", "Audio", "Incoming", "Accepted", 4000),
        )
        conn.execute(
            "INSERT INTO callsHistory VALUES (?,?,?,?,?,?,?,?)",
            ("call-2", "conv-bob", None, "Direct", "Video", "Incoming", "Missed", 5000),
        )

    conn.commit()
    conn.close()


def _find_frames_by_type(frames: list[Frame], item_type: str) -> list[Frame]:
    return [f for f in frames if f.WhichOneof("item") == item_type]


def _find_chat_items(frames: list[Frame]) -> list[Frame]:
    return _find_frames_by_type(frames, "chatItem")


def _find_chat_items_with_standard_message(frames: list[Frame]) -> list[Frame]:
    return [
        f for f in _find_chat_items(frames)
        if f.chatItem.WhichOneof("item") == "standardMessage"
    ]


def _find_chat_items_with_update_message(frames: list[Frame]) -> list[Frame]:
    return [
        f for f in _find_chat_items(frames)
        if f.chatItem.WhichOneof("item") == "updateMessage"
    ]


class TestMapDesktopToFramesE2E:
    """Full pipeline test: synthetic DB → map_desktop_to_frames → verify frames."""

    def setup_method(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self._tmpdir) / "desktop.sqlite"
        self.attachments_dir = Path(self._tmpdir) / "attachments"
        self.attachments_dir.mkdir()

        _create_desktop_db(self.db_path)

        result = map_desktop_to_frames(
            db_path=self.db_path,
            attachments_dir=self.attachments_dir,
            seed_backup_info=_seed_backup_info(),
            seed_account_frame=_seed_account_frame(),
            seed_frames=[],
            self_aci=SELF_ACI,
            output_files_dir=None,
        )
        self.result = result
        self.frames = result.frames
        self.stats = result.stats

    # --- Structural ---

    @pytest.mark.validator
    def test_frames_pass_libsignal_validator(
        self, validator: Callable[..., ValidationResult]
    ) -> None:
        _assert_validates(validator, self.result)

    def test_first_frame_is_account_data(self) -> None:
        assert self.frames[0].WhichOneof("item") == "account"

    def test_recipients_created(self) -> None:
        recipients = _find_frames_by_type(self.frames, "recipient")
        assert len(recipients) >= 3  # self + alice + bob

    def test_chats_created(self) -> None:
        chats = _find_frames_by_type(self.frames, "chat")
        assert len(chats) >= 2  # alice + bob

    def test_stats_counts(self) -> None:
        assert self.stats["recipients"] >= 2
        assert self.stats["chats"] >= 2
        assert self.stats["messages"] == 7
        assert self.stats["skipped_messages"] == 1

    def test_no_item_less_chat_items(self) -> None:
        for f in _find_chat_items(self.frames):
            assert f.chatItem.WhichOneof("item") is not None

    def test_reaction_only_message_dropped(self) -> None:
        assert not any(f.chatItem.dateSent == 8000 for f in _find_chat_items(self.frames))

    def test_stats_messages_matches_emitted_chat_items(self) -> None:
        assert self.stats["messages"] == len(_find_chat_items(self.frames))

    # --- Text messages ---

    def test_incoming_text_message(self) -> None:
        std_msgs = _find_chat_items_with_standard_message(self.frames)
        incoming = [
            f for f in std_msgs
            if f.chatItem.HasField("incoming")
            and f.chatItem.standardMessage.text.body == "Hello from Alice"
        ]
        assert len(incoming) == 1

    def test_outgoing_text_message(self) -> None:
        std_msgs = _find_chat_items_with_standard_message(self.frames)
        outgoing = [
            f for f in std_msgs
            if f.chatItem.HasField("outgoing")
            and f.chatItem.standardMessage.text.body == "Replying to you"
        ]
        assert len(outgoing) == 1

    # --- Reactions ---

    def test_reactions_on_incoming_message(self) -> None:
        std_msgs = _find_chat_items_with_standard_message(self.frames)
        msg = next(
            f for f in std_msgs
            if f.chatItem.standardMessage.text.body == "Hello from Alice"
        )
        reactions = list(msg.chatItem.standardMessage.reactions)
        assert len(reactions) == 2
        emojis = {r.emoji for r in reactions}
        assert "\U0001f44d" in emojis
        assert "❤️" in emojis

    def test_reaction_author_resolved(self) -> None:
        std_msgs = _find_chat_items_with_standard_message(self.frames)
        msg = next(
            f for f in std_msgs
            if f.chatItem.standardMessage.text.body == "Hello from Alice"
        )
        reactions = list(msg.chatItem.standardMessage.reactions)
        author_ids = {r.authorId for r in reactions}
        assert 0 not in author_ids

    def test_reaction_sort_order_uses_received_at(self) -> None:
        std_msgs = _find_chat_items_with_standard_message(self.frames)
        msg = next(
            f for f in std_msgs
            if f.chatItem.standardMessage.text.body == "Hello from Alice"
        )
        heart = next(r for r in msg.chatItem.standardMessage.reactions if r.emoji == "❤️")
        assert heart.sortOrder == 1250

    # --- Quotes ---

    def test_quote_on_outgoing_message(self) -> None:
        std_msgs = _find_chat_items_with_standard_message(self.frames)
        msg = next(
            f for f in std_msgs
            if f.chatItem.standardMessage.text.body == "Replying to you"
        )
        quote = msg.chatItem.standardMessage.quote
        assert quote.targetSentTimestamp == 1000
        assert quote.text.body == "Hello from Alice"
        assert quote.authorId != 0

    def test_quote_with_author_uuid_fallback(self) -> None:
        std_msgs = _find_chat_items_with_standard_message(self.frames)
        msg = next(
            f for f in std_msgs
            if f.chatItem.standardMessage.text.body == "Quoting you Bob"
        )
        quote = msg.chatItem.standardMessage.quote
        assert quote.targetSentTimestamp == 3000
        assert quote.text.body == "Hey there"
        assert quote.authorId != 0

    def test_quote_of_own_message_resolves_to_self_recipient(self) -> None:
        std_msgs = _find_chat_items_with_standard_message(self.frames)
        msg = next(
            f for f in std_msgs
            if f.chatItem.standardMessage.text.body == "Quoting myself"
        )
        self_rid = next(
            f.recipient.id for f in _find_frames_by_type(self.frames, "recipient")
            if f.recipient.HasField("self")
        )
        assert msg.chatItem.standardMessage.quote.authorId == self_rid
        assert msg.chatItem.authorId == self_rid

    # --- Combined reactions + quote ---

    def test_message_with_both_reactions_and_quote(self) -> None:
        std_msgs = _find_chat_items_with_standard_message(self.frames)
        msg = next(
            f for f in std_msgs
            if f.chatItem.standardMessage.text.body == "Quoting you Bob"
        )
        assert len(msg.chatItem.standardMessage.reactions) == 1
        assert msg.chatItem.standardMessage.reactions[0].emoji == "\U0001f389"
        assert msg.chatItem.standardMessage.quote.targetSentTimestamp == 3000

    # --- Call history ---

    def test_individual_audio_call(self) -> None:
        updates = _find_chat_items_with_update_message(self.frames)
        audio_calls = [
            f for f in updates
            if f.chatItem.updateMessage.HasField("individualCall")
            and f.chatItem.updateMessage.individualCall.type == IndividualCall.Type.AUDIO_CALL
        ]
        assert len(audio_calls) == 1
        call = audio_calls[0].chatItem.updateMessage.individualCall
        assert call.direction == IndividualCall.Direction.INCOMING
        assert call.state == IndividualCall.State.ACCEPTED

    def test_individual_video_call_missed(self) -> None:
        updates = _find_chat_items_with_update_message(self.frames)
        video_calls = [
            f for f in updates
            if f.chatItem.updateMessage.HasField("individualCall")
            and f.chatItem.updateMessage.individualCall.type == IndividualCall.Type.VIDEO_CALL
        ]
        assert len(video_calls) == 1
        call = video_calls[0].chatItem.updateMessage.individualCall
        assert call.direction == IndividualCall.Direction.INCOMING
        assert call.state == IndividualCall.State.MISSED

    def test_call_items_have_directionless(self) -> None:
        updates = _find_chat_items_with_update_message(self.frames)
        for f in updates:
            assert f.chatItem.HasField("directionless")


class TestMapDesktopCallFallback:
    """Test call history when callsHistory table doesn't exist (JSON fallback)."""

    def setup_method(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self._tmpdir) / "desktop.sqlite"
        self.attachments_dir = Path(self._tmpdir) / "attachments"
        self.attachments_dir.mkdir()

        conn = sqlite3.connect(str(self.db_path))
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

        conn.execute(
            "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
            ("conv-self", json.dumps({"serviceId": SELF_ACI}), 1000, "private", None, SELF_ACI, "Test", "User"),
        )
        alice_json = json.dumps({"serviceId": ALICE_ACI, "profileName": "Alice"})
        conn.execute(
            "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
            ("conv-alice", alice_json, 2000, "private", None, ALICE_ACI, "Alice", ""),
        )

        declined_json = json.dumps({
            "callHistoryDetails": {
                "callId": "99",
                "callMode": "Direct",
                "wasIncoming": False,
                "wasVideoCall": True,
                "wasDeclined": True,
                "endedTime": 7050,
            }
        })
        conn.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("msg-call-declined", None, "call-history", 7000, 7000, 7000, 7000,
             "conv-alice", None, None, 1, 0, None, None, declined_json),
        )
        missed_json = json.dumps({
            "callHistoryDetails": {
                "callId": "100",
                "wasIncoming": True,
                "wasVideoCall": False,
                "wasDeclined": False,
            }
        })
        conn.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("msg-call-missed", None, "call-history", 8000, 8000, 8000, 8000,
             "conv-alice", None, None, 1, 0, None, None, missed_json),
        )
        accepted_json = json.dumps({
            "callHistoryDetails": {
                "callId": "101",
                "callMode": "Direct",
                "wasIncoming": True,
                "wasVideoCall": False,
                "wasDeclined": False,
                "acceptedTime": 9010,
                "endedTime": 9500,
            }
        })
        conn.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("msg-call-accepted", None, "call-history", 9000, 9000, 9000, 9000,
             "conv-alice", None, None, 1, 0, None, None, accepted_json),
        )

        conn.commit()
        conn.close()

        result = map_desktop_to_frames(
            db_path=self.db_path,
            attachments_dir=self.attachments_dir,
            seed_backup_info=_seed_backup_info(),
            seed_account_frame=_seed_account_frame(),
            seed_frames=[],
            self_aci=SELF_ACI,
        )
        self.result = result
        self.frames = result.frames

    def _call_by_id(self, call_id: int):
        updates = _find_chat_items_with_update_message(self.frames)
        return next(
            f.chatItem.updateMessage.individualCall for f in updates
            if f.chatItem.updateMessage.individualCall.callId == call_id
        )

    @pytest.mark.validator
    def test_frames_pass_libsignal_validator(
        self, validator: Callable[..., ValidationResult]
    ) -> None:
        _assert_validates(validator, self.result)

    def test_all_legacy_calls_emitted(self) -> None:
        assert len(_find_chat_items_with_update_message(self.frames)) == 3

    def test_legacy_declined_outgoing_video(self) -> None:
        call = self._call_by_id(99)
        assert call.type == IndividualCall.Type.VIDEO_CALL
        assert call.direction == IndividualCall.Direction.OUTGOING
        assert call.state == IndividualCall.State.NOT_ACCEPTED
        assert call.startedCallTimestamp == 7050

    def test_legacy_missed_incoming_without_call_mode(self) -> None:
        call = self._call_by_id(100)
        assert call.type == IndividualCall.Type.AUDIO_CALL
        assert call.direction == IndividualCall.Direction.INCOMING
        assert call.state == IndividualCall.State.MISSED
        assert call.startedCallTimestamp == 8000

    def test_legacy_accepted_incoming(self) -> None:
        call = self._call_by_id(101)
        assert call.state == IndividualCall.State.ACCEPTED
        assert call.startedCallTimestamp == 9010


class TestMapDesktopLegacyAttachments:
    """Test the legacy attachment path (no message_attachments table)."""

    def setup_method(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self._tmpdir) / "desktop.sqlite"
        self.attachments_dir = Path(self._tmpdir) / "attachments"
        self.attachments_dir.mkdir()
        self.output_dir = Path(self._tmpdir) / "output_files"

        conn = sqlite3.connect(str(self.db_path))
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

        conn.execute(
            "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
            ("conv-self", json.dumps({"serviceId": SELF_ACI}), 1000, "private", None, SELF_ACI, "Test", "User"),
        )
        alice_json = json.dumps({"serviceId": ALICE_ACI, "profileName": "Alice"})
        conn.execute(
            "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
            ("conv-alice", alice_json, 2000, "private", None, ALICE_ACI, "Alice", ""),
        )

        att_json = json.dumps({
            "attachments": [
                {
                    "path": "ab/test_photo.jpg",
                    "contentType": "image/jpeg",
                    "size": 12,
                    "fileName": "photo.jpg",
                },
            ],
        })
        conn.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("msg-att", "Check this photo", "incoming", 8000, 8000, 8000, 8000,
             "conv-alice", ALICE_ACI, None, 1, 0, None, None, att_json),
        )

        conn.commit()
        conn.close()

        # Create the attachment file on disk (plaintext, no Desktop encryption)
        att_path = self.attachments_dir / "ab" / "test_photo.jpg"
        att_path.parent.mkdir(parents=True)
        att_path.write_bytes(b"fake jpeg!!")

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

    def test_legacy_attachment_encrypted(self) -> None:
        result = self._map()
        assert result.stats["attachments"] >= 1
        assert len(result.media_names) >= 1

    @pytest.mark.validator
    def test_attachment_frames_pass_libsignal_validator(
        self, validator: Callable[..., ValidationResult]
    ) -> None:
        _assert_validates(validator, self._map())

    def test_legacy_no_message_attachments_table(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='message_attachments'"
        ).fetchall()
        conn.close()
        assert len(tables) == 0

    def _insert_bodyless_attachment_message(self, path: str, extra_json: dict | None = None) -> None:
        conn = sqlite3.connect(str(self.db_path))
        msg_json = json.dumps({
            "attachments": [{"path": path, "contentType": "image/png", "size": 4}],
            **(extra_json or {}),
        })
        conn.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("msg-bodyless", None, "incoming", 9000, 9000, 9000, 9000,
             "conv-alice", ALICE_ACI, None, 1, 0, None, None, msg_json),
        )
        conn.commit()
        conn.close()

    def test_bodyless_message_with_missing_file_emits_no_chat_item(self) -> None:
        self._insert_bodyless_attachment_message("zz/missing.png")
        result = self._map()

        chat_items = _find_chat_items(result.frames)
        assert not any(f.chatItem.dateSent == 9000 for f in chat_items)
        assert all(f.chatItem.WhichOneof("item") is not None for f in chat_items)
        assert result.stats["messages"] == 1
        assert result.stats["skipped_messages"] == 1

    def test_bodyless_message_with_present_file_keeps_reactions(self) -> None:
        att_path = self.attachments_dir / "zz" / "present.png"
        att_path.parent.mkdir(parents=True)
        att_path.write_bytes(b"png!")
        reactions = {"reactions": [{"emoji": "\U0001f44d", "fromId": "conv-alice", "timestamp": 9100}]}
        self._insert_bodyless_attachment_message("zz/present.png", reactions)
        result = self._map()

        item = next(f.chatItem for f in _find_chat_items(result.frames) if f.chatItem.dateSent == 9000)
        assert item.WhichOneof("item") == "standardMessage"
        assert len(item.standardMessage.attachments) == 1
        assert [r.emoji for r in item.standardMessage.reactions] == ["\U0001f44d"]
        assert result.stats["messages"] == 2

    @pytest.mark.validator
    def test_bodyless_attachment_with_reactions_passes_libsignal_validator(
        self, validator: Callable[..., ValidationResult]
    ) -> None:
        att_path = self.attachments_dir / "zz" / "present.png"
        att_path.parent.mkdir(parents=True)
        att_path.write_bytes(b"png!")
        reactions = {"reactions": [{"emoji": "\U0001f44d", "fromId": "conv-alice", "timestamp": 9100}]}
        self._insert_bodyless_attachment_message("zz/present.png", reactions)

        _assert_validates(validator, self._map())


class TestMapDesktopModernAttachments:
    """Test the message_attachments path (newer Desktop), with and without a `key` column."""

    def setup_method(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self._tmpdir) / "desktop.sqlite"
        self.attachments_dir = Path(self._tmpdir) / "attachments"
        self.attachments_dir.mkdir()
        self.output_dir = Path(self._tmpdir) / "output_files"
        self.remote_key_b64 = base64.b64encode(b"A" * 64).decode()

        conn = sqlite3.connect(str(self.db_path))
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
        conn.execute(
            "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
            ("conv-self", json.dumps({"serviceId": SELF_ACI}), 1000, "private", None, SELF_ACI, "Test", "User"),
        )
        alice_json = json.dumps({"serviceId": ALICE_ACI, "profileName": "Alice"})
        conn.execute(
            "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
            ("conv-alice", alice_json, 2000, "private", None, ALICE_ACI, "Alice", ""),
        )
        conn.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("msg-att", "Modern photo", "incoming", 8000, 8000, 8000, 8000,
             "conv-alice", ALICE_ACI, None, 1, 0, None, None, "{}"),
        )
        conn.commit()
        conn.close()

        att_path = self.attachments_dir / "ab" / "modern.jpg"
        att_path.parent.mkdir(parents=True)
        att_path.write_bytes(b"fake jpeg!!")

    def _create_message_attachments(
        self, *, with_key_column: bool, db_plaintext_hash: str | None = None
    ) -> None:
        key_column = ", key TEXT" if with_key_column else ""
        conn = sqlite3.connect(str(self.db_path))
        conn.execute(f"""
            CREATE TABLE message_attachments (
                messageId TEXT, contentType TEXT, path TEXT, size INTEGER,
                width INTEGER, height INTEGER, fileName TEXT, plaintextHash TEXT,
                blurHash TEXT, caption TEXT, localKey TEXT{key_column}
            )
        """)
        columns = "messageId, contentType, path, size, fileName, plaintextHash"
        values = ["msg-att", "image/jpeg", "ab/modern.jpg", 11, "photo.jpg", db_plaintext_hash]
        if with_key_column:
            columns += ", key"
            values.append(self.remote_key_b64)
        placeholders = ",".join("?" * len(values))
        conn.execute(f"INSERT INTO message_attachments ({columns}) VALUES ({placeholders})", values)
        conn.commit()
        conn.close()

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

    def _attachment_locator(self, result: MappingResult):
        item = next(f.chatItem for f in _find_chat_items(result.frames) if f.chatItem.dateSent == 8000)
        assert len(item.standardMessage.attachments) == 1
        return item.standardMessage.attachments[0].pointer.locatorInfo

    def test_key_column_preserved_as_remote_key(self) -> None:
        self._create_message_attachments(with_key_column=True)
        result = self._map()

        locator = self._attachment_locator(result)
        assert locator.key == b"A" * 64
        assert len(locator.plaintextHash) == 32
        assert result.stats["attachments"] == 1

    def test_missing_key_column_generates_remote_key(self) -> None:
        self._create_message_attachments(with_key_column=False)
        result = self._map()

        locator = self._attachment_locator(result)
        assert len(locator.key) == 64
        assert len(locator.plaintextHash) == 32
        assert result.stats["attachments"] == 1

    @pytest.mark.validator
    @pytest.mark.parametrize("with_key_column", [True, False])
    def test_modern_attachment_frames_pass_libsignal_validator(
        self, validator: Callable[..., ValidationResult], with_key_column: bool
    ) -> None:
        self._create_message_attachments(with_key_column=with_key_column)

        _assert_validates(validator, self._map())

    def test_disagreeing_db_plaintext_hash_loses_to_file_hash(self) -> None:
        self._create_message_attachments(with_key_column=True, db_plaintext_hash="ab" * 32)
        result = self._map()

        locator = self._attachment_locator(result)
        assert locator.plaintextHash == hashlib.sha256(b"fake jpeg!!").digest()
        assert result.stats["plaintext_hash_mismatch"] == 1

    def test_agreeing_db_plaintext_hash_is_not_a_mismatch(self) -> None:
        file_hash = hashlib.sha256(b"fake jpeg!!").hexdigest()
        self._create_message_attachments(with_key_column=True, db_plaintext_hash=file_hash)
        result = self._map()

        assert self._attachment_locator(result).plaintextHash == bytes.fromhex(file_hash)
        assert result.stats["plaintext_hash_mismatch"] == 0

    @pytest.mark.validator
    def test_every_file_pointer_maps_to_an_encrypted_file_on_disk(
        self, validator: Callable[..., ValidationResult]
    ) -> None:
        self._create_message_attachments(with_key_column=True)
        result = self._map()
        _assert_validates(validator, result)

        locators = [
            att.pointer.locatorInfo
            for f in _find_chat_items(result.frames)
            for att in f.chatItem.standardMessage.attachments
        ] + [
            f.chatItem.standardMessage.longText.locatorInfo
            for f in _find_chat_items(result.frames)
            if f.chatItem.standardMessage.HasField("longText")
        ]
        assert locators
        expected = {
            hashlib.sha256(loc.plaintextHash + loc.localKey).hexdigest() for loc in locators
        }
        assert set(result.media_names) == expected
        for media_name in expected:
            assert (self.output_dir / media_name[:2] / media_name).is_file()

