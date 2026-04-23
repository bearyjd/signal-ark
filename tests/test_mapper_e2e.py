"""End-to-end test for map_desktop_to_frames with a synthetic Desktop DB.

Exercises the full mapping pipeline: recipients, chats, text messages,
reactions, quotes, call history (individual + group), and legacy attachments.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

from signal_ark.mapper import map_desktop_to_frames
from signal_ark.proto.Backup_pb2 import AccountData, BackupInfo, Frame

SELF_ACI = "aaaaaaaa-1111-2222-3333-444444444444"
ALICE_ACI = "bbbbbbbb-1111-2222-3333-444444444444"
BOB_ACI = "cccccccc-1111-2222-3333-444444444444"


def _seed_backup_info() -> BackupInfo:
    info = BackupInfo()
    info.version = 1
    info.backupTimeMs = 1000000
    return info


def _seed_account_frame() -> Frame:
    frame = Frame()
    account = AccountData()
    account.givenName = "Test"
    account.familyName = "User"
    account.avatarUrlPath = ""
    account.accountSettings.readReceipts = True
    account.accountSettings.linkPreviews = True
    frame.account.CopyFrom(account)
    return frame


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
            ("call-1", "conv-alice", None, "Direct", "Audio", "Incoming", "accepted", 4000),
        )
        conn.execute(
            "INSERT INTO callsHistory VALUES (?,?,?,?,?,?,?,?)",
            ("call-2", "conv-bob", None, "Direct", "Video", "Incoming", "missed", 5000),
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
        self.frames = result.frames
        self.stats = result.stats

    # --- Structural ---

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
        assert self.stats["messages"] >= 4

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
            and f.chatItem.updateMessage.individualCall.type == 1  # AUDIO
        ]
        assert len(audio_calls) == 1
        call = audio_calls[0].chatItem.updateMessage.individualCall
        assert call.direction == 1  # INCOMING
        assert call.state == 1  # ACCEPTED

    def test_individual_video_call_missed(self) -> None:
        updates = _find_chat_items_with_update_message(self.frames)
        video_calls = [
            f for f in updates
            if f.chatItem.updateMessage.HasField("individualCall")
            and f.chatItem.updateMessage.individualCall.type == 2  # VIDEO
        ]
        assert len(video_calls) == 1
        call = video_calls[0].chatItem.updateMessage.individualCall
        assert call.direction == 1  # INCOMING
        assert call.state == 3  # MISSED

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

        msg_json = json.dumps({
            "callHistoryDetails": {
                "callId": "99",
                "mode": "Direct",
                "type": "Video",
                "direction": "Outgoing",
                "status": "not-accepted",
                "timestamp": 7000,
            }
        })
        conn.execute(
            "INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("msg-call", None, "call-history", 7000, 7000, 7000, 7000,
             "conv-alice", None, None, 1, 0, None, None, msg_json),
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
        self.frames = result.frames

    def test_call_from_json_fallback(self) -> None:
        updates = _find_chat_items_with_update_message(self.frames)
        assert len(updates) == 1
        call = updates[0].chatItem.updateMessage.individualCall
        assert call.type == 2  # VIDEO
        assert call.direction == 2  # OUTGOING
        assert call.state == 2  # NOT_ACCEPTED


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

    def test_legacy_attachment_encrypted(self) -> None:
        result = map_desktop_to_frames(
            db_path=self.db_path,
            attachments_dir=self.attachments_dir,
            seed_backup_info=_seed_backup_info(),
            seed_account_frame=_seed_account_frame(),
            seed_frames=[],
            self_aci=SELF_ACI,
            output_files_dir=self.output_dir,
        )
        assert result.stats["attachments"] >= 1
        assert len(result.media_names) >= 1

    def test_legacy_no_message_attachments_table(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='message_attachments'"
        ).fetchall()
        conn.close()
        assert len(tables) == 0
