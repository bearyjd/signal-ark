"""End-to-end coverage for mapper guards: quote/body caps, attachment path
containment, orphaned group attachments, long-text routing, and decrypt
failure accounting."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from signal_ark.mapper import (
    MAX_BODY_BYTES_WITH_LONG_TEXT,
    MAX_QUOTE_BODY_BYTES,
    MappingResult,
    map_desktop_to_frames,
)
from signal_ark.proto.Backup_pb2 import Frame
from signal_ark.validate import ValidationResult

from tests.test_mapper_e2e import (
    ALICE_ACI,
    SELF_ACI,
    _assert_validates,
    _create_desktop_db,
    _find_chat_items,
    _seed_account_frame,
    _seed_backup_info,
)

LONG_TEXT_CONTENT_TYPE = "text/x-signal-plain"
MESSAGE_COLUMNS = "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?"


def _insert_message(
    db_path: Path,
    msg_id: str,
    body: str | None,
    sent_at: int,
    msg_json: dict,
    *,
    conv_id: str = "conv-alice",
) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        f"INSERT INTO messages VALUES ({MESSAGE_COLUMNS})",
        (msg_id, body, "incoming", sent_at, sent_at, sent_at, sent_at,
         conv_id, ALICE_ACI, None, 1, 0, None, None, json.dumps(msg_json)),
    )
    conn.commit()
    conn.close()


def _create_message_attachments_table(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE message_attachments (
            messageId TEXT, contentType TEXT, path TEXT, size INTEGER,
            width INTEGER, height INTEGER, fileName TEXT, plaintextHash TEXT,
            blurHash TEXT, caption TEXT, localKey TEXT
        )
    """)
    conn.commit()
    conn.close()


def _insert_attachment(
    db_path: Path,
    message_id: str,
    path: str,
    size: int,
    *,
    content_type: str = "image/jpeg",
    local_key: str | None = None,
) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO message_attachments (messageId, contentType, path, size, localKey)"
        " VALUES (?,?,?,?,?)",
        (message_id, content_type, path, size, local_key),
    )
    conn.commit()
    conn.close()


def _insert_group_conversation(db_path: Path, conv_id: str) -> None:
    conn = sqlite3.connect(str(db_path))
    conv_json = json.dumps({"masterKey": base64.b64encode(b"k" * 32).decode(), "name": "G"})
    conn.execute(
        "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
        (conv_id, conv_json, 5000, "group", None, None, None, None),
    )
    conn.commit()
    conn.close()


def _chat_item_at(frames: list[Frame], sent_at: int) -> Frame | None:
    return next((f for f in _find_chat_items(frames) if f.chatItem.dateSent == sent_at), None)


class TestMapperGuardsE2E:
    @pytest.fixture(autouse=True)
    def _workspace(self, tmp_path: Path) -> None:
        self.db_path = tmp_path / "desktop.sqlite"
        self.attachments_dir = tmp_path / "attachments"
        self.attachments_dir.mkdir()
        self.output_dir = tmp_path / "output_files"
        self.outside_file = tmp_path / "escape.bin"
        _create_desktop_db(self.db_path)

    def _map(self, *, with_output: bool = True) -> MappingResult:
        return map_desktop_to_frames(
            db_path=self.db_path,
            attachments_dir=self.attachments_dir,
            seed_backup_info=_seed_backup_info(),
            seed_account_frame=_seed_account_frame(),
            seed_frames=[],
            self_aci=SELF_ACI,
            output_files_dir=self.output_dir if with_output else None,
        )

    def _write_attachment(self, rel_path: str, data: bytes) -> None:
        target = self.attachments_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    # --- H1 ---

    @pytest.mark.validator
    def test_long_quote_is_trimmed_and_passes_validator(
        self, validator: Callable[..., ValidationResult]
    ) -> None:
        long_quote = "q" * (MAX_QUOTE_BODY_BYTES + 500)
        _insert_message(
            self.db_path, "msg-lq", "reply", 9000,
            {"quote": {"id": 1000, "authorAci": ALICE_ACI, "text": long_quote}},
        )

        result = self._map(with_output=False)

        item = _chat_item_at(result.frames, 9000)
        assert item is not None
        body = item.chatItem.standardMessage.quote.text.body
        assert len(body.encode("utf-8")) == MAX_QUOTE_BODY_BYTES
        _assert_validates(validator, result)

    # --- H2 ---

    def test_escaping_attachment_path_is_rejected(self) -> None:
        _create_message_attachments_table(self.db_path)
        self.outside_file.write_bytes(b"secret outside bytes")
        _insert_attachment(self.db_path, "msg-3", "../escape.bin", 20)

        result = self._map()

        assert result.stats["attachments_rejected_path"] == 1
        assert result.stats["attachments"] == 0
        assert result.media_names == []
        item = _chat_item_at(result.frames, 3000)
        assert item is not None
        assert len(item.chatItem.standardMessage.attachments) == 0
        assert not self.output_dir.exists() or not any(self.output_dir.rglob("*"))

    def test_missing_attachment_file_is_counted(self) -> None:
        _create_message_attachments_table(self.db_path)
        _insert_attachment(self.db_path, "msg-3", "ab/does-not-exist.bin", 20)

        result = self._map()

        assert result.stats["attachments_missing_file"] == 1
        assert result.stats["attachments"] == 0
        assert result.media_names == []

    # --- M2 / M3 ---

    def test_group_message_attachment_is_orphaned_not_written(self) -> None:
        _create_message_attachments_table(self.db_path)
        _insert_group_conversation(self.db_path, "conv-group")
        _insert_message(self.db_path, "msg-grp", "group photo", 9500, {}, conv_id="conv-group")
        self._write_attachment("ab/group.jpg", b"group jpeg bytes")
        _insert_attachment(self.db_path, "msg-grp", "ab/group.jpg", 16)

        result = self._map()

        assert result.stats["attachments_orphaned"] == 1
        assert result.stats["attachments"] == 0
        assert result.media_names == []
        assert not any(self.output_dir.rglob("*"))
        assert _chat_item_at(result.frames, 9500) is None

    # --- M4 ---

    @pytest.mark.validator
    def test_long_text_attachment_routes_to_long_text_and_validates(
        self, validator: Callable[..., ValidationResult]
    ) -> None:
        _create_message_attachments_table(self.db_path)
        full_body = "x" * 3000
        _insert_message(self.db_path, "msg-lt", full_body, 9100, {})
        self._write_attachment("cd/long.txt", full_body.encode("utf-8"))
        _insert_attachment(
            self.db_path, "msg-lt", "cd/long.txt", 3000, content_type=LONG_TEXT_CONTENT_TYPE
        )

        result = self._map()

        item = _chat_item_at(result.frames, 9100)
        assert item is not None
        std = item.chatItem.standardMessage
        assert std.HasField("longText")
        assert std.longText.contentType == LONG_TEXT_CONTENT_TYPE
        assert len(std.attachments) == 0
        assert len(std.text.body.encode("utf-8")) <= MAX_BODY_BYTES_WITH_LONG_TEXT
        assert result.stats["attachments"] == 1
        assert result.stats["long_text_without_body"] == 0
        _assert_validates(validator, result)

    def test_long_text_attachment_without_body_is_dropped(self) -> None:
        _create_message_attachments_table(self.db_path)
        _insert_message(self.db_path, "msg-lt-nb", None, 9200, {})
        self._write_attachment("cd/orphan.txt", b"y" * 3000)
        _insert_attachment(
            self.db_path, "msg-lt-nb", "cd/orphan.txt", 3000, content_type=LONG_TEXT_CONTENT_TYPE
        )

        result = self._map()

        assert result.stats["long_text_without_body"] == 1
        assert result.stats["attachments"] == 0
        assert result.media_names == []
        assert _chat_item_at(result.frames, 9200) is None

    # --- M7 ---

    def test_undecryptable_attachment_counts_failure_and_drops_message(self) -> None:
        _create_message_attachments_table(self.db_path)
        _insert_message(self.db_path, "msg-bad", None, 9300, {})
        self._write_attachment("ef/bad.bin", b"\x00" * 64)
        bad_key = base64.b64encode(b"z" * 64).decode()
        _insert_attachment(self.db_path, "msg-bad", "ef/bad.bin", 10, local_key=bad_key)

        result = self._map()

        assert result.stats["attachment_failures"] == 1
        assert result.stats["attachments"] == 0
        assert _chat_item_at(result.frames, 9300) is None

    def test_malformed_local_key_counts_failure_not_plaintext(self) -> None:
        _create_message_attachments_table(self.db_path)
        _insert_message(self.db_path, "msg-badkey", None, 9400, {})
        self._write_attachment("ef/badkey.bin", b"\x00" * 64)
        _insert_attachment(self.db_path, "msg-badkey", "ef/badkey.bin", 10, local_key="not base64!!")

        result = self._map()

        assert result.stats["attachment_failures"] == 1
        assert result.stats["attachments"] == 0
        assert result.media_names == []
        assert _chat_item_at(result.frames, 9400) is None

    # --- Manifest / frame agreement ---

    def test_media_names_match_every_file_pointer_exactly(self) -> None:
        _create_message_attachments_table(self.db_path)
        _insert_message(self.db_path, "msg-lt", "z" * 3000, 9100, {})
        self._write_attachment("cd/long.txt", b"z" * 3000)
        _insert_attachment(
            self.db_path, "msg-lt", "cd/long.txt", 3000, content_type=LONG_TEXT_CONTENT_TYPE
        )
        self._write_attachment("ab/photo.jpg", b"photo bytes")
        _insert_attachment(self.db_path, "msg-3", "ab/photo.jpg", 11)

        result = self._map()

        expected = set()
        for f in _find_chat_items(result.frames):
            std = f.chatItem.standardMessage
            locators = [a.pointer.locatorInfo for a in std.attachments]
            if std.HasField("longText"):
                locators.append(std.longText.locatorInfo)
            for loc in locators:
                expected.add(hashlib.sha256(loc.plaintextHash + loc.localKey).hexdigest())
        assert len(expected) == 2
        assert set(result.media_names) == expected
