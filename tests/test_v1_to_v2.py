"""Integration tests for v1-to-v2 conversion pipeline."""

from __future__ import annotations

import tempfile
from pathlib import Path


from signal_ark.proto.Backup_pb2 import BackupInfo, Frame
from signal_ark.v1_to_v2 import convert_v1_to_v2
from tests.test_v1_parser import build_synthetic_v1_backup, TEST_PASSPHRASE


def _make_seed() -> tuple[BackupInfo, Frame]:
    """Create minimal seed BackupInfo and AccountData frame."""
    info = BackupInfo()
    info.version = 1
    info.backupTimeMs = 1700000000000

    frame = Frame()
    frame.account.profileKey = b"\x00" * 32
    frame.account.givenName = "Test"
    frame.account.familyName = "User"
    frame.account.accountSettings.readReceipts = True

    return info, frame


def _build_v1_with_contacts_and_messages() -> bytes:
    """Build a synthetic v1 backup with realistic recipient + thread + sms tables."""
    sql_statements = [
        # Recipient table (modern schema)
        (
            "CREATE TABLE recipient ("
            "_id INTEGER PRIMARY KEY, "
            "aci TEXT, "
            "e164 TEXT, "
            "profile_joined_name TEXT, "
            "blocked INTEGER DEFAULT 0, "
            "group_id TEXT, "
            "group_type INTEGER DEFAULT 0"
            ")",
            [],
        ),
        ("INSERT INTO recipient VALUES (?, ?, ?, ?, ?, ?, ?)",
         [1, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "+15551234567", "Alice Smith", 0, None, 0]),
        ("INSERT INTO recipient VALUES (?, ?, ?, ?, ?, ?, ?)",
         [2, "11111111-2222-3333-4444-555555555555", "+15559876543", "Bob Jones", 0, None, 0]),
        # Thread table
        (
            "CREATE TABLE thread ("
            "_id INTEGER PRIMARY KEY, "
            "recipient_id INTEGER, "
            "archived INTEGER DEFAULT 0"
            ")",
            [],
        ),
        ("INSERT INTO thread VALUES (?, ?, ?)", [10, 1, 0]),
        ("INSERT INTO thread VALUES (?, ?, ?)", [20, 2, 0]),
        # SMS table
        (
            "CREATE TABLE sms ("
            "_id INTEGER PRIMARY KEY, "
            "thread_id INTEGER, "
            "address TEXT, "
            "type INTEGER, "
            "body TEXT, "
            "date INTEGER, "
            "date_received INTEGER, "
            "read INTEGER DEFAULT 0"
            ")",
            [],
        ),
        # Incoming from Alice
        ("INSERT INTO sms VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
         [100, 10, "1", 1, "Hello from Alice!", 1700000001000, 1700000001500, 1]),
        # Outgoing to Alice
        ("INSERT INTO sms VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
         [101, 10, "1", 23, "Hi Alice!", 1700000002000, 1700000002000, 1]),
        # Incoming from Bob
        ("INSERT INTO sms VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
         [102, 20, "2", 1, "Hey there", 1700000003000, 1700000003500, 0]),
    ]

    return build_synthetic_v1_backup(sql_statements=sql_statements)


def test_convert_basic_pipeline() -> None:
    """End-to-end: v1 backup with contacts + messages → v2 frames."""
    v1_data = _build_v1_with_contacts_and_messages()
    seed_info, seed_account = _make_seed()

    with tempfile.NamedTemporaryFile(suffix=".backup", delete=False) as f:
        f.write(v1_data)
        v1_path = Path(f.name)

    try:
        result = convert_v1_to_v2(
            v1_path=v1_path,
            v1_passphrase=TEST_PASSPHRASE,
            seed_backup_info=seed_info,
            seed_account_frame=seed_account,
            self_aci="00000000-0000-0000-0000-000000000000",
        )
    finally:
        v1_path.unlink()

    # Verify frame ordering: AccountData first
    assert result.frames[0].HasField("account")

    # Self recipient second
    assert result.frames[1].HasField("recipient")
    assert result.frames[1].recipient.HasField("self")

    # Stats
    assert result.stats["recipients"] == 2  # Alice + Bob
    assert result.stats["chats"] == 2
    assert result.stats["messages"] == 3

    # All recipients come before chats, chats before chatItems
    frame_types = [f.WhichOneof("item") for f in result.frames]
    first_chat = frame_types.index("chat")
    first_chat_item = frame_types.index("chatItem")
    last_recipient = len(frame_types) - 1 - frame_types[::-1].index("recipient")

    assert last_recipient < first_chat
    assert first_chat < first_chat_item


def test_convert_with_attachment() -> None:
    """v1 backup with inline attachment → v2 with re-encrypted file."""
    attachment_data = b"fake jpeg image data " * 100

    # Build v1 with mms table and part table referencing the attachment
    sql_statements = [
        ("CREATE TABLE recipient (_id INTEGER PRIMARY KEY, aci TEXT, e164 TEXT, "
         "profile_joined_name TEXT, blocked INTEGER DEFAULT 0, group_id TEXT, group_type INTEGER DEFAULT 0)", []),
        ("INSERT INTO recipient VALUES (?, ?, ?, ?, ?, ?, ?)",
         [1, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "+15551234567", "Alice", 0, None, 0]),
        ("CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER, archived INTEGER DEFAULT 0)", []),
        ("INSERT INTO thread VALUES (?, ?, ?)", [10, 1, 0]),
        ("CREATE TABLE mms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, "
         "type INTEGER, body TEXT, date INTEGER, date_received INTEGER, read INTEGER DEFAULT 0)", []),
        ("INSERT INTO mms VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
         [200, 10, "1", 1, "Check this photo", 1700000010000, 1700000010500, 1]),
        ("CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER, unique_id INTEGER, "
         "ct TEXT, data_size INTEGER)", []),
        ("INSERT INTO part VALUES (?, ?, ?, ?, ?)", [1, 200, 100, "image/jpeg", len(attachment_data)]),
    ]

    v1_data = build_synthetic_v1_backup(
        sql_statements=sql_statements,
        attachment_data=attachment_data,
    )
    seed_info, seed_account = _make_seed()

    with tempfile.NamedTemporaryFile(suffix=".backup", delete=False) as f:
        f.write(v1_data)
        v1_path = Path(f.name)

    with tempfile.TemporaryDirectory() as tmpdir:
        files_dir = Path(tmpdir) / "files"

        try:
            result = convert_v1_to_v2(
                v1_path=v1_path,
                v1_passphrase=TEST_PASSPHRASE,
                seed_backup_info=seed_info,
                seed_account_frame=seed_account,
                self_aci="00000000-0000-0000-0000-000000000000",
                output_files_dir=files_dir,
            )
        finally:
            v1_path.unlink()

    assert result.stats["recipients"] == 1
    assert result.stats["chats"] == 1
    assert result.stats["messages"] == 1
    assert result.stats["v1_attachments"] == 1


def test_convert_empty_backup() -> None:
    """v1 backup with no data → only AccountData + Self frames."""
    v1_data = build_synthetic_v1_backup(sql_statements=[])
    seed_info, seed_account = _make_seed()

    with tempfile.NamedTemporaryFile(suffix=".backup", delete=False) as f:
        f.write(v1_data)
        v1_path = Path(f.name)

    try:
        result = convert_v1_to_v2(
            v1_path=v1_path,
            v1_passphrase=TEST_PASSPHRASE,
            seed_backup_info=seed_info,
            seed_account_frame=seed_account,
            self_aci="00000000-0000-0000-0000-000000000000",
        )
    finally:
        v1_path.unlink()

    assert result.stats["recipients"] == 0
    assert result.stats["chats"] == 0
    assert result.stats["messages"] == 0
    assert len(result.frames) == 2  # AccountData + Self


def test_convert_progress_callback() -> None:
    """Progress callback is invoked during conversion."""
    v1_data = _build_v1_with_contacts_and_messages()
    seed_info, seed_account = _make_seed()

    calls: list[tuple[str, int, int]] = []

    def callback(stage: str, done: int, skipped: int) -> None:
        calls.append((stage, done, skipped))

    with tempfile.NamedTemporaryFile(suffix=".backup", delete=False) as f:
        f.write(v1_data)
        v1_path = Path(f.name)

    try:
        convert_v1_to_v2(
            v1_path=v1_path,
            v1_passphrase=TEST_PASSPHRASE,
            seed_backup_info=seed_info,
            seed_account_frame=seed_account,
            self_aci="00000000-0000-0000-0000-000000000000",
            progress_callback=callback,
        )
    finally:
        v1_path.unlink()

    stages = [c[0] for c in calls]
    assert "v1 parsed" in stages
    assert "recipients mapped" in stages
    assert "messages mapped" in stages
