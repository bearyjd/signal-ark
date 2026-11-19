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


def _build_v1_with_contacts_and_messages(alice_aci: str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") -> bytes:
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
         [1, alice_aci, "+15551234567", "Alice Smith", 0, None, 0]),
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


def test_v1_attachment_pointer_carries_encrypt_attachment_contract() -> None:
    """The importer must wire encrypt_attachment's result into a FilePointer:
    without localKey/plaintextHash the content-store blob is unrecoverable."""
    import hashlib

    attachment_data = b"fake jpeg image data " * 100
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
    v1_data = build_synthetic_v1_backup(sql_statements=sql_statements, attachment_data=attachment_data)
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

        items = [f.chatItem for f in result.frames if f.HasField("chatItem")]
        attachments = [a for i in items for a in i.standardMessage.attachments]
        assert len(attachments) == 1
        pointer = attachments[0].pointer
        assert pointer.contentType == "image/jpeg"
        info = pointer.locatorInfo
        assert len(info.localKey) == 64
        assert info.plaintextHash == hashlib.sha256(attachment_data).digest()
        media_name = hashlib.sha256(info.plaintextHash + info.localKey).hexdigest()
        assert result.media_names == [media_name]
        assert (files_dir / media_name[:2] / media_name).exists()


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


def test_convert_malformed_recipient_aci_is_skipped_not_raised() -> None:
    v1_data = _build_v1_with_contacts_and_messages(alice_aci="abcd")
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

    alice = next(
        f.recipient.contact for f in result.frames
        if f.HasField("recipient") and f.recipient.HasField("contact") and f.recipient.contact.e164 == 15551234567
    )
    assert alice.aci == b""
    assert result.stats["recipients"] == 2


def _convert_v1_single_part(*, body: str | None, ct: str, data_size: int, data: bytes):
    """Convert a v1 backup holding one mms with one part; returns (result, files_dir listing)."""
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
         [200, 10, "1", 1, body, 1700000010000, 1700000010500, 1]),
        ("CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER, unique_id INTEGER, "
         "ct TEXT, data_size INTEGER)", []),
        ("INSERT INTO part VALUES (?, ?, ?, ?, ?)", [1, 200, 100, ct, data_size]),
    ]
    v1_data = build_synthetic_v1_backup(sql_statements=sql_statements, attachment_data=data)
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
        blobs = [p for p in files_dir.rglob("*") if p.is_file()] if files_dir.exists() else []
        return result, blobs


def test_v1_pointer_size_uses_actual_blob_length_not_stale_data_size() -> None:
    data = b"fake jpeg image data " * 100
    result, _ = _convert_v1_single_part(body="hi", ct="image/jpeg", data_size=12345, data=data)
    items = [f.chatItem for f in result.frames if f.HasField("chatItem")]
    pointer = items[0].standardMessage.attachments[0].pointer
    assert pointer.locatorInfo.size == len(data)


def test_v1_long_text_without_body_leaves_no_orphan_blob() -> None:
    data = b"long text payload " * 50
    result, blobs = _convert_v1_single_part(
        body=None, ct="text/x-signal-plain", data_size=len(data), data=data
    )
    assert blobs == []
    assert result.media_names == []
    assert result.stats["attachments"] == 0


def test_v1_long_text_with_body_sets_long_text_and_trims_body() -> None:
    data = b"long text payload " * 50
    body = "x" * 5000
    result, blobs = _convert_v1_single_part(
        body=body, ct="text/x-signal-plain", data_size=len(data), data=data
    )
    items = [f.chatItem for f in result.frames if f.HasField("chatItem")]
    std = items[0].standardMessage
    assert std.HasField("longText")
    assert len(std.text.body.encode()) < len(body)
    assert len(std.attachments) == 0
    assert len(blobs) == 1
    assert result.stats["attachments"] == 1


def test_v1_long_text_without_body_counts_stat() -> None:
    data = b"long text payload " * 50
    result, _ = _convert_v1_single_part(
        body=None, ct="text/x-signal-plain", data_size=len(data), data=data
    )
    assert result.stats["long_text_without_body"] == 1


def test_v1_thread_ids_do_not_collide_with_recipient_ids() -> None:
    """Thread _id keyspace must stay separate from v1 recipient _id keyspace.

    thread 1 -> recipient 2 and thread 2 -> recipient 1: aliasing thread ids
    into the recipient map would make thread 2 resolve to the wrong recipient.
    """
    alice = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    bob = "11111111-2222-3333-4444-555555555555"
    rec_ins = "INSERT INTO recipient VALUES (?, ?, ?, ?, ?, ?, ?)"
    sms_ins = "INSERT INTO sms VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    stmts = [
        ("CREATE TABLE recipient (_id INTEGER PRIMARY KEY, aci TEXT, e164 TEXT, "
         "profile_joined_name TEXT, blocked INTEGER DEFAULT 0, group_id TEXT, "
         "group_type INTEGER DEFAULT 0)", []),
        (rec_ins, [1, alice, "+15551234567", "Alice", 0, None, 0]),
        (rec_ins, [2, bob, "+15559876543", "Bob", 0, None, 0]),
        ("CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER, "
         "archived INTEGER DEFAULT 0)", []),
        ("INSERT INTO thread VALUES (?, ?, ?)", [1, 2, 0]),  # thread 1 -> Bob
        ("INSERT INTO thread VALUES (?, ?, ?)", [2, 1, 0]),  # thread 2 -> Alice
        ("CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, "
         "type INTEGER, body TEXT, date INTEGER, date_received INTEGER, "
         "read INTEGER DEFAULT 0)", []),
        (sms_ins, [100, 1, "2", 1, "from bob", 1700000001000, 1700000001000, 1]),
        (sms_ins, [101, 2, "1", 1, "from alice", 1700000002000, 1700000002000, 1]),
        (sms_ins, [102, 1, "2", 23, "to bob", 1700000003000, 1700000003000, 1]),
        (sms_ins, [103, 2, "1", 23, "to alice", 1700000004000, 1700000004000, 1]),
    ]
    seed_info, seed_account = _make_seed()
    with tempfile.NamedTemporaryFile(suffix=".backup", delete=False) as f:
        f.write(build_synthetic_v1_backup(sql_statements=stmts))
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

    rid_by_e164 = {
        f.recipient.contact.e164: f.recipient.id
        for f in result.frames
        if f.HasField("recipient") and f.recipient.HasField("contact")
    }
    alice_rid, bob_rid = rid_by_e164[15551234567], rid_by_e164[15559876543]
    chats = [f.chat for f in result.frames if f.HasField("chat")]
    # chats allocated in thread order: thread 1 (Bob), thread 2 (Alice)
    assert [c.recipientId for c in chats] == [bob_rid, alice_rid]
    items = {i.chatItem.dateSent: i.chatItem for i in result.frames if i.HasField("chatItem")}
    assert items[1700000001000].authorId == bob_rid
    assert items[1700000002000].authorId == alice_rid
    assert items[1700000003000].outgoing.sendStatus[0].recipientId == bob_rid
    assert items[1700000004000].outgoing.sendStatus[0].recipientId == alice_rid
