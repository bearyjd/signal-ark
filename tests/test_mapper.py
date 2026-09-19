"""Tests for mapper: reactions, quotes, call history, and legacy attachments."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from pathlib import Path

from signal_ark.mapper import (
    IdAllocator,
    _attach_file_pointer_to_message,
    _build_message_attachment,
    _collect_legacy_attachments,
    encrypt_attachment,
    _get_call_info,
    _has_column,
    _has_table,
    _map_quote,
    _map_reactions,
    _resolve_recipient_id,
    build_call_item,
    build_chat_item,
    build_self_recipient,
)
from signal_ark.proto.Backup_pb2 import Frame

SELF_ACI = "aci-self"


# --- Helpers ---


def _make_ids() -> IdAllocator:
    ids = IdAllocator()
    build_self_recipient(ids, "conv-self", SELF_ACI)
    ids.alloc_recipient("conv-alice", service_id="aci-alice")
    ids.alloc_recipient("conv-bob", service_id="aci-bob")
    return ids


def _make_msg_row(
    conv_id: str = "conv-alice",
    msg_type: str = "incoming",
    body: str | None = "hello",
    sent_at: int = 1000,
) -> dict:
    return {
        "id": "msg-1",
        "conversationId": conv_id,
        "type": msg_type,
        "body": body,
        "sent_at": sent_at,
        "received_at": sent_at,
        "received_at_ms": sent_at,
        "timestamp": sent_at,
        "sourceServiceId": "aci-alice",
        "serverTimestamp": None,
        "readStatus": 1,
        "unidentifiedDeliveryReceived": False,
        "expireTimer": None,
        "expirationStartTimestamp": None,
        "json": "{}",
    }


# --- _resolve_recipient_id ---


def test_resolve_by_service_id() -> None:
    ids = _make_ids()
    assert _resolve_recipient_id(ids, "aci-alice") == ids.service_id_to_recipient["aci-alice"]


def test_resolve_by_conversation_id() -> None:
    ids = _make_ids()
    assert _resolve_recipient_id(ids, "conv-bob") == ids.conversation_to_recipient["conv-bob"]


def test_resolve_unknown_returns_zero() -> None:
    ids = _make_ids()
    assert _resolve_recipient_id(ids, "unknown-id") == 0


def test_resolve_none_returns_zero() -> None:
    ids = _make_ids()
    assert _resolve_recipient_id(ids, None) == 0


# --- build_self_recipient ---


def test_self_recipient_registers_real_aci() -> None:
    ids = IdAllocator()
    frame = build_self_recipient(ids, "conv-self", SELF_ACI)
    rid = frame.recipient.id
    assert frame.recipient.HasField("self")
    assert ids.service_id_to_recipient["__self__"] == rid
    assert ids.service_id_to_recipient[SELF_ACI] == rid
    assert ids.conversation_to_recipient["conv-self"] == rid


def test_self_recipient_without_aci_still_registers_placeholder() -> None:
    ids = IdAllocator()
    frame = build_self_recipient(ids, "conv-self")
    assert ids.service_id_to_recipient["__self__"] == frame.recipient.id


def test_quote_of_own_message_resolves_to_self() -> None:
    ids = _make_ids()
    quote = _map_quote({"quote": {"id": 1, "authorAci": SELF_ACI, "text": "mine"}}, ids)
    assert quote is not None
    assert quote.authorId == ids.service_id_to_recipient["__self__"]
    assert quote.authorId != 0


# --- _map_reactions ---


def test_map_reactions_basic() -> None:
    ids = _make_ids()
    msg_json = {
        "reactions": [
            {"emoji": "👍", "fromId": "conv-alice", "timestamp": 2000},
            {"emoji": "❤️", "fromId": "aci-bob", "timestamp": 3000},
        ]
    }
    reactions = _map_reactions(msg_json, ids)
    assert len(reactions) == 2
    assert reactions[0].emoji == "👍"
    assert reactions[0].authorId == ids.conversation_to_recipient["conv-alice"]
    assert reactions[0].sentTimestamp == 2000
    assert reactions[1].emoji == "❤️"
    assert reactions[1].authorId == ids.service_id_to_recipient["aci-bob"]


def test_map_reactions_empty() -> None:
    ids = _make_ids()
    assert _map_reactions({}, ids) == []
    assert _map_reactions({"reactions": []}, ids) == []


def test_map_reactions_unknown_author_dropped() -> None:
    ids = _make_ids()
    msg_json = {
        "reactions": [
            {"emoji": "🔥", "fromId": "gone", "timestamp": 1},
            {"emoji": "👍", "fromId": "aci-bob", "timestamp": 2},
        ]
    }
    reactions = _map_reactions(msg_json, ids)
    assert len(reactions) == 1
    assert reactions[0].emoji == "👍"
    assert reactions[0].authorId == ids.service_id_to_recipient["aci-bob"]


def test_map_reactions_empty_emoji_dropped() -> None:
    ids = _make_ids()
    msg_json = {
        "reactions": [
            {"emoji": "", "fromId": "aci-bob", "timestamp": 1},
            {"fromId": "aci-bob", "timestamp": 2},
        ]
    }
    assert _map_reactions(msg_json, ids) == []


def test_map_reactions_sort_order_uses_received_at() -> None:
    ids = _make_ids()
    msg_json = {
        "reactions": [
            {"emoji": "👍", "fromId": "conv-alice", "timestamp": 100, "receivedAtDate": 200},
        ]
    }
    reactions = _map_reactions(msg_json, ids)
    assert reactions[0].sortOrder == 200


# --- _map_quote ---


def test_map_quote_basic() -> None:
    ids = _make_ids()
    msg_json = {
        "quote": {
            "id": 5000,
            "authorAci": "aci-alice",
            "text": "quoted text",
        }
    }
    quote = _map_quote(msg_json, ids)
    assert quote is not None
    assert quote.targetSentTimestamp == 5000
    assert quote.authorId == ids.service_id_to_recipient["aci-alice"]
    assert quote.text.body == "quoted text"
    assert quote.type == 1  # NORMAL


def test_map_quote_with_author_uuid_fallback() -> None:
    ids = _make_ids()
    msg_json = {"quote": {"id": 1, "authorUuid": "aci-bob", "text": "hi"}}
    quote = _map_quote(msg_json, ids)
    assert quote is not None
    assert quote.authorId == ids.service_id_to_recipient["aci-bob"]


def test_map_quote_no_text_no_attachments_dropped() -> None:
    ids = _make_ids()
    for quote_data in (
        {"id": 1, "authorAci": "aci-alice"},
        {"id": 1, "authorAci": "aci-alice", "text": ""},
        {"id": 1, "authorAci": "aci-alice", "text": None, "attachments": []},
    ):
        assert _map_quote({"quote": quote_data}, ids) is None


def test_map_quote_unknown_author_dropped() -> None:
    ids = _make_ids()
    msg_json = {"quote": {"id": 1, "authorAci": "gone", "text": "hi"}}
    assert _map_quote(msg_json, ids) is None
    assert _map_quote({"quote": {"id": 1, "text": "hi"}}, ids) is None


def test_map_quote_attachments_only() -> None:
    ids = _make_ids()
    msg_json = {
        "quote": {
            "id": 1,
            "authorAci": "aci-alice",
            "attachments": [
                {"contentType": "image/jpeg", "fileName": "pic.jpg", "thumbnail": {"path": "x"}},
                {"contentType": "audio/aac"},
            ],
        }
    }
    quote = _map_quote(msg_json, ids)
    assert quote is not None
    assert not quote.HasField("text")
    assert len(quote.attachments) == 2
    assert quote.attachments[0].contentType == "image/jpeg"
    assert quote.attachments[0].fileName == "pic.jpg"
    assert not quote.attachments[0].HasField("thumbnail")
    assert quote.attachments[1].contentType == "audio/aac"
    assert not quote.attachments[1].HasField("fileName")


def test_map_quote_referenced_message_not_found_leaves_target_unset() -> None:
    ids = _make_ids()
    msg_json = {
        "quote": {"id": 1, "authorAci": "aci-alice", "text": "hi", "referencedMessageNotFound": True}
    }
    quote = _map_quote(msg_json, ids)
    assert quote is not None
    assert not quote.HasField("targetSentTimestamp")
    assert quote.text.body == "hi"


def test_map_quote_absent() -> None:
    ids = _make_ids()
    assert _map_quote({}, ids) is None


# --- build_chat_item with reactions and quotes ---


def test_chat_item_with_reactions() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    msg_json = {
        "reactions": [
            {"emoji": "👍", "fromId": "conv-alice", "timestamp": 2000},
        ]
    }
    msg_row = _make_msg_row()
    frame = build_chat_item(ids, msg_row, msg_json)

    assert frame is not None
    std = frame.chatItem.standardMessage
    assert len(std.reactions) == 1
    assert std.reactions[0].emoji == "👍"


def test_chat_item_with_quote() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    msg_json = {"quote": {"id": 999, "authorAci": "aci-alice", "text": "original"}}
    msg_row = _make_msg_row()
    frame = build_chat_item(ids, msg_row, msg_json)

    assert frame is not None
    q = frame.chatItem.standardMessage.quote
    assert q.targetSentTimestamp == 999
    assert q.text.body == "original"


def test_chat_item_body_with_reactions_and_quote() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    msg_json = {
        "reactions": [{"emoji": "❤️", "fromId": "conv-alice", "timestamp": 1}],
        "quote": {"id": 500, "authorAci": "aci-bob", "text": "q"},
    }
    msg_row = _make_msg_row(body="reply text")
    frame = build_chat_item(ids, msg_row, msg_json)

    assert frame is not None
    std = frame.chatItem.standardMessage
    assert std.text.body == "reply text"
    assert len(std.reactions) == 1
    assert std.quote.targetSentTimestamp == 500


def test_chat_item_reactions_only_no_body_has_no_standard_message() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    msg_json = {"reactions": [{"emoji": "🎉", "fromId": "conv-alice", "timestamp": 1}]}
    msg_row = _make_msg_row(body=None)
    frame = build_chat_item(ids, msg_row, msg_json)

    assert frame is not None
    assert frame.chatItem.WhichOneof("item") is None


def test_chat_item_quote_only_no_body_keeps_standard_message() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    msg_json = {"quote": {"id": 7, "authorAci": "aci-bob", "text": "q"}}
    frame = build_chat_item(ids, _make_msg_row(body=None), msg_json)

    assert frame is not None
    std = frame.chatItem.standardMessage
    assert frame.chatItem.WhichOneof("item") == "standardMessage"
    assert not std.HasField("text")
    assert std.quote.targetSentTimestamp == 7


def test_chat_item_dropped_quote_and_no_body_has_no_standard_message() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    msg_json = {"quote": {"id": 7, "authorAci": "gone", "text": "q"}}
    frame = build_chat_item(ids, _make_msg_row(body=None), msg_json)

    assert frame is not None
    assert frame.chatItem.WhichOneof("item") is None


# --- Call history ---


def _make_call_db(calls: list[dict] | None = None) -> sqlite3.Connection:
    """Create an in-memory DB with conversations, messages, and optionally callsHistory."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    conn.execute("CREATE TABLE conversations (id TEXT, type TEXT, json TEXT, serviceId TEXT, active_at INTEGER)")
    conn.execute("CREATE TABLE messages (id TEXT, type TEXT, conversationId TEXT, sent_at INTEGER, json TEXT,"
                 " body TEXT, received_at INTEGER, received_at_ms INTEGER, timestamp INTEGER,"
                 " sourceServiceId TEXT, serverTimestamp INTEGER, readStatus INTEGER,"
                 " unidentifiedDeliveryReceived INTEGER, expireTimer INTEGER, expirationStartTimestamp INTEGER)")

    if calls is not None:
        conn.execute("CREATE TABLE callsHistory (callId TEXT, peerId TEXT, ringerId TEXT,"
                     " mode TEXT, type TEXT, direction TEXT, status TEXT, timestamp INTEGER)")
        for c in calls:
            conn.execute(
                "INSERT INTO callsHistory VALUES (?,?,?,?,?,?,?,?)",
                (c["callId"], c.get("peerId", ""), c.get("ringerId"),
                 c["mode"], c["type"], c["direction"], c["status"], c["timestamp"]),
            )

    return conn


def _direct_call(callId: str, status: str, direction: str = "Incoming",
                 call_type: str = "Audio", timestamp: int = 5000) -> dict:
    return {"callId": callId, "mode": "Direct", "type": call_type,
            "direction": direction, "status": status, "timestamp": timestamp}


def _build_direct_call(status: str, direction: str = "Incoming", call_type: str = "Audio"):
    ids = _make_ids()
    ids.alloc_chat("conv-alice")
    conn = _make_call_db([_direct_call("1", status, direction, call_type)])
    msg_row = _make_msg_row(msg_type="call-history", body=None, sent_at=5000)
    return build_call_item(ids, msg_row, {"callId": "1"}, conn, has_calls_table=True)


def test_get_call_info_from_table() -> None:
    conn = _make_call_db([_direct_call("42", "Accepted", timestamp=9000)])
    info = _get_call_info({"callId": "42"}, conn, has_calls_table=True)
    assert info is not None
    assert info["mode"] == "Direct"
    assert info["status"] == "Accepted"


def test_get_call_info_legacy_direct_normalized() -> None:
    conn = _make_call_db()
    msg_json = {
        "callHistoryDetails": {
            "callId": "99", "callMode": "Direct", "wasIncoming": False,
            "wasVideoCall": True, "wasDeclined": False,
            "acceptedTime": 1234, "endedTime": 1300,
        }
    }
    info = _get_call_info(msg_json, conn, has_calls_table=False)
    assert info is not None
    assert info["mode"] == "Direct"
    assert info["type"] == "Video"
    assert info["direction"] == "Outgoing"
    assert info["status"] == "Accepted"
    assert info["timestamp"] == 1234
    assert info["callId"] == "99"


def test_get_call_info_no_data() -> None:
    conn = _make_call_db()
    assert _get_call_info({}, conn, has_calls_table=False) is None


def test_build_call_item_individual_audio() -> None:
    frame = _build_direct_call("Accepted")
    assert frame is not None

    call = frame.chatItem.updateMessage.individualCall
    assert call.callId == 1
    assert call.type == 1  # AUDIO_CALL
    assert call.direction == 1  # INCOMING
    assert call.state == 1  # ACCEPTED
    assert call.startedCallTimestamp == 5000
    assert call.read is True


def test_build_call_item_individual_video_outgoing_declined() -> None:
    frame = _build_direct_call("Declined", direction="Outgoing", call_type="Video")
    assert frame is not None

    call = frame.chatItem.updateMessage.individualCall
    assert call.type == 2  # VIDEO_CALL
    assert call.direction == 2  # OUTGOING
    assert call.state == 2  # NOT_ACCEPTED


def test_build_call_item_missed() -> None:
    frame = _build_direct_call("Missed")
    assert frame is not None
    assert frame.chatItem.updateMessage.individualCall.state == 3  # MISSED


def test_build_call_item_missed_notification_profile() -> None:
    frame = _build_direct_call("MissedNotificationProfile")
    assert frame is not None
    assert frame.chatItem.updateMessage.individualCall.state == 4


def test_build_call_item_pending_depends_on_direction() -> None:
    incoming = _build_direct_call("Pending", direction="Incoming")
    outgoing = _build_direct_call("Pending", direction="Outgoing")
    assert incoming is not None and outgoing is not None
    assert incoming.chatItem.updateMessage.individualCall.state == 3  # MISSED
    assert outgoing.chatItem.updateMessage.individualCall.state == 2  # NOT_ACCEPTED


def test_build_call_item_deleted_skipped() -> None:
    assert _build_direct_call("Deleted") is None


def test_build_call_item_unknown_values_are_skipped() -> None:
    assert _build_direct_call("Whatever") is None
    assert _build_direct_call("Accepted", direction="Sideways") is None
    assert _build_direct_call("Accepted", call_type="Hologram") is None


def test_build_call_item_lowercase_status_is_not_matched() -> None:
    assert _build_direct_call("accepted") is None


def test_build_call_item_null_columns_are_safe() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")
    conn = _make_call_db([{"callId": "1", "mode": "Direct", "type": None,
                           "direction": None, "status": None, "timestamp": None}])
    msg_row = _make_msg_row(msg_type="call-history", body=None, sent_at=5000)
    assert build_call_item(ids, msg_row, {"callId": "1"}, conn, has_calls_table=True) is None


def test_build_call_item_adhoc_skipped() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")
    conn = _make_call_db([{"callId": "1", "mode": "Adhoc", "type": "Adhoc",
                           "direction": "Incoming", "status": "Joined", "timestamp": 5}])
    msg_row = _make_msg_row(msg_type="call-history", body=None, sent_at=5000)
    assert build_call_item(ids, msg_row, {"callId": "1"}, conn, has_calls_table=True) is None


def _build_group_call(status: str, ringer: str | None = "aci-alice"):
    ids = _make_ids()
    ids.alloc_recipient("conv-group")
    ids.alloc_chat("conv-group")
    conn = _make_call_db([{
        "callId": "10", "mode": "Group", "type": "Group",
        "direction": "Incoming", "status": status,
        "timestamp": 8000, "ringerId": ringer,
    }])
    msg_row = _make_msg_row(conv_id="conv-group", msg_type="call-history", body=None, sent_at=8000)
    return ids, build_call_item(ids, msg_row, {"callId": "10"}, conn, has_calls_table=True)


def test_build_call_item_group_call() -> None:
    ids, frame = _build_group_call("Accepted")
    assert frame is not None
    gc = frame.chatItem.updateMessage.groupCall
    assert gc.callId == 10
    assert gc.state == 4  # ACCEPTED
    assert gc.startedCallTimestamp == 8000
    assert gc.ringerRecipientId == ids.service_id_to_recipient["aci-alice"]


def test_build_call_item_group_call_states() -> None:
    expected = {
        "GenericGroupCall": 1, "Joined": 2, "Ringing": 3, "Accepted": 4,
        "Declined": 5, "Missed": 6, "MissedNotificationProfile": 7,
        "OutgoingRing": 8,
    }
    for status, state in expected.items():
        _, frame = _build_group_call(status)
        assert frame is not None, status
        assert frame.chatItem.updateMessage.groupCall.state == state, status
    for status in ("generic", "Bogus"):
        _, frame = _build_group_call(status)
        assert frame is None, status


def test_build_call_item_group_call_deleted_skipped() -> None:
    _, frame = _build_group_call("Deleted")
    assert frame is None


def test_build_call_item_no_chat_returns_none() -> None:
    ids = _make_ids()
    conn = _make_call_db()
    msg_row = _make_msg_row(conv_id="no-chat", msg_type="call-history")
    assert build_call_item(ids, msg_row, {}, conn, has_calls_table=False) is None


def test_build_call_item_directionless() -> None:
    frame = _build_direct_call("Accepted")
    assert frame is not None
    assert frame.chatItem.HasField("directionless")
    assert frame.chatItem.authorId == _make_ids().service_id_to_recipient["__self__"]


# --- Legacy callHistoryDetails ---


def _build_legacy_call(details: dict, conv_id: str = "conv-alice", sent_at: int = 7000):
    ids = _make_ids()
    if conv_id != "conv-alice":
        ids.alloc_recipient(conv_id)
    ids.alloc_chat(conv_id)
    conn = _make_call_db()
    msg_row = _make_msg_row(conv_id=conv_id, msg_type="call-history", body=None, sent_at=sent_at)
    return ids, build_call_item(ids, msg_row, {"callHistoryDetails": details}, conn, has_calls_table=False)


def test_legacy_call_accepted_incoming_audio() -> None:
    _, frame = _build_legacy_call({
        "callId": "11", "callMode": "Direct", "wasIncoming": True, "wasVideoCall": False,
        "wasDeclined": False, "acceptedTime": 6500, "endedTime": 6900,
    })
    assert frame is not None
    call = frame.chatItem.updateMessage.individualCall
    assert call.callId == 11
    assert call.type == 1  # AUDIO
    assert call.direction == 1  # INCOMING
    assert call.state == 1  # ACCEPTED
    assert call.startedCallTimestamp == 6500


def test_legacy_call_declined_outgoing_video() -> None:
    _, frame = _build_legacy_call({
        "callId": "12", "callMode": "Direct", "wasIncoming": False, "wasVideoCall": True,
        "wasDeclined": True, "endedTime": 6900,
    })
    assert frame is not None
    call = frame.chatItem.updateMessage.individualCall
    assert call.type == 2  # VIDEO
    assert call.direction == 2  # OUTGOING
    assert call.state == 2  # NOT_ACCEPTED
    assert call.startedCallTimestamp == 6900


def test_legacy_call_missed_incoming() -> None:
    _, frame = _build_legacy_call({
        "callId": "13", "callMode": "Direct", "wasIncoming": True, "wasVideoCall": False,
        "wasDeclined": False,
    })
    assert frame is not None
    call = frame.chatItem.updateMessage.individualCall
    assert call.direction == 1
    assert call.state == 3  # MISSED
    assert call.startedCallTimestamp == 7000  # falls back to the message row


def test_legacy_call_without_call_mode_is_direct() -> None:
    _, frame = _build_legacy_call({
        "callId": "14", "wasIncoming": True, "wasVideoCall": True, "wasDeclined": False,
        "acceptedTime": 6600,
    })
    assert frame is not None
    assert frame.chatItem.updateMessage.HasField("individualCall")
    call = frame.chatItem.updateMessage.individualCall
    assert call.type == 2
    assert call.state == 1


def test_legacy_group_call() -> None:
    ids, frame = _build_legacy_call(
        {"callMode": "Group", "creatorUuid": "aci-alice", "eraId": "era", "startedTime": 6400},
        conv_id="conv-group",
    )
    assert frame is not None
    gc = frame.chatItem.updateMessage.groupCall
    assert not gc.HasField("callId")
    assert gc.state == 1  # GENERIC
    assert gc.startedCallTimestamp == 6400
    assert gc.ringerRecipientId == ids.service_id_to_recipient["aci-alice"]


def test_legacy_group_call_started_time_fallback() -> None:
    _, frame = _build_legacy_call(
        {"callMode": "Group", "creatorUuid": "gone", "eraId": "era"},
        conv_id="conv-group",
    )
    assert frame is not None
    gc = frame.chatItem.updateMessage.groupCall
    assert gc.startedCallTimestamp == 7000
    assert not gc.HasField("ringerRecipientId")


# --- _attach_file_pointer_to_message ---


PLAINTEXT_HASH = hashlib.sha256(b"attachment bytes").digest()


def _att(sent_at: int, message_id: str | None = None) -> dict:
    att = {"contentType": "image/jpeg", "fileName": "p.jpg", "size": 3, "sent_at": sent_at}
    if message_id is not None:
        att["messageId"] = message_id
    return att


# --- FilePointer locator integrity (libsignal requires plaintextHash + key) ---


def test_build_message_attachment_sets_plaintext_hash_and_key() -> None:
    ma = _build_message_attachment(_att(5000), "AAAA", PLAINTEXT_HASH)

    locator = ma.pointer.locatorInfo
    assert locator.plaintextHash == PLAINTEXT_HASH
    assert locator.WhichOneof("integrityCheck") == "plaintextHash"
    assert len(locator.key) == 64
    assert locator.localKey == base64.b64decode("AAAA")


def test_build_message_attachment_preserves_desktop_remote_key() -> None:
    remote_key = os.urandom(64)
    att = {**_att(5000), "key": base64.b64encode(remote_key).decode()}

    ma = _build_message_attachment(att, "AAAA", PLAINTEXT_HASH)

    assert ma.pointer.locatorInfo.key == remote_key


def test_build_message_attachment_falls_back_when_desktop_key_wrong_length() -> None:
    att = {**_att(5000), "key": base64.b64encode(os.urandom(32)).decode()}

    ma = _build_message_attachment(att, "AAAA", PLAINTEXT_HASH)

    assert len(ma.pointer.locatorInfo.key) == 64
    assert ma.pointer.locatorInfo.key != base64.b64decode(att["key"])


def test_build_message_attachment_falls_back_when_desktop_key_malformed() -> None:
    att = {**_att(5000), "key": "not base64!!"}

    ma = _build_message_attachment(att, "AAAA", PLAINTEXT_HASH)

    assert len(ma.pointer.locatorInfo.key) == 64


def test_encrypt_attachment_computed_hash_wins_over_disagreeing_db_hash(tmp_path: Path) -> None:
    src = tmp_path / "plain.bin"
    src.write_bytes(b"attachment bytes")

    result = encrypt_attachment(src, tmp_path / "out", db_plaintext_hash="ab" * 32)

    assert result is not None
    assert result.plaintext_hash == PLAINTEXT_HASH
    assert result.plaintext_hash_mismatch is True
    local_key = base64.b64decode(result.local_key_b64)
    assert result.media_name == hashlib.sha256(PLAINTEXT_HASH + local_key).hexdigest()


def test_encrypt_attachment_agreeing_db_hash_is_not_a_mismatch(tmp_path: Path) -> None:
    src = tmp_path / "plain.bin"
    src.write_bytes(b"attachment bytes")

    result = encrypt_attachment(src, tmp_path / "out", db_plaintext_hash=PLAINTEXT_HASH.hex())

    assert result is not None
    assert result.plaintext_hash_mismatch is False


def test_encrypt_attachment_malformed_db_hash_does_not_raise(tmp_path: Path) -> None:
    src = tmp_path / "plain.bin"
    src.write_bytes(b"attachment bytes")

    result = encrypt_attachment(src, tmp_path / "out", db_plaintext_hash="not-hex")

    assert result is not None
    assert result.plaintext_hash == PLAINTEXT_HASH
    assert result.plaintext_hash_mismatch is True


def test_encrypt_attachment_returns_plaintext_hash_used_for_media_name(tmp_path: Path) -> None:
    src = tmp_path / "plain.bin"
    src.write_bytes(b"attachment bytes")

    result = encrypt_attachment(src, tmp_path / "out")

    assert result is not None
    assert result.plaintext_hash == PLAINTEXT_HASH
    local_key = base64.b64decode(result.local_key_b64)
    assert result.media_name == hashlib.sha256(PLAINTEXT_HASH + local_key).hexdigest()


def test_collect_legacy_attachments_includes_remote_key() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE messages (id TEXT, type TEXT, sent_at INTEGER, json TEXT)")
    att_json = json.dumps({"attachments": [{"path": "ab/f.jpg", "key": "c2VjcmV0"}]})
    conn.execute("INSERT INTO messages VALUES (?, ?, ?, ?)", ("m1", "incoming", 1000, att_json))

    result = _collect_legacy_attachments(conn)

    assert result[0]["key"] == "c2VjcmV0"


def test_attach_file_pointer_skips_call_item_with_same_date_sent() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")
    conn = _make_call_db([_direct_call("1", "Accepted", timestamp=5000)])
    call_row = _make_msg_row(msg_type="call-history", body=None, sent_at=5000)
    call_frame = build_call_item(ids, call_row, {"callId": "1"}, conn, has_calls_table=True)
    std_frame = build_chat_item(ids, _make_msg_row(body="photo", sent_at=5000), {})
    assert call_frame is not None and std_frame is not None
    frames = [call_frame, std_frame]

    _attach_file_pointer_to_message(
        frames, _att(5000), "AAAA", "ab" * 32, ids, plaintext_hash=PLAINTEXT_HASH
    )

    assert frames[0].chatItem.WhichOneof("item") == "updateMessage"
    assert frames[0].chatItem.updateMessage.HasField("individualCall")
    assert len(frames[1].chatItem.standardMessage.attachments) == 1


def test_attach_file_pointer_uses_message_id_index() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")
    first = build_chat_item(ids, _make_msg_row(body="first", sent_at=5000), {})
    second = build_chat_item(ids, _make_msg_row(body="second", sent_at=5000), {})
    assert first is not None and second is not None
    frames = [Frame(), first, second]

    _attach_file_pointer_to_message(
        frames,
        _att(5000, "m2"),
        "AAAA",
        "ab" * 32,
        ids,
        frame_index={"m1": 1, "m2": 2},
        plaintext_hash=PLAINTEXT_HASH,
    )

    assert len(frames[1].chatItem.standardMessage.attachments) == 0
    assert len(frames[2].chatItem.standardMessage.attachments) == 1


def test_attach_file_pointer_creates_standard_message_with_reactions() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")
    msg_json = {"reactions": [{"emoji": "🎉", "fromId": "conv-alice", "timestamp": 1}]}
    frame = build_chat_item(ids, _make_msg_row(body=None, sent_at=5000), msg_json)
    assert frame is not None
    assert frame.chatItem.WhichOneof("item") is None
    frames = [frame]

    att = {**_att(5000), "json": json.dumps(msg_json)}
    _attach_file_pointer_to_message(
        frames, att, "AAAA", "ab" * 32, ids, plaintext_hash=PLAINTEXT_HASH
    )

    std = frames[0].chatItem.standardMessage
    assert len(std.attachments) == 1
    assert len(std.reactions) == 1
    assert std.reactions[0].emoji == "🎉"


# --- _has_table ---


def test_has_table_exists() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE foo (id INTEGER)")
    assert _has_table(conn, "foo") is True


def test_has_table_missing() -> None:
    conn = sqlite3.connect(":memory:")
    assert _has_table(conn, "nonexistent") is False


def test_has_column_detects_presence_and_absence() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE message_attachments (path TEXT, localKey TEXT)")
    assert _has_column(conn, "message_attachments", "localKey") is True
    assert _has_column(conn, "message_attachments", "key") is False
    assert _has_column(conn, "no_such_table", "key") is False


# --- Legacy attachments ---


def test_collect_legacy_attachments() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE messages (id TEXT, type TEXT, sent_at INTEGER, json TEXT)")

    att_json = json.dumps({
        "attachments": [
            {"path": "ab/file1.jpg", "contentType": "image/jpeg", "size": 100, "fileName": "photo.jpg"},
            {"path": "cd/file2.png", "contentType": "image/png", "size": 200},
        ]
    })
    conn.execute("INSERT INTO messages VALUES (?, ?, ?, ?)", ("m1", "incoming", 1000, att_json))

    no_att_json = json.dumps({"body": "text only"})
    conn.execute("INSERT INTO messages VALUES (?, ?, ?, ?)", ("m2", "outgoing", 2000, no_att_json))

    result = _collect_legacy_attachments(conn)
    assert len(result) == 2
    assert result[0]["path"] == "ab/file1.jpg"
    assert result[0]["contentType"] == "image/jpeg"
    assert result[0]["sent_at"] == 1000
    assert result[1]["path"] == "cd/file2.png"


def test_collect_legacy_attachments_skips_no_path() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE messages (id TEXT, type TEXT, sent_at INTEGER, json TEXT)")

    att_json = json.dumps({"attachments": [{"contentType": "image/jpeg", "size": 100}]})
    conn.execute("INSERT INTO messages VALUES (?, ?, ?, ?)", ("m1", "incoming", 1000, att_json))

    result = _collect_legacy_attachments(conn)
    assert len(result) == 0


def test_collect_legacy_attachments_skips_call_history() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE messages (id TEXT, type TEXT, sent_at INTEGER, json TEXT)")

    att_json = json.dumps({"attachments": [{"path": "x/y.jpg"}]})
    conn.execute("INSERT INTO messages VALUES (?, ?, ?, ?)", ("m1", "call-history", 1000, att_json))

    result = _collect_legacy_attachments(conn)
    assert len(result) == 0
