"""Tests for mapper: reactions, quotes, call history, and legacy attachments."""

from __future__ import annotations

import json
import sqlite3

from signal_ark.mapper import (
    IdAllocator,
    _collect_legacy_attachments,
    _get_call_info,
    _has_table,
    _map_quote,
    _map_reactions,
    _resolve_recipient_id,
    build_call_item,
    build_chat_item,
)


# --- Helpers ---


def _make_ids() -> IdAllocator:
    ids = IdAllocator()
    ids.alloc_recipient("conv-self", service_id="__self__")
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


def test_map_reactions_unknown_author() -> None:
    ids = _make_ids()
    reactions = _map_reactions({"reactions": [{"emoji": "🔥", "fromId": "gone", "timestamp": 1}]}, ids)
    assert len(reactions) == 1
    assert reactions[0].authorId == 0


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


def test_map_quote_no_text() -> None:
    ids = _make_ids()
    msg_json = {"quote": {"id": 1, "authorAci": "aci-alice"}}
    quote = _map_quote(msg_json, ids)
    assert quote is not None
    assert quote.text.body == ""


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


def test_chat_item_reactions_only_no_body() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    msg_json = {"reactions": [{"emoji": "🎉", "fromId": "conv-alice", "timestamp": 1}]}
    msg_row = _make_msg_row(body=None)
    frame = build_chat_item(ids, msg_row, msg_json)

    assert frame is not None
    std = frame.chatItem.standardMessage
    assert std.text.body == ""
    assert len(std.reactions) == 1


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


def test_get_call_info_from_table() -> None:
    conn = _make_call_db([{
        "callId": "42", "mode": "Direct", "type": "Audio",
        "direction": "Incoming", "status": "accepted", "timestamp": 9000,
    }])
    info = _get_call_info({"callId": "42"}, conn, has_calls_table=True)
    assert info is not None
    assert info["mode"] == "Direct"
    assert info["status"] == "accepted"


def test_get_call_info_fallback_to_json() -> None:
    conn = _make_call_db()  # no callsHistory table
    msg_json = {
        "callHistoryDetails": {
            "callId": "99", "mode": "Direct", "type": "Video",
            "direction": "Outgoing", "status": "missed", "timestamp": 1234,
        }
    }
    info = _get_call_info(msg_json, conn, has_calls_table=False)
    assert info is not None
    assert info["type"] == "Video"
    assert info["status"] == "missed"


def test_get_call_info_no_data() -> None:
    conn = _make_call_db()
    assert _get_call_info({}, conn, has_calls_table=False) is None


def test_build_call_item_individual_audio() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    conn = _make_call_db([{
        "callId": "1", "mode": "Direct", "type": "Audio",
        "direction": "Incoming", "status": "accepted", "timestamp": 5000,
    }])
    msg_row = _make_msg_row(msg_type="call-history", body=None, sent_at=5000)
    msg_json = {"callId": "1"}

    frame = build_call_item(ids, msg_row, msg_json, conn, has_calls_table=True)
    assert frame is not None

    call = frame.chatItem.updateMessage.individualCall
    assert call.callId == 1
    assert call.type == 1  # AUDIO_CALL
    assert call.direction == 1  # INCOMING
    assert call.state == 1  # ACCEPTED
    assert call.startedCallTimestamp == 5000
    assert call.read is True


def test_build_call_item_individual_video_outgoing() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    conn = _make_call_db([{
        "callId": "2", "mode": "Direct", "type": "Video",
        "direction": "Outgoing", "status": "not-accepted", "timestamp": 6000,
    }])
    msg_row = _make_msg_row(msg_type="call-history", body=None, sent_at=6000)
    msg_json = {"callId": "2"}

    frame = build_call_item(ids, msg_row, msg_json, conn, has_calls_table=True)
    assert frame is not None

    call = frame.chatItem.updateMessage.individualCall
    assert call.type == 2  # VIDEO_CALL
    assert call.direction == 2  # OUTGOING
    assert call.state == 2  # NOT_ACCEPTED


def test_build_call_item_missed() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    conn = _make_call_db([{
        "callId": "3", "mode": "Direct", "type": "Audio",
        "direction": "Incoming", "status": "missed", "timestamp": 7000,
    }])
    msg_row = _make_msg_row(msg_type="call-history", body=None, sent_at=7000)
    frame = build_call_item(ids, msg_row, {"callId": "3"}, conn, has_calls_table=True)

    assert frame is not None
    assert frame.chatItem.updateMessage.individualCall.state == 3  # MISSED


def test_build_call_item_group_call() -> None:
    ids = _make_ids()
    ids.alloc_recipient("conv-group", service_id="group-aci")
    ids.alloc_chat("conv-group")

    conn = _make_call_db([{
        "callId": "10", "mode": "Group", "type": "Video",
        "direction": "Incoming", "status": "accepted",
        "timestamp": 8000, "ringerId": "aci-alice",
    }])
    msg_row = _make_msg_row(conv_id="conv-group", msg_type="call-history", body=None, sent_at=8000)
    frame = build_call_item(ids, msg_row, {"callId": "10"}, conn, has_calls_table=True)

    assert frame is not None
    gc = frame.chatItem.updateMessage.groupCall
    assert gc.callId == 10
    assert gc.state == 4  # ACCEPTED
    assert gc.ringerRecipientId == ids.service_id_to_recipient["aci-alice"]


def test_build_call_item_no_chat_returns_none() -> None:
    ids = _make_ids()
    conn = _make_call_db()
    msg_row = _make_msg_row(conv_id="no-chat", msg_type="call-history")
    assert build_call_item(ids, msg_row, {}, conn, has_calls_table=False) is None


def test_build_call_item_directionless() -> None:
    ids = _make_ids()
    ids.alloc_chat("conv-alice")

    conn = _make_call_db([{
        "callId": "5", "mode": "Direct", "type": "Audio",
        "direction": "Incoming", "status": "accepted", "timestamp": 1,
    }])
    msg_row = _make_msg_row(msg_type="call-history", body=None)
    frame = build_call_item(ids, msg_row, {"callId": "5"}, conn, has_calls_table=True)

    assert frame is not None
    assert frame.chatItem.HasField("directionless")


# --- _has_table ---


def test_has_table_exists() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE foo (id INTEGER)")
    assert _has_table(conn, "foo") is True


def test_has_table_missing() -> None:
    conn = sqlite3.connect(":memory:")
    assert _has_table(conn, "nonexistent") is False


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
