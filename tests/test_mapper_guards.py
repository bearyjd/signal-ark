"""Unit tests for mapper input guards: body trimming, path containment,
decode/int coercion, and long-text routing."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from signal_ark.mapper import (
    MAX_BODY_BYTES,
    MAX_BODY_BYTES_WITH_LONG_TEXT,
    MAX_QUOTE_BODY_BYTES,
    IdAllocator,
    _attach_file_pointer_to_message,
    _b64_to_bytes,
    _build_message_attachment,
    _encrypt_attachment_row,
    _find_attachment_target,
    _has_column,
    _map_quote,
    _map_reactions,
    _resolve_attachment_source,
    _to_int,
    _trim_utf8,
    build_call_item,
    build_chat_item,
    build_self_recipient,
)
from signal_ark.proto.Backup_pb2 import Quote

SELF_ACI = "aci-self"
PLAINTEXT_HASH = hashlib.sha256(b"attachment bytes").digest()
LONG_TEXT_CONTENT_TYPE = "text/x-signal-plain"


def _make_ids() -> IdAllocator:
    ids = IdAllocator()
    build_self_recipient(ids, "conv-self", SELF_ACI)
    ids.alloc_recipient("conv-alice", service_id="aci-alice")
    ids.alloc_chat("conv-alice")
    return ids


def _make_msg_row(body: str | None = "hello", sent_at: int = 1000) -> dict:
    return {
        "id": "msg-1",
        "conversationId": "conv-alice",
        "type": "incoming",
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


def _att(content_type: str = "image/jpeg", **extra: object) -> dict:
    return {"messageId": "msg-1", "contentType": content_type, "size": 3, "sent_at": 1000, **extra}


# --- _trim_utf8 ---


def test_trim_utf8_keeps_text_at_limit() -> None:
    text = "a" * 2048
    assert _trim_utf8(text, 2048) == text


def test_trim_utf8_trims_to_limit() -> None:
    trimmed = _trim_utf8("a" * 2049, 2048)
    assert len(trimmed.encode("utf-8")) == 2048


def test_trim_utf8_drops_straddling_multibyte_char_whole() -> None:
    text = "a" * 2047 + "€" + "b"
    trimmed = _trim_utf8(text, 2048)
    assert trimmed == "a" * 2047
    assert len(trimmed.encode("utf-8")) <= 2048
    trimmed.encode("utf-8")


def test_trim_utf8_multibyte_within_limit_is_kept() -> None:
    text = "a" * 2045 + "€"
    assert _trim_utf8(text, 2048) == text


# --- H1: quote body cap ---


def test_map_quote_body_at_limit_is_kept() -> None:
    text = "q" * MAX_QUOTE_BODY_BYTES
    quote = _map_quote({"quote": {"id": 1, "authorAci": "aci-alice", "text": text}}, _make_ids())
    assert quote is not None
    assert quote.text.body == text


def test_map_quote_body_over_limit_is_trimmed() -> None:
    text = "q" * (MAX_QUOTE_BODY_BYTES + 1)
    quote = _map_quote({"quote": {"id": 1, "authorAci": "aci-alice", "text": text}}, _make_ids())
    assert quote is not None
    assert len(quote.text.body.encode("utf-8")) == MAX_QUOTE_BODY_BYTES


def test_map_quote_body_straddling_multibyte_is_valid_utf8() -> None:
    text = "q" * (MAX_QUOTE_BODY_BYTES - 1) + "\U0001f600"
    quote = _map_quote({"quote": {"id": 1, "authorAci": "aci-alice", "text": text}}, _make_ids())
    assert quote is not None
    assert quote.text.body == "q" * (MAX_QUOTE_BODY_BYTES - 1)


def test_map_quote_uses_enum_type() -> None:
    quote = _map_quote({"quote": {"id": 1, "authorAci": "aci-alice", "text": "x"}}, _make_ids())
    assert quote is not None
    assert quote.type == Quote.Type.NORMAL


# --- M4: body cap without long text ---


def test_chat_item_body_capped_at_max_body_bytes() -> None:
    frame = build_chat_item(_make_ids(), _make_msg_row(body="b" * (MAX_BODY_BYTES + 10)), {})
    assert frame is not None
    assert len(frame.chatItem.standardMessage.text.body.encode("utf-8")) == MAX_BODY_BYTES


# --- H2: _resolve_attachment_source ---


@pytest.mark.parametrize("rel_path", ["../x", "/etc/passwd", "a/../../x", "", None])
def test_resolve_attachment_source_rejects_escapes(tmp_path: Path, rel_path: str | None) -> None:
    assert _resolve_attachment_source(tmp_path / "attachments", rel_path) is None


def test_resolve_attachment_source_accepts_contained_path(tmp_path: Path) -> None:
    attachments_dir = tmp_path / "attachments"
    resolved = _resolve_attachment_source(attachments_dir, "ab/cd")
    assert resolved == (attachments_dir / "ab" / "cd").resolve()


# --- M6: decode / int guards ---


def test_b64_to_bytes_returns_empty_on_malformed_input() -> None:
    assert _b64_to_bytes("not base64!!") == b""
    assert _b64_to_bytes("A") == b""
    assert _b64_to_bytes(None) == b""


def test_b64_to_bytes_decodes_valid_input() -> None:
    assert _b64_to_bytes(base64.b64encode(b"ok").decode()) == b"ok"


def test_encrypt_attachment_row_local_key_without_size_is_failure(tmp_path: Path) -> None:
    src = tmp_path / "blob"
    src.write_bytes(b"\x00" * 32)
    local_key = base64.b64encode(b"k" * 64).decode()
    for size in (None, 0, "", "abc"):
        att = {"localKey": local_key, "size": size}
        assert _encrypt_attachment_row(att, src, tmp_path / "out") is None


def test_to_int_defaults_on_bad_values() -> None:
    assert _to_int(None) == 0
    assert _to_int("abc") == 0
    assert _to_int({}) == 0
    assert _to_int("abc", default=7) == 7


def test_to_int_coerces_valid_values() -> None:
    assert _to_int("5") == 5
    assert _to_int(6) == 6
    assert _to_int(7.9) == 7


def test_map_quote_non_numeric_id_leaves_target_unset() -> None:
    quote = _map_quote({"quote": {"id": "abc", "authorAci": "aci-alice", "text": "x"}}, _make_ids())
    assert quote is not None
    assert not quote.HasField("targetSentTimestamp")


def test_build_message_attachment_non_numeric_size_is_skipped() -> None:
    ma = _build_message_attachment(_att(size="huge"), "AAAA", PLAINTEXT_HASH)
    assert ma.pointer.locatorInfo.size == 0


def test_call_item_non_numeric_timestamp_defaults_to_zero() -> None:
    import sqlite3

    ids = _make_ids()
    conn = sqlite3.connect(":memory:")
    details = {"callId": "5", "callMode": "Direct", "wasIncoming": True, "acceptedTime": "soon"}
    row = {**_make_msg_row(body=None, sent_at=0), "type": "call-history"}
    frame = build_call_item(ids, row, {"callHistoryDetails": details}, conn, has_calls_table=False)
    assert frame is not None
    assert frame.chatItem.updateMessage.individualCall.startedCallTimestamp == 0


def test_map_reactions_null_timestamps_do_not_raise() -> None:
    msg_json = {"reactions": [{"emoji": "x", "fromId": "conv-alice", "timestamp": None, "receivedAtDate": None}]}
    reactions = _map_reactions(msg_json, _make_ids())
    assert len(reactions) == 1
    assert reactions[0].sentTimestamp == 0
    assert reactions[0].sortOrder == 0


# --- LOW: _has_column allowlist ---


def test_has_column_rejects_unknown_table_name() -> None:
    import sqlite3

    with pytest.raises(ValueError):
        _has_column(sqlite3.connect(":memory:"), "sqlite_master; DROP TABLE x", "name")


# --- LOW: IdAllocator.alias_service_id ---


def test_alias_service_id_maps_to_existing_recipient() -> None:
    ids = IdAllocator()
    rid = ids.alloc_recipient("conv-self", service_id="__self__")
    ids.alias_service_id("aci-real", rid)
    assert ids.service_id_to_recipient["aci-real"] == rid


# --- M3: _find_attachment_target never falls back to dateSent ---


def test_find_attachment_target_unindexed_message_id_returns_none() -> None:
    ids = _make_ids()
    frame = build_chat_item(ids, _make_msg_row(body="same time"), {})
    assert frame is not None
    assert _find_attachment_target([frame], _att(messageId="msg-other"), {"msg-1": 0}) is None


def test_find_attachment_target_missing_message_id_returns_none() -> None:
    ids = _make_ids()
    frame = build_chat_item(ids, _make_msg_row(body="same time"), {})
    assert frame is not None
    att = {k: v for k, v in _att().items() if k != "messageId"}
    assert _find_attachment_target([frame], att, {"msg-1": 0}) is None


def test_find_attachment_target_indexed_call_item_returns_none() -> None:
    import sqlite3

    ids = _make_ids()
    details = {"callId": "5", "callMode": "Direct", "wasIncoming": True, "acceptedTime": 1000}
    row = {**_make_msg_row(body=None), "type": "call-history"}
    frame = build_call_item(ids, row, {"callHistoryDetails": details}, sqlite3.connect(":memory:"), False)
    assert frame is not None
    assert _find_attachment_target([frame], _att(), {"msg-1": 0}) is None


# --- M4: long text routing ---


def test_long_text_attachment_becomes_long_text_pointer_and_trims_body() -> None:
    ids = _make_ids()
    frame = build_chat_item(ids, _make_msg_row(body="b" * 3000), {})
    assert frame is not None

    _attach_file_pointer_to_message(
        frame, _att(LONG_TEXT_CONTENT_TYPE, size=3000), "AAAA", ids, plaintext_hash=PLAINTEXT_HASH
    )

    std = frame.chatItem.standardMessage
    assert std.HasField("longText")
    assert std.longText.contentType == LONG_TEXT_CONTENT_TYPE
    assert std.longText.locatorInfo.plaintextHash == PLAINTEXT_HASH
    assert std.longText.locatorInfo.size == 3000
    assert len(std.attachments) == 0
    assert len(std.text.body.encode("utf-8")) == MAX_BODY_BYTES_WITH_LONG_TEXT


def test_regular_attachment_still_goes_to_attachments() -> None:
    ids = _make_ids()
    frame = build_chat_item(ids, _make_msg_row(body="b" * 3000), {})
    assert frame is not None

    _attach_file_pointer_to_message(frame, _att(), "AAAA", ids, plaintext_hash=PLAINTEXT_HASH)

    std = frame.chatItem.standardMessage
    assert not std.HasField("longText")
    assert len(std.attachments) == 1
    assert len(std.text.body) == 3000


def test_attach_file_pointer_creates_standard_message_with_reactions() -> None:
    ids = _make_ids()
    msg_json = {"reactions": [{"emoji": "\U0001f389", "fromId": "conv-alice", "timestamp": 1}]}
    frame = build_chat_item(ids, _make_msg_row(body=None), msg_json)
    assert frame is not None
    assert frame.chatItem.WhichOneof("item") is None

    _attach_file_pointer_to_message(
        frame, _att(json=json.dumps(msg_json)), "AAAA", ids, plaintext_hash=PLAINTEXT_HASH
    )

    std = frame.chatItem.standardMessage
    assert len(std.attachments) == 1
    assert [r.emoji for r in std.reactions] == ["\U0001f389"]


def test_attach_file_pointer_leaves_empty_frame_untouched_for_long_text() -> None:
    ids = _make_ids()
    frame = build_chat_item(ids, _make_msg_row(body=None), {})
    assert frame is not None

    _attach_file_pointer_to_message(
        frame, _att(LONG_TEXT_CONTENT_TYPE), "AAAA", ids, plaintext_hash=PLAINTEXT_HASH
    )

    assert frame.chatItem.WhichOneof("item") is None


# --- M6: malformed contact keys are left unset, not set to b"" ---


def test_contact_recipient_malformed_keys_are_left_unset() -> None:
    from signal_ark.mapper import build_contact_recipient

    conv = {"serviceId": "aci-alice", "profileKey": "not base64!!", "identityKey": "A"}
    frame = build_contact_recipient(IdAllocator(), conv, "conv-alice")

    assert frame is not None
    assert not frame.recipient.contact.HasField("profileKey")
    assert not frame.recipient.contact.HasField("identityKey")
