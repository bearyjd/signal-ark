"""Unit tests for group-chat support in the Desktop → v2 build path."""

from __future__ import annotations

import base64
import json
import sqlite3

import pytest

from signal_ark.mapping import (
    IdAllocator,
    build_call_item,
    build_chat_item,
    build_contact_recipient,
    build_group_recipient,
    build_self_recipient,
)
from signal_ark.mapping.desktop_db import _load_active_conversations, _load_group_sender_acis
from signal_ark.mapping.ids import _resolve_recipient_id
from signal_ark.mapping.pipeline import (
    _emit_chats,
    _emit_group_member_recipients,
    _emit_group_sender_recipients,
)
from signal_ark.mapping.recipients import build_member_recipient
from signal_ark.mapping.util import _normalize_aci, _uuid_str_to_bytes
from signal_ark.proto.Backup_pb2 import Frame

from tests.test_mapper import _make_call_db

SELF_ACI = "aaaaaaaa-1111-2222-3333-444444444444"
ALICE_ACI = "bbbbbbbb-1111-2222-3333-444444444444"
BOB_ACI = "cccccccc-1111-2222-3333-444444444444"
GHOST_ACI = "dddddddd-1111-2222-3333-444444444444"
MASTER_KEY_B64 = base64.b64encode(b"k" * 32).decode()


def _group_json(members: list[str], *, master_key: bool = True) -> dict:
    conv = {"name": "Group", "membersV2": [{"aci": m, "role": 1} for m in members]}
    if master_key:
        conv["masterKey"] = MASTER_KEY_B64
    return conv


def _make_ids() -> IdAllocator:
    ids = IdAllocator()
    build_self_recipient(ids, "conv-self", SELF_ACI)
    ids.alloc_recipient("conv-alice", service_id=ALICE_ACI)
    ids.alloc_chat("conv-alice")
    return ids


def _make_group_ids() -> IdAllocator:
    ids = _make_ids()
    build_group_recipient(ids, _group_json([SELF_ACI, ALICE_ACI]), "conv-group")
    ids.alloc_chat("conv-group")
    return ids


def _make_msg_row(conv_id: str, msg_type: str = "incoming", source: str | None = ALICE_ACI) -> dict:
    return {
        "id": "msg-1",
        "conversationId": conv_id,
        "type": msg_type,
        "body": "hello",
        "sent_at": 1000,
        "received_at": 1000,
        "received_at_ms": 1000,
        "timestamp": 1000,
        "sourceServiceId": source,
        "serverTimestamp": None,
        "readStatus": 1,
        "unidentifiedDeliveryReceived": False,
        "expireTimer": None,
        "expirationStartTimestamp": None,
        "json": "{}",
    }


def _make_conn(conversations: list[tuple[str, str, dict]], messages: list[tuple]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE conversations (id TEXT PRIMARY KEY, json TEXT, active_at INTEGER, type TEXT, serviceId TEXT)")
    conn.execute("CREATE TABLE messages (id TEXT PRIMARY KEY, type TEXT, conversationId TEXT, sourceServiceId TEXT)")
    for conv_id, conv_type, conv in conversations:
        conn.execute(
            "INSERT INTO conversations VALUES (?,?,?,?,?)",
            (conv_id, json.dumps(conv), 1, conv_type, conv.get("serviceId")),
        )
    for msg_id, conv_id, *source in messages:
        conn.execute("INSERT INTO messages VALUES (?,?,?,?)", (msg_id, "incoming", conv_id, source[0] if source else None))
    return conn


# --- _load_active_conversations ---


def test_load_active_conversations_includes_groups_with_messages_only() -> None:
    conn = _make_conn(
        [
            ("conv-self", "private", {"serviceId": SELF_ACI}),
            ("conv-alice", "private", {"serviceId": ALICE_ACI}),
            ("conv-group", "group", _group_json([SELF_ACI, ALICE_ACI])),
            ("conv-quiet-group", "group", _group_json([SELF_ACI])),
        ],
        [("m1", "conv-alice"), ("m2", "conv-group")],
    )

    active = {row["id"] for row in _load_active_conversations(conn, "conv-self")}

    assert active == {"conv-alice", "conv-group"}


# --- _emit_chats ---


def test_emit_chats_skips_group_without_recipient_and_counts_it() -> None:
    conn = _make_conn(
        [("conv-group", "group", _group_json([SELF_ACI], master_key=False))],
        [("m1", "conv-group")],
    )
    ids = _make_ids()
    frames: list[Frame] = []
    stats = {"chats": 0, "chats_without_recipient": 0}

    _emit_chats(conn, ids, frames, stats, "conv-self")

    assert frames == []
    assert stats == {"chats": 0, "chats_without_recipient": 1}
    assert "conv-group" not in ids.conversation_to_chat


# --- build_chat_item author resolution ---


def test_group_incoming_unresolved_author_returns_none() -> None:
    ids = _make_group_ids()

    frame = build_chat_item(ids, _make_msg_row("conv-group", source=BOB_ACI), {})

    assert frame is None


def test_group_incoming_resolved_author_uses_member_recipient() -> None:
    ids = _make_group_ids()
    member = build_member_recipient(ids, BOB_ACI)
    assert member is not None

    frame = build_chat_item(ids, _make_msg_row("conv-group", source=BOB_ACI), {})

    assert frame is not None
    assert frame.chatItem.authorId == member.recipient.id
    assert frame.chatItem.authorId != ids.conversation_to_recipient["conv-group"]


def test_private_incoming_unresolved_author_falls_back_to_conversation() -> None:
    ids = _make_ids()

    frame = build_chat_item(ids, _make_msg_row("conv-alice", source="unknown-aci"), {})

    assert frame is not None
    assert frame.chatItem.authorId == ids.conversation_to_recipient["conv-alice"]


def test_group_outgoing_send_status_skips_group_recipient() -> None:
    ids = _make_group_ids()
    msg_json = {
        "sendStateByConversationId": {
            "conv-alice": {"status": "Read", "updatedAt": 1100},
            "conv-group": {"status": "Sent", "updatedAt": 1100},
        }
    }

    frame = build_chat_item(ids, _make_msg_row("conv-group", msg_type="outgoing", source=None), msg_json)

    assert frame is not None
    recipients = [ss.recipientId for ss in frame.chatItem.outgoing.sendStatus]
    assert recipients == [ids.conversation_to_recipient["conv-alice"]]


# --- build_member_recipient ---


def test_build_member_recipient_shape_and_registration() -> None:
    ids = _make_ids()

    frame = build_member_recipient(ids, BOB_ACI)

    assert frame is not None
    contact = frame.recipient.contact
    assert contact.aci == _uuid_str_to_bytes(BOB_ACI)
    assert contact.HasField("registered")
    assert contact.profileGivenName == ""
    assert not contact.pni and not contact.e164
    assert ids.service_id_to_recipient[BOB_ACI] == frame.recipient.id


@pytest.mark.parametrize("aci", ["not-a-uuid", "abcd", "PNI:" + BOB_ACI, ""])
def test_build_member_recipient_malformed_aci_is_skipped(aci: str) -> None:
    ids = _make_ids()
    before = dict(ids.service_id_to_recipient)

    assert build_member_recipient(ids, aci) is None
    assert ids.service_id_to_recipient == before


# --- build_group_recipient ---


def test_build_group_recipient_registers_group_conversation() -> None:
    ids = _make_ids()

    build_group_recipient(ids, _group_json([SELF_ACI]), "conv-group")

    assert "conv-group" in ids.group_conversations


def test_build_group_recipient_skips_malformed_member_aci() -> None:
    ids = _make_ids()

    frame = build_group_recipient(ids, _group_json([SELF_ACI, "abcd"]), "conv-group")

    assert frame is not None
    members = [m.userId for m in frame.recipient.group.snapshot.members]
    assert members == [_uuid_str_to_bytes(SELF_ACI)]


# --- _emit_group_member_recipients ---


def test_emit_group_member_recipients_emits_only_unknown_members() -> None:
    conn = _make_conn(
        [
            ("conv-group", "group", _group_json([SELF_ACI, ALICE_ACI, BOB_ACI, "abcd"])),
            ("conv-keyless", "group", _group_json(["dddddddd-1111-2222-3333-444444444444"], master_key=False)),
        ],
        [],
    )
    ids = _make_ids()
    build_group_recipient(ids, _group_json([SELF_ACI, ALICE_ACI, BOB_ACI]), "conv-group")
    frames: list[Frame] = []
    stats = {"recipients": 0, "group_member_recipients": 0}

    _emit_group_member_recipients(conn, ids, frames, stats, SELF_ACI)

    assert [f.recipient.contact.aci for f in frames] == [_uuid_str_to_bytes(BOB_ACI)]
    assert stats == {"recipients": 1, "group_member_recipients": 1}


# --- _uuid_str_to_bytes ---


@pytest.mark.parametrize("value", ["abcd", "zz" * 16, ""])
def test_uuid_str_to_bytes_rejects_malformed(value: str) -> None:
    with pytest.raises(ValueError):
        _uuid_str_to_bytes(value)


def test_uuid_str_to_bytes_accepts_canonical_uuid() -> None:
    assert len(_uuid_str_to_bytes(BOB_ACI)) == 16


# --- ACI normalization (M1) ---


def test_normalize_aci_canonicalizes_case_and_rejects_malformed() -> None:
    assert _normalize_aci(BOB_ACI.upper()) == BOB_ACI
    assert _normalize_aci("abcd") is None
    assert _normalize_aci("PNI:" + BOB_ACI) is None
    assert _normalize_aci("") is None


def test_contact_recipient_resolves_by_either_aci_spelling() -> None:
    ids = IdAllocator()
    build_self_recipient(ids, "conv-self", SELF_ACI)
    frame = build_contact_recipient(ids, {"serviceId": ALICE_ACI.upper()}, "conv-alice")

    assert frame is not None
    assert ids.resolve_service_id(ALICE_ACI) == frame.recipient.id
    assert ids.resolve_service_id(ALICE_ACI.upper()) == frame.recipient.id


def test_member_recipient_is_keyed_on_canonical_aci() -> None:
    ids = _make_ids()

    frame = build_member_recipient(ids, BOB_ACI.upper())

    assert frame is not None
    assert ids.resolve_service_id(BOB_ACI) == frame.recipient.id
    assert ids.resolve_service_id(BOB_ACI.upper()) == frame.recipient.id


def test_emit_group_member_recipients_dedupes_by_canonical_aci() -> None:
    conn = _make_conn(
        [("conv-group", "group", _group_json([SELF_ACI.upper(), ALICE_ACI.upper(), BOB_ACI.upper()]))],
        [],
    )
    ids = _make_ids()
    build_group_recipient(ids, _group_json([SELF_ACI]), "conv-group")
    frames: list[Frame] = []
    stats = {"recipients": 0, "group_member_recipients": 0}

    _emit_group_member_recipients(conn, ids, frames, stats, SELF_ACI)

    assert [f.recipient.contact.aci for f in frames] == [_uuid_str_to_bytes(BOB_ACI)]


# --- Ringer guard (M2) ---


def test_resolve_recipient_id_never_returns_group_recipient() -> None:
    ids = _make_group_ids()

    assert _resolve_recipient_id(ids, "conv-group") == 0
    assert _resolve_recipient_id(ids, "conv-alice") == ids.conversation_to_recipient["conv-alice"]


def test_group_call_with_group_ringer_has_no_ringer_recipient() -> None:
    ids = _make_group_ids()
    conn = _make_call_db([{
        "callId": "10", "mode": "Group", "type": "Group", "direction": "Incoming",
        "status": "Joined", "timestamp": 8000, "ringerId": "conv-group",
    }])
    msg_row = _make_msg_row("conv-group", msg_type="call-history", source=None)

    frame = build_call_item(ids, msg_row, {"callId": "10"}, conn, has_calls_table=True)

    assert frame is not None
    assert not frame.chatItem.updateMessage.groupCall.HasField("ringerRecipientId")


# --- Former-member senders (M3) ---


def test_load_group_sender_acis_returns_distinct_group_senders() -> None:
    conn = _make_conn(
        [
            ("conv-alice", "private", {"serviceId": ALICE_ACI}),
            ("conv-group", "group", _group_json([SELF_ACI])),
        ],
        [("m1", "conv-alice", ALICE_ACI), ("m2", "conv-group", BOB_ACI), ("m3", "conv-group", BOB_ACI),
         ("m4", "conv-group", None), ("m5", "conv-group", GHOST_ACI)],
    )

    senders = _load_group_sender_acis(conn)

    assert sorted(senders) == sorted([("conv-group", BOB_ACI), ("conv-group", GHOST_ACI)])


def test_emit_group_sender_recipients_emits_unknown_senders_only() -> None:
    conn = _make_conn(
        [
            ("conv-group", "group", _group_json([SELF_ACI])),
            ("conv-keyless", "group", _group_json([SELF_ACI], master_key=False)),
        ],
        [("m1", "conv-group", ALICE_ACI), ("m2", "conv-group", GHOST_ACI.upper()),
         ("m3", "conv-group", SELF_ACI), ("m4", "conv-keyless", BOB_ACI)],
    )
    ids = _make_ids()
    build_group_recipient(ids, _group_json([SELF_ACI]), "conv-group")
    frames: list[Frame] = []
    stats = {"recipients": 0, "group_member_recipients": 0}

    _emit_group_sender_recipients(conn, ids, frames, stats, SELF_ACI)

    assert [f.recipient.contact.aci for f in frames] == [_uuid_str_to_bytes(GHOST_ACI)]
    assert stats == {"recipients": 1, "group_member_recipients": 1}
    assert ids.resolve_service_id(GHOST_ACI.upper()) == frames[0].recipient.id


def test_group_incoming_without_source_counts_unresolved_author() -> None:
    ids = _make_group_ids()
    stats = {"skipped_unresolved_author": 0}

    assert build_chat_item(ids, _make_msg_row("conv-group", source=None), {}, stats) is None
    assert stats["skipped_unresolved_author"] == 1


# --- Unknown message types (LOW) ---


def test_build_chat_item_unknown_type_returns_none() -> None:
    ids = _make_group_ids()

    assert build_chat_item(ids, _make_msg_row("conv-group", msg_type="group-v2-change"), {}) is None
