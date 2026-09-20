"""Build call-history ChatItem frames from Desktop callsHistory rows or legacy message JSON."""

from __future__ import annotations

import sqlite3

from signal_ark.mapping.ids import IdAllocator, _resolve_recipient_id
from signal_ark.mapping.util import _to_int
from signal_ark.proto.Backup_pb2 import (
    ChatItem,
    Frame,
    GroupCall,
    IndividualCall,
)

_CALL_TYPES = {
    "Audio": IndividualCall.Type.AUDIO_CALL,
    "Video": IndividualCall.Type.VIDEO_CALL,
}
_CALL_DIRECTIONS = {
    "Incoming": IndividualCall.Direction.INCOMING,
    "Outgoing": IndividualCall.Direction.OUTGOING,
}
_INDIVIDUAL_CALL_STATES = {
    "Accepted": IndividualCall.State.ACCEPTED,
    "Declined": IndividualCall.State.NOT_ACCEPTED,
    "Missed": IndividualCall.State.MISSED,
    "MissedNotificationProfile": IndividualCall.State.MISSED_NOTIFICATION_PROFILE,
}
_GROUP_CALL_STATES = {
    "GenericGroupCall": GroupCall.State.GENERIC,
    "Joined": GroupCall.State.JOINED,
    "Ringing": GroupCall.State.RINGING,
    "Accepted": GroupCall.State.ACCEPTED,
    "Declined": GroupCall.State.DECLINED,
    "Missed": GroupCall.State.MISSED,
    "MissedNotificationProfile": GroupCall.State.MISSED_NOTIFICATION_PROFILE,
    "OutgoingRing": GroupCall.State.OUTGOING_RING,
}
_CALL_STATUS_DELETED = "Deleted"


def _normalize_legacy_call(details: dict, msg_row: dict | None) -> dict:
    """Convert pre-callsHistory ``callHistoryDetails`` JSON into the modern
    callsHistory row shape (mirrors Desktop migration 89-call-history)."""
    sent_at = (msg_row or {}).get("sent_at") or (msg_row or {}).get("timestamp") or 0

    if details.get("callMode") == "Group" or "startedTime" in details:
        return {
            "callId": details.get("callId"),
            "mode": "Group",
            "direction": "Incoming",
            "status": "GenericGroupCall",
            "timestamp": details.get("startedTime") or sent_at,
            "ringerId": details.get("creatorUuid"),
        }

    accepted_time = details.get("acceptedTime")
    if accepted_time is not None:
        status = "Accepted"
    elif details.get("wasDeclined"):
        status = "Declined"
    else:
        status = "Missed"

    return {
        "callId": details.get("callId"),
        "mode": "Direct",
        "type": "Video" if details.get("wasVideoCall") else "Audio",
        "direction": "Incoming" if details.get("wasIncoming") else "Outgoing",
        "status": status,
        "timestamp": accepted_time or details.get("endedTime") or sent_at,
        "ringerId": None,
    }


def _get_call_info(
    msg_json: dict,
    conn: sqlite3.Connection,
    has_calls_table: bool,
    msg_row: dict | None = None,
) -> dict | None:
    """Look up call details from callsHistory table or message JSON fallback."""
    call_id = msg_json.get("callId")
    if call_id and has_calls_table:
        row = conn.execute(
            "SELECT callId, peerId, ringerId, mode, type, direction, status, timestamp"
            " FROM callsHistory WHERE callId = ?",
            (str(call_id),),
        ).fetchone()
        if row:
            return dict(row)

    details = msg_json.get("callHistoryDetails")
    if not details:
        return None
    return _normalize_legacy_call(details, msg_row)


def _individual_call_state(status: str | None, direction: str | None) -> int:
    if status == "Pending":
        if direction == "Incoming":
            return IndividualCall.State.MISSED
        return IndividualCall.State.NOT_ACCEPTED
    return _INDIVIDUAL_CALL_STATES.get(status or "", IndividualCall.State.UNKNOWN_STATE)


def _set_call_id(call: IndividualCall | GroupCall, call_id: object) -> None:
    if call_id is None or call_id == "":
        return
    try:
        call.callId = int(call_id)
    except (ValueError, TypeError):
        pass


def _build_individual_call(call_info: dict) -> IndividualCall | None:
    direction = call_info.get("direction")
    call_type = _CALL_TYPES.get(call_info.get("type") or "", IndividualCall.Type.UNKNOWN_TYPE)
    call_direction = _CALL_DIRECTIONS.get(
        direction or "", IndividualCall.Direction.UNKNOWN_DIRECTION
    )
    state = _individual_call_state(call_info.get("status"), direction)
    # libsignal's validator rejects UNKNOWN_* on all three fields
    if not (call_type and call_direction and state):
        return None
    call = IndividualCall()
    _set_call_id(call, call_info.get("callId"))
    call.type = call_type
    call.direction = call_direction
    call.state = state
    call.startedCallTimestamp = _to_int(call_info.get("timestamp"))
    call.read = True
    return call


def _build_group_call(call_info: dict, ids: IdAllocator) -> GroupCall | None:
    state = _GROUP_CALL_STATES.get(call_info.get("status") or "", GroupCall.State.UNKNOWN_STATE)
    if not state:
        return None
    call = GroupCall()
    _set_call_id(call, call_info.get("callId"))
    call.state = state
    call.startedCallTimestamp = _to_int(call_info.get("timestamp"))
    ringer_rid = _resolve_recipient_id(ids, call_info.get("ringerId"))
    if ringer_rid:
        call.ringerRecipientId = ringer_rid
    call.read = True
    return call


def build_call_item(
    ids: IdAllocator,
    msg_row: dict,
    msg_json: dict,
    conn: sqlite3.Connection,
    has_calls_table: bool,
) -> Frame | None:
    """Build a ChatItem frame for a call-history message."""
    conv_id = msg_row["conversationId"]
    chat_id = ids.conversation_to_chat.get(conv_id)
    if chat_id is None:
        return None

    call_info = _get_call_info(msg_json, conn, has_calls_table, msg_row)
    if not call_info or call_info.get("status") == _CALL_STATUS_DELETED:
        return None

    mode = call_info.get("mode")
    if mode not in ("Direct", "Group"):
        return None

    call = (
        _build_individual_call(call_info)
        if mode == "Direct"
        else _build_group_call(call_info, ids)
    )
    if call is None:
        return None

    frame = Frame()
    item = frame.chatItem
    item.chatId = chat_id
    item.dateSent = msg_row.get("sent_at") or msg_row.get("timestamp") or 0
    item.authorId = ids.service_id_to_recipient.get("__self__", 0)
    item.directionless.CopyFrom(ChatItem.DirectionlessMessageDetails())

    if mode == "Direct":
        item.updateMessage.individualCall.CopyFrom(call)
    else:
        item.updateMessage.groupCall.CopyFrom(call)

    return frame
