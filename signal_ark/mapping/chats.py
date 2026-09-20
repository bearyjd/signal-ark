"""Build Chat and message ChatItem frames (body, reactions, quote) from Desktop rows."""

from __future__ import annotations

from signal_ark.mapping.ids import IdAllocator, _resolve_recipient_id
from signal_ark.mapping.util import (
    MAX_BODY_BYTES,
    MAX_QUOTE_BODY_BYTES,
    _to_int,
    _trim_utf8,
)
from signal_ark.proto.Backup_pb2 import (
    ChatItem,
    Frame,
    Quote,
    Reaction,
    SendStatus,
    StandardMessage,
)


def _map_reactions(msg_json: dict, ids: IdAllocator) -> list[Reaction]:
    """Extract reactions from Desktop message JSON."""
    reactions_data = msg_json.get("reactions")
    if not reactions_data:
        return []

    result = []
    for r in reactions_data:
        emoji = r.get("emoji")
        author_id = _resolve_recipient_id(ids, r.get("fromId"))
        if not emoji or not author_id:
            continue
        reaction = Reaction()
        reaction.emoji = emoji
        reaction.authorId = author_id
        sent_ts = r.get("timestamp") or 0
        reaction.sentTimestamp = sent_ts
        reaction.sortOrder = r.get("receivedAtDate") or sent_ts
        result.append(reaction)

    return result


def _map_quote(msg_json: dict, ids: IdAllocator) -> Quote | None:
    """Extract quote from Desktop message JSON.

    Drops the quote when the author cannot be resolved or when it carries
    neither text nor attachments (both are rejected by the backup validator).
    """
    quote_data = msg_json.get("quote")
    if not quote_data:
        return None

    author_id = _resolve_recipient_id(
        ids, quote_data.get("authorAci") or quote_data.get("authorUuid")
    )
    if not author_id:
        return None

    quote = Quote()
    quote.authorId = author_id

    target_ts = _to_int(quote_data.get("id"))
    if target_ts and not quote_data.get("referencedMessageNotFound"):
        quote.targetSentTimestamp = target_ts

    text = quote_data.get("text")
    if text:
        quote.text.body = _trim_utf8(text, MAX_QUOTE_BODY_BYTES)

    for att in quote_data.get("attachments") or []:
        quoted = quote.attachments.add()
        if att.get("contentType"):
            quoted.contentType = att["contentType"]
        if att.get("fileName"):
            quoted.fileName = att["fileName"]

    if not quote.HasField("text") and not quote.attachments:
        return None

    quote.type = Quote.Type.NORMAL
    return quote


def build_chat(ids: IdAllocator, conv_id: str, conv: dict) -> Frame | None:
    """Build a Chat frame from a Desktop conversation."""
    recipient_id = ids.conversation_to_recipient.get(conv_id)
    if recipient_id is None:
        return None

    chat_id = ids.alloc_chat(conv_id)

    frame = Frame()
    frame.chat.id = chat_id
    frame.chat.recipientId = recipient_id

    if conv.get("isArchived"):
        frame.chat.archived = True
    if conv.get("markedUnread"):
        frame.chat.markedUnread = True
    if conv.get("expireTimer"):
        frame.chat.expirationTimerMs = int(conv["expireTimer"]) * 1000
    if conv.get("expireTimerVersion"):
        frame.chat.expireTimerVersion = int(conv["expireTimerVersion"])
    if conv.get("muteExpiresAt"):
        frame.chat.muteUntilMs = int(conv["muteExpiresAt"])

    return frame


def _resolve_incoming_author(ids: IdAllocator, conv_id: str, source_sid: str | None) -> int | None:
    """Recipient ID for an incoming message's author.

    Falls back to the conversation's own recipient for 1:1 chats; a group
    recipient is never a valid author, so unresolved group authors yield None.
    """
    author_rid = ids.resolve_service_id(source_sid)
    if author_rid is not None:
        return author_rid
    if conv_id in ids.group_conversations:
        return None
    return ids.conversation_to_recipient.get(conv_id, 0)


def _fill_incoming(
    item: ChatItem, ids: IdAllocator, msg_row: dict, stats: dict[str, int] | None
) -> bool:
    """Populate incoming details; False when the author cannot be attributed."""
    author_rid = _resolve_incoming_author(ids, msg_row["conversationId"], msg_row.get("sourceServiceId"))
    if author_rid is None:
        if stats is not None:
            stats["skipped_unresolved_author"] += 1
        return False
    item.authorId = author_rid

    incoming = item.incoming
    incoming.dateReceived = msg_row.get("received_at_ms") or msg_row.get("received_at") or 0
    server_ts = msg_row.get("serverTimestamp")
    if server_ts:
        incoming.dateServerSent = server_ts
    incoming.read = (msg_row.get("readStatus") or 0) >= 1
    incoming.sealedSender = bool(msg_row.get("unidentifiedDeliveryReceived"))
    return True


def _map_send_status(dest_rid: int, state: dict) -> SendStatus:
    ss = SendStatus()
    ss.recipientId = dest_rid
    ss.timestamp = state.get("updatedAt", 0)
    status_str = state.get("status", "Sent")
    if status_str == "Delivered":
        ss.delivered.sealedSender = True
    elif status_str == "Read":
        ss.read.sealedSender = True
    elif status_str == "Viewed":
        ss.viewed.sealedSender = True
    elif status_str == "Sent":
        ss.sent.sealedSender = True
    else:
        ss.sent.sealedSender = False
    return ss


def _fill_outgoing(item: ChatItem, ids: IdAllocator, msg_row: dict, msg_json: dict) -> None:
    """Populate outgoing details; group conversations are never send-status targets."""
    item.authorId = ids.service_id_to_recipient.get("__self__", 0)

    outgoing = item.outgoing
    outgoing.dateReceived = msg_row.get("received_at_ms") or msg_row.get("received_at") or 0

    send_state = msg_json.get("sendStateByConversationId", {})
    for dest_conv_id, state in send_state.items():
        dest_rid = ids.conversation_to_recipient.get(dest_conv_id)
        if dest_rid is None or dest_conv_id in ids.group_conversations:
            continue
        outgoing.sendStatus.append(_map_send_status(dest_rid, state))


def build_chat_item(
    ids: IdAllocator,
    msg_row: dict,
    msg_json: dict,
    stats: dict[str, int] | None = None,
) -> Frame | None:
    """Build a ChatItem frame from a Desktop message row."""
    chat_id = ids.conversation_to_chat.get(msg_row["conversationId"])
    if chat_id is None:
        return None

    msg_type = msg_row["type"]
    if msg_type not in ("incoming", "outgoing"):
        return None

    frame = Frame()
    item = frame.chatItem
    item.chatId = chat_id
    item.dateSent = msg_row.get("sent_at") or msg_row.get("timestamp") or 0

    if msg_type == "incoming":
        if not _fill_incoming(item, ids, msg_row, stats):
            return None
    elif msg_type == "outgoing":
        _fill_outgoing(item, ids, msg_row, msg_json)
    else:
        return None

    # Message body, reactions, and quote. Reactions alone don't make a valid
    # StandardMessage; attachments may still be added later.
    body = msg_row.get("body")
    quote = _map_quote(msg_json, ids)

    if body or quote:
        std_msg = StandardMessage()
        if body:
            std_msg.text.body = _trim_utf8(body, MAX_BODY_BYTES)
        if quote:
            std_msg.quote.CopyFrom(quote)
        std_msg.reactions.extend(_map_reactions(msg_json, ids))
        item.standardMessage.CopyFrom(std_msg)

    # Expiration
    expire_timer = msg_row.get("expireTimer")
    if expire_timer:
        item.expiresInMs = int(expire_timer) * 1000
    expire_start = msg_row.get("expirationStartTimestamp")
    if expire_start:
        item.expireStartDate = int(expire_start)

    return frame


def _drop_empty_chat_items(frames: list[Frame]) -> tuple[list[Frame], int]:
    """Return frames without item-less ChatItems, plus how many were dropped."""
    kept = [
        f for f in frames
        if not (f.HasField("chatItem") and f.chatItem.WhichOneof("item") is None)
    ]
    return kept, len(frames) - len(kept)
