"""Recipient/chat ID allocation and Desktop identifier resolution."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IdAllocator:
    """Allocates unique IDs for recipients and chats."""
    _next_recipient_id: int = 1
    _next_chat_id: int = 1
    # Desktop conversation ID → our recipient ID
    conversation_to_recipient: dict[str, int] = field(default_factory=dict)
    # Desktop conversation ID → our chat ID
    conversation_to_chat: dict[str, int] = field(default_factory=dict)
    # serviceId (ACI) → recipient ID
    service_id_to_recipient: dict[str, int] = field(default_factory=dict)

    def alloc_recipient(self, conversation_id: str, service_id: str | None = None) -> int:
        rid = self._next_recipient_id
        self._next_recipient_id += 1
        self.conversation_to_recipient[conversation_id] = rid
        if service_id:
            self.service_id_to_recipient[service_id] = rid
        return rid

    def alias_service_id(self, service_id: str, rid: int) -> None:
        self.service_id_to_recipient[service_id] = rid

    def alloc_chat(self, conversation_id: str) -> int:
        cid = self._next_chat_id
        self._next_chat_id += 1
        self.conversation_to_chat[conversation_id] = cid
        return cid


def _resolve_recipient_id(ids: IdAllocator, identifier: str | None) -> int:
    """Resolve a Desktop identifier to a backup recipient ID."""
    if not identifier:
        return 0
    return (
        ids.service_id_to_recipient.get(identifier)
        or ids.conversation_to_recipient.get(identifier)
        or 0
    )
