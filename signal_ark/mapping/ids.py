"""Recipient/chat ID allocation and Desktop identifier resolution."""

from __future__ import annotations

from dataclasses import dataclass, field

from signal_ark.mapping.util import _normalize_aci


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
    # Desktop conversation IDs whose recipient is a Group (never a valid author)
    group_conversations: set[str] = field(default_factory=set)

    def alloc_recipient(self, conversation_id: str, service_id: str | None = None) -> int:
        rid = self._next_recipient_id
        self._next_recipient_id += 1
        self.conversation_to_recipient[conversation_id] = rid
        if service_id:
            self.alias_service_id(service_id, rid)
        return rid

    def alias_service_id(self, service_id: str, rid: int) -> None:
        """Register a service ID under both its given and canonical spellings."""
        self.service_id_to_recipient[service_id] = rid
        canonical = _normalize_aci(service_id)
        if canonical:
            self.service_id_to_recipient[canonical] = rid

    def resolve_service_id(self, service_id: str | None) -> int | None:
        """Recipient ID for a service ID in any spelling, or None when unknown."""
        if not service_id:
            return None
        rid = self.service_id_to_recipient.get(service_id)
        if rid is not None:
            return rid
        canonical = _normalize_aci(service_id)
        return self.service_id_to_recipient.get(canonical) if canonical else None

    def alloc_chat(self, conversation_id: str) -> int:
        cid = self._next_chat_id
        self._next_chat_id += 1
        self.conversation_to_chat[conversation_id] = cid
        return cid


def _resolve_recipient_id(ids: IdAllocator, identifier: str | None) -> int:
    """Resolve a Desktop identifier to a backup recipient ID (never a Group)."""
    if not identifier:
        return 0
    rid = ids.resolve_service_id(identifier)
    if rid is not None:
        return rid
    if identifier in ids.group_conversations:
        return 0
    return ids.conversation_to_recipient.get(identifier) or 0
