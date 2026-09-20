"""Map Signal Desktop SQLite data to v2 backup archive frames (public API)."""

from signal_ark.mapping.attachments import (
    EncryptedAttachment,
    decrypt_desktop_attachment,
    encrypt_attachment,
)
from signal_ark.mapping.calls import build_call_item
from signal_ark.mapping.chats import build_chat, build_chat_item
from signal_ark.mapping.ids import IdAllocator
from signal_ark.mapping.pipeline import MappingResult, map_desktop_to_frames
from signal_ark.mapping.recipients import (
    build_account_frame,
    build_contact_recipient,
    build_group_recipient,
    build_self_recipient,
)
from signal_ark.mapping.util import (
    LONG_TEXT_CONTENT_TYPE,
    MAX_BODY_BYTES,
    MAX_BODY_BYTES_WITH_LONG_TEXT,
    MAX_QUOTE_BODY_BYTES,
)

__all__ = [
    "LONG_TEXT_CONTENT_TYPE",
    "MAX_BODY_BYTES",
    "MAX_BODY_BYTES_WITH_LONG_TEXT",
    "MAX_QUOTE_BODY_BYTES",
    "EncryptedAttachment",
    "IdAllocator",
    "MappingResult",
    "build_account_frame",
    "build_call_item",
    "build_chat",
    "build_chat_item",
    "build_contact_recipient",
    "build_group_recipient",
    "build_self_recipient",
    "decrypt_desktop_attachment",
    "encrypt_attachment",
    "map_desktop_to_frames",
]
