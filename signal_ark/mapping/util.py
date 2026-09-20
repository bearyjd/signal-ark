"""Small conversion helpers and libsignal body-size limits shared by the mapping package."""

from __future__ import annotations

import base64
import binascii

# Body limits enforced by libsignal (message-backup/src/backup/chat/text.rs)
MAX_BODY_BYTES = 128 * 1024
MAX_BODY_BYTES_WITH_LONG_TEXT = 2 * 1024
MAX_QUOTE_BODY_BYTES = 2 * 1024
LONG_TEXT_CONTENT_TYPE = "text/x-signal-plain"


def _uuid_str_to_bytes(uuid_str: str) -> bytes:
    """Convert UUID string to 16 raw bytes."""
    return bytes.fromhex(uuid_str.replace("-", ""))


def _b64_to_bytes(b64: str | None) -> bytes:
    if not b64:
        return b""
    try:
        return base64.b64decode(b64)
    except (binascii.Error, ValueError):
        return b""


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return default


def _trim_utf8(text: str, max_bytes: int) -> str:
    """Trim text to at most max_bytes of UTF-8 without splitting a codepoint."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")
