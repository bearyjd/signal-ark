"""Read-only queries against the decrypted Signal Desktop SQLite database."""

from __future__ import annotations

import json
import sqlite3

_KNOWN_TABLES = frozenset({"conversations", "messages", "message_attachments", "callsHistory"})


def _has_table(conn: sqlite3.Connection, table_name: str) -> bool:
    """Check if a table exists in the SQLite database."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _has_column(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    """Check if a column exists on a table (Desktop schemas vary by version)."""
    if table_name not in _KNOWN_TABLES:
        raise ValueError(f"unknown table {table_name!r}")
    columns = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(col[1] == column_name for col in columns)


def _find_self_conversation(conn: sqlite3.Connection, self_aci: str) -> sqlite3.Row | None:
    """Locate our own conversation row, falling back to the "Note to Self" pattern."""
    self_conv = conn.execute(
        "SELECT id FROM conversations WHERE serviceId = ? OR type = 'private' AND e164 IS NULL AND serviceId IS NULL",
        (self_aci,),
    ).fetchone()

    # Also check for "Note to Self" pattern
    if not self_conv:
        self_conv = conn.execute(
            "SELECT id FROM conversations WHERE type = 'private' AND serviceId = ?",
            (self_aci,),
        ).fetchone()
    return self_conv


def _load_group_conversations(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Group conversation rows, most recently active first."""
    return conn.execute("""
        SELECT id, json
        FROM conversations
        WHERE type = 'group'
        ORDER BY active_at DESC
    """).fetchall()


def _load_contact_conversations(conn: sqlite3.Connection, self_aci: str) -> list[sqlite3.Row]:
    """Private conversation rows for contacts other than ourselves."""
    return conn.execute("""
        SELECT id, json, active_at, type, e164, serviceId, profileName, profileFamilyName
        FROM conversations
        WHERE type = 'private' AND serviceId IS NOT NULL AND serviceId != ?
        ORDER BY active_at DESC
    """, (self_aci,)).fetchall()


def _load_active_conversations(conn: sqlite3.Connection, self_conv_id: str) -> list[sqlite3.Row]:
    """Private (including our own) and group conversations with at least one mappable message."""
    return conn.execute("""
        SELECT DISTINCT c.id, c.json
        FROM conversations c
        INNER JOIN messages m ON m.conversationId = c.id
        WHERE ((c.type = 'private' AND (c.serviceId IS NOT NULL OR c.id = ?)) OR c.type = 'group')
        AND m.type IN ('incoming', 'outgoing', 'call-history')
    """, (self_conv_id,)).fetchall()


def _load_group_sender_acis(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """Distinct (conversationId, sourceServiceId) pairs of incoming group messages."""
    rows = conn.execute("""
        SELECT DISTINCT m.conversationId, m.sourceServiceId
        FROM messages m
        INNER JOIN conversations c ON c.id = m.conversationId
        WHERE c.type = 'group' AND m.type = 'incoming' AND m.sourceServiceId IS NOT NULL
    """).fetchall()
    return [(row[0], row[1]) for row in rows]


def _load_messages(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Mappable message rows in received-timestamp order."""
    return conn.execute("""
        SELECT m.id, m.body, m.type, m.sent_at, m.received_at, m.received_at_ms,
               m.timestamp, m.conversationId, m.sourceServiceId, m.serverTimestamp,
               m.readStatus, m.unidentifiedDeliveryReceived, m.expireTimer,
               m.expirationStartTimestamp, m.json
        FROM messages m
        WHERE m.type IN ('incoming', 'outgoing', 'call-history')
        ORDER BY m.received_at ASC, m.sent_at ASC
    """).fetchall()


def _collect_modern_attachments(conn: sqlite3.Connection) -> list[dict]:
    """Read attachment rows from the message_attachments table (newer Desktop)."""
    key_column = "ma.key" if _has_column(conn, "message_attachments", "key") else "NULL AS key"
    rows = conn.execute(f"""
        SELECT ma.messageId, ma.contentType, ma.path, ma.size,
               ma.width, ma.height, ma.fileName, ma.plaintextHash,
               ma.blurHash, ma.caption, ma.localKey, {key_column}, m.sent_at, m.json
        FROM message_attachments ma
        JOIN messages m ON m.id = ma.messageId
        WHERE ma.path IS NOT NULL
        AND m.type IN ('incoming', 'outgoing')
        ORDER BY m.sent_at ASC
    """).fetchall()
    return [dict(r) for r in rows]


def _collect_legacy_attachments(conn: sqlite3.Connection) -> list[dict]:
    """Parse attachment info from message JSON for older Desktop versions."""
    messages = conn.execute("""
        SELECT m.id, m.sent_at, m.json
        FROM messages m
        WHERE m.type IN ('incoming', 'outgoing')
        AND m.json LIKE '%"attachments"%'
        ORDER BY m.sent_at ASC
    """).fetchall()

    result = []
    for msg in messages:
        msg_json = json.loads(msg["json"] or "{}")
        for att in msg_json.get("attachments") or []:
            path = att.get("path")
            if not path:
                continue
            result.append({
                "messageId": msg["id"],
                "contentType": att.get("contentType"),
                "path": path,
                "size": att.get("size"),
                "width": att.get("width"),
                "height": att.get("height"),
                "fileName": att.get("fileName"),
                "plaintextHash": att.get("plaintextHash"),
                "blurHash": att.get("blurHash"),
                "caption": att.get("caption"),
                "localKey": att.get("localKey"),
                "key": att.get("key"),
                "sent_at": msg["sent_at"],
                "json": msg["json"],
            })

    return result
