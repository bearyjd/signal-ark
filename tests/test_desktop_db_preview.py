"""count_preview must agree with the queries the build pipeline runs."""

from __future__ import annotations

import sqlite3

import pytest

from signal_ark.mapping.desktop_db import (
    _collect_modern_attachments,
    _load_messages,
    count_preview,
)


@pytest.fixture
def conn() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript("""
        CREATE TABLE conversations (id TEXT, type TEXT, json TEXT);
        CREATE TABLE messages (
            id TEXT, body TEXT, type TEXT, sent_at INTEGER, received_at INTEGER,
            received_at_ms INTEGER, timestamp INTEGER, conversationId TEXT,
            sourceServiceId TEXT, serverTimestamp INTEGER, readStatus INTEGER,
            unidentifiedDeliveryReceived INTEGER, expireTimer INTEGER,
            expirationStartTimestamp INTEGER, json TEXT);
        CREATE TABLE message_attachments (
            messageId TEXT, contentType TEXT, path TEXT, size INTEGER, width INTEGER,
            height INTEGER, fileName TEXT, plaintextHash TEXT, blurHash TEXT,
            caption TEXT, localKey TEXT);
        INSERT INTO conversations VALUES ('c1','private','{}'), ('g1','group','{}');
        INSERT INTO messages (id, type, sent_at, received_at, conversationId) VALUES
            ('m1','incoming',1,1,'c1'), ('m2','outgoing',2,2,'c1'),
            ('m3','call-history',3,3,'c1'), ('m4','keychange',4,4,'c1'),
            ('m5','incoming',5,5,'g1');
        INSERT INTO message_attachments (messageId, path) VALUES
            ('m1','a/b'), ('m5','a/c'), ('m3','a/d'), ('m4','a/e'),
            ('m2',NULL), ('orphan','a/f');
    """)
    return c


def test_counts_include_call_history_and_exclude_other_types(conn) -> None:
    stats = count_preview(conn)
    assert stats["conversations"] == 2
    assert stats["messages"] == 4


def test_attachments_skip_null_path_orphans_and_non_message_types(conn) -> None:
    assert count_preview(conn)["attachments"] == 2  # m1, m5


def test_preview_matches_pipeline(conn) -> None:
    stats = count_preview(conn)
    assert stats["messages"] == len(_load_messages(conn))
    assert stats["attachments"] == len(_collect_modern_attachments(conn))


def test_missing_attachments_table_falls_back_to_zero(conn) -> None:
    conn.execute("DROP TABLE message_attachments")
    assert count_preview(conn)["attachments"] == 0
