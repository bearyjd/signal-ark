"""Content-store helpers and a pin test that `inspect` output is unchanged."""

from __future__ import annotations

import hashlib
from pathlib import Path

from click.testing import CliRunner

from signal_ark.cli import main as cli_main
from signal_ark.content_store import frame_stats, media_name, store_path
from signal_ark.mapping.attachments import encrypt_attachment
from signal_ark.proto.Backup_pb2 import Frame

from tests.helpers.synthetic_seed import default_seed_frames, synthetic_seed_dir


def test_media_name_is_sha256_of_hash_and_key() -> None:
    h, k = b"\x01" * 32, b"\x02" * 64
    assert media_name(h, k) == hashlib.sha256(h + k).hexdigest()


def test_store_path_is_sharded_by_first_two_chars(tmp_path: Path) -> None:
    assert store_path(tmp_path, "abcdef") == tmp_path / "ab" / "abcdef"


def _attachment_frame(sent: int, key: bytes, digest: bytes, size: int) -> Frame:
    frame = Frame()
    ci = frame.chatItem
    ci.dateSent = sent
    ma = ci.standardMessage.attachments.add()
    ma.pointer.contentType = "image/png"
    ma.pointer.locatorInfo.localKey = key
    ma.pointer.locatorInfo.plaintextHash = digest
    ma.pointer.locatorInfo.size = size
    return frame


def test_frame_stats_counts_and_pointers() -> None:
    frames = [*default_seed_frames(), _attachment_frame(42, b"k" * 64, b"h" * 32, 3)]
    counts, pointers = frame_stats(frames)
    assert counts == {"account": 1, "recipient": 1, "chatItem": 1}
    assert [(sent, fp.contentType) for sent, fp in pointers] == [("42", "image/png")]


def test_frame_stats_includes_long_text_pointer() -> None:
    frame = Frame()
    ci = frame.chatItem
    ci.dateSent = 7
    ci.standardMessage.longText.contentType = "text/x-signal-plain"
    ci.standardMessage.longText.locatorInfo.localKey = b"k" * 64
    _counts, pointers = frame_stats([frame])
    assert [(sent, fp.contentType) for sent, fp in pointers] == [("7", "text/x-signal-plain")]


def test_inspect_output_pinned_with_attachment(tmp_path: Path) -> None:
    src = tmp_path / "pic.bin"
    src.write_bytes(b"hello attachment")
    files_dir = tmp_path / "files"
    enc = encrypt_attachment(src, files_dir)
    import base64

    key = base64.b64decode(enc.local_key_b64)
    frame = _attachment_frame(42, key, enc.plaintext_hash, len(b"hello attachment"))
    seed = synthetic_seed_dir(tmp_path, frames=[*default_seed_frames(), frame])

    result = CliRunner().invoke(
        cli_main,
        ["inspect", "--backup-dir", str(seed.dir), "--passphrase", seed.aep,
         "--files-dir", str(files_dir)],
    )
    assert result.exit_code == 0, result.output
    assert "Frame counts:" in result.output
    assert "Attachments in frames: 1" in result.output
    assert "  [42] image/png       decrypt=OK  hash=OK  size=True  16 bytes" in result.output
    assert "No issues found." in result.output
