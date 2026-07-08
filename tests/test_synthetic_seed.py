"""Prove the synthetic seed-backup generator round-trips through the real
decrypt path, and use it to reproduce a bug-report-style edge case
(`inspect` against a backup with an empty AccountData frame) that was
previously impossible to build without a real device backup.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from signal_ark.cli import main as cli_main
from signal_ark.decrypt import decrypt_main, parse_frames
from signal_ark.kdf import backup_key_to_message_backup_key
from signal_ark.metadata import decrypt_metadata
from signal_ark.proto.Backup_pb2 import Frame

from tests.helpers.synthetic_seed import default_account_frame, synthetic_seed_dir


def test_synthetic_seed_roundtrips_through_decrypt(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path)

    meta = decrypt_metadata(seed.dir / "metadata", seed.backup_key)
    assert meta.backup_id == seed.backup_id

    hmac_key, aes_key = backup_key_to_message_backup_key(seed.backup_key, seed.backup_id)
    plaintext = decrypt_main((seed.dir / "main").read_bytes(), hmac_key, aes_key)
    result = parse_frames(plaintext)

    assert result.backup_info.version == 1
    assert len(result.frames) == 1
    assert result.frames[0].account.givenName == "Synthetic"
    assert result.frames[0].account.familyName == "Seed"


def test_synthetic_seed_custom_frames_and_aci(tmp_path: Path) -> None:
    custom_aci = "11111111-2222-4333-8444-555555555555"
    frame = default_account_frame(givenName="Alice", familyName="Example")

    seed = synthetic_seed_dir(tmp_path, aci=custom_aci, frames=[frame])

    assert seed.aci == custom_aci
    hmac_key, aes_key = backup_key_to_message_backup_key(seed.backup_key, seed.backup_id)
    plaintext = decrypt_main((seed.dir / "main").read_bytes(), hmac_key, aes_key)
    result = parse_frames(plaintext)

    assert result.frames[0].account.givenName == "Alice"
    assert result.frames[0].account.familyName == "Example"


def test_inspect_handles_empty_account_data(tmp_path: Path) -> None:
    """Repro for: 'inspect crashes on a backup with an empty AccountData'.

    Before the synthetic seed generator, reproducing this required a real
    device backup. An empty AccountData frame (all fields default/unset)
    should not crash `inspect` — it should just report zero attachments and
    no account-specific fields to check.
    """
    empty_account_frame = Frame()
    empty_account_frame.account.SetInParent()

    seed = synthetic_seed_dir(tmp_path, frames=[empty_account_frame])

    runner = CliRunner()
    invoke_result = runner.invoke(
        cli_main,
        [
            "inspect",
            "--backup-dir",
            str(seed.dir),
            "--passphrase",
            seed.aep,
        ],
    )

    assert invoke_result.exit_code == 0, invoke_result.output
    assert "No issues found." in invoke_result.output
    assert "account" in invoke_result.output
