"""Decrypted output files must be created owner-only (0600), regardless of umask."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from click.testing import CliRunner

from signal_ark.cli import main as cli_main
from signal_ark.fsutil import open_private
from tests.helpers.synthetic_seed import default_account_frame, synthetic_seed_dir


def test_decrypt_outputs_are_owner_only(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path / "seed", frames=[default_account_frame()])
    out = tmp_path / "out"

    old_umask = os.umask(0o022)
    try:
        result = CliRunner().invoke(
            cli_main,
            ["decrypt", "--seed-dir", str(seed.dir), "--passphrase", seed.aep, "-o", str(out)],
        )
    finally:
        os.umask(old_umask)

    assert result.exit_code == 0, result.output
    produced = sorted(p for p in out.iterdir() if p.is_file())
    assert {p.name for p in produced} >= {
        "main.plaintext",
        "frames.jsonl",
        "metadata.json",
    }
    for path in produced:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name


def test_decrypt_rerun_tightens_existing_0644_files(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path / "seed", frames=[default_account_frame()])
    out = tmp_path / "out"
    out.mkdir()
    names = ("main.plaintext", "frames.jsonl", "metadata.json")
    for name in names:
        (out / name).write_text("old")
        (out / name).chmod(0o644)

    result = CliRunner().invoke(
        cli_main,
        ["decrypt", "--seed-dir", str(seed.dir), "--passphrase", seed.aep, "-o", str(out)],
    )

    assert result.exit_code == 0, result.output
    for name in names:
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600, name


def test_open_private_works_without_fchmod(tmp_path: Path, monkeypatch) -> None:
    """Windows (Python < 3.13) has no os.fchmod; open_private must not need it."""
    monkeypatch.delattr(os, "fchmod", raising=False)
    path = tmp_path / "f"
    with os.fdopen(open_private(path), "wb") as f:
        f.write(b"x")
    assert path.read_bytes() == b"x"


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="O_NOFOLLOW unavailable")
def test_open_private_refuses_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("keep")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported")
    with pytest.raises(OSError):
        open_private(link)
    assert target.read_text() == "keep"
