"""Passphrase input channels and key-material output for the CLI."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from signal_ark.cli import main
from signal_ark.kdf import aep_to_backup_key, validate_aep

from tests.helpers.synthetic_seed import synthetic_seed_dir


def _decrypt(args: list[str], tmp_path: Path, **kwargs):
    seed = synthetic_seed_dir(tmp_path / "seed")
    out = tmp_path / "out"
    result = CliRunner().invoke(
        main, ["decrypt", "--seed-dir", str(seed.dir), "-o", str(out), *args], **kwargs
    )
    return seed, result


def test_passphrase_from_env(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path / "seed")
    result = CliRunner().invoke(
        main,
        ["decrypt", "--seed-dir", str(seed.dir), "-o", str(tmp_path / "out")],
        env={"SIGNAL_ARK_PASSPHRASE": seed.aep},
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "out" / "metadata.json").exists()


def test_passphrase_from_file(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path / "seed")
    pf = tmp_path / "pass.txt"
    pf.write_text(seed.aep + "\n")
    result = CliRunner().invoke(
        main,
        ["decrypt", "--seed-dir", str(seed.dir), "-o", str(tmp_path / "out"),
         "--passphrase-file", str(pf)],
    )
    assert result.exit_code == 0, result.output


def test_passphrase_from_stdin(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path / "seed")
    result = CliRunner().invoke(
        main,
        ["decrypt", "--seed-dir", str(seed.dir), "-o", str(tmp_path / "out"),
         "--passphrase-file", "-"],
        input=seed.aep + "\n",
    )
    assert result.exit_code == 0, result.output


def test_missing_passphrase_errors(tmp_path: Path) -> None:
    _, result = _decrypt([], tmp_path)
    assert result.exit_code != 0
    assert "passphrase" in result.output.lower()


def test_keys_not_printed_by_default(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path / "seed")
    result = CliRunner().invoke(
        main,
        ["decrypt", "--seed-dir", str(seed.dir), "-o", str(tmp_path / "out"),
         "--passphrase", seed.aep],
    )
    assert result.exit_code == 0, result.output
    key_hex = aep_to_backup_key(validate_aep(seed.aep)).hex()
    assert key_hex not in result.output
    assert "HMAC key" not in result.output
    assert "AES key" not in result.output


def test_show_keys_prints_them(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path / "seed")
    result = CliRunner().invoke(
        main,
        ["decrypt", "--seed-dir", str(seed.dir), "-o", str(tmp_path / "out"),
         "--passphrase", seed.aep, "--show-keys"],
    )
    assert result.exit_code == 0, result.output
    assert aep_to_backup_key(validate_aep(seed.aep)).hex() in result.output


def test_passphrase_prompt_hidden(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path / "seed")
    result = CliRunner().invoke(
        main,
        ["decrypt", "--seed-dir", str(seed.dir), "-o", str(tmp_path / "out")],
        input=seed.aep + "\n",
    )
    assert result.exit_code == 0, result.output
    assert seed.aep not in result.output


def test_passphrase_flag_warns_deprecated(tmp_path: Path) -> None:
    _, result = _decrypt(["--passphrase", "x" * 64], tmp_path)
    assert "deprecated" in result.output.lower()


def _dump_v1(monkeypatch, tmp_path: Path, args: list[str], **kwargs):
    seen: list[str] = []

    def fake_parse(path, passphrase):
        seen.append(passphrase)
        return iter(())

    monkeypatch.setattr("signal_ark.v1_parser.parse_v1_backup", fake_parse)
    backup = tmp_path / "x.backup"
    backup.write_bytes(b"")
    result = CliRunner().invoke(
        main, ["dump-v1", "--v1-backup", str(backup), "-o", str(tmp_path / "o"), *args], **kwargs
    )
    return seen, result


V1_PASS = "123456789012345678901234567890"


def test_v1_passphrase_from_env(monkeypatch, tmp_path: Path) -> None:
    seen, result = _dump_v1(monkeypatch, tmp_path, [], env={"SIGNAL_ARK_V1_PASSPHRASE": V1_PASS})
    assert result.exit_code == 0, result.output
    assert seen == [V1_PASS]


def test_v1_passphrase_from_prompt(monkeypatch, tmp_path: Path) -> None:
    seen, result = _dump_v1(monkeypatch, tmp_path, [], input=V1_PASS + "\n")
    assert result.exit_code == 0, result.output
    assert seen == [V1_PASS]
    assert V1_PASS not in result.output


def test_v1_passphrase_flag_warns_deprecated(monkeypatch, tmp_path: Path) -> None:
    seen, result = _dump_v1(monkeypatch, tmp_path, ["--v1-passphrase", V1_PASS])
    assert result.exit_code == 0, result.output
    assert seen == [V1_PASS]
    assert "deprecated" in result.output.lower()
