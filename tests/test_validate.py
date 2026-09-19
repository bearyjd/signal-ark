"""Tests for the libsignal backup-validator gate (signal_ark.validate)."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from signal_ark import validate as validate_module
from signal_ark.encrypt import serialize_frames
from signal_ark.proto.Backup_pb2 import Frame
from signal_ark.validate import (
    ValidationResult,
    ValidatorError,
    ValidatorUnavailable,
    validate_backup_dir,
    validate_plaintext,
    validator_available,
)

from tests.helpers.synthetic_seed import (
    default_account_frame,
    default_backup_info,
    default_self_recipient_frame,
    synthetic_seed_dir,
)


def _minimal_valid_frames() -> list[Frame]:
    return [default_account_frame(), default_self_recipient_frame()]


def _dangling_chat_item() -> Frame:
    frame = Frame()
    item = frame.chatItem
    item.chatId = 999
    item.authorId = default_self_recipient_frame().recipient.id
    item.dateSent = 1
    item.outgoing.SetInParent()
    item.standardMessage.text.body = "orphaned"
    return frame


@pytest.mark.validator
def test_minimal_valid_stream_is_accepted(validator: Callable[..., ValidationResult]) -> None:
    plaintext = serialize_frames(default_backup_info(), _minimal_valid_frames())

    result = validator(plaintext)

    assert result.ok, result.error
    assert result.frames == 2
    assert result.error is None


@pytest.mark.validator
def test_dangling_chat_reference_is_rejected(validator: Callable[..., ValidationResult]) -> None:
    frames = [*_minimal_valid_frames(), _dangling_chat_item()]
    plaintext = serialize_frames(default_backup_info(), frames)

    result = validator(plaintext)

    assert result.ok is False
    assert result.error
    assert "no record for chat" in result.error


@pytest.mark.validator
def test_missing_media_root_backup_key_is_rejected(
    validator: Callable[..., ValidationResult],
) -> None:
    info = default_backup_info()
    info.ClearField("mediaRootBackupKey")
    plaintext = serialize_frames(info, _minimal_valid_frames())

    result = validator(plaintext)

    assert result.ok is False
    assert result.error
    assert "mediaRootBackupKey" in result.error


@pytest.mark.validator
def test_empty_frame_is_passed_to_libsignal_not_skipped(
    validator: Callable[..., ValidationResult],
) -> None:
    plaintext = serialize_frames(default_backup_info(), [*_minimal_valid_frames(), Frame()])

    result = validator(plaintext)

    assert result.ok is False
    assert result.frames == 2
    assert result.error


@pytest.mark.validator
def test_synthetic_seed_dir_validates(
    tmp_path: Path, validator: Callable[..., ValidationResult]
) -> None:
    seed = synthetic_seed_dir(tmp_path)

    result = validate_backup_dir(seed.dir, seed.aep, seed.aci)

    assert result.ok, result.error
    assert result.frames == 2


@pytest.mark.validator
def test_validate_mjs_still_accepts_a_file_argument(
    tmp_path: Path, validator: Callable[..., ValidationResult]
) -> None:
    plaintext_path = tmp_path / "stream.plaintext"
    plaintext_path.write_bytes(serialize_frames(default_backup_info(), _minimal_valid_frames()))

    proc = subprocess.run(
        [validate_module.NODE_BINARY, str(validate_module.VALIDATOR_SCRIPT), str(plaintext_path)],
        capture_output=True,
        check=False,
    )

    assert proc.returncode == validate_module.EXIT_OK, proc.stderr
    assert b'"ok":true' in proc.stdout


def test_validator_unavailable_when_node_modules_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(validate_module, "LIBSIGNAL_CLIENT_DIR", tmp_path / "missing")

    assert validator_available() is False
    with pytest.raises(ValidatorUnavailable, match="npm ci --prefix tools/validator"):
        validate_plaintext(b"")


def test_validator_unavailable_when_node_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    assert validator_available() is False
    with pytest.raises(ValidatorUnavailable, match="node"):
        validate_plaintext(b"")


@pytest.mark.validator
def test_unparsable_stream_raises_validator_error(
    validator: Callable[..., ValidationResult],
) -> None:
    with pytest.raises(ValidatorError, match="Truncated"):
        validator(b"\x05ab")


def test_validate_backup_dir_wrong_aci_raises_value_error(tmp_path: Path) -> None:
    seed = synthetic_seed_dir(tmp_path)

    with pytest.raises(ValueError, match="ACI"):
        validate_backup_dir(seed.dir, seed.aep, "ffffffff-ffff-4fff-8fff-ffffffffffff")


def _pretend_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validate_module, "_unavailable_reason", lambda: None)


def test_plaintext_is_piped_over_stdin_not_written_to_disk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pretend_available(monkeypatch)
    calls: list[dict[str, object]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append({"argv": argv, **kwargs})
        return subprocess.CompletedProcess(argv, 0, stdout=b'{"ok":true,"frames":1}\n', stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = validate_plaintext(b"\x01\x02payload")

    assert result == ValidationResult(ok=True, frames=1, error=None)
    assert calls[0]["input"] == b"\x01\x02payload"
    assert all(".plaintext" not in str(arg) for arg in calls[0]["argv"])  # type: ignore[union-attr]
    assert not hasattr(validate_module, "tempfile")


def test_timeout_is_reported_as_validator_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _pretend_available(monkeypatch)

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(ValidatorError, match="timed out"):
        validate_plaintext(b"")


def test_required_but_unavailable_validator_fails_inside_test_body() -> None:
    from tests.conftest import _fail_unavailable

    with pytest.raises(pytest.fail.Exception, match="npm ci"):
        _fail_unavailable(b"")
