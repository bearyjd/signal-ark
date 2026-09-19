"""Gate backup frame streams through libsignal's official validator.

Python owns all crypto: `validate_backup_dir` decrypts with the existing KDF
chain and hands only plaintext to `tools/validator/validate.mjs`, a thin Node
wrapper around `@signalapp/libsignal-client`'s `OnlineBackupValidator`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from signal_ark.decrypt import decrypt_main
from signal_ark.kdf import (
    aep_to_backup_key,
    backup_key_to_backup_id,
    backup_key_to_message_backup_key,
    validate_aep,
)
from signal_ark.metadata import decrypt_metadata

VALIDATOR_DIR = Path(__file__).resolve().parent.parent / "tools" / "validator"
VALIDATOR_SCRIPT = VALIDATOR_DIR / "validate.mjs"
LIBSIGNAL_CLIENT_DIR = VALIDATOR_DIR / "node_modules" / "@signalapp" / "libsignal-client"
NODE_BINARY = "node"
DEFAULT_PURPOSE = "remote-backup"
VALIDATOR_TIMEOUT_SECONDS = 300

EXIT_OK = 0
EXIT_INVALID = 1


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    frames: int
    error: str | None


class ValidatorError(RuntimeError):
    """The validator subprocess failed to produce a verdict (usage/IO error)."""


class ValidatorUnavailable(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            f"libsignal validator unavailable ({reason}). "
            f"Install Node (`{NODE_BINARY}` must be on PATH) and run "
            "`npm ci --prefix tools/validator`."
        )


def _unavailable_reason() -> str | None:
    if shutil.which(NODE_BINARY) is None:
        return f"`{NODE_BINARY}` not found on PATH"
    if not LIBSIGNAL_CLIENT_DIR.is_dir():
        return f"{LIBSIGNAL_CLIENT_DIR} does not exist"
    return None


def validator_available() -> bool:
    return _unavailable_reason() is None


def _run_validator(plaintext_path: Path, purpose: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [NODE_BINARY, str(VALIDATOR_SCRIPT), str(plaintext_path), "--purpose", purpose],
        capture_output=True,
        text=True,
        timeout=VALIDATOR_TIMEOUT_SECONDS,
        check=False,
    )


def _parse_result_line(stdout: str) -> dict[str, object] | None:
    for line in reversed(stdout.splitlines()):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "ok" in parsed:
            return parsed
    return None


def _to_result(proc: subprocess.CompletedProcess[str]) -> ValidationResult:
    parsed = _parse_result_line(proc.stdout) if proc.returncode in (EXIT_OK, EXIT_INVALID) else None
    if parsed is None:
        raise ValidatorError(
            f"validator exited with {proc.returncode} and no result line.\n"
            f"stdout: {proc.stdout.strip()}\nstderr: {proc.stderr.strip()}"
        )
    error = parsed.get("error")
    return ValidationResult(
        ok=bool(parsed["ok"]),
        frames=int(parsed.get("frames", 0)),
        error=str(error) if error is not None else None,
    )


def validate_plaintext(plaintext: bytes, purpose: str = DEFAULT_PURPOSE) -> ValidationResult:
    reason = _unavailable_reason()
    if reason is not None:
        raise ValidatorUnavailable(reason)

    with tempfile.NamedTemporaryFile(suffix=".plaintext") as handle:
        handle.write(plaintext)
        handle.flush()
        proc = _run_validator(Path(handle.name), purpose)
    return _to_result(proc)


def validate_backup_dir(
    backup_dir: Path,
    passphrase: str,
    aci: str,
    purpose: str = DEFAULT_PURPOSE,
) -> ValidationResult:
    backup_key = aep_to_backup_key(validate_aep(passphrase))
    backup_id = decrypt_metadata(backup_dir / "metadata", backup_key).backup_id
    if backup_key_to_backup_id(backup_key, aci) != backup_id:
        raise ValueError(
            f"ACI {aci} does not match the BackupId recorded in {backup_dir / 'metadata'}"
        )
    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, backup_id)
    plaintext = decrypt_main((backup_dir / "main").read_bytes(), hmac_key, aes_key)
    return validate_plaintext(plaintext, purpose)
