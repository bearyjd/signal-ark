"""Build a synthetic, on-disk v2 seed-backup directory for tests.

Not re-exported from `tests/__init__.py` — this is an opt-in helper, not a
fixture-by-default. Import it explicitly:

    from tests.helpers.synthetic_seed import synthetic_seed_dir

Produces a real `metadata` + `main` pair using the exact same code paths as
`signal-ark build` / `signal-ark decrypt` (signal_ark.encrypt and
signal_ark.metadata), so anything that passes against a synthetic seed dir
is exercising production encoding logic, not a parallel hand-rolled one.

No real backup data is used or required — every key, ACI, and frame here is
synthetic (see CLAUDE.md "Privacy / real data handling").
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from signal_ark.encrypt import write_backup_directory
from signal_ark.kdf import (
    aep_to_backup_key,
    backup_key_to_backup_id,
    backup_key_to_message_backup_key,
    validate_aep,
)
from signal_ark.proto.Backup_pb2 import AccountData, BackupInfo, Frame

# 64 chars, restricted to kdf.AEP_CHARSET ([0-9a-z]) — an arbitrary but fixed
# synthetic passphrase, not derived from any real account.
DEFAULT_AEP = "0123456789abcdefghijklmnopqrstuv" * 2
DEFAULT_ACI = "00000000-0000-4000-8000-000000000001"


@dataclass(frozen=True)
class SyntheticSeed:
    """A synthetic seed backup written to disk, plus the keys used to build it."""

    dir: Path
    aep: str
    aci: str
    backup_key: bytes
    backup_id: bytes


def default_account_frame(**overrides: object) -> Frame:
    """A minimal valid AccountData frame; pass field overrides to customize."""
    account = AccountData()
    account.givenName = str(overrides.pop("givenName", "Synthetic"))
    account.familyName = str(overrides.pop("familyName", "Seed"))
    account.avatarUrlPath = str(overrides.pop("avatarUrlPath", ""))
    account.accountSettings.readReceipts = bool(overrides.pop("readReceipts", True))
    account.accountSettings.linkPreviews = bool(overrides.pop("linkPreviews", True))
    if not overrides.pop("no_profile_key", False):
        account.profileKey = os.urandom(32)
    if overrides:
        raise TypeError(f"Unknown overrides: {sorted(overrides)}")

    frame = Frame()
    frame.account.CopyFrom(account)
    return frame


def synthetic_seed_dir(
    tmp_path: Path,
    *,
    aep: str = DEFAULT_AEP,
    aci: str = DEFAULT_ACI,
    frames: list[Frame] | None = None,
    version: int = 1,
    backup_time_ms: int = 1_700_000_000_000,
) -> SyntheticSeed:
    """Write a real v2 seed-backup directory (metadata + main) to tmp_path.

    `frames` defaults to a single valid AccountData frame. Pass `frames=[]`
    (or frames missing an `account` field) to build edge-case fixtures, e.g.
    a seed with no AccountData frame at all.

    Returns a `SyntheticSeed` whose `.dir` can be fed straight into
    `signal-ark decrypt --seed-dir ...` or `signal_ark.decrypt.decrypt_main`
    / `parse_frames` after re-deriving keys from `.aep` / `.aci`.
    """
    aep = validate_aep(aep)
    backup_key = aep_to_backup_key(aep)
    backup_id = backup_key_to_backup_id(backup_key, aci)
    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, backup_id)

    if frames is None:
        frames = [default_account_frame()]

    backup_info = BackupInfo()
    backup_info.version = version
    backup_info.backupTimeMs = backup_time_ms

    output_dir = tmp_path / "seed"
    write_backup_directory(
        output_dir=output_dir,
        backup_info=backup_info,
        frames=frames,
        hmac_key=hmac_key,
        aes_key=aes_key,
        backup_key=backup_key,
        backup_id=backup_id,
        media_names=None,
        version=version,
    )

    return SyntheticSeed(
        dir=output_dir,
        aep=aep,
        aci=aci,
        backup_key=backup_key,
        backup_id=backup_id,
    )
