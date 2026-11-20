"""Worker functions bridging TUI to signal_ark core logic."""

from __future__ import annotations

import shutil
import sqlite3
import threading
from pathlib import Path
from typing import Callable

from signal_ark.tui.app import WizardState


class Cancelled(Exception):
    """Raised when the user cancels a running build/inspect/import."""


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise Cancelled("Cancelled by user")


def _snapshot_files(files_dir: Path) -> frozenset[Path]:
    """Paths present under files_dir before this run writes anything."""
    if not files_dir.exists():
        return frozenset()
    return frozenset(files_dir.rglob("*"))


def _discard_new_files(files_dir: Path, before: frozenset[Path], preexisted: bool) -> None:
    """Remove only what this cancelled run wrote; leave pre-existing files alone."""
    if not files_dir.exists():
        return
    if not preexisted:
        shutil.rmtree(files_dir, ignore_errors=True)
        return
    new_paths = sorted(set(files_dir.rglob("*")) - before, reverse=True)
    for path in new_paths:
        if path.is_symlink():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)


def run_preview(state: WizardState) -> dict[str, int]:
    """Lightweight read-only preview: validate inputs, count data."""
    from signal_ark.kdf import aep_to_backup_key, validate_aep
    from signal_ark.mapping.desktop_db import count_preview
    from signal_ark.metadata import decrypt_metadata

    stats: dict[str, int] = {}

    validate_aep(state.passphrase)
    backup_key = aep_to_backup_key(state.passphrase)

    if state.seed_dir:
        meta = decrypt_metadata(state.seed_dir / "metadata", backup_key)
        stats["backup_version"] = meta.version

    if state.mode == "build" and state.desktop_db:
        conn = sqlite3.connect(f"file:{state.desktop_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            stats.update(count_preview(conn))
        finally:
            conn.close()

    if state.mode == "inspect" and state.seed_dir:
        from signal_ark.decrypt import decrypt_main, parse_frames
        from signal_ark.kdf import backup_key_to_message_backup_key

        meta = decrypt_metadata(state.seed_dir / "metadata", backup_key)
        hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, meta.backup_id)
        main_path = state.seed_dir / "main"
        if main_path.exists():
            plaintext = decrypt_main(main_path.read_bytes(), hmac_key, aes_key)
            result = parse_frames(plaintext)
            stats["frames"] = len(result.frames)
            type_counts: dict[str, int] = {}
            for frame in result.frames:
                t = frame.WhichOneof("item") or "unknown"
                type_counts[t] = type_counts.get(t, 0) + 1
            stats.update(type_counts)

    return stats


def run_build(
    state: WizardState,
    on_log: Callable[[str], None],
    cancel: threading.Event | None = None,
) -> dict[str, int]:
    """Execute a full build and return stats.

    Cancellation is cooperative: checkpoints run between steps. A single
    step already in progress (metadata decrypt, seed decrypt, or the
    map_desktop_to_frames call) cannot be interrupted and finishes first.
    """
    from signal_ark.decrypt import decrypt_main, parse_frames
    from signal_ark.encrypt import write_backup_directory
    from signal_ark.kdf import aep_to_backup_key, backup_key_to_message_backup_key, validate_aep
    from signal_ark.mapping import map_desktop_to_frames
    from signal_ark.metadata import decrypt_metadata

    _check_cancel(cancel)
    aep = validate_aep(state.passphrase)
    backup_key = aep_to_backup_key(aep)
    on_log("Derived backup key.")

    assert state.seed_dir is not None
    meta = decrypt_metadata(state.seed_dir / "metadata", backup_key)
    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, meta.backup_id)
    on_log(f"Decrypted seed metadata (version {meta.version}).")

    _check_cancel(cancel)
    seed_plaintext = decrypt_main((state.seed_dir / "main").read_bytes(), hmac_key, aes_key)
    seed_result = parse_frames(seed_plaintext)
    on_log(f"Parsed seed: {len(seed_result.frames)} frames.")

    seed_account_frame = None
    for f in seed_result.frames:
        if f.HasField("account"):
            seed_account_frame = f
            break

    if seed_account_frame is None:
        raise RuntimeError("No AccountData frame found in seed backup")

    assert state.output_dir is not None
    files_dir = state.output_dir / "files"
    files_dir_preexisted = files_dir.exists()
    files_before = _snapshot_files(files_dir)
    _check_cancel(cancel)
    on_log("Mapping Desktop data to backup frames...")

    assert state.desktop_db is not None
    assert state.attachments_dir is not None
    try:
        result = map_desktop_to_frames(
            db_path=state.desktop_db,
            attachments_dir=state.attachments_dir,
            seed_backup_info=seed_result.backup_info,
            seed_account_frame=seed_account_frame,
            seed_frames=seed_result.frames,
            self_aci=state.self_aci,
            output_files_dir=files_dir,
        )
        _check_cancel(cancel)
    except Cancelled:
        _discard_new_files(files_dir, files_before, files_dir_preexisted)
        raise

    on_log(f"Mapped: {result.stats}")

    backup_dir = state.output_dir / "signal-backup-rebuilt"
    write_backup_directory(
        output_dir=backup_dir,
        backup_info=result.backup_info,
        frames=result.frames,
        hmac_key=hmac_key,
        aes_key=aes_key,
        backup_key=backup_key,
        backup_id=meta.backup_id,
        media_names=result.media_names,
        version=meta.version,
    )

    on_log(f"Wrote backup to {backup_dir}")
    on_log(f"Files: {files_dir} ({len(result.media_names)} entries)")
    on_log("Done.")

    state.result_output_dir = backup_dir
    state.result_files_dir = files_dir
    state.result_stats = dict(result.stats)
    return dict(result.stats)


def run_import_v1(
    state: WizardState,
    on_log: Callable[[str], None],
    cancel: threading.Event | None = None,
) -> dict[str, int]:
    """Convert a v1 backup to a v2 backup directory and return stats.

    Cancellation is cooperative: checkpoints run between steps. The
    convert_v1_to_v2 call itself cannot be interrupted and finishes first.
    """
    from signal_ark.decrypt import decrypt_main, parse_frames
    from signal_ark.encrypt import write_backup_directory
    from signal_ark.kdf import aep_to_backup_key, backup_key_to_message_backup_key, validate_aep
    from signal_ark.metadata import decrypt_metadata
    from signal_ark.v1_to_v2 import convert_v1_to_v2

    _check_cancel(cancel)
    aep = validate_aep(state.passphrase)
    backup_key = aep_to_backup_key(aep)

    assert state.seed_dir is not None
    meta = decrypt_metadata(state.seed_dir / "metadata", backup_key)
    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, meta.backup_id)
    on_log(f"BackupId: {meta.backup_id.hex()}")

    _check_cancel(cancel)
    seed_plaintext = decrypt_main((state.seed_dir / "main").read_bytes(), hmac_key, aes_key)
    seed_result = parse_frames(seed_plaintext)
    on_log(f"Parsed seed: {len(seed_result.frames)} frames.")

    seed_account_frame = None
    for f in seed_result.frames:
        if f.HasField("account"):
            seed_account_frame = f
            break

    if seed_account_frame is None:
        raise RuntimeError("No AccountData frame found in seed backup")

    assert state.output_dir is not None
    assert state.v1_backup_path is not None
    files_dir = state.output_dir / "files"
    files_dir_preexisted = files_dir.exists()
    files_before = _snapshot_files(files_dir)
    _check_cancel(cancel)
    on_log("Converting v1 backup to v2 frames...")

    def progress(stage: str, done: int, skipped: int) -> None:
        _check_cancel(cancel)
        on_log(f"  [{stage}] processed={done} skipped={skipped}")

    try:
        result = convert_v1_to_v2(
            v1_path=state.v1_backup_path,
            v1_passphrase=state.v1_passphrase,
            seed_backup_info=seed_result.backup_info,
            seed_account_frame=seed_account_frame,
            self_aci=state.self_aci,
            output_files_dir=files_dir,
            progress_callback=progress,
        )
        _check_cancel(cancel)
    except Cancelled:
        _discard_new_files(files_dir, files_before, files_dir_preexisted)
        raise

    on_log(f"Mapped: {result.stats}")

    backup_dir = state.output_dir / "signal-backup-rebuilt"
    write_backup_directory(
        output_dir=backup_dir,
        backup_info=result.backup_info,
        frames=result.frames,
        hmac_key=hmac_key,
        aes_key=aes_key,
        backup_key=backup_key,
        backup_id=meta.backup_id,
        media_names=result.media_names,
        version=meta.version,
    )

    on_log(f"Wrote backup to {backup_dir}")
    on_log(f"Files: {files_dir} ({len(result.media_names)} entries)")
    on_log("Done.")

    state.result_output_dir = backup_dir
    state.result_files_dir = files_dir
    state.result_stats = dict(result.stats)
    return dict(result.stats)


def run_inspect(
    state: WizardState,
    on_log: Callable[[str], None],
    cancel: threading.Event | None = None,
) -> dict[str, int]:
    """Inspect a backup and return frame stats.

    Cancellation is cooperative: checkpoints run between steps, so a step
    already in progress (e.g. decrypting the main file) finishes first.
    """
    from signal_ark.content_store import frame_stats
    from signal_ark.decrypt import decrypt_main, parse_frames
    from signal_ark.kdf import aep_to_backup_key, backup_key_to_message_backup_key, validate_aep
    from signal_ark.metadata import decrypt_metadata

    _check_cancel(cancel)
    aep = validate_aep(state.passphrase)
    backup_key = aep_to_backup_key(aep)

    assert state.seed_dir is not None
    meta = decrypt_metadata(state.seed_dir / "metadata", backup_key)
    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, meta.backup_id)
    on_log(f"BackupId: {meta.backup_id.hex()}")

    _check_cancel(cancel)
    plaintext = decrypt_main((state.seed_dir / "main").read_bytes(), hmac_key, aes_key)
    _check_cancel(cancel)
    result = parse_frames(plaintext)
    on_log(f"BackupInfo version: {result.backup_info.version}")

    type_counts, _pointers = frame_stats(result.frames)
    stats: dict[str, int] = {"total_frames": len(result.frames), **type_counts}

    for t, c in sorted(stats.items()):
        on_log(f"  {t:25s} {c}")

    on_log("Done.")
    state.result_stats = stats
    return stats
