"""Worker functions bridging TUI to signal_ark core logic."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable

from signal_ark.tui.app import WizardState


def run_preview(state: WizardState) -> dict[str, int]:
    """Lightweight read-only preview: validate inputs, count data."""
    from signal_ark.kdf import aep_to_backup_key, validate_aep
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
            stats["conversations"] = conn.execute(
                "SELECT COUNT(*) FROM conversations"
            ).fetchone()[0]
            stats["messages"] = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE type IN ('incoming', 'outgoing')"
            ).fetchone()[0]
            try:
                stats["attachments"] = conn.execute(
                    "SELECT COUNT(*) FROM message_attachments WHERE path IS NOT NULL"
                ).fetchone()[0]
            except sqlite3.OperationalError:
                stats["attachments"] = 0
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
) -> dict[str, int]:
    """Execute a full build and return stats."""
    from signal_ark.decrypt import decrypt_main, parse_frames
    from signal_ark.encrypt import write_backup_directory
    from signal_ark.kdf import aep_to_backup_key, backup_key_to_message_backup_key, validate_aep
    from signal_ark.mapper import map_desktop_to_frames
    from signal_ark.metadata import decrypt_metadata

    aep = validate_aep(state.passphrase)
    backup_key = aep_to_backup_key(aep)
    on_log("Derived backup key.")

    assert state.seed_dir is not None
    meta = decrypt_metadata(state.seed_dir / "metadata", backup_key)
    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, meta.backup_id)
    on_log(f"Decrypted seed metadata (version {meta.version}).")

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
    on_log("Mapping Desktop data to backup frames...")

    assert state.desktop_db is not None
    assert state.attachments_dir is not None
    result = map_desktop_to_frames(
        db_path=state.desktop_db,
        attachments_dir=state.attachments_dir,
        seed_backup_info=seed_result.backup_info,
        seed_account_frame=seed_account_frame,
        seed_frames=seed_result.frames,
        self_aci=state.self_aci,
        output_files_dir=files_dir,
    )

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
) -> dict[str, int]:
    """Inspect a backup and return frame stats."""
    from signal_ark.decrypt import decrypt_main, parse_frames
    from signal_ark.kdf import aep_to_backup_key, backup_key_to_message_backup_key, validate_aep
    from signal_ark.metadata import decrypt_metadata

    aep = validate_aep(state.passphrase)
    backup_key = aep_to_backup_key(aep)

    assert state.seed_dir is not None
    meta = decrypt_metadata(state.seed_dir / "metadata", backup_key)
    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, meta.backup_id)
    on_log(f"BackupId: {meta.backup_id.hex()}")

    plaintext = decrypt_main((state.seed_dir / "main").read_bytes(), hmac_key, aes_key)
    result = parse_frames(plaintext)
    on_log(f"BackupInfo version: {result.backup_info.version}")

    stats: dict[str, int] = {"total_frames": len(result.frames)}
    for frame in result.frames:
        t = frame.WhichOneof("item") or "unknown"
        stats[t] = stats.get(t, 0) + 1

    for t, c in sorted(stats.items()):
        on_log(f"  {t:25s} {c}")

    on_log("Done.")
    state.result_stats = stats
    return stats
