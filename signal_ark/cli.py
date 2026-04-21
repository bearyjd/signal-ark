"""CLI for signal-ark: decrypt and inspect Signal v2 backups."""

from __future__ import annotations

import json
from pathlib import Path

import click

from signal_ark.decrypt import (
    backup_info_to_dict,
    decrypt_main,
    frame_to_dict,
    parse_files_manifest,
    parse_frames,
)
from signal_ark.kdf import (
    aep_to_backup_key,
    backup_key_to_backup_id,
    backup_key_to_message_backup_key,
    validate_aep,
)
from signal_ark.metadata import decrypt_metadata


@click.group()
def main() -> None:
    """signal-ark: Signal v2 backup tools."""


@main.command()
@click.option("--seed-dir", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--passphrase", required=True, help="64-char AccountEntropyPool")
@click.option("--aci", default=None, help="ACI UUID (auto-detected from metadata if omitted)")
@click.option("--output", "-o", default="decrypted", type=click.Path(path_type=Path))
def decrypt(seed_dir: Path, passphrase: str, aci: str | None, output: Path) -> None:
    """Decrypt a v2 backup seed directory."""
    output.mkdir(parents=True, exist_ok=True)

    aep = validate_aep(passphrase)
    backup_key = aep_to_backup_key(aep)
    click.echo(f"BackupKey: {backup_key.hex()}")

    metadata_path = seed_dir / "metadata"
    if not metadata_path.exists():
        raise click.ClickException(f"No metadata file found at {metadata_path}")

    meta = decrypt_metadata(metadata_path, backup_key)
    click.echo(f"BackupId:  {meta.backup_id.hex()}")
    click.echo(f"Version:   {meta.version}")

    (output / "metadata.json").write_text(json.dumps(meta.to_dict(), indent=2))
    click.echo(f"Wrote {output / 'metadata.json'}")

    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, meta.backup_id)
    click.echo(f"HMAC key:  {hmac_key.hex()}")
    click.echo(f"AES key:   {aes_key.hex()}")

    main_path = seed_dir / "main"
    if not main_path.exists():
        raise click.ClickException(f"No main file found at {main_path}")

    main_data = main_path.read_bytes()
    click.echo(f"Main file: {len(main_data)} bytes, first 8: {main_data[:8].hex()}")

    plaintext = decrypt_main(main_data, hmac_key, aes_key)
    (output / "main.plaintext").write_bytes(plaintext)
    click.echo(f"Wrote {output / 'main.plaintext'} ({len(plaintext)} bytes)")

    result = parse_frames(plaintext)
    click.echo(f"BackupInfo version: {result.backup_info.version}")
    click.echo(f"Frames: {len(result.frames)}")

    with open(output / "frames.jsonl", "w") as f:
        info_dict = backup_info_to_dict(result.backup_info)
        f.write(json.dumps({"_type": "BackupInfo", **info_dict}) + "\n")
        for frame in result.frames:
            d = frame_to_dict(frame)
            item_type = frame.WhichOneof("item") or "unknown"
            f.write(json.dumps({"_type": item_type, **d}) + "\n")

    click.echo(f"Wrote {output / 'frames.jsonl'}")

    files_path = seed_dir / "files"
    if files_path.exists():
        files_data = files_path.read_bytes()
        click.echo(f"Files manifest: {len(files_data)} bytes")
        media_names = parse_files_manifest(files_data)
        (output / "files_manifest.json").write_text(json.dumps(media_names, indent=2))
        click.echo(f"Wrote {output / 'files_manifest.json'} ({len(media_names)} entries)")

    click.echo("Done.")


@main.command()
@click.option("--seed-dir", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--passphrase", required=True, help="64-char AccountEntropyPool")
@click.option("--desktop-db", required=True, type=click.Path(exists=True, path_type=Path),
              help="Decrypted Signal Desktop SQLite database")
@click.option("--attachments-dir", required=True, type=click.Path(exists=True, path_type=Path),
              help="Signal Desktop attachments.noindex/ directory")
@click.option("--output", "-o", required=True, type=click.Path(path_type=Path),
              help="Output directory for rebuilt backup")
@click.option("--self-aci", required=True, help="Your ACI UUID (from Desktop items table)")
def build(
    seed_dir: Path,
    passphrase: str,
    desktop_db: Path,
    attachments_dir: Path,
    output: Path,
    self_aci: str,
) -> None:
    """Build a v2 backup from Desktop data + seed backup."""
    from signal_ark.encrypt import write_backup_directory
    from signal_ark.mapper import map_desktop_to_frames

    aep = validate_aep(passphrase)
    backup_key = aep_to_backup_key(aep)
    meta = decrypt_metadata(seed_dir / "metadata", backup_key)
    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, meta.backup_id)

    click.echo(f"BackupKey: {backup_key.hex()}")
    click.echo(f"BackupId:  {meta.backup_id.hex()}")

    # Decrypt seed to get BackupInfo and AccountData
    seed_plaintext = decrypt_main((seed_dir / "main").read_bytes(), hmac_key, aes_key)
    seed_result = parse_frames(seed_plaintext)
    click.echo(f"Seed: {len(seed_result.frames)} frames")

    seed_account_frame = None
    for f in seed_result.frames:
        if f.HasField("account"):
            seed_account_frame = f
            break

    if seed_account_frame is None:
        raise click.ClickException("No AccountData frame found in seed backup")

    # Map Desktop data to frames
    files_dir = output / "files"
    click.echo("Mapping Desktop data to backup frames...")

    result = map_desktop_to_frames(
        db_path=desktop_db,
        attachments_dir=attachments_dir,
        seed_backup_info=seed_result.backup_info,
        seed_account_frame=seed_account_frame,
        seed_frames=seed_result.frames,
        self_aci=self_aci,
        output_files_dir=files_dir,
    )

    click.echo(f"Mapped: {result.stats}")

    # Write backup directory
    backup_dir = output / "signal-backup-rebuilt"
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

    click.echo(f"Wrote backup to {backup_dir}")
    click.echo(f"Files content store: {files_dir} ({len(result.media_names)} entries)")
    click.echo("Done. Push to phone and test restore in Molly.")


if __name__ == "__main__":
    main()
