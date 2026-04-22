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


@main.command()
@click.option("--backup-dir", required=True, type=click.Path(exists=True, path_type=Path),
              help="Backup directory containing main, metadata, files")
@click.option("--passphrase", required=True, help="64-char AccountEntropyPool")
@click.option("--files-dir", default=None, type=click.Path(exists=True, path_type=Path),
              help="Attachment content store (files/ directory with XX/ shards)")
def inspect(backup_dir: Path, passphrase: str, files_dir: Path | None) -> None:
    """Inspect a v2 backup: validate structure, check attachments, report issues."""
    import hashlib

    aep = validate_aep(passphrase)
    backup_key = aep_to_backup_key(aep)
    meta = decrypt_metadata(backup_dir / "metadata", backup_key)
    hmac_key, aes_key = backup_key_to_message_backup_key(backup_key, meta.backup_id)

    click.echo(f"BackupId:  {meta.backup_id.hex()}")
    click.echo(f"Version:   {meta.version}")

    seed_plaintext = decrypt_main((backup_dir / "main").read_bytes(), hmac_key, aes_key)
    result = parse_frames(seed_plaintext)
    click.echo(f"BackupInfo version: {result.backup_info.version}")

    # Frame stats
    type_counts: dict[str, int] = {}
    file_pointers: list[tuple[str, object]] = []
    for frame in result.frames:
        item_type = frame.WhichOneof("item") or "unknown"
        type_counts[item_type] = type_counts.get(item_type, 0) + 1
        if item_type == "chatItem":
            ci = frame.chatItem
            if ci.HasField("standardMessage"):
                for ma in ci.standardMessage.attachments:
                    fp = ma.pointer
                    file_pointers.append((str(ci.dateSent), fp))

    click.echo(f"\nFrame counts:")
    for t, c in sorted(type_counts.items()):
        click.echo(f"  {t:25s} {c}")

    click.echo(f"\nAttachments in frames: {len(file_pointers)}")

    # Files manifest
    manifest_path = backup_dir / "files"
    manifest_names: list[str] = []
    if manifest_path.exists() and manifest_path.is_file():
        manifest_names = parse_files_manifest(manifest_path.read_bytes())
        click.echo(f"Files manifest entries: {len(manifest_names)}")

    # Check FilePointer fields
    issues: list[str] = []
    missing_local_key = 0
    missing_plaintext_hash = 0
    missing_size = 0
    for sent_at, fp in file_pointers:
        li = fp.locatorInfo
        if not li.localKey:
            missing_local_key += 1
        if not li.plaintextHash:
            missing_plaintext_hash += 1
        if not li.size:
            missing_size += 1

    if missing_local_key:
        issues.append(f"{missing_local_key} attachments missing locatorInfo.localKey")
    if missing_plaintext_hash:
        issues.append(f"{missing_plaintext_hash} attachments missing locatorInfo.plaintextHash")
    if missing_size:
        issues.append(f"{missing_size} attachments missing locatorInfo.size")

    # Cross-reference manifest with content store
    if files_dir and manifest_names:
        missing_files = 0
        for name in manifest_names:
            shard = name[:2]
            if not (files_dir / shard / name).exists():
                missing_files += 1
        if missing_files:
            issues.append(f"{missing_files}/{len(manifest_names)} manifest entries have no file in content store")
        else:
            click.echo(f"Content store:  all {len(manifest_names)} files present")

    # Verify a sample attachment round-trip
    if files_dir and file_pointers:
        click.echo(f"\nSample attachment validation:")
        for sent_at, fp in file_pointers[:3]:
            li = fp.locatorInfo
            if not li.localKey or not li.plaintextHash:
                continue
            media_name = hashlib.sha256(bytes(li.plaintextHash) + bytes(li.localKey)).hexdigest()
            shard = media_name[:2]
            fpath = files_dir / shard / media_name
            if not fpath.exists():
                click.echo(f"  [{sent_at}] {fp.contentType} — FILE MISSING ({media_name[:16]}...)")
                continue
            try:
                from cryptography.hazmat.primitives import hashes as _h, hmac as _hmac, padding
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

                enc = fpath.read_bytes()
                iv, ct, mac = enc[:16], enc[16:-32], enc[-32:]
                lk = bytes(li.localKey)
                h = _hmac.HMAC(lk[32:], _h.SHA256())
                h.update(iv)
                h.update(ct)
                h.verify(mac)

                cipher = Cipher(algorithms.AES(lk[:32]), modes.CBC(iv))
                dec = cipher.decryptor()
                padded = dec.update(ct) + dec.finalize()
                unpadder = padding.PKCS7(128).unpadder()
                pt = unpadder.update(padded) + unpadder.finalize()

                pt_hash = hashlib.sha256(pt).digest()
                hash_ok = pt_hash == bytes(li.plaintextHash)
                size_ok = len(pt) == li.size if li.size else "no size"

                click.echo(f"  [{sent_at}] {fp.contentType:15s} decrypt=OK  hash={'OK' if hash_ok else 'MISMATCH'}  size={size_ok}  {len(pt)} bytes")
            except Exception as e:
                click.echo(f"  [{sent_at}] {fp.contentType} — DECRYPT FAILED: {e}")

    # Summary
    if issues:
        click.echo(f"\nIssues found:")
        for i in issues:
            click.echo(f"  - {i}")
    else:
        click.echo(f"\nNo issues found.")


if __name__ == "__main__":
    main()
