# signal-ark

Reconstruct Signal v2 backup archives from Signal Desktop data. Restores chat history and media attachments to Signal Android or Molly.

## Prerequisites

- Python 3.12+
- A Signal v2 seed backup from your phone (provides AccountData and encryption keys)
- A decrypted Signal Desktop SQLite database
- Your 64-character AccountEntropyPool (AEP) passphrase

## Installation

```bash
uv sync            # recommended (uses uv)
pip install .      # or with pip
```

## Commands

<!-- AUTO-GENERATED:commands -->
| Command | Description |
|---------|-------------|
| `signal-ark decrypt` | Decrypt a v2 backup seed directory and dump frames as JSONL |
| `signal-ark build` | Build a v2 backup from Desktop data + seed backup |
| `signal-ark inspect` | Validate a built backup: frame structure, manifest, attachment decryption |
| `signal-ark tui` | Launch the interactive TUI wizard (requires `[tui]` extra) |
<!-- /AUTO-GENERATED:commands -->

### TUI Wizard (optional)

```bash
pip install signal-ark[tui]   # or: uv sync --extra tui
signal-ark tui
```

The TUI provides a step-by-step wizard for building backups and inspecting them, with file browsing, masked passphrase entry, and progress tracking.

## Usage

### Decrypt an existing backup

```bash
python -m signal_ark.cli decrypt \
  --seed-dir /path/to/seed-backup \
  --passphrase "YOUR64CHARACCOUNTENTROPYPOOL..." \
  -o decrypted/
```

Outputs: `metadata.json`, `main.plaintext`, `frames.jsonl`, `files_manifest.json`

### Build a new backup from Desktop data

```bash
python -m signal_ark.cli build \
  --seed-dir /path/to/seed-backup \
  --passphrase "YOUR64CHARACCOUNTENTROPYPOOL..." \
  --desktop-db /path/to/decrypted-desktop.sqlite \
  --attachments-dir /path/to/Signal/attachments.noindex \
  --self-aci "your-aci-uuid" \
  -o output/
```

Outputs:
- `output/signal-backup-rebuilt/` — backup directory (`main`, `metadata`, `files` manifest)
- `output/files/` — encrypted attachment content store (sharded by first 2 hex chars)

### Deploy to phone

```bash
adb push output/signal-backup-rebuilt /sdcard/SignalBackups/signal-backup-rebuilt
adb push output/files /sdcard/SignalBackups/files
```

Then restore in Signal Android: Settings > Chats > Restore from backup.

## Workflow

```
Signal Desktop DB ──┐
                    ├──→ signal-ark build ──→ v2 backup dir ──→ adb push ──→ Signal Android
Seed backup ────────┘
```

1. **Get a seed backup** — pull from phone via `adb pull /sdcard/SignalBackups/<backup-dir>`
2. **Decrypt Desktop DB** — Signal Desktop uses SQLCipher; decrypt with the key from `config.json`
3. **Find your ACI** — in the Desktop DB: `SELECT json FROM items WHERE id = 'uuid_id'`
4. **Build** — run `signal-ark build` with all inputs
5. **Push** — `adb push` the output to `/sdcard/SignalBackups/`
6. **Restore** — fresh install or restore from local backup in Signal Android

## Decrypting the Desktop Database

Signal Desktop encrypts its SQLite DB with SQLCipher. The key is in `config.json`:

```python
pip install sqlcipher3-binary

import sqlcipher3, json
key = json.load(open("config.json"))["key"]
db = sqlcipher3.connect("sql/db.sqlite")
db.execute(f"PRAGMA key=\"x'{key}'\"")
db.execute("PRAGMA cipher_compatibility = 4")
db.execute("ATTACH DATABASE 'decrypted.sqlite' AS plaintext KEY ''")
db.execute('SELECT sqlcipher_export("plaintext")')
db.execute("DETACH DATABASE plaintext")
```

## Architecture

```
signal_ark/
├── cli.py       — Click CLI (decrypt, build commands)
├── kdf.py       — Key derivation (AEP → BackupKey → BackupId → message keys)
├── metadata.py  — Metadata file encrypt/decrypt (BackupId in AES-256-CTR)
├── decrypt.py   — Main file decryption (AES-256-CBC + HMAC-SHA256, gzip, protobuf)
├── encrypt.py   — Main file encryption + backup directory writer
├── mapper.py    — Desktop DB → v2 backup frame mapper + attachment encryption
└── proto/       — Generated protobuf bindings (Backup.proto, LocalArchive.proto)
```

See [v2 Backup Format Specification](docs/v2-backup-format.md) for a complete description of the binary format, crypto, and frame structure.

## What gets restored

| Content | Status |
|---------|--------|
| 1:1 text messages | Supported |
| Group text messages | Supported |
| Image/video/file attachments | Supported |
| Contact profiles | Supported |
| Conversation metadata | Supported |
| Reactions, quotes | Not yet |
| Call history | Not yet |
| Stickers | Passed through from seed |
| Disappearing messages config | Supported |

## Known Issues

- **Molly**: Blocked by [Issue #733](https://github.com/nickeito/molly/issues/733) — StorageSyncJob runs before restore completes. Use Signal Android until fixed.
- **Older Desktop versions**: Schema differs (JSON blobs vs separate tables). The mapper targets the current Desktop schema with `message_attachments` table.
- **Attachments without plaintextHash**: ~1% of attachments may lack this field; media name derivation falls back to file hash (correct for unencrypted files, wrong for encrypted).

## Credits

Inspired by [transistor-man's writeup](https://transistor-man.com/restoring_android_signal_from_desktop.html) on restoring Android Signal from Desktop.

## License

AGPL-3.0-only
