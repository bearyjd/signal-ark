# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

signal-ark reconstructs Signal v2 backup archives from Signal Desktop data so they can be restored on Signal Android or Molly. It decrypts a seed backup from the phone, maps Desktop's SQLite DB into v2 backup frames, encrypts the result, and produces a directory that Signal Android can restore.

## Build & Run

```bash
uv sync                          # install dependencies (uses uv, not pip)
uv run signal-ark --help         # CLI entry point
uv run signal-ark decrypt --help
uv run signal-ark build --help
uv run signal-ark inspect --help
```

### Proto regeneration

Proto bindings live in `signal_ark/proto/` (generated, not checked in fully). Regenerate from `proto/` sources:

```bash
protoc -I=proto --python_out=signal_ark/proto proto/Backup.proto proto/LocalArchive.proto proto/V1Backup.proto
```

### Tests

```bash
uv run pytest                    # all tests
uv run pytest tests/test_kdf.py  # just KDF vectors
uv run pytest -k roundtrip       # just round-trip tests
```

KDF tests validate against libsignal's published test vectors (PLAN.md section 2). If these fail, nothing else will work.

## Architecture

### Crypto pipeline (the core flow)

```
AEP (64-char passphrase)
  → BackupKey (HKDF)
    → BackupId (HKDF with ACI)
      → MessageBackupKey = (hmac_key, aes_key) for main file
      → LocalMetadataKey for metadata file
```

All derivation constants are date-prefixed strings (e.g. `"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:"`). Legacy vs modern format is determined by whether a forward-secrecy token is present.

### Module responsibilities

- **kdf.py** — Pure KDF chain. No I/O. Tested against libsignal vectors.
- **metadata.py** — Read/write the `metadata` file (AES-256-CTR encrypted BackupId).
- **decrypt.py** — Decrypt `main` file: detect legacy/modern format, verify HMAC, AES-256-CBC decrypt, gzip decompress, parse varint-delimited protobuf frames. Also has `_write_varint` used by encrypt.py.
- **encrypt.py** — Reverse of decrypt: serialize frames → gzip → AES-CBC → HMAC. Also writes the files manifest and the complete backup directory.
- **mapper.py** — The big one. Reads Desktop's SQLite DB and produces v2 `Frame` protobufs. Handles Recipients (self, contacts, groups), Chats, ChatItems (incoming/outgoing messages), and attachment encryption. Uses `IdAllocator` to map Desktop conversation IDs to backup recipient/chat IDs.
- **v1_decrypt.py** — v1 backup KDF and per-frame decryption. SHA-512 iterated 250K times → HKDF("Backup Export") → cipher_key + mac_key. Stateful `V1FrameDecryptor` with counter-bump AES-256-CTR, truncated HMAC verification.
- **v1_parser.py** — Streaming v1 backup parser. Yields typed `V1ParsedFrame` objects (statements, preferences, attachments with inline data). `collect_v1_database()` replays SQL into in-memory SQLite.
- **v1_to_v2.py** — Converts parsed v1 backup into v2 frames. Maps recipients (modern `recipient` table or legacy `recipient_preferences`), threads, sms/mms messages, and re-encrypts inline attachments.
- **cli.py** — Click CLI with five commands: `decrypt`, `build`, `inspect`, `dump-v1` (dump v1 backup as JSONL), `import-v1` (convert v1 → v2 backup directory).

### Encryption envelope (used for main file and individual attachments; files manifest is unencrypted raw protobuf)

```
[16-byte IV] [AES-256-CBC ciphertext, PKCS7 padded] [32-byte HMAC-SHA256(IV || ciphertext)]
```

### Backup directory structure produced by `build`

```
output/signal-backup-rebuilt/
  main          — encrypted frame stream
  metadata      — encrypted BackupId
  files         — files manifest (list of mediaNames)
output/files/
  XX/           — sharded by first 2 hex chars of mediaName
    <mediaName> — individually encrypted attachment
```

### Frame ordering (enforced by Backup.proto)

1. Exactly one `AccountData` first
2. Referenced-before-referencing (Recipient before Chat, Chat before ChatItem)
3. All ChatItems in global received-timestamp order
4. ChatFolders last (after all Recipients and Chats)

### Attachment content store

Each attachment gets a random 64-byte `localKey` (first 32 = AES, last 32 = HMAC). The `mediaName` is `hex(SHA256(plaintextHash || localKey))`. Files are sharded into `files/XX/` by first two hex chars of mediaName.

### Desktop attachment encryption

Desktop stores attachments encrypted at rest using a per-file `localKey` (64 bytes, in `message_attachments.localKey`). Format: `[IV 16][AES-256-CBC, PKCS7][HMAC-SHA256 32]`. Plaintext is zero-padded to a block boundary; truncate to `message_attachments.size` after decryption.

The `message_attachments` table only exists in newer Desktop versions. Older versions embed attachment metadata in the `messages.json` blob and may store files as plaintext.

The `decrypt_desktop_attachment` function in `mapper.py` handles this decryption. `encrypt_attachment` accepts optional `desktop_local_key` and `plaintext_size` params to decrypt before re-encrypting for the backup.

## Open questions

- **Backup directory layout on phone** — Does Signal Android expect `files/` as a sibling to the backup dir or inside it? Current code produces them as siblings under `output/`. Needs verification against a working restore.
- **Older Desktop DB support** — The mapper queries `message_attachments` which doesn't exist in older Desktop versions. Needs a fallback path that reads attachment info from `messages.json`.

## Reference material

- **PLAN.md** — Full crypto spec, KDF test vectors, file format details, implementation phases
- **docs/v1-backup-format.md** — v1 backup format specification (file layout, KDF chain, per-frame crypto)
- **proto/Backup.proto** — Signal's v2 backup frame schema (from Signal-Android)
- **proto/V1Backup.proto** — v1 backup frame schema (proto2, `signal_v1` package)
- **proto/LocalArchive.proto** — Metadata and FilesFrame schemas
- **Signal-Android-ref/**, **libsignal-ref/**, **molly-ref/** — Checked-out reference repos (not part of this project's code)
