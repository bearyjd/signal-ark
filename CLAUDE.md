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

### Lint / type-check

No `ruff`/`mypy` config exists yet. `mypy-protobuf` (dev dependency) only generates typed `.pyi` stubs during proto regeneration — it is not a project-wide type checker. There is currently no automated lint/type-check gate; run `uv run pytest` as the sole automated correctness signal until one is added (see `.agent_native/agent_roadmap.md`).

## Agent-native audit

`.agent_native/agent_roadmap.md` contains a prioritized audit of gaps that block an AI agent from autonomously reproducing, implementing, testing, and verifying a bug fix or feature end-to-end (missing synthetic-backup fixtures, missing CLI-level tests, structural entanglement in `mapper.py`, etc.). Consult it before starting non-trivial work — it flags what to build first for the biggest reduction in required human attention.

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

### Recipient mapping is duplicated across two paths — change both or neither

There are **two independent implementations** of "conversation JSON → v2 Recipient frame":

- `mapper.py`'s `build_contact_recipient` / `build_group_recipient` — used by the Desktop-DB → v2 `build` path.
- `v1_to_v2.py`'s `_map_recipients_modern` / `_map_recipients_legacy` — used by the v1-backup → v2 `import-v1` path.

They are not layered on top of each other. A bug or field-mapping fix in one (e.g. avatar color, profile name, group membership) very likely exists in the other and must be checked/fixed there too. There is no shared abstraction yet (tracked in `.agent_native/agent_roadmap.md` item 4) — until that lands, treat any recipient-mapping change as a two-file change.

### Consulting the reference repos

`Signal-Android-ref/`, `libsignal-ref/`, and `molly-ref/` are checked-out third-party clones for **source lookup only** — never edit them, never audit them as part of this project, and they have no bearing on this repo's own build/test/lint commands. Use them when the proto schema or a format detail is ambiguous:

- **Proto field semantics unclear** (e.g. what a `FilePointer` variant means, how a field is actually populated/read) → grep the Kotlin/Java model and (de)serialization code in `Signal-Android-ref/` for the same field name.
- **KDF/crypto constants, derivation order, or forward-secrecy-token behavior in question** → grep the Rust backup crate in `libsignal-ref/` — it's the canonical implementation this project ports from.
- **Molly-specific restore behavior** (e.g. whether a field or directory layout differs from stock Signal Android) → check `molly-ref/`.

Example: the "Backup directory layout on phone" open question below should be resolved by reading `Signal-Android-ref`'s backup-restore/import code for the expected `files/` path relative to the backup directory, rather than only guessing from this codebase.

## Open questions

- **Backup directory layout on phone** — Does Signal Android expect `files/` as a sibling to the backup dir or inside it? Current code produces them as siblings under `output/`. Needs verification against a working restore.

## Reference material

- **tests/helpers/synthetic_seed.py** — Builds a real, on-disk v2 seed-backup directory (`metadata` + `main`) via the production `encrypt.py`/`metadata.py` code paths, for repro/tests that need a seed dir without a real device backup. Import explicitly: `from tests.helpers.synthetic_seed import synthetic_seed_dir`.
- **PLAN.md** — Full crypto spec, KDF test vectors, file format details, implementation phases
- **docs/v1-backup-format.md** — v1 backup format specification (file layout, KDF chain, per-frame crypto)
- **proto/Backup.proto** — Signal's v2 backup frame schema (from Signal-Android)
- **proto/V1Backup.proto** — v1 backup frame schema (proto2, `signal_v1` package)
- **proto/LocalArchive.proto** — Metadata and FilesFrame schemas
- **Signal-Android-ref/**, **libsignal-ref/**, **molly-ref/** — Checked-out reference repos (not part of this project's code; see "Consulting the reference repos" above)
- **.agent_native/agent_roadmap.md** — Prioritized gaps blocking autonomous agent bug-repro/implement/verify workflows

## Privacy / real data handling

`work/` holds **real, decrypted Signal backup data** (a real seed backup, decrypted Desktop SQLite databases, and built output containing real encrypted attachments) used for manual end-to-end verification against an actual device backup. It is gitignored — never remove it from `.gitignore`, never copy anything from it into `tests/`, fixtures, docs, or any other deliverable, and never run destructive operations against it without explicit instruction. All test fixtures must be synthetic (see `.agent_native/agent_roadmap.md` item 2 for the planned synthetic-seed-backup generator).
