# signal-ark: Signal v2 Backup Reconstruction

**signal-ark** — Reconstruct Signal/Molly v2 backup archives from Signal Desktop data.

## 1. Prior Art Assessment

### bepaald/signalbackup-tools
- Issue [#382](https://github.com/bepaald/signalbackup-tools/issues/382) tracks v2 support — acknowledged, not implemented.
- Recent commit `7c75161` adds detection of v2 directories (prints informative error, does not parse).
- `--importfromdesktop` works but emits **legacy v1 `.backup` format only**.
- **Verdict:** Cannot use for v2 output. Still useful for `--dumpdesktopdb` to get plaintext Desktop SQLite.

### Standalone third-party tools
- **No standalone tool decrypts v2 encrypted backups.** Several tools read the *plaintext* Desktop export (`main.jsonl` + `files/`), but that's a different format.
- `signalapp/libsignal` (Rust) is the **only** v2 encrypt/decrypt implementation.
- `mollyim/mollyim-android` uses libsignal under the hood for v2 — not a standalone tool.

### Decision: Build fresh (Python), guided by libsignal source
- No existing tool to fork.
- libsignal's Rust code is the reference — we port the crypto and frame logic to Python.
- Proto schemas come directly from Signal-Android (`Backup.proto`, `LocalArchive.proto`).

---

## 2. Crypto & KDF Chain

### Inputs
- **AccountEntropyPool (AEP):** 64-char string from `[0-9a-z]`, ~330 bits entropy.
- **ACI (Account Identity):** Your UUID, stored as 17-byte service ID binary (1-byte prefix `0x01` + 16-byte UUID).

### Key Derivation (all HKDF-SHA256, no salt unless noted)

| Step | Input | HKDF Info | Output |
|------|-------|-----------|--------|
| BackupKey | AEP bytes | `"20240801_SIGNAL_BACKUP_KEY"` | 32 bytes |
| BackupId | BackupKey | `"20241024_SIGNAL_BACKUP_ID:" \|\| ACI_binary` | 16 bytes |
| MessageBackupKey (legacy, no FS token) | BackupKey | `"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:" \|\| BackupId` | 64 bytes (32 HMAC + 32 AES) |
| MessageBackupKey (modern, with FS token) | BackupKey, salt=token | `"20250708_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:" \|\| BackupId` | 64 bytes (32 HMAC + 32 AES) |
| LocalMetadataKey | BackupKey | `"20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY"` | 32 bytes |
| MediaEncryptionKey | BackupKey | `"20241007_SIGNAL_BACKUP_ENCRYPT_MEDIA:" \|\| MediaId` | 64 bytes (32 HMAC + 32 AES) |
| MediaId | BackupKey | `"20241007_SIGNAL_BACKUP_MEDIA_ID:" \|\| mediaName` | 15 bytes |

### Test Vectors (from libsignal source)

```
AEP:       "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l"
ACI:       659aa5f4-a28d-fcc1-1ea1-b997537a3d95
BackupKey: ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985
BackupId:  8a624fbc45379043f39f1391cddc5fe8

Legacy MessageBackupKey:
  hmac_key: f425e22a607c529717e1e1b29f9fe139f9d1c7e7d01e371c7753c544a3026649
  aes_key:  e143f4ad5668d8bfed2f88562f0693f53bda2c0e55c9d71730f30e24695fd6df

Modern MessageBackupKey (with FS token = "69207061737320746865206b6e69666520746f207468652061786f6c6f746c21"):
  hmac_key: 20e6ab57b87e051f3e695e953cf8a261dd307e4f92ae2921673f1d397e07887b
  aes_key:  602af6ecfc09d695a8d58da9f18225e967979c5e03543ca0224a03cca3d9735e
```

---

## 3. `main` File Format

### Two variants based on magic number

**Modern (starts with `SBACKUP\x01`):**
```
[8 bytes: magic "SBACKUP\x01"]
[varint: forward_secrecy_metadata_length]
[FS metadata bytes — protobuf with ct/pw_salt pairs + 12-byte IV]
[16 bytes: CBC IV]
[AES-256-CBC ciphertext, PKCS7 padded]
[32 bytes: HMAC-SHA256 tag]
```

**Legacy (no magic):**
```
[16 bytes: CBC IV]
[AES-256-CBC ciphertext, PKCS7 padded]
[32 bytes: HMAC-SHA256 tag]
```

### Crypto details
- **Cipher:** AES-256-CBC with PKCS7 padding (NOT AES-GCM).
- **MAC:** HMAC-SHA256 over `IV || ciphertext`. 32-byte tag appended at end.
- **Verification:** MAC checked first (read whole file), then decrypt in second pass.
- **Plaintext:** gzip-compressed stream of varint-length-delimited protobuf frames.
- Optionally zero-padded to a bucket boundary before compression.

### Which variant is our seed backup?
The seed backup's `main` is 198,352 bytes. We need to check the first 8 bytes — if they're `SBACKUP\x01`, it's modern format with FS metadata. If not, it's legacy format (starts directly with 16-byte IV). A Molly 8.7.3 local backup likely uses the **legacy** variant (no forward secrecy token — that's for cloud backups).

---

## 4. Internal Frame Structure

Inside the decrypted+decompressed stream:

```
[varint length][BackupInfo protobuf]     ← exactly one, always first
[varint length][Frame protobuf]          ← repeated
[varint length][Frame protobuf]
...
```

### Frame ordering rules (from Backup.proto)
1. Exactly one `AccountData` — must be the first Frame.
2. Referenced-before-referencing: `Recipient` before `Chat` referencing it; `Chat` before `ChatItem` referencing it.
3. All `ChatItem`s in global rendering order (received timestamp order).
4. `ChatFolder`s in render order, but can appear anywhere after their referenced Recipients/Chats.

### Key frame types for our use case
| Frame Type | Maps From (Desktop DB) | Priority |
|-----------|----------------------|----------|
| `AccountData` | Desktop profile / settings | Must |
| `Recipient` (Self) | Our own account | Must |
| `Recipient` (Contact) | `conversations` table | Must |
| `Recipient` (Group) | `conversations` table (type='group') | Nice-to-have |
| `Chat` | `conversations` table | Must |
| `ChatItem` (StandardMessage) | `messages` table | Must |
| `ChatItem` (attachments) | `messages` + `attachments.noindex/` | Must (images) |
| `StickerPack` | — | Skip |
| `AdHocCall` | — | Skip |
| `NotificationProfile` | — | Skip |
| `ChatFolder` | — | Skip |

---

## 5. `metadata` File Format

Defined by `LocalArchive.proto`:

```protobuf
message Metadata {
  uint32 version = 1;
  EncryptedBackupId backupId = 2;
}

message EncryptedBackupId {
  bytes iv = 1;     // 12 bytes, random
  bytes encryptedId = 2;  // AES-256-CTR(key=LocalMetadataKey, plaintext=BackupId)
}
```

The 36-byte seed metadata file is this Metadata message. It contains:
- A version number
- The BackupId encrypted with AES-256-CTR using LocalMetadataKey (derived from BackupKey with info `"20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY"`).

To reconstruct: we derive the LocalMetadataKey from our BackupKey, then can both decrypt the existing metadata (to extract BackupId for verification) and re-encrypt a new one.

---

## 6. `files` Manifest and Content Store

### `files` manifest (the 335-byte file in the backup dir)
- Same encryption as `main`: `[IV][AES-256-CBC ciphertext][HMAC-SHA256]`
- Plaintext is gzip-compressed varint-delimited `FilesFrame` messages
- Each `FilesFrame` contains a `mediaName` string

### `files/` directory (sibling content store)
- Sharded by first byte of filename: `files/00/`, `files/01/`, ... `files/ff/`
- Each file is an independently encrypted attachment
- **Filename:** `hex(SHA256(plaintextHash || localKey))` — content-addressed
- **File format:** `[16-byte IV][AES-256-CBC ciphertext, PKCS7][32-byte HMAC-SHA256]`
- **Key:** 64-byte `localKey` from `FilePointer.LocatorInfo`, split into first 32 = AES key, second 32 = HMAC key
- The `localKey` is per-attachment, stored in the frame that references it

---

## 7. Implementation Plan

### Phase 1: Decrypt-only proof of life
**Goal:** Decrypt the empty seed backup and dump frames as JSONL.

1. **Set up Python project** (`~/signal_fix/newformat/`)
   - `uv` for env management, Python 3.12
   - Dependencies: `cryptography`, `protobuf`
   - Copy `Backup.proto` and `LocalArchive.proto` from Signal-Android, generate Python bindings with `protoc`

2. **Implement KDF module** (`kdf.py`)
   - `aep_to_backup_key(aep: str) -> bytes`
   - `backup_key_to_backup_id(backup_key: bytes, aci: bytes) -> bytes`
   - `backup_key_to_message_backup_key(backup_key: bytes, backup_id: bytes) -> tuple[bytes, bytes]`
   - `backup_key_to_local_metadata_key(backup_key: bytes) -> bytes`
   - Unit tests against libsignal test vectors — **must pass before proceeding**

3. **Implement metadata parser** (`metadata.py`)
   - Parse `metadata` file as `LocalArchive.Metadata` protobuf
   - Decrypt `EncryptedBackupId` using LocalMetadataKey + AES-256-CTR
   - Extract BackupId, derive MessageBackupKey

4. **Implement main decryptor** (`decrypt.py`)
   - Detect magic number to determine legacy vs modern format
   - Read HMAC tag from end of file (last 32 bytes)
   - Verify HMAC-SHA256 over `IV || ciphertext`
   - Decrypt AES-256-CBC
   - Decompress gzip
   - Parse varint-delimited frames
   - Dump BackupInfo + all Frames as JSONL

5. **CLI entry point** (`cli.py`)
   - `--seed-dir`, `--passphrase` (the 64-char AEP), `--aci` (your UUID)
   - Output: `decrypted/main.plaintext`, `decrypted/frames.jsonl`, `decrypted/metadata.json`

### Phase 2: Encrypt (round-trip)
**Goal:** Decrypt seed → re-encrypt → restore on phone → verify identical behavior.

1. **Implement encryptor** (`encrypt.py`)
   - Generate random 16-byte IV
   - Serialize frames as varint-delimited protobuf stream
   - Gzip compress
   - AES-256-CBC encrypt with PKCS7 padding
   - Compute HMAC-SHA256 over `IV || ciphertext`
   - Write `[IV][ciphertext][HMAC]`

2. **Implement metadata writer**
   - Generate new random 12-byte IV for metadata
   - Encrypt BackupId with AES-256-CTR using LocalMetadataKey
   - Serialize as `LocalArchive.Metadata` protobuf

3. **Implement files manifest writer**
   - Same encryption scheme as main
   - Write `FilesFrame` entries for each attachment

4. **Round-trip test**
   - Decrypt seed → get frames
   - Re-encrypt same frames → produce new archive dir
   - User pushes to phone, restores in Molly
   - Success = Molly accepts and shows empty state

### Phase 3: Desktop DB → archive frames
**Goal:** Map Signal Desktop data into v2 archive frames.

1. **Extract Desktop data**
   - Use `signalbackup-tools --dumpdesktopdb` to get plaintext SQLite
   - OR read Desktop's encrypted SQLite directly (signalbackup-tools already handles this)

2. **Build frame mapper** (`mapper.py`)
   - Reference: `signalbackup-tools/signalbackup/importfromdesktop.cc`
   - `conversations` → `Recipient` + `Chat` frames
   - `messages` → `ChatItem` frames (text, timestamps, delivery status)
   - Attachments → `FilePointer` with `localKey`, encrypted into `files/` store

3. **Scope for v1:**
   - Text messages in 1:1 conversations: **must work**
   - Group conversations: **nice-to-have**
   - Image attachments: **must work**
   - Other attachment types: **nice-to-have**
   - Reactions, quotes, call logs, stickers: **skip**

4. **Attachment encryption**
   - For each attachment: generate random 64-byte `localKey`
   - Encrypt with AES-256-CBC + HMAC-SHA256 using that key
   - Compute `mediaName = hex(SHA256(plaintextHash || localKey))`
   - Write to `files/XX/mediaName`
   - Reference in frame via `FilePointer.LocatorInfo.localKey`

### Phase 4: End-to-end
**Goal:** Produce complete rebuilt backup directory, restore on phone.

1. Merge seed AccountData frame with Desktop-sourced Recipient/Chat/ChatItem frames
2. Produce `rebuilt-backup/` with `main`, `metadata`, `files` manifest
3. Produce sibling `files/` content store with encrypted attachments
4. User pushes to phone via adb
5. Restore in Molly — iterate on schema mismatches

---

## 8. Key Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| ACI unknown — needed for BackupId derivation | Extract from seed backup's metadata (decrypt EncryptedBackupId) or from Desktop DB |
| Molly validates fields we don't populate | Start with round-trip of seed (Phase 2) to establish baseline, add fields incrementally |
| Frame ordering wrong → Molly rejects | Follow ordering rules strictly; sort ChatItems by received timestamp |
| Attachment localKey scheme wrong | Test with one known attachment in Phase 2 round-trip before doing bulk |
| Desktop DB schema differs from what importfromdesktop.cc expects | Use `--dumpdesktopdb` for a clean SQLite, inspect schema before mapping |

---

## 9. Open Questions (to resolve in Phase 1)

1. **Is the seed backup legacy or modern format?** Check first 8 bytes of `main`.
2. **Where is the ACI?** Likely in Desktop's `items` table or extractable from the seed's decrypted metadata.
3. **Does Molly 8.7.3 use the `20241007` or `20250708` HKDF info string?** The seed backup will tell us — if it has no magic number, it's legacy MessageBackupKey derivation.
4. **What version number does Molly expect in BackupInfo?** Extract from seed.
5. **Does the `files` manifest need to exactly match the `files/` directory contents?** Likely yes — test in Phase 2.

---

## 10. Extended Roadmap

Phases 1–4 above are the immediate goal: get MY messages restored. Beyond that, signal-ark becomes a general-purpose tool.

### Phase 5: CLI polish & cross-platform
**Goal:** Reliable CLI that runs on Linux, macOS, and Windows.

- Package as a proper Python CLI with `click` or `typer`
- Publish to PyPI as `signal-ark`
- Test matrix: Linux (x86_64, aarch64), macOS (Apple Silicon), Windows 10/11
- Use `cryptography` library (has wheels for all platforms) — no native compilation needed
- CI with GitHub Actions: lint, type-check, test on all three OS targets
- Provide standalone binaries via PyInstaller or `shiv` for users without Python

### Phase 6: TUI / Web UI
**Goal:** Make it accessible to non-CLI users.

- **TUI (first):** `textual` or `rich`-based terminal UI
  - Step-by-step wizard: select seed backup → enter AEP → select Desktop data dir → preview conversations → build archive
  - Progress bars for decryption, frame mapping, encryption
  - Preview of what will be restored (conversation list, message counts)

- **Web UI (later):** Local-only web app (Flask/FastAPI + simple frontend)
  - Drag-and-drop seed backup directory
  - Paste AEP
  - Browse Desktop conversations, select which to include
  - Download rebuilt archive as a zip
  - **All processing local** — no data leaves the machine
  - Could package as an Electron app or Tauri app for desktop distribution

### Phase 7: Generalization
**Goal:** Support more source/target combinations.

- Import from: Signal Desktop (current), legacy v1 `.backup` files, Signal iOS backups
- Export to: v2 archive (current), HTML archive, PDF per-conversation
- Merge backups: combine messages from multiple sources, deduplicate by timestamp+author
- Conversation filtering: include/exclude specific chats, date ranges
- Attachment handling: skip attachments (metadata-only backup), transcode large videos

### Phase 8: Community & ecosystem
- Plugin architecture for custom importers/exporters
- Contribute v2 format documentation back to the community
- Coordinate with bepaald/signalbackup-tools on potential integration
