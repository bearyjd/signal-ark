# Signal v2 Backup Format Specification

**Version**: 1.0 (April 2026)
**Status**: Derived from libsignal source and empirical analysis
**Covers**: Signal Android and Molly local backup format as of early 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Directory Layout](#2-directory-layout)
3. [Key Derivation Chain](#3-key-derivation-chain)
4. [Metadata File](#4-metadata-file)
5. [Main File](#5-main-file)
6. [Frame Structure](#6-frame-structure)
7. [Files Manifest](#7-files-manifest)
8. [Content Store](#8-content-store)
9. [Test Vectors](#9-test-vectors)
10. [References](#10-references)

---

## 1. Overview

Signal v2 is the current backup format used by Signal Android (and Molly) for local and cloud backups. It replaces the legacy v1 format which used a streaming SQL-statement-based approach.

A v2 backup consists of:

- A **protobuf frame stream** containing account data, recipients, chats, and messages, encrypted and compressed into a single `main` file.
- A **metadata file** containing the encrypted BackupId and format version.
- A **files manifest** listing the media names of all backed-up attachments.
- A **content store** of individually encrypted attachment files, sharded into subdirectories.

All encryption keys are derived from a single root secret: the 64-character **AccountEntropyPool (AEP)**.

---

## 2. Directory Layout

A local v2 backup occupies two directory trees:

```
<backup-dir>/
├── main              encrypted + compressed protobuf frame stream
├── metadata          encrypted BackupId + version (protobuf)
└── files             files manifest: list of mediaNames (raw protobuf)

<content-store>/
├── 00/               shard by first 2 hex chars of mediaName
│   └── 00a1b2c3...   individually encrypted attachment
├── 01/
│   └── ...
...
└── ff/
```

The content store is typically a sibling directory named `files/`, but its path is independent of the backup directory.

### File sizes

| File | Typical size | Contents |
|------|-------------|----------|
| `metadata` | ~36 bytes | Protobuf with encrypted BackupId |
| `main` | Varies (KB to hundreds of MB) | All frames, compressed and encrypted |
| `files` | Varies | One varint-delimited entry per attachment |

---

## 3. Key Derivation Chain

All keys derive from the **AccountEntropyPool (AEP)** via HKDF-SHA256 (RFC 5869).

### Inputs

| Input | Format | Description |
|-------|--------|-------------|
| AEP | 64-char string from `[0-9a-z]` (~330 bits entropy) | Root secret, stored on-device |
| ACI | UUID (16 bytes) | Account identity, also called the service ID |

### ACI Binary Encoding

When the ACI is used as input to HKDF, it is encoded as **raw 16-byte UUID bytes** (no prefix byte, big-endian fields). For example, the UUID `659aa5f4-a28d-fcc1-1ea1-b997537a3d95` becomes the 16 bytes `659aa5f4a28dfcc11ea1b997537a3d95`.

> **Note**: Some Signal documentation references a 17-byte "service ID binary" with a `0x01` prefix byte. The v2 backup KDF uses the **16-byte raw UUID** without prefix. This is confirmed by libsignal's test vectors.

### Derivation Steps

All steps use HKDF-SHA256 with **no salt** unless noted.

| Step | IKM (Input Key Material) | Info String | Output Length | Output |
|------|--------------------------|-------------|---------------|--------|
| 1. BackupKey | AEP (UTF-8 bytes) | `20240801_SIGNAL_BACKUP_KEY` | 32 bytes | BackupKey |
| 2. BackupId | BackupKey | `20241024_SIGNAL_BACKUP_ID:` ‖ ACI (16 bytes) | 16 bytes | BackupId |
| 3a. MessageBackupKey (legacy) | BackupKey | `20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:` ‖ BackupId | 64 bytes | HMAC key (0..31) ‖ AES key (32..63) |
| 3b. MessageBackupKey (modern) | BackupKey, **salt** = FS token | `20250708_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:` ‖ BackupId | 64 bytes | HMAC key (0..31) ‖ AES key (32..63) |
| 4. LocalMetadataKey | BackupKey | `20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY` | 32 bytes | AES key for metadata file |
| 5. MediaId | BackupKey | `20241007_SIGNAL_BACKUP_MEDIA_ID:` ‖ mediaName (UTF-8) | 15 bytes | MediaId |
| 6. MediaEncryptionKey | BackupKey | `20241007_SIGNAL_BACKUP_ENCRYPT_MEDIA:` ‖ MediaId | 64 bytes | HMAC key (0..31) ‖ AES key (32..63) |

### Legacy vs Modern MessageBackupKey

- **Legacy** (step 3a): Used for local backups. No salt. Info string prefix `20241007_`.
- **Modern** (step 3b): Used for cloud backups with forward-secrecy tokens. The token is passed as the HKDF salt. Info string prefix `20250708_`.

The format is determined by the `main` file's magic number (see [Section 5](#5-main-file)).

### MediaId and MediaEncryptionKey

Steps 5 and 6 are used for **cloud** (transit/media-tier) attachment encryption. Local backups use a different per-attachment key scheme described in [Section 8](#8-content-store).

---

## 4. Metadata File

The `metadata` file is a serialized `Metadata` protobuf message (defined in `LocalArchive.proto`).

### Protobuf Schema

```protobuf
message Metadata {
  message EncryptedBackupId {
    bytes iv = 1;           // 12 bytes, randomly generated
    bytes encryptedId = 2;  // AES-256-CTR encrypted BackupId
  }
  uint32 version = 1;
  EncryptedBackupId backupId = 2;
}
```

### Encryption

The BackupId is encrypted with **AES-256-CTR**:

- **Key**: LocalMetadataKey (32 bytes, from KDF step 4)
- **IV**: 12 random bytes, zero-padded to 16 bytes for the CTR nonce: `iv ‖ 0x00000000`
- **Plaintext**: BackupId (16 bytes)
- **Ciphertext**: 16 bytes stored in `encryptedId`

There is no MAC on the metadata file. If the metadata decrypts incorrectly (wrong key), the `main` file decryption will fail at HMAC verification.

### Reading the metadata

1. Parse the file as a `Metadata` protobuf.
2. Derive `LocalMetadataKey` from the BackupKey.
3. Decrypt `encryptedId` using AES-256-CTR with the stored IV (padded to 16 bytes).
4. The result is the 16-byte BackupId.

---

## 5. Main File

The `main` file contains all backup frames (account data, recipients, chats, messages) encrypted as a single blob.

### Format Detection

Two variants exist, distinguished by a magic number in the first 8 bytes:

| First 8 bytes | Variant | Usage |
|---------------|---------|-------|
| `SBACKUP\x01` (hex: `5342 4143 4b55 5001`) | Modern | Cloud backups with forward-secrecy |
| Anything else | Legacy | Local backups |

### Legacy Layout

```
┌──────────────────────────────────────────────────┐
│  16 bytes: IV                                    │
│  N bytes:  AES-256-CBC ciphertext (PKCS7 padded) │
│  32 bytes: HMAC-SHA256 tag                       │
└──────────────────────────────────────────────────┘
```

Total size = 16 + N + 32 bytes.

### Modern Layout

```
┌──────────────────────────────────────────────────┐
│  8 bytes:  magic "SBACKUP\x01"                   │
│  varint:   forward-secrecy metadata length        │
│  M bytes:  FS metadata (protobuf)                 │
│  16 bytes: IV                                     │
│  N bytes:  AES-256-CBC ciphertext (PKCS7 padded)  │
│  32 bytes: HMAC-SHA256 tag                        │
└──────────────────────────────────────────────────┘
```

The FS metadata contains the forward-secrecy token used as salt in KDF step 3b.

### Encryption Details

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-CBC |
| Key | AES key from MessageBackupKey (bytes 32..63 of KDF step 3a/3b) |
| IV | 16 random bytes, stored at the start of the encrypted payload |
| Padding | PKCS7 (block size 16) |
| MAC algorithm | HMAC-SHA256 |
| MAC key | HMAC key from MessageBackupKey (bytes 0..31 of KDF step 3a/3b) |
| MAC input | IV ‖ ciphertext (everything except the MAC itself) |
| MAC output | 32 bytes, appended at end of file |

### Decryption Procedure

1. **Detect format**: Check first 8 bytes for magic number.
2. **Locate encrypted payload**: Skip magic + FS metadata for modern; start at byte 0 for legacy.
3. **Extract components**: IV = first 16 bytes, MAC = last 32 bytes, ciphertext = everything between.
4. **Verify MAC first**: Compute HMAC-SHA256(key=hmac_key, data=IV ‖ ciphertext). Compare with stored MAC. Reject if mismatch.
5. **Decrypt**: AES-256-CBC with the IV and AES key.
6. **Remove padding**: PKCS7 unpad.
7. **Decompress**: gzip decompress the plaintext.
8. **Parse frames**: Read varint-delimited protobuf messages (see [Section 6](#6-frame-structure)).

> **Security property**: The MAC is verified before any decryption occurs. This prevents padding oracle attacks and ensures ciphertext integrity before processing.

---

## 6. Frame Structure

The decompressed plaintext from the `main` file is a sequence of varint-length-delimited protobuf messages.

### Varint Encoding

Each message is preceded by its byte length encoded as a protobuf varint (base-128, little-endian, MSB continuation bit):

```
[varint: message_length][message_length bytes: serialized protobuf]
[varint: message_length][message_length bytes: serialized protobuf]
...
```

### Message Sequence

The first message is always a **`BackupInfo`** (a distinct protobuf message type). All subsequent messages are **`Frame`** messages.

```protobuf
message BackupInfo {
  uint64 version = 1;
  uint64 backupTimeMs = 2;
  bytes mediaRootBackupKey = 3;
  string currentAppVersion = 4;
  string firstAppVersion = 5;
}
```

### Frame Type

Each `Frame` contains exactly one item via a `oneof`:

```protobuf
message Frame {
  oneof item {
    AccountData account = 1;
    Recipient recipient = 2;
    Chat chat = 3;
    ChatItem chatItem = 4;
    StickerPack stickerPack = 5;
    AdHocCall adHocCall = 6;
    NotificationProfile notificationProfile = 7;
    ChatFolder chatFolder = 8;
  }
}
```

If the `oneof` is unset, importers should skip the frame without error.

### Ordering Rules

Frames must follow these ordering rules:

1. **AccountData first**: Exactly one `AccountData` frame, and it must be the first `Frame` after `BackupInfo`.
2. **Referenced-before-referencing**: A frame referenced by ID must appear before the frame that references it. For example, a `Recipient` must appear before any `Chat` that references its recipient ID.
3. **ChatItems in global order**: All `ChatItem` frames must appear in the order they were received by the client (global rendering order across all chats).
4. **ChatFolders in render order**: `ChatFolder` frames appear in display order (e.g., left-to-right for LTR locales), but can appear anywhere that respects rule 2 (after all referenced Recipients and Chats).

Recipients, Chats, StickerPacks, AdHocCalls, and NotificationProfiles can appear in any order relative to each other, as long as rule 2 is satisfied.

### Key Frame Types

| Frame Type | Description |
|-----------|-------------|
| `AccountData` | Profile info, settings, subscription data, username |
| `Recipient` | A contact, group, self, release notes channel, call link, or distribution list |
| `Chat` | A conversation thread, references a Recipient by ID |
| `ChatItem` | A message within a chat — incoming, outgoing, update, or info |
| `StickerPack` | An installed sticker pack |
| `ChatFolder` | A user-created chat folder with filter rules |
| `AdHocCall` | A call history entry |
| `NotificationProfile` | Custom notification settings |

### Attachment References

Attachments are referenced via `FilePointer` messages embedded in `ChatItem` frames (within `MessageAttachment` wrappers).

```protobuf
message FilePointer {
  message LocatorInfo {
    bytes key = 1;                         // Transit encryption key
    oneof integrityCheck {
      bytes plaintextHash = 10;            // SHA256 of plaintext (if downloaded)
      bytes encryptedDigest = 11;          // Digest from sender (if not downloaded)
    }
    uint32 size = 3;                       // Plaintext size in bytes
    optional string transitCdnKey = 4;
    optional uint32 transitCdnNumber = 5;
    optional uint32 mediaTierCdnNumber = 7;
    optional bytes localKey = 9;           // 64-byte key for local backup encryption
  }

  optional string contentType = 4;
  optional string fileName = 7;
  optional uint32 width = 8;
  optional uint32 height = 9;
  optional string caption = 10;
  optional string blurHash = 11;
  LocatorInfo locatorInfo = 13;
}
```

The `localKey` field (field 9 on `LocatorInfo`) is the per-attachment encryption key used in the local content store. See [Section 8](#8-content-store) for the encryption scheme.

---

## 7. Files Manifest

The `files` file in the backup directory is a **files manifest** listing all attachment media names.

### Format

For **local backups**, the manifest is **unencrypted** raw varint-delimited protobuf:

```
[varint: length][FilesFrame protobuf]
[varint: length][FilesFrame protobuf]
...
```

Each `FilesFrame` contains a single media name:

```protobuf
message FilesFrame {
  oneof item {
    string mediaName = 1;
  }
}
```

### Media Name

The `mediaName` is a 64-character lowercase hex string derived from the attachment's content:

```
mediaName = hex(SHA256(plaintextHash ‖ localKey))
```

Where:
- `plaintextHash` = SHA-256 digest of the unencrypted attachment bytes
- `localKey` = the 64-byte per-attachment encryption key
- `‖` = byte concatenation

This makes the content store **content-addressed**: the same plaintext encrypted with the same key always produces the same media name.

> **Note on encryption**: Some documentation (including earlier versions of this project's PLAN.md) states the files manifest uses the same encryption as the `main` file. This is **incorrect for local backups**. Empirical analysis confirms the manifest is raw unencrypted protobuf. Cloud backups may differ.

---

## 8. Content Store

Each attachment is stored as an individually encrypted file in the content store directory.

### Directory Structure

Files are sharded by the first two hex characters of the media name:

```
files/{mediaName[0:2]}/{mediaName}
```

For example, a media name starting with `a3` would be stored at `files/a3/a3f7b2...`.

### Per-Attachment Key

Each attachment has a unique 64-byte `localKey` stored in the `FilePointer.LocatorInfo.localKey` field of the referencing frame:

| Bytes | Purpose |
|-------|---------|
| 0..31 | AES-256 key |
| 32..63 | HMAC-SHA256 key |

### Encryption Envelope

Each encrypted attachment file has this binary layout:

```
┌──────────────────────────────────────────────────┐
│  16 bytes: IV (random)                           │
│  N bytes:  AES-256-CBC ciphertext (PKCS7 padded) │
│  32 bytes: HMAC-SHA256 tag                       │
└──────────────────────────────────────────────────┘
```

This is the same envelope as the `main` file (Section 5), but with the per-attachment keys instead of the MessageBackupKey.

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-CBC |
| Key | `localKey[0:32]` |
| IV | 16 random bytes |
| Padding | PKCS7 (block size 16) |
| MAC algorithm | HMAC-SHA256 |
| MAC key | `localKey[32:64]` |
| MAC input | IV ‖ ciphertext |
| MAC output | 32 bytes, appended at end |

### Decryption Procedure

1. Read the file.
2. Extract: IV (first 16 bytes), MAC (last 32 bytes), ciphertext (middle).
3. Verify HMAC-SHA256(key=localKey[32:64], data=IV ‖ ciphertext) against stored MAC.
4. Decrypt AES-256-CBC(key=localKey[0:32], iv=IV, data=ciphertext).
5. Remove PKCS7 padding.
6. The result is the plaintext attachment.

### Encryption Procedure (for backup creation)

1. Generate a random 64-byte `localKey`.
2. Generate a random 16-byte IV.
3. Compute `plaintextHash = SHA256(plaintext)`.
4. PKCS7-pad the plaintext.
5. Encrypt with AES-256-CBC(key=localKey[0:32], iv=IV).
6. Compute MAC = HMAC-SHA256(key=localKey[32:64], data=IV ‖ ciphertext).
7. Write: IV ‖ ciphertext ‖ MAC.
8. Compute `mediaName = hex(SHA256(plaintextHash ‖ localKey))`.
9. Store at `files/{mediaName[0:2]}/{mediaName}`.
10. Set `localKey`, `plaintextHash`, and `size` on the `FilePointer.LocatorInfo` in the referencing frame.
11. Add `mediaName` to the files manifest.

---

## 9. Test Vectors

These test vectors are sourced from libsignal's public test suite.

### KDF Chain

```
AEP:        "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l"
ACI:        659aa5f4-a28d-fcc1-1ea1-b997537a3d95
ACI binary: 659aa5f4a28dfcc11ea1b997537a3d95

BackupKey:  ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985
BackupId:   8a624fbc45379043f39f1391cddc5fe8
```

### Legacy MessageBackupKey (no forward-secrecy token)

```
HMAC key: f425e22a607c529717e1e1b29f9fe139f9d1c7e7d01e371c7753c544a3026649
AES key:  e143f4ad5668d8bfed2f88562f0693f53bda2c0e55c9d71730f30e24695fd6df
```

### Modern MessageBackupKey (with forward-secrecy token)

```
FS token (hex): 69207061737320746865206b6e69666520746f207468652061786f6c6f746c21

HMAC key: 20e6ab57b87e051f3e695e953cf8a261dd307e4f92ae2921673f1d397e07887b
AES key:  602af6ecfc09d695a8d58da9f18225e967979c5e03543ca0224a03cca3d9735e
```

### Verification

To verify your implementation:

1. Derive BackupKey from AEP using HKDF-SHA256(ikm=AEP bytes, info=`20240801_SIGNAL_BACKUP_KEY`, length=32).
2. Derive BackupId from BackupKey using HKDF-SHA256(ikm=BackupKey, info=`20241024_SIGNAL_BACKUP_ID:` ‖ ACI binary, length=16).
3. Derive legacy MessageBackupKey from BackupKey using HKDF-SHA256(ikm=BackupKey, info=`20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:` ‖ BackupId, length=64). Split: first 32 = HMAC key, last 32 = AES key.
4. Compare outputs against the hex values above.

---

## 10. References

- **Backup.proto**: Signal's v2 backup frame schema. Defined in Signal-Android, used by libsignal. Contains all frame types, field definitions, and ordering rules.
- **LocalArchive.proto**: Metadata and FilesFrame protobuf definitions for the local backup directory format.
- **libsignal** (`signalapp/libsignal`): The only reference implementation of v2 backup encrypt/decrypt. The KDF chain, format detection, and crypto are implemented in Rust under `rust/message-backup/`.
- **RFC 5869**: HMAC-based Extract-and-Expand Key Derivation Function (HKDF). Used for all key derivation in the v2 format.
- **NIST SP 800-38A**: AES block cipher modes (CBC used for main file and attachments).
- **RFC 2104**: HMAC specification. HMAC-SHA256 used for integrity verification.
- **RFC 1952**: gzip compression format. Used between encryption and protobuf framing.
- **Protocol Buffers encoding**: Varint encoding used for frame length delimiting.

---

*This specification was derived from analysis of libsignal source code, Signal-Android's proto definitions, and empirical testing against working Signal Android backups. It is not an official Signal Foundation document.*
