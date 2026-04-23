# Signal v1 Backup Format Specification

This document describes the legacy Signal backup format (v1) used by Signal Android prior to the v2 migration. These `.backup` files contain a complete dump of the Signal database, preferences, attachments, stickers, and avatars in a single encrypted file.

## Overview

| Property | Value |
|----------|-------|
| File extension | `.backup` |
| Encryption | AES-256-CTR per frame |
| MAC | HMAC-SHA256, truncated to 10 bytes |
| KDF | SHA-512 (250K rounds) → HKDF-SHA256 |
| Passphrase | 30 decimal digits (displayed with spaces) |
| Protobuf | proto2 syntax with optional fields |
| Compression | None (unlike v2 which uses gzip) |
| Structure | Single sequential stream |

## File Layout

```
┌──────────────────────────────────────────────────┐
│  4 bytes: header_length (big-endian uint32)       │
├──────────────────────────────────────────────────┤
│  header_length bytes: UNENCRYPTED BackupFrame     │
│  (contains Header with IV, salt, version)         │
├──────────────────────────────────────────────────┤
│  Repeating encrypted frames:                      │
│  ┌──────────────────────────────────────────────┐│
│  │  4 bytes: frame_length*                      ││
│  │  (frame_length - 10) bytes: AES-CTR ciphertext│
│  │  10 bytes: truncated HMAC-SHA256             ││
│  └──────────────────────────────────────────────┘│
│  ...                                              │
│  ┌──────────────────────────────────────────────┐│
│  │  End frame (BackupFrame with end=true)        ││
│  └──────────────────────────────────────────────┘│
└──────────────────────────────────────────────────┘

* frame_length may itself be encrypted (version >= 1)
```

### Inline Attachments

When a `BackupFrame` contains an `attachment`, `sticker`, or `avatar` field, the binary data follows immediately in the stream:

```
┌──────────────────────────────┐
│  Encrypted BackupFrame       │  ← contains Attachment{length=N}
├──────────────────────────────┤
│  N bytes: AES-CTR ciphertext │  ← attachment data (own counter bump)
├──────────────────────────────┤
│  10 bytes: HMAC              │  ← covers IV + ciphertext
└──────────────────────────────┘
```

## Key Derivation

The KDF chain produces a 32-byte cipher key and 32-byte MAC key from the user's passphrase and the salt stored in the backup header.

```
passphrase (30 digits, spaces stripped)
  │
  ▼
input = passphrase.replace(" ", "").encode("utf-8")
hash = input
  │
  ▼
SHA-512 iterated 250,000 times:
  ┌─────────────────────────────────────────────┐
  │ if salt: digest.update(salt)    ← first round only │
  │ for i in range(250_000):                    │
  │     digest.update(hash)                     │
  │     hash = digest.digest(input)             │
  │     # equivalent to: hash = SHA-512(hash ‖ input)  │
  │     # digest resets after .digest()         │
  └─────────────────────────────────────────────┘
  │
  ▼
backup_key = hash[:32]   (first 32 bytes of final SHA-512)
  │
  ▼
HKDF-SHA256(ikm=backup_key, info="Backup Export", length=64)
  │
  ▼
cipher_key = derived[:32]    (AES-256 key)
mac_key    = derived[32:64]  (HMAC-SHA256 key)
```

### Passphrase Format

The passphrase is 30 decimal digits, typically displayed grouped in threes with spaces:

```
123 456 789 012 345 678 901 234 567 890
```

Spaces are stripped before use. The resulting string must be exactly 30 digits `[0-9]`.

### Critical: HKDF Step

Many third-party implementations miss the HKDF step and split the SHA-512 output directly. This produces garbage decryption. The HKDF step was added in Signal Android and is present in `BackupRecordInputStream.java`:

```java
byte[] key     = getBackupKey(passphrase, salt);          // SHA-512 rounds → 32 bytes
byte[] derived = HKDF.deriveSecrets(key, "Backup Export".getBytes(), 64);  // HKDF!
byte[][] split = ByteUtil.split(derived, 32, 32);
cipherKey = split[0];
macKey    = split[1];
```

## Per-Frame Encryption

Each frame uses AES-256-CTR with a counter that increments per frame.

### Counter Management

```
Initial IV: 16 bytes from Header
Initial counter: int.from_bytes(iv[0:4], 'big')

For each frame or attachment:
    iv[0:4] = counter.to_bytes(4, 'big')
    counter += 1
    cipher = AES-CTR(cipher_key, iv)
```

The counter occupies the first 4 bytes of the 16-byte IV. The remaining 12 bytes stay constant. Each frame/attachment gets a **fresh cipher init** with the bumped counter — this is NOT continuous CTR mode.

### Frame Decryption

```
Read 4-byte frame_length (big-endian uint32)
  │
  ├─ if version >= 1: frame_length bytes are encrypted
  │   → bump counter, init cipher
  │   → MAC the 4 encrypted bytes
  │   → decrypt to get actual length
  │
  ├─ if version == 0: frame_length is plaintext
  │
  ▼
Read frame_length bytes from stream
  │
  ▼
Split: encrypted_body = bytes[:-10], their_mac = bytes[-10:]
  │
  ▼
MAC(encrypted_body) → truncate to 10 bytes → verify against their_mac
  │
  ▼
Decrypt encrypted_body with AES-CTR → plaintext protobuf
  │
  ▼
Parse as BackupFrame
```

### Attachment Decryption

When a frame contains an attachment/sticker/avatar with a `length` field:

```
Bump counter, init new cipher
  │
  ▼
MAC the IV (mac.update(iv))     ← attachments MAC the IV, frames don't
  │
  ▼
Read `length` bytes of encrypted data
  (MAC each chunk before decrypting)
  │
  ▼
cipher.doFinal() → plaintext attachment
  │
  ▼
Read trailing 10-byte HMAC from stream
  │
  ▼
Verify HMAC
```

## BackupFrame Proto Schema

```protobuf
syntax = "proto2";
package signal;

message BackupFrame {
    optional Header           header     = 1;
    optional SqlStatement     statement  = 2;
    optional SharedPreference preference = 3;
    optional Attachment       attachment = 4;
    optional DatabaseVersion  version    = 5;
    optional bool             end        = 6;
    optional Avatar           avatar     = 7;
    optional Sticker          sticker    = 8;
    optional KeyValue         keyValue   = 9;
}
```

### Frame Types

| Field | Description |
|-------|-------------|
| `header` | First frame only (unencrypted). Contains IV (16 bytes), salt, backup version. |
| `version` | Database schema version number. |
| `statement` | SQL statement with typed parameters. Used to reconstruct the database. |
| `preference` | SharedPreference key-value pair. |
| `attachment` | Attachment metadata (rowId, attachmentId, length). Inline data follows. |
| `sticker` | Sticker metadata (rowId, length). Inline data follows. |
| `avatar` | Avatar metadata (name/recipientId, length). Inline data follows. |
| `keyValue` | Key-value store entry (blob, bool, float, int, long, or string). |
| `end` | Terminal frame. Set to `true` to signal end of backup. |

### Processing Order

As implemented in `FullBackupImporter.java`:

```
header → [version] → statement* → preference* → attachment* →
         sticker* → avatar* → keyValue* → end
```

The order is not strictly enforced — the importer processes each frame by checking which field is set.

## Differences from v2

| Aspect | v1 | v2 |
|--------|-----|-----|
| Structure | Single sequential file | Directory (main + metadata + files/) |
| Encryption | AES-256-CTR per frame | AES-256-CBC whole file |
| MAC | 10-byte truncated per frame | 32-byte full over entire file |
| Compression | None | Gzip (whole plaintext stream) |
| KDF | SHA-512 250K rounds + HKDF | HKDF from AccountEntropyPool |
| Passphrase | 30 digits | 64-char alphanumeric AEP |
| Protobuf | proto2 (BackupFrame) | proto3 (Frame with oneof) |
| Attachments | Inline in stream | Separate files in content store |
| Data model | Raw SQL statements | Typed protobuf frames |
| Frame length | Optionally encrypted (v>=1) | Varint-delimited |

## References

- `Signal-Android-ref/app/src/main/java/org/thoughtcrime/securesms/backup/BackupRecordInputStream.java` — Frame decryption
- `Signal-Android-ref/app/src/main/java/org/thoughtcrime/securesms/backup/FullBackupBase.java` — KDF (SHA-512 rounds)
- `Signal-Android-ref/app/src/main/java/org/thoughtcrime/securesms/backup/FullBackupImporter.java` — Frame processing
- `Signal-Android-ref/app/src/main/java/org/thoughtcrime/securesms/backup/BackupVersions.kt` — Version constants
- `Signal-Android-ref/app/src/main/protowire/Backups.proto` — Proto schema
