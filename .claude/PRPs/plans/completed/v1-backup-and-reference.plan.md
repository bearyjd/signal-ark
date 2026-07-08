# Plan: v1 Backup Import and Reference Guide

## Summary
Two deliverables: (1) a standalone `docs/v1-backup-format.md` specification covering the legacy Signal v1 backup format, mirroring the structure and quality of the existing v2 spec; (2) full v1 import/dump code that decrypts v1 `.backup` files and converts them to v2 backup directories. Together these give signal-ark complete coverage of both Signal backup generations.

## User Story
As a Signal user with an old v1 backup,
I want to understand the format and convert it to v2,
So that I can restore it on current Signal Android or Molly.

## Problem → Solution
Legacy v1 `.backup` files are undocumented and incompatible with current Signal restore → standalone format spec + conversion tool.

## Metadata
- **Complexity**: Large
- **Source PRD**: N/A
- **PRD Phase**: N/A (roadmap item)
- **Estimated Files**: 9 new + 3 modified

---

## UX Design

### Before
```
$ signal-ark --help
# No v1 support, no v1 documentation
```

### After
```
$ signal-ark dump-v1 --v1-backup backup.bin --v1-passphrase "123 456 ..."
# Dumps v1 backup as JSONL for debugging

$ signal-ark import-v1 --v1-backup backup.bin --v1-passphrase "123 456 ..." \
    --seed-dir /path/to/seed --passphrase <AEP> -o output/
# Converts v1 → v2 backup directory
```

### Interaction Changes
| Touchpoint | Before | After | Notes |
|---|---|---|---|
| CLI | No v1 support | `dump-v1` and `import-v1` commands | Two new commands |
| Docs | Only v2 spec | Both v1 and v2 specs | `docs/v1-backup-format.md` |

---

## Mandatory Reading

| Priority | File | Lines | Why |
|---|---|---|---|
| P0 (critical) | `Signal-Android-ref/app/src/main/java/org/thoughtcrime/securesms/backup/BackupRecordInputStream.java` | all | Actual v1 decrypt implementation |
| P0 (critical) | `Signal-Android-ref/app/src/main/java/org/thoughtcrime/securesms/backup/FullBackupBase.java` | all | KDF: SHA-512 250K rounds |
| P0 (critical) | `Signal-Android-ref/app/src/main/protowire/Backups.proto` | all | v1 BackupFrame proto schema |
| P0 (critical) | `Signal-Android-ref/app/src/main/java/org/thoughtcrime/securesms/backup/FullBackupImporter.java` | 94-163 | Frame processing loop |
| P1 (important) | `docs/v2-backup-format.md` | all | Structure to mirror for v1 doc |
| P1 (important) | `signal_ark/decrypt.py` | all | v2 decrypt patterns to mirror |
| P1 (important) | `signal_ark/mapper.py` | 1-50, 327-500 | IdAllocator, encrypt_attachment |
| P1 (important) | `signal_ark/kdf.py` | all | KDF module pattern |
| P2 (reference) | `signal_ark/encrypt.py` | all | write_backup_directory for output |
| P2 (reference) | `tests/test_kdf.py` | all | Test vector pattern |

## External Documentation

| Topic | Source | Key Takeaway |
|---|---|---|
| v1 KDF | FullBackupBase.java | SHA-512 iterated 250K times → 32-byte key → HKDF("Backup Export", 64) → split cipherKey + macKey |
| v1 frame crypto | BackupRecordInputStream.java | AES-256-CTR per-frame (counter bumped in IV[0:4]), 10-byte truncated HMAC-SHA256 |
| v1 proto | Backups.proto (proto2) | BackupFrame with header/statement/preference/attachment/version/end/avatar/sticker/keyValue |

---

## Patterns to Mirror

### V2_FORMAT_DOC
// SOURCE: docs/v2-backup-format.md
Same TOC structure: Overview, File Layout, KDF, Crypto, Frame Structure, Test Vectors, References.

### KDF_PURE_FUNCTION
// SOURCE: signal_ark/kdf.py
Pure functions, no I/O. `validate_v1_passphrase(p: str) -> str`, `derive_v1_keys(passphrase: str, salt: bytes) -> V1Keys`.

### FROZEN_DATACLASS
// SOURCE: signal_ark/metadata.py:13-28
Frozen dataclasses for result types: `V1Keys`, `V1Header`, `V1ImportResult`.

### CLI_COMMAND
// SOURCE: signal_ark/cli.py:95-171
Click command with deferred imports, key derivation, then operation.

### TEST_VECTORS
// SOURCE: tests/test_kdf.py
Known-answer tests with precomputed hex strings.

### ENCRYPT_ATTACHMENT
// SOURCE: signal_ark/mapper.py (encrypt_attachment function)
Reuse directly for re-encrypting v1 attachments into v2 content store.

---

## v1 Backup Format Reference (for implementation and doc)

### KDF Chain (corrected from reference source)
```
passphrase: 30 digits (spaces stripped)
input = passphrase.replace(" ", "").encode()
hash = input

if salt:
    digest.update(salt)

for i in range(250_000):
    digest.update(hash)
    hash = digest.digest(input)    # SHA-512(hash || input), resets digest

backup_key = hash[:32]

derived = HKDF-SHA256(ikm=backup_key, info=b"Backup Export", length=64)
cipher_key = derived[:32]
mac_key = derived[32:64]
```

### File Structure
```
[4 bytes: header_length, big-endian uint32]
[header_length bytes: UNENCRYPTED BackupFrame protobuf (has Header field)]
-- repeating:
[4 bytes: frame_length, big-endian uint32 (encrypted if version flag set)]
[frame_length - 10 bytes: AES-256-CTR encrypted BackupFrame protobuf]
[10 bytes: truncated HMAC-SHA256]
```

### Per-Frame Crypto
- IV is 16 bytes from Header
- Counter = `int(iv[0:4])`, incremented per frame/attachment
- Each frame: `iv[0:4] = counter++`, init AES/CTR/NoPadding with updated IV
- Frame length may be encrypted (version-dependent): MAC then decrypt 4 bytes
- Frame body: last 10 bytes = HMAC, rest = encrypted protobuf
- HMAC computed over encrypted bytes only, truncated to 10 bytes
- Decrypt with `cipher.doFinal(encrypted_body)`

### Inline Attachments
When BackupFrame has attachment/sticker/avatar field:
- New `iv[0:4] = counter++`, new cipher init
- MAC the IV first
- Read `length` bytes of encrypted data (MAC each chunk, then decrypt)
- Read trailing 10-byte HMAC
- Verify HMAC

### BackupFrame Proto (proto2)
```protobuf
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

---

## Files to Change

| File | Action | Justification |
|---|---|---|
| `docs/v1-backup-format.md` | CREATE | Standalone v1 format specification |
| `proto/V1Backup.proto` | CREATE | v1 BackupFrame proto schema (proto2) |
| `signal_ark/proto/V1Backup_pb2.py` | CREATE (generated) | Proto bindings |
| `signal_ark/v1_decrypt.py` | CREATE | v1 KDF + streaming frame decryption |
| `signal_ark/v1_parser.py` | CREATE | v1 frame parser + SQL collector |
| `signal_ark/v1_to_v2.py` | CREATE | v1-to-v2 frame mapper |
| `tests/test_v1_decrypt.py` | CREATE | v1 crypto tests with computed vectors |
| `tests/test_v1_parser.py` | CREATE | v1 parser tests with synthetic backup |
| `tests/test_v1_to_v2.py` | CREATE | Integration test: v1 → v2 pipeline |
| `signal_ark/cli.py` | UPDATE | Add `dump-v1` and `import-v1` commands |
| `README.md` | UPDATE | Add v1 commands and docs link |
| `CLAUDE.md` | UPDATE | Document v1 modules |

## NOT Building

- v1 export (writing v1 format — read-only)
- Old-style group migration (groups without masterKey)
- Pre-4.x Signal schema support
- Automatic seed generation from v1 data (seed backup still required)
- v1 SharedPreference or KeyValue import (only SQL data and attachments)

---

## Step-by-Step Tasks

### Task 1: Write v1 format specification
- **ACTION**: Create `docs/v1-backup-format.md` mirroring `docs/v2-backup-format.md` structure
- **IMPLEMENT**: Sections: Overview, File Structure, KDF Chain (with HKDF step), Per-Frame Encryption, BackupFrame Proto, Inline Attachments, Frame Types, Differences from v2, References. Include ASCII diagrams for file layout and crypto flow. Reference Signal-Android source files.
- **MIRROR**: `docs/v2-backup-format.md` TOC and formatting style
- **GOTCHA**: Must include the HKDF("Backup Export") step — many third-party docs miss this
- **VALIDATE**: Doc renders correctly, all claims match BackupRecordInputStream.java

### Task 2: Create v1 BackupFrame proto schema
- **ACTION**: Create `proto/V1Backup.proto` with all message types
- **IMPLEMENT**: Copy from `Signal-Android-ref/app/src/main/protowire/Backups.proto` with `package signal_v1;` to avoid name collisions. Messages: SqlStatement (with SqlParameter), SharedPreference, Attachment, Sticker, Avatar, DatabaseVersion, Header, KeyValue, BackupFrame.
- **MIRROR**: Same directory/naming as `proto/Backup.proto`
- **GOTCHA**: Must be `syntax = "proto2"` with `optional` fields
- **VALIDATE**: `protoc -I=proto --python_out=signal_ark/proto proto/V1Backup.proto` generates bindings

### Task 3: Implement v1 KDF
- **ACTION**: Create `signal_ark/v1_decrypt.py` with passphrase validation and key derivation
- **IMPLEMENT**: `V1Keys` frozen dataclass (cipher_key, mac_key). `validate_v1_passphrase(p: str) -> str` strips spaces, validates 30 digits. `derive_v1_keys(passphrase: str, salt: bytes) -> V1Keys`: SHA-512 iterated 250K times (first round includes salt), truncate to 32 bytes, HKDF-SHA256(key, info="Backup Export", length=64), split into cipher_key and mac_key.
- **MIRROR**: `kdf.py` pure-function style
- **IMPORTS**: `hashlib`, `dataclasses`, `cryptography.hazmat.primitives.kdf.hkdf.HKDF`
- **GOTCHA**: The HKDF step is critical — without it, all decryption silently produces garbage. SHA-512 loop: `digest.update(hash); hash = digest.digest(input)` where first round prepends salt. Use `hmac` module for HKDF or `cryptography` HKDF.
- **VALIDATE**: Unit test with precomputed vector (generate from Java reference)

### Task 4: Write v1 KDF tests
- **ACTION**: Create `tests/test_v1_decrypt.py`
- **IMPLEMENT**: Test passphrase validation (strips spaces, rejects non-digits, rejects wrong length). Test KDF with synthetic vector: all-zero passphrase + all-zero salt → compute expected output by running the same algorithm in Python. Also test against a real backup if available.
- **MIRROR**: `tests/test_kdf.py` pattern
- **VALIDATE**: `uv run pytest tests/test_v1_decrypt.py -v`

### Task 5: Implement v1 streaming frame decryptor
- **ACTION**: Extend `signal_ark/v1_decrypt.py` with `V1FrameDecryptor` class
- **IMPLEMENT**: Stateful class holding cipher_key, mac_key, iv, counter. Methods: `__init__(cipher_key, mac_key, iv)` sets counter from `int.from_bytes(iv[0:4], 'big')`. `read_frame(stream) -> bytes` reads 4-byte length, bumps counter into iv[0:4], inits AES-CTR cipher, reads frame_length bytes, splits off last 10 bytes as HMAC, verifies HMAC, decrypts remainder. `read_attachment(stream, length) -> bytes` same counter bump pattern, reads length encrypted bytes + 10-byte trailing HMAC, MAC includes IV.
- **MIRROR**: `decrypt.py` for cipher patterns from `cryptography` library
- **IMPORTS**: `cryptography.hazmat.primitives.ciphers` (Cipher, algorithms, modes.CTR), `cryptography.hazmat.primitives.hmac`
- **GOTCHA**: Counter bumps are `iv[0:4] = counter.to_bytes(4, 'big'); counter += 1`. NOT continuous CTR — each frame gets a fresh cipher init with bumped counter. For attachments: MAC the IV first, then MAC each chunk of ciphertext before decrypting.
- **VALIDATE**: Unit test with synthetic encrypted frame

### Task 6: Implement v1 streaming parser
- **ACTION**: Create `signal_ark/v1_parser.py` with generator-based parser
- **IMPLEMENT**: `parse_v1_header(stream) -> V1Header` reads 4-byte length + unencrypted BackupFrame. `parse_v1_backup(path, passphrase) -> Iterator[V1ParsedFrame]` generator yielding typed frames. `V1ParsedFrame` has frame_type and data fields. `collect_v1_database(frames) -> sqlite3.Connection` executes SQL statements against in-memory SQLite, returns populated DB.
- **MIRROR**: `decrypt.py:_read_varint` stream pattern
- **IMPORTS**: `struct`, `sqlite3`
- **GOTCHA**: Generator pattern essential for multi-GB backups. Attachment data must be consumed immediately (it's inline in the stream). Index attachments by (rowId, attachmentId).
- **VALIDATE**: Test with synthetic v1 backup

### Task 7: Write v1 parser tests
- **ACTION**: Create `tests/test_v1_parser.py` with `build_synthetic_v1_backup` helper
- **IMPLEMENT**: Helper constructs valid v1 backup bytes: unencrypted header frame + encrypted SQL statement frames + encrypted attachment frame with inline data + encrypted End frame. Tests verify: header parsing, frame types, SQL execution populates tables, attachment extraction.
- **MIRROR**: `tests/test_attachments.py:_make_desktop_encrypted_file` helper pattern
- **VALIDATE**: `uv run pytest tests/test_v1_parser.py -v`

### Task 8: Implement v1-to-v2 mapper
- **ACTION**: Create `signal_ark/v1_to_v2.py` with conversion orchestration
- **IMPLEMENT**: `V1ImportResult` frozen dataclass (backup_info, frames, media_names, stats). `convert_v1_to_v2(v1_path, v1_passphrase, seed_dir, aep, self_aci, output_files_dir) -> V1ImportResult`. Flow: parse v1 → collect DB → introspect schema → map recipients (contacts from `recipient` or `recipient_preferences` table) → map chats (from `thread` table) → map messages (from `mms`/`sms` tables, decode type bitmask) → re-encrypt attachments → prepend seed AccountData. Reuse `IdAllocator` and `encrypt_attachment` from mapper.py.
- **MIRROR**: `mapper.py:map_desktop_to_frames` orchestration
- **IMPORTS**: Reuse from `signal_ark.mapper`: `IdAllocator`, `encrypt_attachment`
- **GOTCHA**: v1 message type bitmask: `type & 0x1F` gives base type (1=incoming, 2=outgoing). Focus on common cases, log and skip unknown. Schema varies — check for `recipient` vs `recipient_preferences` table.
- **VALIDATE**: End-to-end test with synthetic data

### Task 9: Add CLI commands
- **ACTION**: Add `dump-v1` and `import-v1` commands to `signal_ark/cli.py`
- **IMPLEMENT**: `dump-v1`: takes --v1-backup + --v1-passphrase + -o, writes frames as JSONL. `import-v1`: takes --v1-backup + --v1-passphrase + --seed-dir + --passphrase (AEP) + --self-aci + -o, runs full conversion pipeline, calls `write_backup_directory`.
- **MIRROR**: `build` command pattern (deferred imports, key derivation, then operation)
- **VALIDATE**: `uv run signal-ark dump-v1 --help` and `uv run signal-ark import-v1 --help`

### Task 10: Write integration tests
- **ACTION**: Create `tests/test_v1_to_v2.py`
- **IMPLEMENT**: Build synthetic v1 backup with contacts + messages + attachment → convert to v2 → verify frame structure (AccountData first, Recipients before Chats, ChatItems in timestamp order). Verify stats dict has expected counts.
- **MIRROR**: `tests/test_roundtrip.py` round-trip pattern
- **VALIDATE**: `uv run pytest tests/test_v1_to_v2.py -v`

### Task 11: Update documentation
- **ACTION**: Update README.md commands table, CLAUDE.md architecture section
- **IMPLEMENT**: Add `dump-v1` and `import-v1` to commands table. Add v1 modules to architecture diagram. Add link to `docs/v1-backup-format.md`. Update TUI "coming soon" note to indicate v1 import is available (enable radio button in screens.py).
- **VALIDATE**: Documentation is accurate

---

## Testing Strategy

### Unit Tests

| Test | Input | Expected Output | Edge Case? |
|---|---|---|---|
| v1 passphrase validation | "123 456 789 012 345 678 901 234 567 890" | "123456789012345678901234567890" | Spaces stripped |
| v1 passphrase reject | "12345" | ValueError | Too short |
| v1 KDF | Known passphrase + salt | Precomputed cipher_key + mac_key | |
| HKDF step | Known 32-byte key | Precomputed 64-byte derived | |
| Header parsing | Synthetic header bytes | V1Header with correct IV, salt, version | |
| Frame decryption | Synthetic CTR-encrypted frame | Correct plaintext protobuf | |
| Truncated HMAC verify | Known data + key | First 10 bytes match | Bad HMAC rejected |
| SQL collection | CREATE + INSERT frames | Populated SQLite tables | |
| Message type bitmask | type=1 → incoming, type=23 → outgoing | Correct direction | Unknown type |
| Recipient mapping | v1 recipient row | v2 Recipient frame | |
| Full pipeline | Synthetic v1 backup | Valid v2 frames + stats | |

### Edge Cases Checklist
- [ ] Empty v1 backup (header + End frame, no data)
- [ ] v1 backup with only SMS (no MMS table)
- [ ] Wrong passphrase (HMAC fails on first frame)
- [ ] Corrupt HMAC mid-stream (raises, doesn't produce garbage)
- [ ] Large attachment (streaming, not loaded into memory)
- [ ] Old schema (recipient_preferences vs recipient table)

---

## Validation Commands

### Proto Generation
```bash
protoc -I=proto --python_out=signal_ark/proto proto/V1Backup.proto
```
EXPECT: `signal_ark/proto/V1Backup_pb2.py` generated

### Static Analysis
```bash
uv run python -m py_compile signal_ark/v1_decrypt.py
uv run python -m py_compile signal_ark/v1_parser.py
uv run python -m py_compile signal_ark/v1_to_v2.py
```
EXPECT: OK for all

### Unit Tests
```bash
uv run pytest tests/test_v1_decrypt.py tests/test_v1_parser.py -v
```
EXPECT: All pass

### Integration Tests
```bash
uv run pytest tests/test_v1_to_v2.py -v
```
EXPECT: All pass

### Full Suite
```bash
uv run pytest
```
EXPECT: No regressions

---

## Acceptance Criteria
- [ ] `docs/v1-backup-format.md` is a complete standalone spec
- [ ] `signal-ark dump-v1` decrypts and dumps v1 backup as JSONL
- [ ] `signal-ark import-v1` converts v1 to valid v2 backup directory
- [ ] v1 KDF includes HKDF("Backup Export") step
- [ ] v1 parser handles header, SQL, inline attachments, End frame
- [ ] v1-to-v2 integration test passes
- [ ] Frame ordering follows v2 spec (AccountData first, etc.)
- [ ] Attachments re-encrypted for v2 content store
- [ ] All existing tests still pass (22 current + new v1 tests)
- [ ] No new pyproject.toml dependencies

## Completion Checklist
- [ ] v1 crypto matches BackupRecordInputStream.java exactly
- [ ] HKDF step present (not just SHA-512 truncation)
- [ ] Per-frame counter bump (not continuous CTR)
- [ ] Generator-based parsing for memory efficiency
- [ ] Reuses IdAllocator and encrypt_attachment from mapper.py
- [ ] CLI commands follow existing Click patterns
- [ ] v1 format doc mirrors v2 doc structure
- [ ] Documentation updated (CLAUDE.md, README.md)

## Risks
| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Counter bump logic wrong | High | Critical | Match BackupRecordInputStream.java exactly, test with synthetic data |
| Missing HKDF step | High | Critical | Explicitly documented in plan, test KDF end-to-end |
| v1 schema variation | Medium | Medium | Check table existence before querying, start with recent schema |
| Message type bitmask | Medium | Low | Focus on type & 0x1F common cases, log unknowns |
| Memory for large backups | Medium | High | Generator parsing, temp files for attachment data |
| No real v1 test fixture | Medium | Medium | Build comprehensive synthetic backup; verify with bepaald/signalbackup-tools if possible |

## Notes
- The existing plan at `.claude/PRPs/plans/v1-backup-import.plan.md` had the KDF wrong — it said `cipher_key = digest[:32], mac_key = digest[32:64]` but the actual code uses `HKDF(SHA-512_output[:32], "Backup Export")`. This plan supersedes it.
- The `dump-v1` diagnostic command is essential for debugging before attempting conversion.
- v1 groups without masterKey (old GV1 style) are out of scope — most active groups migrated to GV2.
- No new dependencies needed: `hashlib.sha512` + `cryptography` HKDF + CTR cover everything.
- Signal-Android source files for cross-referencing: `BackupRecordInputStream.java`, `FullBackupBase.java`, `FullBackupImporter.java`, `Backups.proto`.
