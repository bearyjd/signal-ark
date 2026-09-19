# Plan: v1 Backup Import

## Summary
Add a `import-v1` command that reads legacy Signal Android `.backup` files (v1 format), decrypts them, parses the SQL-statement-based frame stream, maps extracted data into v2 protobuf Frames, and writes a v2 backup directory. This is the "v1 to v2 upgrade" path that no existing tool provides.

## User Story
As a Signal user with an old v1 backup,
I want to convert it to v2 format,
So that I can restore it on current Signal Android or Molly.

## Problem -> Solution
Legacy v1 `.backup` files are incompatible with current Signal restore -> Convert v1 to v2 on the fly.

## Metadata
- **Complexity**: Large
- **Source PRD**: N/A
- **PRD Phase**: N/A (roadmap item)
- **Estimated Files**: 8 new + 3 modified

---

## UX Design

N/A -- internal/CLI change.

### Interaction Changes
| Touchpoint | Before | After | Notes |
|---|---|---|---|
| CLI | No v1 support | `signal-ark import-v1` and `signal-ark dump-v1` | Two new commands |

---

## Mandatory Reading

| Priority | File | Lines | Why |
|---|---|---|---|
| P0 (critical) | `signal_ark/decrypt.py` | all | v2 decryption patterns to mirror |
| P0 (critical) | `signal_ark/mapper.py` | 1-50, 300-500 | IdAllocator, encrypt_attachment, map_desktop_to_frames orchestration |
| P0 (critical) | `signal_ark/encrypt.py` | all | write_backup_directory for final output |
| P1 (important) | `signal_ark/kdf.py` | all | KDF patterns to mirror for v1 KDF |
| P1 (important) | `signal_ark/metadata.py` | all | Frozen dataclass pattern |
| P1 (important) | `signal_ark/cli.py` | all | Click CLI patterns for new commands |
| P2 (reference) | `tests/test_attachments.py` | all | Test helper pattern |
| P2 (reference) | `tests/test_kdf.py` | all | Test vector pattern |

---

## Patterns to Mirror

### FROZEN_DATACLASS
// SOURCE: signal_ark/metadata.py:13-28
Frozen dataclasses for result types. V1Keys, V1Header, V1Frame, V1ImportResult all follow this.

### KDF_PURE_FUNCTION
// SOURCE: signal_ark/kdf.py
Pure functions with no I/O. v1 KDF follows same pattern: input bytes, output bytes, no side effects.

### CLI_COMMAND
// SOURCE: signal_ark/cli.py:105-171
Click command with deferred imports, key derivation, seed decryption, then main operation.

### STREAM_PARSER
// SOURCE: signal_ark/decrypt.py:29-43
`_read_varint` with stream-based reading. v1 parser uses same generator/stream approach.

### ENCRYPT_ATTACHMENT
// SOURCE: signal_ark/mapper.py (encrypt_attachment function)
Reuse directly for v1 attachment re-encryption.

### TEST_SYNTHETIC_DATA
// SOURCE: tests/test_attachments.py:13-35
`_make_desktop_encrypted_file` helper builds synthetic encrypted data for testing.

---

## Files to Change

| File | Action | Justification |
|---|---|---|
| `proto/V1Backup.proto` | CREATE | v1 BackupFrame protobuf schema |
| `signal_ark/proto/V1Backup_pb2.py` | CREATE (generated) | Proto bindings |
| `signal_ark/v1_decrypt.py` | CREATE | v1 crypto (SHA-512 KDF, AES-256-CTR, truncated HMAC) |
| `signal_ark/v1_parser.py` | CREATE | v1 streaming frame parser |
| `signal_ark/v1_to_v2.py` | CREATE | v1-to-v2 frame mapper |
| `tests/test_v1_decrypt.py` | CREATE | v1 crypto unit tests |
| `tests/test_v1_parser.py` | CREATE | v1 parser tests with synthetic backup |
| `tests/test_v1_to_v2.py` | CREATE | End-to-end integration tests |
| `signal_ark/cli.py` | UPDATE | Add `import-v1` and `dump-v1` commands |
| `CLAUDE.md` | UPDATE | Document v1 modules and commands |
| `README.md` | UPDATE | Add v1 commands to table and usage |

## NOT Building

- v1 export (writing v1 format)
- v1 group migration for old-style groups without masterKey
- Support for very old Signal versions (pre-4.x) with radically different schemas
- Automatic seed generation from v1 data (seed backup still required)

---

## v1 Backup Format Reference

### Passphrase and KDF
- 30 digits, displayed as 5 groups of 6 (spaces cosmetic)
- `digest = SHA-512(passphrase_bytes || salt)` iterated 250,000 times
- `cipher_key = digest[:32]`, `mac_key = digest[32:64]`

### File structure
```
[4B: header_length (big-endian uint32)]
[header_length bytes: UNENCRYPTED BackupFrame with Header]
-- repeating:
[4B: frame_length (big-endian uint32)]
[frame_length - 10 bytes: AES-256-CTR encrypted BackupFrame]
[10B: truncated HMAC-SHA256]
```

### Per-frame encryption
- AES-256-CTR with 16-byte IV from Header, continuous keystream across all frames
- HMAC-SHA256 over encrypted bytes, truncated to first 10 bytes
- IV/counter state carries across frame boundaries and inline attachment data

### Inline attachments
When Attachment/Avatar/Sticker frame appears, next N bytes are encrypted data (same CTR stream), followed by 10-byte HMAC.

---

## Step-by-Step Tasks

### Task 1: Create v1 BackupFrame proto schema
- **ACTION**: Create `proto/V1Backup.proto` with BackupFrame, Header, SqlStatement, Attachment, Avatar, Sticker, SharedPreference, KeyValue, DatabaseVersion
- **IMPLEMENT**: Proto2 syntax matching Signal-Android's legacy backup proto
- **MIRROR**: Same directory pattern as `proto/Backup.proto`
- **GOTCHA**: Use `optional` fields (proto2 style) to match Signal's original schema
- **VALIDATE**: `protoc -I=proto --python_out=signal_ark/proto proto/V1Backup.proto` generates bindings

### Task 2: Implement v1 KDF
- **ACTION**: Create `signal_ark/v1_decrypt.py` with `validate_v1_passphrase` and `derive_v1_keys`
- **IMPLEMENT**: `V1Keys` frozen dataclass, SHA-512 iterated 250,000 times via `hashlib.sha512`, split into cipher_key[:32] and mac_key[32:64]
- **MIRROR**: `kdf.py` pure-function style, `metadata.py` frozen dataclass
- **IMPORTS**: `hashlib`, `dataclasses`
- **GOTCHA**: Must iterate exactly 250,000 times (off-by-one = wrong keys, all subsequent decryption fails silently with garbage)
- **VALIDATE**: Unit test with precomputed vector

### Task 3: Write v1 KDF tests
- **ACTION**: Create `tests/test_v1_decrypt.py`
- **IMPLEMENT**: Test passphrase validation (spaces, non-digits, wrong length). Test KDF with synthetic vector using all-zero passphrase and salt.
- **MIRROR**: `tests/test_kdf.py` pattern
- **VALIDATE**: `uv run pytest tests/test_v1_decrypt.py -v`

### Task 4: Implement v1 frame decryption
- **ACTION**: Extend `signal_ark/v1_decrypt.py` with continuous-stream CTR decryption and truncated HMAC verification
- **IMPLEMENT**: Use a SINGLE `Cipher(AES, CTR)` object for the entire backup stream. Feed frame bytes and attachment bytes through the same decryptor. Verify 10-byte truncated HMAC per frame.
- **MIRROR**: `decrypt.py` for cipher/HMAC patterns from `cryptography` library
- **IMPORTS**: `cryptography.hazmat.primitives.ciphers` (Cipher, algorithms, modes.CTR)
- **GOTCHA**: Do NOT create a new cipher per frame — CTR counter must be continuous. This is the highest-risk part of the implementation.
- **VALIDATE**: Unit test with synthetic encrypted frame

### Task 5: Implement v1 streaming parser
- **ACTION**: Create `signal_ark/v1_parser.py` with generator-based parser
- **IMPLEMENT**: `V1Header` and `V1Frame` frozen dataclasses. `parse_v1_header(stream)` reads unencrypted header. `parse_v1_backup(path, passphrase)` yields `V1Frame` objects including inline attachment data. `collect_v1_database(frames)` executes SQL statements against in-memory SQLite.
- **MIRROR**: `decrypt.py:_read_varint` stream pattern
- **IMPORTS**: `struct` for big-endian uint32, `sqlite3` for database reconstruction
- **GOTCHA**: Generator pattern essential for multi-GB backups. Attachment data indexed by (rowId, attachmentId) for later correlation.
- **VALIDATE**: Test with synthetic v1 backup

### Task 6: Write v1 parser tests
- **ACTION**: Create `tests/test_v1_parser.py` with `build_synthetic_v1_backup` helper
- **IMPLEMENT**: Helper constructs valid v1 backup in memory (header + SQL statements + attachment + End frame). Tests verify header parsing, frame types, SQL execution, attachment extraction.
- **MIRROR**: `tests/test_attachments.py:_make_desktop_encrypted_file` helper pattern
- **VALIDATE**: `uv run pytest tests/test_v1_parser.py -v`

### Task 7: Implement v1-to-v2 recipient mapping
- **ACTION**: Create `signal_ark/v1_to_v2.py` with `detect_v1_schema_version` and `map_v1_recipients`
- **IMPLEMENT**: Introspect v1 SQLite tables (recipient vs recipient_preferences). Map contacts to v2 Recipient frames. Handle Self recipient. Skip old-style groups without masterKey.
- **MIRROR**: `mapper.py:build_contact_recipient` and `mapper.py:build_group_recipient`
- **IMPORTS**: Reuse `IdAllocator` from `mapper.py`
- **GOTCHA**: v1 schema varies across Signal Android versions. Start with recent schema (5.x+), add fallback for older tables.
- **VALIDATE**: Unit test with synthetic recipient table

### Task 8: Implement v1-to-v2 chat and message mapping
- **ACTION**: Extend `v1_to_v2.py` with `map_v1_chats` and `map_v1_messages`
- **IMPLEMENT**: Map `thread` table to Chat frames. Map `mms` (and `sms` for older schemas) to ChatItem frames. Decode v1 type bitmask (`type & 0x1F`: 1=incoming, 2=outgoing, 20=incoming push, 23=outgoing push). Sort ChatItems by timestamp.
- **MIRROR**: `mapper.py:build_chat_item` and `mapper.py:build_chat`
- **GOTCHA**: v1 message type bitmask is complex. Focus on common cases first, log and skip unknown types.
- **VALIDATE**: Unit test with synthetic message rows

### Task 9: Implement top-level conversion function
- **ACTION**: Add `convert_v1_to_v2` orchestration function and `V1ImportResult` dataclass
- **IMPLEMENT**: Parse v1 -> collect DB -> map recipients/chats/messages -> encrypt attachments -> prepend seed AccountData -> return V1ImportResult with frames, media_names, stats
- **MIRROR**: `mapper.py:map_desktop_to_frames` orchestration pattern
- **GOTCHA**: Memory for large backups — write attachment data to temp files during parsing, not hold in dict
- **VALIDATE**: End-to-end integration test

### Task 10: Add CLI commands
- **ACTION**: Add `import-v1` and `dump-v1` commands to `signal_ark/cli.py`
- **IMPLEMENT**: `import-v1` takes v1 backup + passphrase + seed dir + AEP + output. `dump-v1` takes v1 backup + passphrase + output dir (diagnostic).
- **MIRROR**: `build` command pattern exactly
- **VALIDATE**: `uv run signal-ark import-v1 --help` shows options

### Task 11: Write integration tests
- **ACTION**: Create `tests/test_v1_to_v2.py` with full pipeline test
- **IMPLEMENT**: Build synthetic v1 backup with contacts/messages/attachment -> convert to v2 -> encrypt -> decrypt -> verify frame structure and counts
- **MIRROR**: `tests/test_attachments.py:test_encrypt_attachment_with_desktop_decryption` full-pipeline pattern
- **VALIDATE**: `uv run pytest tests/test_v1_to_v2.py -v`

### Task 12: Update documentation
- **ACTION**: Update CLAUDE.md, README.md, PLAN.md
- **IMPLEMENT**: Add v1 modules to architecture, add commands to tables, add v1 format details
- **VALIDATE**: Documentation reads correctly

---

## Testing Strategy

### Unit Tests

| Test | Input | Expected Output | Edge Case? |
|---|---|---|---|
| v1 passphrase validation | "123456 789012 345678 901234 567890" | Stripped "123456789012345678901234567890" | Spaces, non-digits |
| v1 KDF | Zero passphrase + zero salt | Precomputed cipher_key + mac_key | |
| Header parsing | Synthetic header bytes | V1Header with correct IV, salt | |
| Frame decryption | Synthetic CTR-encrypted frame | Correct plaintext | |
| Truncated HMAC | Known data + key | First 10 bytes of HMAC-SHA256 | |
| SQL collection | CREATE + INSERT statements | Populated SQLite tables | |
| Message type bitmask | type=1, type=23 | incoming, outgoing | Unknown type |

### Edge Cases Checklist
- [ ] Empty v1 backup (header + end, no data)
- [ ] v1 backup with only SMS messages (no MMS table)
- [ ] v1 backup with old-style groups (no masterKey)
- [ ] Large inline attachment (tests memory handling)
- [ ] Corrupt HMAC (should raise, not silently produce garbage)
- [ ] Wrong passphrase (HMAC verification fails on first frame)

---

## Validation Commands

### Static Analysis
```bash
uv run python -m py_compile signal_ark/v1_decrypt.py && echo OK
uv run python -m py_compile signal_ark/v1_parser.py && echo OK
uv run python -m py_compile signal_ark/v1_to_v2.py && echo OK
```
EXPECT: OK for all

### Unit Tests
```bash
uv run pytest tests/test_v1_decrypt.py tests/test_v1_parser.py -v
```
EXPECT: All tests pass

### Integration Tests
```bash
uv run pytest tests/test_v1_to_v2.py -v
```
EXPECT: All tests pass

### Full Test Suite
```bash
uv run pytest
```
EXPECT: No regressions

---

## Acceptance Criteria
- [ ] `signal-ark dump-v1` decrypts and dumps a v1 backup as JSONL
- [ ] `signal-ark import-v1` converts v1 to valid v2 backup directory
- [ ] v1 KDF tests pass with precomputed vectors
- [ ] v1 parser handles header, SQL, inline attachments, End frame
- [ ] v1-to-v2 integration test round-trips successfully
- [ ] Frame ordering follows v2 spec
- [ ] Text messages appear as ChatItems with correct timestamps and direction
- [ ] Attachments re-encrypted for v2 content store
- [ ] All existing tests still pass
- [ ] No new dependencies required

## Completion Checklist
- [ ] v1 crypto matches reference implementations
- [ ] Single CTR cipher object for entire backup stream
- [ ] Generator-based parsing for memory efficiency
- [ ] Reuses IdAllocator and encrypt_attachment from mapper.py
- [ ] CLI commands follow existing Click patterns
- [ ] Documentation updated (CLAUDE.md, README.md)

## Risks
| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| CTR counter continuity bugs | High | Critical | Single cipher object, not per-frame |
| v1 schema variation | Medium | Medium | Start with recent schema, fallback for older |
| Message type bitmask complexity | Medium | Medium | Focus on common cases, log unknowns |
| Memory for large backups | Medium | High | Generator parsing, temp files for attachments |
| Seed backup requirement | Low | Low | Document clearly, no workaround needed now |

## Notes
- No new pyproject.toml dependencies needed — hashlib.sha512 and cryptography cover everything
- The `dump-v1` diagnostic command is essential for debugging the parser before attempting conversion
- v1 groups without masterKey (old-style) are out of scope — most active groups have migrated to GV2
- Consider streaming attachments to temp files rather than holding in memory for backups > 1GB
