# Plan: v2 Format Documentation

## Summary
Create a standalone, community-facing specification document for the Signal v2 backup format. No such documentation exists outside of libsignal's Rust source code. This fills a critical gap for interoperability and positions signal-ark as the authoritative reference.

## User Story
As a developer building Signal backup tools,
I want a clear specification of the v2 backup format,
So that I can implement compatible readers/writers without reverse-engineering libsignal Rust source.

## Problem → Solution
Scattered knowledge across libsignal Rust, Backup.proto comments, and tribal knowledge → Single authoritative document covering crypto, file layout, frame structure, and content store.

## Metadata
- **Complexity**: Medium
- **Source PRD**: N/A
- **PRD Phase**: N/A (standalone from prioritized roadmap item 4)
- **Estimated Files**: 1 primary doc + minor README update

---

## UX Design

N/A — internal/documentation change. The deliverable is a Markdown document.

---

## Mandatory Reading

| Priority | File | Lines | Why |
|---|---|---|---|
| P0 (critical) | `PLAN.md` | 31-175 | Crypto spec, KDF chain, test vectors, file formats |
| P0 (critical) | `signal_ark/proto/Backup.proto` | all | Frame definitions, field semantics, ordering rules |
| P1 (important) | `signal_ark/proto/LocalArchive.proto` | all | Metadata and FilesFrame definitions |
| P1 (important) | `signal_ark/decrypt.py` | all | Legacy vs modern format detection, HMAC/CBC flow |
| P1 (important) | `signal_ark/encrypt.py` | all | Serialization, encryption, manifest writing |
| P2 (reference) | `signal_ark/kdf.py` | all | HKDF derivation chain implementation |
| P2 (reference) | `signal_ark/metadata.py` | all | Metadata encrypt/decrypt with AES-256-CTR |
| P2 (reference) | `signal_ark/mapper.py` | attachment functions | Desktop attachment encryption, mediaName derivation |

## External Documentation

| Topic | Source | Key Takeaway |
|---|---|---|
| HKDF-SHA256 | RFC 5869 | Standard KDF used throughout the chain |
| AES-256-CBC | NIST SP 800-38A | Block cipher mode for main file and attachments |
| HMAC-SHA256 | RFC 2104 | MAC scheme, computed over IV ‖ ciphertext |
| Protobuf varint | protobuf encoding spec | Length-delimited framing for backup stream |
| gzip | RFC 1952 | Compression layer between encryption and frames |

---

## Patterns to Mirror

### PLAN.md STRUCTURE
// SOURCE: PLAN.md:31-175
The existing PLAN.md uses tables for KDF steps, code blocks for binary layouts, and ASCII diagrams. The spec document should follow the same conventions for consistency.

### TEST_VECTOR FORMAT
// SOURCE: PLAN.md:49-64
```
AEP:       "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l"
ACI:       659aa5f4-a28d-fcc1-1ea1-b997537a3d95
BackupKey: ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985
```
Hex-encoded values on labeled lines. Keep this format.

---

## Files to Change

| File | Action | Justification |
|---|---|---|
| `docs/v2-backup-format.md` | CREATE | The specification document |
| `README.md` | UPDATE | Add link to format spec in Architecture section |

## NOT Building

- No code changes
- No new CLI commands
- No changes to proto files
- No test changes
- No tooling or automation for doc generation

---

## Step-by-Step Tasks

### Task 1: Create docs/ directory and spec document skeleton
- **ACTION**: Create `docs/v2-backup-format.md` with section structure
- **IMPLEMENT**: Sections: Overview, Directory Layout, KDF Chain, Metadata File, Main File, Frame Structure, Files Manifest, Content Store, Attachment Encryption, Test Vectors, References
- **MIRROR**: PLAN.md table and code-block style
- **IMPORTS**: N/A (documentation only)
- **GOTCHA**: Don't copy PLAN.md verbatim — PLAN.md is an internal development journal. The spec should be clean, third-party-readable, and focus on "what the format IS" not "how we built signal-ark"
- **VALIDATE**: Document has all section headers, reads as a standalone spec

### Task 2: Write Directory Layout section
- **ACTION**: Document the v2 backup directory structure
- **IMPLEMENT**:
  ```
  backup-dir/
  ├── main          — encrypted protobuf frame stream
  ├── metadata      — encrypted BackupId + version
  └── files         — unencrypted media name manifest
  files/            — sibling content store
  ├── 00/           — shard by first 2 hex chars of mediaName
  │   └── 00abc...  — individually encrypted attachment
  ├── 01/
  ...
  └── ff/
  ```
- **MIRROR**: ASCII tree diagrams from README.md
- **GOTCHA**: Clarify that `files` (the manifest) is UNENCRYPTED raw varint-delimited protobuf for local backups. This was a misconception in our own PLAN.md (section 6 claims same encryption as main — empirically false).
- **VALIDATE**: Layout matches what signal-ark produces and what Signal Android accepts

### Task 3: Write KDF Chain section
- **ACTION**: Document the full key derivation chain with inputs, HKDF parameters, and outputs
- **IMPLEMENT**: Table format matching PLAN.md section 2. Cover:
  - AEP → BackupKey (info: `20240801_SIGNAL_BACKUP_KEY`)
  - BackupKey + ACI → BackupId (info: `20241024_SIGNAL_BACKUP_ID:` ‖ ACI_binary)
  - BackupKey + BackupId → MessageBackupKey legacy (info: `20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:` ‖ BackupId)
  - BackupKey + BackupId + token → MessageBackupKey modern (info: `20250708_...`, salt=token)
  - BackupKey → LocalMetadataKey (info: `20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY`)
  - BackupKey + mediaName → MediaEncryptionKey (info: `20241007_SIGNAL_BACKUP_ENCRYPT_MEDIA:` ‖ MediaId)
  - BackupKey + mediaName → MediaId (info: `20241007_SIGNAL_BACKUP_MEDIA_ID:` ‖ mediaName)
- **MIRROR**: PLAN.md:38-47 table format
- **GOTCHA**: ACI binary is 17 bytes (0x01 prefix + 16-byte UUID), not 16. Document this explicitly.
- **VALIDATE**: Test vectors from libsignal match when following the spec

### Task 4: Write Metadata File section
- **ACTION**: Document metadata protobuf structure and encryption
- **IMPLEMENT**: Cover LocalArchive.proto Metadata message, EncryptedBackupId with AES-256-CTR, 12-byte IV
- **MIRROR**: PLAN.md section 5
- **GOTCHA**: CTR mode (not CBC) — different from main file encryption
- **VALIDATE**: Matches LocalArchive.proto definition

### Task 5: Write Main File section
- **ACTION**: Document both legacy and modern main file binary layout and crypto
- **IMPLEMENT**:
  - Legacy: `[16B IV][AES-256-CBC ciphertext, PKCS7][32B HMAC-SHA256]`
  - Modern: `[8B magic "SBACKUP\x01"][varint FS metadata length][FS metadata][16B IV][CBC ciphertext][32B HMAC]`
  - HMAC computed over `IV ‖ ciphertext`
  - Plaintext is gzip-compressed varint-delimited protobuf
  - First frame is always BackupInfo, followed by Frame messages
- **MIRROR**: PLAN.md section 3
- **GOTCHA**: Verify-then-decrypt (MAC check before decryption). Document this security property.
- **VALIDATE**: Binary layout diagram matches decrypt.py:77-95

### Task 6: Write Frame Structure section
- **ACTION**: Document the protobuf frame stream, ordering rules, and key frame types
- **IMPLEMENT**: Cover:
  - Varint length-delimited framing
  - BackupInfo always first (not a Frame — separate message type)
  - Frame ordering: AccountData first, Recipients before Chats, Chats before ChatItems
  - ChatItems in global timestamp order
  - Key frame types: AccountData, Recipient (Contact/Group/Self/etc), Chat, ChatItem, StickerPack, ChatFolder, NotificationProfile, AdHocCall
  - FilePointer.LocatorInfo for attachment references
- **MIRROR**: PLAN.md section 4, Backup.proto comments
- **GOTCHA**: BackupInfo is a separate protobuf message type, not a Frame oneof variant
- **VALIDATE**: Ordering rules match Backup.proto header comments

### Task 7: Write Files Manifest section
- **ACTION**: Document the files manifest format
- **IMPLEMENT**: Varint-delimited FilesFrame protobuf messages (each contains a mediaName string). For local backups: UNENCRYPTED. Note that cloud backups may use encryption.
- **MIRROR**: encrypt.py:58-67 serialize_files_manifest
- **GOTCHA**: Our PLAN.md section 6 incorrectly states "Same encryption as main" — empirically verified as unencrypted raw protobuf for local backups
- **VALIDATE**: Matches what Signal Android parses successfully

### Task 8: Write Content Store / Attachment Encryption section
- **ACTION**: Document per-attachment encryption and content-addressed storage
- **IMPLEMENT**:
  - Per-attachment 64-byte localKey (first 32 = AES, last 32 = HMAC)
  - Binary format: `[16B IV][AES-256-CBC ciphertext, PKCS7][32B HMAC-SHA256]`
  - HMAC over `IV ‖ ciphertext`
  - mediaName = `hex(SHA256(plaintextHash ‖ localKey))` — content-addressed
  - Sharding: `files/{mediaName[:2]}/{mediaName}`
  - plaintextHash = SHA256 of the unencrypted attachment bytes
- **MIRROR**: mapper.py encrypt_attachment function
- **GOTCHA**: Desktop also encrypts attachments at rest with a different localKey — that's a Desktop implementation detail, not part of the backup format spec. Keep the spec about the backup format only.
- **VALIDATE**: Attachment round-trip test in test_attachments.py confirms the format

### Task 9: Write Test Vectors section
- **ACTION**: Include libsignal's test vectors for KDF chain verification
- **IMPLEMENT**: Copy test vectors from PLAN.md section 2 (sourced from libsignal). Add a note about their origin.
- **MIRROR**: PLAN.md:49-64
- **GOTCHA**: These are from libsignal's public test suite — attribution is appropriate
- **VALIDATE**: Values match libsignal source

### Task 10: Write References section
- **ACTION**: Link to primary sources
- **IMPLEMENT**: Links to Signal-Android Backup.proto, libsignal backup module, RFC 5869, relevant Signal blog posts
- **VALIDATE**: All links resolve

### Task 11: Update README.md
- **ACTION**: Add link to the format spec in the Architecture section
- **IMPLEMENT**: Add a line like `- [v2 Backup Format Specification](docs/v2-backup-format.md)` in the Architecture section
- **VALIDATE**: Link works, README renders correctly

---

## Testing Strategy

### Manual Validation
- [ ] Document is self-contained and readable without signal-ark source code
- [ ] All binary layouts match actual file bytes (spot-check against a real backup)
- [ ] Test vectors produce correct outputs when followed step-by-step
- [ ] No signal-ark implementation details leak into the spec (it's format-only)
- [ ] A developer unfamiliar with signal-ark could implement a compatible reader from this doc alone

### Review Checklist
- [ ] KDF table matches libsignal source
- [ ] Binary layouts match decrypt.py / encrypt.py behavior
- [ ] Frame ordering rules match Backup.proto comments
- [ ] Files manifest correctly documented as unencrypted (correcting PLAN.md)
- [ ] Attachment mediaName derivation formula is correct

---

## Validation Commands

### Static Analysis
```bash
# No code changes — N/A
```

### Existing Tests Still Pass
```bash
uv run pytest tests/ -v
```
EXPECT: All tests pass (no code changes)

### Manual Validation
- [ ] Read through document end-to-end as an outsider
- [ ] Cross-reference each crypto parameter against libsignal source
- [ ] Verify binary layout diagrams against hex dumps of real backup files

---

## Acceptance Criteria
- [ ] `docs/v2-backup-format.md` exists and is complete
- [ ] All 10 sections written (Overview through References)
- [ ] Test vectors included with attribution
- [ ] Files manifest correctly documented as unencrypted for local backups
- [ ] README.md links to the spec
- [ ] No signal-ark code changes required
- [ ] Document passes the "cold reader" test — implementable without other sources

## Completion Checklist
- [ ] Spec covers: directory layout, KDF chain, metadata, main file, frames, manifest, content store
- [ ] Both legacy and modern main file variants documented
- [ ] ACI binary format (17 bytes with 0x01 prefix) called out explicitly
- [ ] HMAC-then-encrypt security property documented
- [ ] No internal development notes or signal-ark implementation details
- [ ] README updated with link

## Risks
| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Format changes in future Signal releases | Medium | Medium | Version the spec, note it covers the format as of 2026-04 |
| Incomplete coverage of modern/FS format | Low | Medium | Document what we know, mark unknowns explicitly |
| PLAN.md errors propagated to spec | Medium | High | Cross-reference every claim against actual code behavior and empirical tests |

## Notes
- PLAN.md section 6 claims files manifest uses "same encryption as main" — this is WRONG for local backups. Empirically verified: both seed and rebuilt manifests start with raw protobuf bytes. The spec must correct this.
- The modern format with forward secrecy tokens is used for cloud backups. Local backups (what signal-ark produces) use the legacy variant. Document both but note which is which.
- This document could become the basis for a community standard or RFC-style spec if other tools adopt it.
