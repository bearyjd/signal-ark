# Plan: signal-ark Comprehensive Feature Roadmap

## Summary
A competitive analysis of all Signal backup/recovery tools in the ecosystem, mapped against signal-ark's current capabilities, producing a prioritized feature roadmap that covers the gaps no existing tool fills — particularly v2 backup creation from Desktop, richer message type support, cross-platform migration, and user-friendly interfaces.

## User Story
As a Signal user who has lost their phone or wants to migrate platforms,
I want a comprehensive tool that can reconstruct, transform, and verify Signal backups from any available source,
So that I never lose my message history regardless of what device or platform I'm on.

## Problem → Solution
**Current state:** The Signal backup ecosystem is fragmented — tools are either read-only exporters, limited to Android v1 format, or abandoned. No single tool handles Desktop→Android v2 migration end-to-end. signal-ark does this but only maps text messages, contacts, groups, and attachments.

**Desired state:** signal-ark becomes the definitive Swiss-army-knife for Signal backup operations: Desktop→Android migration with full message fidelity, HTML/Markdown export for archival, backup verification, and eventually iOS support — all with a clean CLI and optional TUI/web UI.

## Metadata
- **Complexity**: XL
- **Source PRD**: N/A (competitive analysis → roadmap)
- **PRD Phase**: N/A
- **Estimated Files**: 15–30 across all phases

---

## Competitive Landscape

### Tool Comparison Matrix

| Tool | Language | Stars | Last Active | Input Sources | Output Formats | v2 Support | Desktop Import | Create Backup |
|------|----------|-------|-------------|---------------|----------------|------------|----------------|---------------|
| **signalbackup-tools** (bepaald) | C++ | 1,312 | Apr 2026 | Android v1 encrypted | HTML, TXT, CSV, XML, re-encrypted | No | Yes (limited) | Yes (v1 only) |
| **signal-export** (carderne) | Python | 728 | Mar 2026 | Desktop SQLite | Markdown, HTML | No | N/A (reads Desktop) | No |
| **signal-back** (xeals) | Go | 721 | Inactive (2018) | Android v1 encrypted | XML, CSV, raw | No | No | No |
| **sigtop** (tbvdm) | Go | 543 | Mar 2026 | Desktop SQLite | JSON, text | No | N/A (reads Desktop) | No |
| **signal-backup-decode** (pajowu) | Rust | 230 | Inactive (2021) | Android v1 encrypted | RAW DB, CSV | No | No | No |
| **signal2html** (GjjvdBurg) | Python | 117 | Unmaintained | Decrypted Android DB | HTML | No | No | No |
| **signal-backup-shrink** | Python | 13 | Nov 2025 | Android backups | Shrunk backup | No | No | No |
| **signal-backup-ios** | Python | 9 | Jul 2025 | iOS (via Frida) | Export | No | No | No |
| **signal-ark** (ours) | Python | — | Apr 2026 | Desktop SQLite | **v2 encrypted backup** | **Yes** | **Yes** | **Yes (v2)** |

### Key Differentiators — signal-ark Is Unique In:
1. **Creates v2 backups** — No other tool writes Signal's modern (2024+) backup format
2. **Desktop → Android migration** — bepaald does limited Desktop import into v1; signal-ark does full v2
3. **Correct v2 crypto** — HKDF chain, AES-256-CBC, HMAC-SHA256, forward secrecy detection
4. **Seed-based reconstruction** — Uses a minimal phone backup as the AccountData source

### Gaps In The Ecosystem (Opportunities):
1. **No tool exports to PDF** — common request in forensic/legal contexts
2. **No iOS ↔ Android migration** — signal-backup-ios uses Frida but is experimental
3. **No backup verification tool** — validate a backup will restore before pushing to phone
4. **No incremental/delta backup** — every operation is full rebuild
5. **No merge across sources** — can't combine Desktop + old Android v1 + new phone
6. **No GUI** — every tool is CLI-only
7. **No reactions/quotes/stickers/calls** in Desktop→Android mapping (signal-ark gap)

---

## Common Recovery Scenarios

| Scenario | Frequency | Current Solution | signal-ark Coverage |
|----------|-----------|-----------------|-------------------|
| **Bricked phone, Desktop has history** | High | None (data loss) | **Solved** (build command) |
| **Switch Android → Android** | High | Signal's built-in transfer | Not needed |
| **Switch iOS → Android** | Medium | None (Signal doesn't support) | **Opportunity** |
| **Archive conversations for records** | Medium | signal-export (Markdown) | **Opportunity** (HTML/PDF export) |
| **Legal discovery / forensics** | Low | Cellebrite ($$$) | **Opportunity** (verification + export) |
| **Merge old + new backups** | Medium | bepaald (v1 only) | **Opportunity** (v2 merge) |
| **Corrupt backup recovery** | Low | bepaald (v1, limited) | **Opportunity** |
| **Reduce backup size** | Low | signal-backup-shrink | Low priority |

---

## Feature Roadmap — Phased

### Phase 5: Message Fidelity (Current Priority)
**Goal:** Map all remaining Desktop message types to v2 frames.

| Feature | Desktop Source | v2 Target Frame | Effort |
|---------|--------------|-----------------|--------|
| Reactions | `messages.json → reactions[]` | `StandardMessage.reactions` | Small |
| Quotes/Replies | `messages.json → quote` | `StandardMessage.quote` | Small |
| Link Previews | `messages.json → preview[]` | `StandardMessage.linkPreview` | Small |
| Sticker Messages | `messages.json → sticker` | `StickerMessage` | Small |
| View-Once Messages | `messages.json → isViewOnce` | `ViewOnceMessage` | Small |
| Voice Notes | `message_attachments → flags` | `MessageAttachment (voice note flag)` | Small |
| Contact Cards | `messages.json → contact[]` | `ContactMessage` | Medium |
| Group Update Messages | `messages.json → group_update` | `ChatUpdateMessage` | Medium |
| Profile Change Messages | `messages.json → profileChange` | `ChatUpdateMessage.profileChange` | Small |
| Disappearing Message Timers | `messages.json → expirationTimerUpdate` | `ChatUpdateMessage.expirationTimerChange` | Small |
| Call History | `messages.json → callHistoryDetails` | `IndividualCall` / `GroupCall` | Medium |
| Story Replies | `messages.json → storyReplyContext` | `DirectStoryReplyMessage` | Medium |
| Body Ranges (bold/italic/spoiler/mention) | `messages.json → bodyRanges[]` | `Text.bodyRanges` | Medium |

**Acceptance:** All message types present in a typical Desktop DB are mapped. Diff a fresh backup against the Desktop DB — zero unhandled message types for common conversations.

### Phase 6: Export & Archival
**Goal:** Read v2 backups and export to human-readable formats.

| Feature | Description | Effort |
|---------|-------------|--------|
| HTML Export | Conversation-per-page HTML with inline media, dark/light themes, search | Large |
| Markdown Export | Per-conversation .md files with attachment links (signal-export parity) | Medium |
| PDF Export | Print-ready conversation archives (via HTML→PDF or WeasyPrint) | Medium |
| JSON Export | Structured JSONL per conversation for programmatic access | Small |
| Conversation Browser (CLI) | `signal-ark browse` — list conversations, preview messages | Small |
| Statistics | Message counts, top contacts, activity timelines, media breakdown | Small |

**Acceptance:** `signal-ark export --format html` produces a self-contained archive viewable in any browser.

### Phase 7: Verification & Integrity
**Goal:** Validate backups before pushing to phone.

| Feature | Description | Effort |
|---------|-------------|--------|
| `signal-ark verify` | Decrypt, parse all frames, check ordering rules, validate HMAC | Medium |
| Frame Statistics | Count by type, identify missing required frames | Small |
| Attachment Audit | Verify all FilePointer mediaNames exist in files/ directory | Small |
| Diff Two Backups | Compare frame-by-frame, report added/removed/changed | Medium |
| Dry-Run Build | `signal-ark build --dry-run` — map everything, report stats, don't encrypt | Small |

**Acceptance:** `signal-ark verify <backup-dir>` exits 0 for valid backups, non-zero with specific error messages for invalid ones.

### Phase 8: CLI Polish & UX
**Goal:** Production-quality CLI experience.

| Feature | Description | Effort |
|---------|-------------|--------|
| Progress Bars | Rich/click progress for long operations (attachment encryption) | Small |
| Conversation Filtering | `--include-chat` / `--exclude-chat` patterns | Small |
| Date Range Filtering | `--after 2024-01-01 --before 2025-01-01` | Small |
| Config File | `~/.config/signal-ark/config.toml` for defaults | Small |
| `signal-ark info` | Show backup metadata without full decryption | Small |
| Verbose/Quiet Modes | `-v` for debug logging, `-q` for scripts | Small |
| Shell Completions | Click's built-in completion for bash/zsh/fish | Small |
| ACI Auto-Detection | Read ACI from Desktop DB `items` table automatically | Small |

**Acceptance:** A new user can `pip install signal-ark && signal-ark --help` and successfully build a backup following only CLI guidance.

### Phase 9: Cross-Source Migration
**Goal:** Import from sources beyond Desktop.

| Feature | Description | Effort |
|---------|-------------|--------|
| Android v1 → v2 Upgrade | Read old encrypted backups, re-emit as v2 | Large |
| Merge Desktop + Android v1 | Combine two sources, deduplicate by timestamp+sender | Large |
| Telegram Import | Read Telegram JSON export, map to Signal frames | Large |
| WhatsApp Import | Read WhatsApp export (txt/zip), map to Signal frames | Large |
| iOS Backup Read | Parse iOS Signal SQLite (requires jailbreak or iTunes backup) | Large |

**Acceptance:** `signal-ark import --source telegram --input export.json` produces valid v2 frames.

### Phase 10: TUI & Web UI
**Goal:** Accessible interfaces for non-CLI users.

| Feature | Description | Effort |
|---------|-------------|--------|
| Textual TUI | 5-step wizard: select source → configure → preview → build → verify | Large |
| FastAPI Web UI | Local web server with drag-and-drop, conversation browser, build progress | XL |
| Tauri Desktop App | Cross-platform native wrapper around web UI | XL |

**Acceptance:** A non-technical user can complete a Desktop→Android migration using only the TUI without reading documentation.

### Phase 11: Distribution & Packaging
**Goal:** Easy installation on all platforms.

| Feature | Description | Effort |
|---------|-------------|--------|
| PyPI Release | `pip install signal-ark` with proper metadata | Small |
| Standalone Binaries | PyInstaller/Nuitka for Windows/macOS/Linux | Medium |
| Homebrew Formula | `brew install signal-ark` | Small |
| Flatpak | Linux desktop packaging | Medium |
| AUR Package | Arch Linux | Small |
| Docker Image | `docker run signal-ark build ...` | Small |
| GitHub Releases | CI/CD with auto-built binaries on tag | Medium |

---

## Priority Matrix

| Phase | Priority | Justification |
|-------|----------|---------------|
| **Phase 5: Message Fidelity** | P0 — Critical | Most impactful for existing users; reactions/quotes are the most visible gaps |
| **Phase 7: Verification** | P0 — Critical | Users need confidence before pushing to phone; prevents data loss |
| **Phase 8: CLI Polish** | P1 — High | Progress bars and filtering are table-stakes for a released tool |
| **Phase 6: Export** | P1 — High | Archival is the #2 use case after migration; HTML export has broad appeal |
| **Phase 11: Distribution** | P1 — High | PyPI + standalone binaries unlock 90% of users |
| **Phase 9: Cross-Source** | P2 — Medium | v1→v2 upgrade and merge are valuable but niche |
| **Phase 10: TUI/Web UI** | P3 — Low | CLI covers power users; UI is a growth play |

---

## Mandatory Reading

Files that MUST be read before implementing any phase:

| Priority | File | Lines | Why |
|----------|------|-------|-----|
| P0 | `signal_ark/mapper.py` | all (620) | Core mapping engine; all new message types go here |
| P0 | `proto/Backup.proto` | all (1,455) | Defines every frame type; consult before mapping |
| P0 | `signal_ark/cli.py` | all (176) | CLI entry point; new commands/options added here |
| P1 | `signal_ark/encrypt.py` | all (95) | Backup directory writer; verify command extends this |
| P1 | `signal_ark/decrypt.py` | all (161) | Frame parser; export commands build on this |
| P1 | `PLAN.md` | all (340) | Design decisions and crypto details |
| P2 | `signal_ark/kdf.py` | all (95) | Key derivation; needed for v1→v2 upgrade |
| P2 | `tests/test_kdf.py` | all (56) | Test patterns to follow |
| P2 | `tests/test_roundtrip.py` | all (47) | Integration test pattern |

---

## Patterns to Mirror

### FRAME_BUILDER_PATTERN
```python
# SOURCE: signal_ark/mapper.py:88-152
def build_contact_recipient(ids: IdAllocator, conv: dict, conv_id: str) -> Frame | None:
    """Each builder: takes IdAllocator + Desktop data, returns Frame or None to skip."""
    service_id = conv.get("serviceId")
    if not service_id:
        return None
    rid = ids.alloc_recipient(conv_id, service_id=service_id)
    frame = Frame()
    frame.recipient.id = rid
    # ... map fields ...
    return frame
```

### CLI_COMMAND_PATTERN
```python
# SOURCE: signal_ark/cli.py:105-171
@main.command()
@click.option("--seed-dir", required=True, type=click.Path(exists=True))
@click.option("--passphrase", required=True)
# ... more options ...
def build(seed_dir, passphrase, desktop_db, attachments_dir, self_aci, output):
    """Build a v2 backup from Desktop data + seed backup."""
    # 1. Validate inputs
    # 2. Decrypt seed
    # 3. Map Desktop data
    # 4. Write output
```

### TEST_PATTERN
```python
# SOURCE: tests/test_roundtrip.py:10-39
def test_roundtrip_main():
    """Create frames, serialize, encrypt, decrypt, verify identical."""
    info = BackupInfo()
    info.version = 1
    # ... build test data ...
    plaintext = serialize_frames(info, frames)
    encrypted = encrypt_main(plaintext, hmac_key, aes_key)
    decrypted = decrypt_main(encrypted, hmac_key, aes_key)
    result = parse_frames(decrypted)
    assert len(result.frames) == len(frames)
```

### ID_ALLOCATION_PATTERN
```python
# SOURCE: signal_ark/mapper.py:35-58
# IdAllocator manages monotonic IDs. Always use alloc_recipient/alloc_chat.
# Never hardcode IDs. Store mappings for cross-reference in ChatItem building.
```

---

## Files to Change (Phase 5 — Message Fidelity)

| File | Action | Justification |
|------|--------|---------------|
| `signal_ark/mapper.py` | UPDATE | Add reaction, quote, link preview, sticker, call, body range mappers |
| `tests/test_mapper.py` | CREATE | Integration tests for Desktop→frame mapping |
| `tests/fixtures/` | CREATE | Sample Desktop DB rows as JSON for mapper tests |

## Files to Change (Phase 7 — Verification)

| File | Action | Justification |
|------|--------|---------------|
| `signal_ark/verify.py` | CREATE | Verification logic: frame ordering, HMAC, attachment audit |
| `signal_ark/cli.py` | UPDATE | Add `verify` and `info` commands |
| `tests/test_verify.py` | CREATE | Tests for verification logic |

## Files to Change (Phase 6 — Export)

| File | Action | Justification |
|------|--------|---------------|
| `signal_ark/export_html.py` | CREATE | HTML export with templates |
| `signal_ark/export_md.py` | CREATE | Markdown export |
| `signal_ark/cli.py` | UPDATE | Add `export` command with `--format` option |
| `signal_ark/templates/` | CREATE | Jinja2 HTML templates for conversation rendering |
| `tests/test_export.py` | CREATE | Export output tests |

---

## NOT Building (Out of Scope for Roadmap)

- Signal protocol implementation (we read/write backups, not messages)
- Real-time sync with Signal servers
- Backup scheduling/automation (cron is sufficient)
- Cloud backup upload (Signal app handles this)
- Contact discovery or phone number lookup
- Message search across backups (defer to export + external tools)
- Windows GUI installer (standalone binary is sufficient)
- Mobile app (the phone already has Signal)

---

## Step-by-Step Tasks — Phase 5 (Message Fidelity)

### Task 1: Add Reactions Mapping
- **ACTION**: Map Desktop `messages.json → reactions[]` to `StandardMessage.reactions`
- **IMPLEMENT**: In `build_chat_item()`, parse `msg_json.get("reactions", [])` and create `ChatItem.StandardMessage.Reaction` for each (emoji, authorId, sentTimestamp, receivedTimestamp)
- **MIRROR**: FRAME_BUILDER_PATTERN — follow existing `build_chat_item` structure
- **IMPORTS**: None new needed
- **GOTCHA**: Reaction author is by ACI (serviceId) — must look up via `ids.service_id_to_recipient`; skip reactions from unknown senders
- **VALIDATE**: Build a backup with reacted messages, restore on Signal Android, verify reactions appear

### Task 2: Add Quote/Reply Mapping
- **ACTION**: Map Desktop `messages.json → quote` to `StandardMessage.quote`
- **IMPLEMENT**: Parse `msg_json.get("quote")` → create `Quote(targetSentTimestamp, authorId, text, attachments)`
- **MIRROR**: FRAME_BUILDER_PATTERN
- **IMPORTS**: None new
- **GOTCHA**: `quote.author` is a serviceId, needs `ids.service_id_to_recipient` lookup. Quote attachments need separate `FilePointer` handling.
- **VALIDATE**: Restore backup, verify reply threads display correctly

### Task 3: Add Link Preview Mapping
- **ACTION**: Map Desktop `messages.json → preview[]` to `StandardMessage.linkPreview`
- **IMPLEMENT**: Parse `msg_json.get("preview", [])` → create `LinkPreview(url, title, description, image FilePointer)`
- **MIRROR**: FRAME_BUILDER_PATTERN
- **GOTCHA**: Preview image is an attachment — needs `encrypt_attachment()` flow if image file exists
- **VALIDATE**: Restore backup, verify link previews render with thumbnails

### Task 4: Add Sticker Message Mapping
- **ACTION**: Map Desktop sticker messages to `StickerMessage`
- **IMPLEMENT**: Detect `msg_json.get("sticker")`, create `StickerMessage(packId, packKey, stickerId, data FilePointer, emoji)`
- **MIRROR**: FRAME_BUILDER_PATTERN
- **GOTCHA**: Sticker data file path differs from regular attachments; packId/packKey are hex strings
- **VALIDATE**: Restore backup, verify stickers display

### Task 5: Add Body Ranges (Formatting)
- **ACTION**: Map Desktop `bodyRanges[]` to `Text.bodyRanges`
- **IMPLEMENT**: Parse `msg_json.get("bodyRanges", [])` → create `BodyRange(start, length, style/mentionAci)`
- **MIRROR**: Extend existing Text mapping in `build_chat_item()`
- **GOTCHA**: Mention ranges reference ACI UUIDs that must exist as recipients; bold/italic/spoiler are style enums
- **VALIDATE**: Restore backup, verify bold/italic/mentions render

### Task 6: Add View-Once Message Mapping
- **ACTION**: Map Desktop view-once messages to `ViewOnceMessage`
- **IMPLEMENT**: Detect `msg_json.get("isViewOnce")`, create `ViewOnceMessage` with attachment if present
- **MIRROR**: FRAME_BUILDER_PATTERN
- **GOTCHA**: View-once attachments may already be deleted from Desktop; map what's available
- **VALIDATE**: Restore backup, verify view-once messages appear (as expired if media gone)

### Task 7: Add Disappearing Message Timer Updates
- **ACTION**: Map timer change messages to `ChatUpdateMessage.expirationTimerChange`
- **IMPLEMENT**: Detect `msg_json.get("flags") == 2` or `expirationTimerUpdate`, create `ExpirationTimerChatUpdate(expiresInMs)`
- **MIRROR**: FRAME_BUILDER_PATTERN
- **GOTCHA**: Timer values in Desktop are in seconds, v2 frames use milliseconds
- **VALIDATE**: Restore backup, verify timer change events display

### Task 8: Add Group Update Messages
- **ACTION**: Map Desktop group update messages to `ChatUpdateMessage.groupChange`
- **IMPLEMENT**: Detect `msg_json.get("group_update")`, create appropriate `GroupChangeChatUpdate` with member additions/removals/title changes
- **MIRROR**: FRAME_BUILDER_PATTERN
- **GOTCHA**: Desktop stores these differently than Android; may need to map multiple update subtypes. Consider mapping as `GenericGroupUpdate` with a description string if full structured mapping is too complex.
- **VALIDATE**: Restore backup, verify group update messages display

### Task 9: Add Call History Mapping
- **ACTION**: Map Desktop call records to `IndividualCall` / `GroupCall`
- **IMPLEMENT**: Detect `msg_json.get("callHistoryDetails")`, create `IndividualCall(callId, type, direction, state, timestamp)` or `GroupCall`
- **MIRROR**: FRAME_BUILDER_PATTERN
- **GOTCHA**: Call types: audio/video; states: missed/accepted/declined. Group calls have different structure.
- **VALIDATE**: Restore backup, verify call history entries display

### Task 10: Integration Tests for Mapper
- **ACTION**: Create `tests/test_mapper.py` with fixture data
- **IMPLEMENT**: Create JSON fixtures representing Desktop DB rows for each message type; test each `build_*` function returns correct Frame structure
- **MIRROR**: TEST_PATTERN from test_roundtrip.py
- **IMPORTS**: `pytest`, mapper functions
- **GOTCHA**: Need realistic Desktop JSON structure — extract sample rows from actual DB or Molly reference code
- **VALIDATE**: `pytest tests/test_mapper.py -v` passes

---

## Testing Strategy

### Unit Tests

| Test | Input | Expected Output | Edge Case? |
|------|-------|----------------|------------|
| `test_build_reaction` | Message JSON with reactions array | Frame with StandardMessage.reactions populated | Empty reactions array |
| `test_build_quote` | Message JSON with quote object | Frame with StandardMessage.quote populated | Quote from unknown author |
| `test_build_link_preview` | Message JSON with preview array | Frame with linkPreview list | Preview without image |
| `test_build_sticker` | Message JSON with sticker object | StickerMessage frame | Missing sticker data file |
| `test_build_body_ranges` | Message JSON with bodyRanges | Text with formatting ranges | Mention to unknown recipient |
| `test_build_view_once` | Message JSON with isViewOnce=true | ViewOnceMessage frame | Expired view-once (no media) |
| `test_build_timer_update` | Timer change message | ExpirationTimerChatUpdate | Timer set to 0 (disabled) |
| `test_build_group_update` | Group update message | GroupChangeChatUpdate | Multiple changes in one message |
| `test_build_call` | Call history message | IndividualCall frame | Missed call, group call |
| `test_full_mapping_roundtrip` | Desktop DB fixture | Valid MappingResult → encrypt → decrypt → verify | Empty DB, DB with only groups |

### Edge Cases Checklist
- [ ] Empty message body (attachment-only messages)
- [ ] Messages from unknown/deleted contacts
- [ ] Reactions from contacts not in conversations table
- [ ] Quotes referencing deleted messages
- [ ] Group messages from non-member senders
- [ ] Unicode emoji in reactions
- [ ] Very large attachments (>100MB)
- [ ] Messages with multiple attachment types
- [ ] Concurrent group updates in same timestamp

---

## Validation Commands

### Static Analysis
```bash
python3 -m py_compile signal_ark/mapper.py
```
EXPECT: Zero syntax errors

### Unit Tests
```bash
pytest tests/ -v
```
EXPECT: All tests pass

### Full Build Test
```bash
signal-ark build --seed-dir <seed> --passphrase <aep> --desktop-db <db> --attachments-dir <att> --self-aci <aci> -o /tmp/test-build
```
EXPECT: Build completes, stats show all message types mapped

### Verification (Phase 7)
```bash
signal-ark verify /tmp/test-build/signal-backup-*/
```
EXPECT: All checks pass

---

## Acceptance Criteria
- [ ] All Phase 5 message types mapped (reactions, quotes, links, stickers, calls, body ranges, view-once, timer updates, group updates)
- [ ] Integration tests for each message type
- [ ] Backup builds successfully with all message types
- [ ] Signal Android restores the enriched backup without errors
- [ ] Mapped message types render correctly on phone

## Completion Checklist
- [ ] Code follows FRAME_BUILDER_PATTERN
- [ ] Error handling: skip unrecognized types, log warning, continue
- [ ] Tests follow TEST_PATTERN
- [ ] No hardcoded values (field names, enum values from proto)
- [ ] Stats dict updated with counts per message type
- [ ] README updated with supported message types

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Desktop JSON schema varies across versions | Medium | High | Test with multiple Desktop DB snapshots; handle missing fields gracefully |
| v2 proto changes in future Signal updates | Low | High | Pin proto version; monitor Signal Android releases |
| Attachment encryption incompatibility | Low | Critical | Roundtrip test every attachment type; verify HMAC on decrypt |
| Molly bug #733 blocks Molly users | High | Medium | Monitor issue; document Signal Android as recommended restore target |
| Message ordering wrong after adding new types | Medium | High | Sort all ChatItems by received timestamp globally; add ordering test |

## Notes

### Competitive Positioning
- **bepaald/signalbackup-tools** is the closest competitor (1,312 stars, C++, actively maintained). It handles v1 format comprehensively but does NOT support v2. signal-ark's v2 support is a clear differentiator.
- **signal-export** (728 stars) is the go-to for Desktop→readable export. signal-ark should match its export quality in Phase 6 while also offering the unique backup-creation capability.
- **sigtop** (543 stars) overlaps with signal-export for Desktop reading. Both are read-only.
- The iOS gap is real but requires jailbreak or iTunes backup access — high effort, niche audience. Defer to Phase 9+.

### Desktop JSON Structure Reference
Key fields in `messages.json` to map (from Signal Desktop source):
- `reactions`: `[{emoji, fromId, targetTimestamp, receivedAtDate}]`
- `quote`: `{id (timestamp), authorUuid, text, attachments[]}`
- `preview`: `[{url, title, description, image (attachment)}]`
- `sticker`: `{packId, packKey, stickerId, data (attachment)}`
- `bodyRanges`: `[{start, length, style?, mentionUuid?}]`
- `isViewOnce`: boolean
- `expirationTimerUpdate`: `{expireTimer, source}`
- `group_update`: `{changes: [{type, ...}]}`
- `callHistoryDetails`: `{callId, callMode, wasIncoming, wasVideoCall, ...}`
