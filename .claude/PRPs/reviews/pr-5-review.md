# PR Review: #5 — feat: reactions, quotes, calls, legacy DB support, and libsignal validator gate

**Reviewed**: 2026-09-19
**Author**: bearyjd
**Branch**: feat/reactions-quotes-calls-legacy → main
**Head**: 3e3df97
**Decision**: REQUEST CHANGES

## Summary

Solid, well-tested change: the validator gate is correctly wired (Python owns crypto, Node sees plaintext only), the supply chain is clean, no secrets in history, and the attachment-locator fix is a real restore-correctness win. Two HIGH findings should land before merge — one is a guaranteed validator rejection on any real Desktop DB with a long quoted message, the other is a DB-controlled path escape that this PR widens. Everything else is a tracked follow-up.

## Findings

### CRITICAL
None

### HIGH

**H1. Quote text not capped at libsignal's 2 KiB limit** — `signal_ark/mapper.py:130-132`
libsignal enforces `MAX_BODY_LENGTH_FOR_QUOTE = 2*1024` bytes (`libsignal-ref/rust/message-backup/src/backup/chat/text.rs:56,67`); Android's own exporter trims quote bodies to fit (`ChatItemArchiveExporter.kt:1205`, `StringUtil.trimToFit`). Verified: a 2,048-byte quote body validates, 2,049 fails with `quote: text error: body was 2049 bytes (too long to be in a quote)`. Any real Desktop DB that quotes a long message will be rejected by this PR's own gate — and by Signal Android on restore. Fix: trim to 2,048 UTF-8 bytes on a codepoint boundary; add a test at the boundary.

**H2. DB-controlled attachment path can escape `attachments_dir`** — `signal_ark/mapper.py:835`
`src_path = attachments_dir / att["path"]` has no containment check; `../` sequences and absolute paths both escape (`pathlib` does not neutralise either). Pre-existing on `message_attachments.path`, but this PR widens the surface: `_collect_legacy_attachments` (`:625-659`) takes `path` from the `messages.json` blob, and on that path `localKey` is usually absent so the file is read and encrypted verbatim into the backup and `files/` store. A malicious/corrupt Desktop DB can therefore copy arbitrary readable local files into the user's backup. Not code execution, hence HIGH not CRITICAL. Fix: reject absolute paths and require `src_path.resolve().is_relative_to(attachments_dir.resolve())`; count rejections in `stats`.

### MEDIUM

**M1. Decrypted backup plaintext written to the system temp dir during validation** — `signal_ark/validate.py:110-113`
`NamedTemporaryFile` is 0600 and deletion is guaranteed on every path (verified incl. `TimeoutExpired`), but the full plaintext frame stream lands in `tempfile.gettempdir()` — a disk write of decrypted Signal data on non-tmpfs `/tmp`. Recommend stdin (`readFileSync(0)` in `validate.mjs`, `input=plaintext` in `subprocess.run`), or a caller-controlled `dir=`. Matters more once `signal-ark verify` runs this against real backups.

**M2. Group-message attachments are collected but can never bind** — `mapper.py:606-656`, `:834-863`
Attachment collectors filter on `m.type` only, while chats exist only for `type='private'` (`:783`). Step 7 encrypts group media, writes it to `files/`, appends to `media_names`, and bumps `stats["attachments"]` before knowing a target frame exists → orphaned manifest entries and inflated stats on any real DB with group media. The validator structurally cannot see this. Suggest asserting `set(media_names) == {sha256(ph||localKey) for every locator}` in the e2e suite. Adjacent to the documented group-chat gap.

**M3. `dateSent` fallback in `_find_attachment_target` can misbind** — `mapper.py:1034-1043`
Now only reachable when the exact message-id lookup misses, i.e. when the correct target does not exist. It then scans all frames and can bind a skipped/group message's attachment to an unrelated 1:1 message with the same `sent_at`. Recommend returning `None` when `messageId` is present but absent from the index.

**M4. Long-text attachments mapped as file attachments** — `mapper.py:1118`
Desktop stores >2 KiB bodies as `text/x-signal-plain` attachments; Android routes those to `StandardMessage.longText` with the body trimmed (`ChatItemArchiveExporter.kt:1141-1168`). The mapper appends them to `attachments[]`, so they restore as a file next to a truncated body. Validator passes, so this is unnoticed. Note libsignal's `LongTextWithoutBody`/`TooLongBodyForLongText` rules when fixing.

**M5. README inaccuracies in rows this PR touches** — `README.md:129`, `:144`
"Group text messages: Supported" is false — `build` skips all group messages (PR body admits it). Known Issue "falls back to file hash… wrong for encrypted" is stale — `encrypt_attachment` now decrypts before hashing and counts DB disagreement. "Call history: Supported" is 1:1-only in practice.

**M6. Unguarded `localKey` base64 decode** — `mapper.py:839` (via `_b64_to_bytes` `:68-71`)
The PR guards `_remote_attachment_key` and `_db_hash_disagrees` (credit), but `_b64_to_bytes(att.get("localKey"))` is unguarded: one malformed row aborts the whole build with a traceback. Same for `int()` on `quote.id` (`:130`), `size` (`:840`), call `timestamp` (`:534`).

**M7. Decrypt failure silently swallowed** — `mapper.py:976-977`
`except Exception: return None` with no stat or log. Pre-existing, but with the new drop sweep the message now vanishes into `skipped_messages` with no diagnostic. Add an `attachment_failures` counter.

**M8. Bare enum ints** — `mapper.py:420-437`, `:499-502`, `:144`
`_CALL_TYPES`/`_*_CALL_STATES`, `_individual_call_state` returning literal `3`/`2`, `quote.type = 1`. Generated proto enums exist (`IndividualCall.Type.AUDIO_CALL`, `Quote.Type.NORMAL`). Pattern is pre-existing; scale is new.

### LOW

- `tests/test_validate.py:30` `pytestmark = validator` over-marks: the two `ValidatorUnavailable` tests don't need Node, but `-m "not validator"` deselects them; `test_validate_backup_dir_wrong_aci_raises_value_error` takes the fixture but raises before reaching Node.
- `SIGNAL_ARK_REQUIRE_VALIDATOR=1` without Node yields ERRORs (fixture `pytest.fail`) rather than FAILs — exit code is non-zero, so the gate works.
- Error-text assertions (`"no record for chat"`, `"mediaRootBackupKey"`) are libsignal displaydoc strings; the exact 0.103.0 pin is the mitigation.
- `validate.mjs:62` silently skips zero-length messages; `_read_varint` in `decrypt.py` and the Node parser disagree on trailing-partial-varint handling (Node stricter).
- `mapper.py:602` `_has_column` f-string `PRAGMA table_info({table_name})`; sole caller is a literal. Suggest an allowlist assert.
- `validate.py:126-128` puts the ACI in a `ValueError`; libsignal errors interpolate IDs/counts, not message content. Don't route `.error` into shipped logs.
- `_attach_file_pointer_to_message` `media_name` param unused (`mapper.py:1097`); `_collect_legacy_attachments` `msg_json.get("attachments", [])` crashes on JSON `null` (`:635`); `_map_reactions` `r.get("timestamp", 0)` → `None` raises on proto assign (`:100`); `build_self_recipient` writes `ids.service_id_to_recipient` directly (`:167`).
- `map_desktop_to_frames` grew ~175→~211 lines; `mapper.py` at 1,121 lines (pre-existing overage, package split tracked in `.agent_native/agent_roadmap.md` item 5).

## Verified clean

- **subprocess**: `shell=False`, argv list, `purpose` allow-listed in `validate.mjs`; plaintext never in argv/env/logs; `process.exitCode` used.
- **Supply chain**: exact `@signalapp/libsignal-client@0.103.0` in manifest and lockfile, sha512 integrity on all 3 packages; transitive deps `node-gyp-build@4.8.4` + `type-fest@4.41.0` only; install script is a benign `echo`; only 3 files tracked under `tools/validator/`; `node_modules/` ignored.
- **Randomness/key size**: `os.urandom(64)` = 32 AES + 32 HMAC, matching Signal's attachment key.
- **mediaName/sharding**: `sha256(plaintext_hash || local_key).hexdigest()[:2]` — no DB-controlled component.
- **Secrets in history**: full `git log -p origin/main..HEAD` grep for 64-char strings, UUIDs, `+1XXXXXXXXXX`; no file under `work/` ever added; only hits are libsignal's published test vectors (already on `main`) and obvious fixtures.
- **Cross-cutting stats/ordering**: message-id index consumed in step 7, frames removed in step 8, chat folders appended after; `messages -= dropped` cannot go negative (`test_stats_messages_matches_emitted_chat_items`). Referenced-before-referencing, received-order ChatItems, ChatFolders-last all survive the drop sweep.
- **v1_to_v2.py**: only the `EncryptedAttachment` NamedTuple unpacking changed; `tests/test_v1_to_v2.py` green.
- **Fixtures**: synthetic AEP, `bytes(range(32))`, `os.urandom(32)`; no `work/` references.

## Validation Results

| Check | Result |
|---|---|
| Type check | Skipped (no mypy/pyright config) |
| Lint | Informational — ruff not configured; PR files 24 → 19 findings vs `main` (no regression) |
| Tests | Pass — `SIGNAL_ARK_REQUIRE_VALIDATOR=1 uv run pytest` → 165 passed |
| Node syntax | Pass — `node --check tools/validator/validate.mjs` |
| Build | Skipped (no build step) |

## Files Reviewed

Source: `signal_ark/mapper.py` (M), `signal_ark/v1_to_v2.py` (M), `signal_ark/validate.py` (A)
Validator: `tools/validator/package.json` (A), `tools/validator/package-lock.json` (A), `tools/validator/validate.mjs` (A)
Tests: `tests/conftest.py` (A), `tests/test_validate.py` (A), `tests/test_mapper.py` (A), `tests/test_mapper_e2e.py` (A), `tests/test_synthetic_seed.py` (A), `tests/helpers/__init__.py` (A), `tests/helpers/synthetic_seed.py` (A), `tests/test_attachments.py` (M)
Config/docs: `.gitignore` (M), `CLAUDE.md` (M), `README.md` (M), `pyproject.toml` (M), `.agent_native/agent_roadmap.md` (A), `.claude/PRPs/**` (A, not reviewed)
