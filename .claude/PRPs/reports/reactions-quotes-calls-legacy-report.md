# Implementation Report: Reactions, Quotes, Call History, and Legacy DB Support

## Summary
Added reactions and quote mapping, call history (individual + group) mapping, and legacy Desktop DB attachment fallback to the v2 backup mapper. All 4 items from the README "Not yet" list and CLAUDE.md open questions are now resolved.

## Assessment vs Reality

| Metric | Predicted (Plan) | Actual |
|---|---|---|
| Complexity | Medium | Medium |
| Confidence | 8/10 | 9/10 |
| Files Changed | 4 modified + 1 new | 3 modified + 1 new |

## Tasks Completed

| # | Task | Status | Notes |
|---|---|---|---|
| 1 | Reactions mapping | Complete | Extracts from msg_json["reactions"], maps fromId to recipient |
| 2 | Quote mapping | Complete | Extracts from msg_json["quote"], maps authorAci/authorUuid |
| 3 | Call history mapping | Complete | Individual + group calls, callsHistory table + JSON fallback |
| 4 | Legacy Desktop DB fallback | Complete | Auto-detects message_attachments table, falls back to JSON parsing |
| 5 | Update README | Complete | "Not yet" → "Supported" for reactions/quotes and call history |
| 6 | Update CLAUDE.md | Complete | Removed "Older Desktop DB support" open question |
| 7 | Write tests | Complete | 30 tests covering all new functionality |

## Validation Results

| Level | Status | Notes |
|---|---|---|
| Static Analysis (ruff) | Pass | Zero errors on changed files |
| Unit Tests | Pass | 30 new tests, all green |
| Full Suite | Pass | 78/78 tests pass (no regressions) |

## Files Changed

| File | Action | Lines |
|---|---|---|
| `signal_ark/mapper.py` | UPDATED | +140 / -10 |
| `tests/test_mapper.py` | CREATED | +290 |
| `README.md` | UPDATED | +2 / -2 |
| `CLAUDE.md` | UPDATED | +0 / -1 |

## Deviations from Plan
- Backup directory layout verification (item 3 from the original 4) was already confirmed correct in the previous session — no code change needed.
- Removed 6 pre-existing unused proto imports from mapper.py (Chat, ChatUpdateMessage, FilePointer, Group, Recipient, Text) that were accessed via field properties rather than direct instantiation.

## Issues Encountered
- None.

## Tests Written

| Test File | Tests | Coverage |
|---|---|---|
| `tests/test_mapper.py` | 30 tests | _resolve_recipient_id (4), reactions mapping (4), quote mapping (4), build_chat_item integration (4), call info lookup (3), build_call_item (6), _has_table (2), legacy attachments (3) |

## Next Steps
- [ ] Code review via `/code-review`
- [ ] Create PR via `/prp-pr`
