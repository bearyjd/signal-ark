# Agent-Native Roadmap for signal-ark

Goal: an AI coding agent should be able to take a raw bug report or feature
request and autonomously reproduce, implement, test, and verify it with
minimal human input. This document audits the gaps that currently force a
human into the loop, ranked by **Human-Attention-Saved per Unit of Effort**
(HAS/UoE) — cheap fixes that remove a recurring manual step rank above
expensive fixes that remove a rare one.

Scope note: `libsignal-ref/`, `molly-ref/`, and `Signal-Android-ref/` are
third-party reference clones checked out for source lookup only (proto
definitions, KDF constants, restore-side behavior). They are not part of
this project's code, are not audited here, and must never be edited.

---

## Top 5 — immediately actionable

### 1. Add `work/` to `.gitignore` (effort: trivial, risk removed: severe) — DONE

**Status:** `work/` is now in `.gitignore` alongside `__pycache__/`. Verified: `git check-ignore -v work` matches `.gitignore:2:work/`.

**Problem:** `signalbackup/.gitignore` currently only ignores `__pycache__/`.
`work/` holds a **real, decrypted Signal backup** — a real seed backup
directory, decrypted Desktop SQLite databases, and a built output tree with
~250 real encrypted attachment files. It is untracked today only because
no one has run `git add -A` yet. An autonomous agent staging a broad commit
(`git add .` / `git add -A`) would leak real message content and media into
git history — unrecoverable once pushed.

**Files:** `.gitignore`

**Change:**
```gitignore
__pycache__/
work/
```

**Acceptance criteria:**
- `git status --short` shows `work/` as ignored (`git check-ignore -v work` returns a match).
- `git add -A && git status` never lists anything under `work/`.

---

### 2. Build a synthetic v2 seed-backup generator (effort: medium, unlocks: bug repro for `decrypt`/`build`/`inspect`) — DONE

**Status:** `tests/helpers/synthetic_seed.py` added — `synthetic_seed_dir()` builds a real on-disk `metadata` + `main` pair via `signal_ark.encrypt.write_backup_directory` / `signal_ark.metadata.write_metadata` (production code paths, no parallel encoder). `tests/test_synthetic_seed.py` proves round-trip through `decrypt_main`/`parse_frames`, and reproduces the exact "inspect crashes on empty AccountData" scenario from the problem statement via `CliRunner` against the `inspect` command — previously impossible without a real device backup. CLAUDE.md's "Reference material" section now points to the helper. `uv run pytest` (99 tests, was 96) all pass.

**Problem:** There is currently no way to construct a valid encrypted v2
seed-backup directory (`metadata` + `main`) without a real phone backup.
`work/seed/` has one real example, but per the privacy constraint it cannot
be copied into fixtures. This means an agent handed a bug report like
"`inspect` crashes on a backup with an empty `AccountData`" has no way to
build a minimal repro — it would need a human to hand over a real backup.

**Files to add:** `tests/helpers/synthetic_seed.py` (new module; keep it out
of `tests/__init__.py` re-exports so it stays an opt-in helper, not a
fixture-by-default)

**What it should do:** given a passphrase/AEP, an ACI, and a list of
`Frame` protos (reuse `signal_ark.encrypt.serialize_frames`,
`encrypt_main`, and `signal_ark.metadata`'s writer), produce a real
on-disk `metadata` + `main` pair using the exact same code paths as
`signal-ark build` — i.e. call the production `encrypt.py`/`metadata.py`
functions, don't hand-roll a parallel encoder. Should return a
`tmp_path`-friendly directory plus the AEP/ACI used, so a test or an agent
script can immediately feed it to `signal-ark decrypt`/`inspect`.

**Acceptance criteria:**
- New `tests/test_synthetic_seed.py` proves `synthetic_seed_dir(...)` output round-trips through `signal_ark.decrypt.decrypt_main` + `parse_frames`.
- At least one existing gap test (e.g. an `inspect` edge case) is rewritten to use the generator instead of being skipped/impossible.
- CLAUDE.md's "Reference material" section gets a one-line pointer to this helper (done as part of this audit — see CLAUDE.md diff).

---

### 3. Add CLI-level integration tests (effort: medium, coverage gained: 5 commands, 0 → covered)

**Problem:** `signal_ark/cli.py` (419 lines, 5 commands: `decrypt`, `build`,
`inspect`, `dump-v1`, `import-v1`, plus `tui`) has **zero** direct test
coverage — no test imports `click.testing.CliRunner` or shells out to the
CLI. All existing tests call internal functions (`map_desktop_to_frames`,
`decrypt_main`, etc.) directly. A regression in argument wiring, exit
codes, or the `inspect` command's ~130 lines of inline validation logic
(`cli.py:175-304`, not extracted into a testable function) would pass every
existing test suite while being completely broken for a real user.

**Files:** new `tests/test_cli.py`; depends on item 2 for a fixture that
produces both a synthetic seed dir and a synthetic Desktop SQLite DB (the
latter already exists inline in `tests/test_mapper_e2e.py` — extract it to
a shared factory rather than duplicating it a third time).

**Acceptance criteria:**
- `CliRunner` invocations of `decrypt`, `build`, and `inspect` chained together (build synthetic seed + synthetic Desktop DB → `build` → `inspect` the result) pass with exit code 0 and no reported issues.
- `inspect`'s validation logic is extracted into `signal_ark/inspect.py` (or similar) as plain functions returning structured results, with the CLI command reduced to formatting/printing — this makes it independently unit-testable, not just testable through stdout scraping.

---

### 4. Consolidate/document the recipient-mapping duplication (effort: medium, prevents: silent divergence bugs)

**Problem:** Recipient/contact/group mapping is implemented **twice**:
`mapper.py` (`build_contact_recipient`, `build_group_recipient`, used by
the Desktop → v2 `build` path) and `v1_to_v2.py`
(`_map_recipients_modern`, `_map_recipients_legacy`, used by the v1 →
v2 `import-v1` path). Nothing in CLAUDE.md documents this; an agent fixing
"group avatar color wrong" in one path has no signal that the same bug
likely exists in the other, un-mapped path.

**Files:** `signal_ark/mapper.py`, `signal_ark/v1_to_v2.py`

**Recommended fix:** extract a shared `signal_ark/recipients.py` with the
common "conversation JSON → Recipient frame" logic, parameterized over the
differences between Desktop's modern schema and v1's legacy schema, and
have both `mapper.py` and `v1_to_v2.py` call into it.

**Acceptance criteria:**
- A single test (parameterized) validates contact/group recipient field mapping once, exercised through both call paths.
- CLAUDE.md documents the shared module and states explicitly: "recipient/contact/group mapping changes must be verified against both the Desktop-build path and the v1-import path" (added in this pass — see CLAUDE.md diff).

---

### 5. Split `mapper.py` into a package (effort: medium-high, structural)

**Problem:** `mapper.py` is 896 lines — over the repo's own 800-line/file
ceiling (`~/.claude/rules/common/coding-style.md`) — and mixes five
concerns: `IdAllocator`/recipient allocation, chat building, chat-item
(message/reaction/quote) building, call-item building, and Desktop
attachment encrypt/decrypt. An agent asked to fix a call-history bug has to
load and reason about all 896 lines to find the ~90 lines that matter.

**Files:** `signal_ark/mapper.py` → `signal_ark/mapping/{__init__.py, recipients.py, chats.py, calls.py, attachments.py}`

**Acceptance criteria:**
- No behavior change: `uv run pytest` passes unmodified (only import paths change).
- Each new file is under ~400 lines and has a single clear responsibility matching this doc's breakdown.
- Public API re-exported from `signal_ark/mapping/__init__.py` so `from signal_ark.mapper import map_desktop_to_frames` callers (cli.py, tests) keep working, or all call sites are updated in the same change.

---

## Audit detail by area

### 1. Human-judgment chokepoints (tribal knowledge not yet codified)

- **Ref-repo consultation is undocumented.** CLAUDE.md lists
  `Signal-Android-ref/`, `libsignal-ref/`, `molly-ref/` as "checked-out
  reference repos" but gives no guidance on *when* or *how* to consult
  them. In practice: proto field ambiguity → grep `Signal-Android-ref` for
  the Kotlin/Java model that reads the field; KDF/crypto constant or
  behavior question → grep `libsignal-ref`'s Rust backup crate; Molly-specific
  restore quirks → `molly-ref`. This is now spelled out in CLAUDE.md.
- **The "Open questions" section (files/ layout) has no experiment path.**
  It states the ambiguity but not how an agent could resolve it (e.g. by
  reading `Signal-Android-ref`'s restore/import code for the expected path
  layout, or by testing both layouts against a Molly restore in a sandbox).
- **Recipient-mapping duplication** (detailed in item 4 above) is invisible
  tribal knowledge — only visible by having read both files.
- **`work/` contains real backup data** and is excluded from `.gitignore`
  only by omission — a human "just knows" not to touch it; an agent has no
  signal short of this audit.

### 2. Verification gaps (missing tests for agent self-verification)

- No `conftest.py` and no shared fixtures anywhere in `tests/` — every file
  hand-builds its own synthetic `sqlite3` Desktop DB inline.
  `tests/test_mapper.py` and `tests/test_mapper_e2e.py` both construct
  overlapping `conversations`/`messages` schemas independently (541 + 451
  lines combined), which is both duplication and a source of drift if the
  schema assumptions diverge between the two files.
- No test invokes the CLI layer at all (detailed in item 3).
- No test exercises the full on-disk `build` output (files manifest +
  sharded `files/XX/` + `main` + `metadata` written to disk) followed by an
  `inspect` pass — `test_roundtrip.py` only covers the in-memory
  serialize/encrypt/decrypt cycle for two frames, not the directory-writing
  side of `encrypt.py` that `build_and_write` — style functions perform.
- `inspect`'s attachment-verification logic (decrypt sample attachment,
  verify HMAC, verify plaintext hash/size) lives only inside the CLI
  command body and is untested by anything other than manual runs against
  `work/` (real data, not CI-safe).

### 3. Reproduction paths (missing generators/replay harnesses)

- No synthetic v2 seed-backup generator (item 2) — blocks reproducing any
  bug in `decrypt`/`build`/`inspect` without a real device backup.
- No synthetic v1 `.backup` file generator exposed as a reusable utility —
  `tests/test_v1_parser.py` builds v1 frames via ad hoc calls into internal
  encoding helpers rather than a documented "build a fake v1 backup file"
  factory. An agent debugging an `import-v1` bug report ("crashes on
  backups with `recipient_preferences` but no `recipient` table") has to
  reverse-engineer the test file's approach rather than call a supported
  helper.
- The synthetic Desktop DB builders in `test_mapper_e2e.py` aren't
  parameterized or exposed as a factory function — they're private to that
  test module, so an agent can't cheaply construct "same DB but with schema
  variant X" for a new repro without copy-pasting ~80 lines of table DDL.

### 4. Structural obstacles

- `mapper.py` at 896 lines exceeds the project's own file-size convention
  and bundles five distinct concerns (item 5).
- Recipient/contact/group mapping duplicated between `mapper.py` and
  `v1_to_v2.py` with no shared abstraction (item 4).
- `inspect`'s validation logic is inlined in the CLI layer instead of being
  a reusable, independently testable library function.
- No `ruff`/`mypy` config exists despite `mypy-protobuf` being a dev
  dependency — that dependency only generates typed proto stubs at proto
  regeneration time, it is not a project-wide type checker. There is
  currently no automated lint/type-check gate an agent can run to
  self-verify style/type correctness before declaring work done; consider
  adding `ruff` (lint) and `mypy` (type check, or `pyright`) as dev
  dependencies with a documented `uv run ruff check .` / `uv run mypy
  signal_ark` command in CLAUDE.md once introduced.
