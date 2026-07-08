# Plan: TUI Wizard

## Summary
Add a step-by-step terminal user interface (TUI) wizard to signal-ark using `textual`. The TUI guides non-CLI users through backup workflows (build from Desktop, import v1, decrypt/inspect) with file browsing, input validation, progress tracking, and result summaries. It is a thin UI layer over existing signal_ark functions — no business logic is duplicated.

## User Story
As a Signal user unfamiliar with CLI tools,
I want a guided interactive wizard,
So that I can build or convert backups without memorizing command flags.

## Problem -> Solution
CLI requires knowing exact flags and paths -> Step-by-step wizard with file browser, validation, and progress feedback.

## Metadata
- **Complexity**: Medium
- **Source PRD**: N/A
- **PRD Phase**: N/A (roadmap item)
- **Estimated Files**: 7 new + 3 modified

---

## UX Design

### Before
```
$ signal-ark build --seed-dir ... --passphrase ... --desktop-db ... \
    --attachments-dir ... --self-aci ... -o ...
# User must know all flags, paths, and their ACI UUID
```

### After
```
$ signal-ark tui
┌─────────────────────────────────────┐
│         signal-ark wizard           │
│                                     │
│  What would you like to do?         │
│  (●) Build backup from Desktop      │
│  ( ) Import v1 backup to v2         │
│  ( ) Decrypt and inspect backup     │
│                                     │
│  [ Next ]                           │
└─────────────────────────────────────┘
```

### Interaction Changes
| Touchpoint | Before | After | Notes |
|---|---|---|---|
| Starting a build | Remember 6 CLI flags | Step-by-step guided wizard | File browser for paths |
| Passphrase entry | Visible in shell history | Masked input with toggle | More secure |
| Progress | click.echo lines | Live progress bars + log | Visual feedback |
| Results | Terminal text | Formatted summary + copyable adb commands | Actionable |

---

## Mandatory Reading

| Priority | File | Lines | Why |
|---|---|---|---|
| P0 (critical) | `signal_ark/cli.py` | all | All commands and parameters to mirror |
| P1 (important) | `signal_ark/mapper.py` | 327-332 | MappingResult dataclass pattern |
| P1 (important) | `signal_ark/kdf.py` | 34-39 | validate_aep for input validation |
| P1 (important) | `signal_ark/encrypt.py` | 70-95 | write_backup_directory signature |
| P2 (reference) | `signal_ark/metadata.py` | 13-28 | Frozen dataclass pattern |
| P2 (reference) | `pyproject.toml` | all | Dependency and entry point patterns |

---

## Patterns to Mirror

### CLI_DEFERRED_IMPORT
// SOURCE: signal_ark/cli.py:114-115
Heavy dependencies imported inside function body, not at module top.

### FROZEN_DATACLASS
// SOURCE: signal_ark/metadata.py:13-28
Frozen dataclasses for structured data. WizardState is mutable (exception — TUI state accumulates across screens).

### BUILD_COMMAND_FLOW
// SOURCE: signal_ark/cli.py:113-171
validate_aep -> aep_to_backup_key -> decrypt_metadata -> decrypt_main -> parse_frames -> map_desktop_to_frames -> write_backup_directory. Worker functions replicate this exact sequence.

---

## Files to Change

| File | Action | Justification |
|---|---|---|
| `signal_ark/tui/__init__.py` | CREATE | Package init with `launch()` entry point |
| `signal_ark/tui/app.py` | CREATE | Main App class, WizardState, screen routing |
| `signal_ark/tui/screens.py` | CREATE | All 5 wizard screens |
| `signal_ark/tui/widgets.py` | CREATE | PassphraseInput, PathBrowserModal |
| `signal_ark/tui/worker.py` | CREATE | Async worker wrappers for signal_ark functions |
| `signal_ark/tui/signal_ark.tcss` | CREATE | Textual CSS stylesheet |
| `tests/test_tui.py` | CREATE | TUI tests using textual pilot |
| `signal_ark/cli.py` | UPDATE | Add `tui` command |
| `pyproject.toml` | UPDATE | Add `[project.optional-dependencies] tui` |
| `README.md` | UPDATE | Document TUI installation and usage |

## NOT Building

- Web UI (future phase)
- Electron/Tauri wrapper
- Custom themes or color scheme configuration
- Drag-and-drop file support (terminal limitation)
- Clipboard integration beyond textual's built-in

---

## Step-by-Step Tasks

### Task 1: Add textual as optional dependency
- **ACTION**: Add `[project.optional-dependencies]` to pyproject.toml
- **IMPLEMENT**: `tui = ["textual>=1.0.0"]` under optional-dependencies. Add `"textual-dev>=1.0.0"` and `"pytest-asyncio>=0.23.0"` to dev group.
- **MIRROR**: Standard PEP 621 optional dependency pattern
- **GOTCHA**: `textual` must NOT be in main `dependencies` — CLI users shouldn't need it
- **VALIDATE**: `uv sync --extra tui` installs textual. `uv sync` alone does not.

### Task 2: Create TUI package with launch() entry point
- **ACTION**: Create `signal_ark/tui/__init__.py` with conditional import
- **IMPLEMENT**: `launch()` function tries to import `SignalArkApp` from `.app`, catches `ImportError` and exits with install hint
- **MIRROR**: `cli.py` deferred import pattern
- **VALIDATE**: `python -c "from signal_ark.tui import launch"` succeeds

### Task 3: Add `tui` CLI command
- **ACTION**: Add Click command to `signal_ark/cli.py`
- **IMPLEMENT**: `@main.command() def tui(): from signal_ark.tui import launch; launch()`
- **MIRROR**: Same deferred-import pattern as `build` command
- **VALIDATE**: `uv run signal-ark tui --help` works. Without textual, shows install hint.

### Task 4: Create App class and WizardState
- **ACTION**: Create `signal_ark/tui/app.py` with SignalArkApp and WizardState
- **IMPLEMENT**: `WizardState` mutable dataclass with fields matching CLI options (seed_dir, passphrase, desktop_db, etc.). `SignalArkApp(App)` with CSS_PATH, SCREENS dict, on_mount pushes WelcomeScreen, keybindings for quit/back.
- **MIRROR**: `metadata.py` dataclass pattern (but mutable for TUI state)
- **GOTCHA**: WizardState must be mutable — screens update it progressively
- **VALIDATE**: App launches and quits with `q`

### Task 5: Create Textual CSS stylesheet
- **ACTION**: Create `signal_ark/tui/signal_ark.tcss`
- **IMPLEMENT**: Signal-blue (#3A76F0) accent, dark background, layout rules for vertical wizard flow, button styling, input field styling, progress bar colors
- **VALIDATE**: Stylesheet loads without parse errors when app launches

### Task 6: Implement WelcomeScreen
- **ACTION**: Add to `signal_ark/tui/screens.py`
- **IMPLEMENT**: ASCII art header, RadioSet with 3 mode options (build/import_v1/inspect), Next button. On Next: set wizard_state.mode, push InputScreen.
- **VALIDATE**: Three options render, selection works, Next transitions to InputScreen

### Task 7: Implement PassphraseInput widget
- **ACTION**: Add to `signal_ark/tui/widgets.py`
- **IMPLEMENT**: Compound widget: Input(password=True) + toggle Button. Toggle swaps password visibility. Exposes .value property.
- **VALIDATE**: Typing shows dots, toggle reveals/hides text

### Task 8: Implement PathBrowserModal
- **ACTION**: Add to `signal_ark/tui/widgets.py`
- **IMPLEMENT**: ModalScreen with DirectoryTree, path Input, Select/Cancel buttons. Constructor takes `is_file: bool`. Returns selected path on dismiss.
- **VALIDATE**: Modal shows filesystem, selecting path returns it to caller

### Task 9: Implement InputScreen
- **ACTION**: Add to `signal_ark/tui/screens.py`
- **IMPLEMENT**: Dynamic form based on wizard_state.mode. Build mode: 6 fields (seed_dir, passphrase, desktop_db, attachments_dir, self_aci, output_dir). Import v1: 5 fields. Inspect: 2 fields. Each path field has Browse button. Validation on Next: check non-empty, validate AEP via `kdf.validate_aep()`, check paths exist. Inline error display.
- **MIRROR**: AEP validation from `kdf.py:34-39`, path validation mirrors Click `exists=True`
- **GOTCHA**: Must handle all three modes with different field sets
- **VALIDATE**: Each mode shows correct fields, validation catches errors

### Task 10: Implement PreviewScreen
- **ACTION**: Add to `signal_ark/tui/screens.py`
- **IMPLEMENT**: On mount, run lightweight preview in textual Worker: validate AEP, decrypt metadata, count conversations/messages/attachments via SQL COUNTs. Display stats table, input summary, Start/Back buttons. Disable Start on error.
- **MIRROR**: SQL count queries from `mapper.py`, decrypt flow from `cli.py:117-128`
- **GOTCHA**: Preview must not modify any files — read-only operations only
- **VALIDATE**: Shows accurate counts, bad passphrase shows error

### Task 11: Create worker functions
- **ACTION**: Create `signal_ark/tui/worker.py`
- **IMPLEMENT**: `run_build(state, on_progress, on_log) -> MappingResult`, `run_inspect(state, on_progress, on_log) -> dict`, `run_preview(state) -> dict[str, int]`. Each wraps existing signal_ark functions with progress callbacks. Synchronous (textual workers run in threads).
- **MIRROR**: Each function's flow mirrors corresponding Click command from `cli.py`
- **VALIDATE**: Unit test with mock callbacks

### Task 12: Add progress callback to map_desktop_to_frames
- **ACTION**: Add optional `progress_callback` parameter to `mapper.py:map_desktop_to_frames`
- **IMPLEMENT**: `progress_callback: Callable[[str, int, int], None] | None = None`. Call after each conversation, every 100 messages, and each attachment. Only when not None.
- **MIRROR**: Backwards-compatible optional parameter
- **GOTCHA**: Call frequency — every 100 messages to avoid callback overhead on large backups
- **VALIDATE**: Existing tests still pass. Manual test with lambda prints progress.

### Task 13: Implement ProgressScreen
- **ACTION**: Add to `signal_ark/tui/screens.py`
- **IMPLEMENT**: Start worker in textual Worker thread. Show labeled ProgressBars (seed decryption, mapping, encryption, writing). RichLog for live output. Disable Back during execution. Auto-advance to ResultsScreen on completion. Error state on failure.
- **MIRROR**: Build command flow from `cli.py:113-171`
- **VALIDATE**: Progress bars advance, log messages appear, completion transitions to results

### Task 14: Implement ResultsScreen
- **ACTION**: Add to `signal_ark/tui/screens.py`
- **IMPLEMENT**: Success banner, stats table (from MappingResult.stats), output paths, pre-formatted adb push commands, New Wizard / Quit buttons.
- **MIRROR**: `cli.py:153-171` output format
- **VALIDATE**: Shows correct stats and paths, adb commands use actual output dir

### Task 15: Write TUI tests
- **ACTION**: Create `tests/test_tui.py` using textual pilot
- **IMPLEMENT**: Test WelcomeScreen radio options, InputScreen field rendering per mode, AEP validation, screen navigation, PassphraseInput toggle, preview with mocked data, progress with mocked worker.
- **MIRROR**: pytest with `pytest.mark.asyncio` for pilot tests
- **VALIDATE**: `uv run pytest tests/test_tui.py -v` passes headless

### Task 16: Update documentation
- **ACTION**: Update README.md with TUI section, update cli.py docstring, add tui to commands table
- **IMPLEMENT**: Installation (`pip install signal-ark[tui]`), usage (`signal-ark tui`), wizard flow description
- **VALIDATE**: README renders correctly, commands table includes tui

---

## Testing Strategy

### Unit Tests

| Test | Input | Expected Output | Edge Case? |
|---|---|---|---|
| WelcomeScreen renders | App launch | 3 radio options visible | |
| InputScreen build mode | mode="build" | 6 input fields | |
| InputScreen inspect mode | mode="inspect" | 2 input fields | |
| AEP validation | 63-char string | Validation error shown | Yes |
| PassphraseInput toggle | Click toggle | Password visibility changes | |
| Screen navigation | Next then Back | Returns to previous screen | |
| Worker progress | Mock build | Callbacks fire with phase names | |

### Edge Cases Checklist
- [ ] Missing textual dependency (graceful error)
- [ ] All fields empty (validation catches before submit)
- [ ] Invalid AEP format (validation error inline)
- [ ] Non-existent path (validation error inline)
- [ ] Bad passphrase (preview screen shows error, Start disabled)
- [ ] Terminal resize during operation (textual handles this)

---

## Validation Commands

### Install and Launch
```bash
uv sync --extra tui
uv run signal-ark tui
```
EXPECT: Wizard launches

### Without Textual
```bash
uv sync
uv run signal-ark tui
```
EXPECT: Clear error message about installing [tui] extra

### Unit Tests
```bash
uv run pytest tests/test_tui.py -v
```
EXPECT: All tests pass headless

### Full Test Suite
```bash
uv run pytest
```
EXPECT: No regressions

---

## Acceptance Criteria
- [ ] `pip install signal-ark[tui]` installs textual; `pip install signal-ark` does not
- [ ] `signal-ark tui` launches wizard
- [ ] Without textual: clear install error message
- [ ] All three modes show correct input fields
- [ ] AEP validation catches malformed passphrases
- [ ] File browser modal works for path selection
- [ ] Preview shows accurate stats
- [ ] Progress bars advance during build
- [ ] Results screen shows correct paths and adb commands
- [ ] Existing CLI commands unaffected
- [ ] TUI tests run headless via pilot

## Completion Checklist
- [ ] TUI is a thin layer — no duplicated business logic
- [ ] Optional dependency pattern correct
- [ ] All screens implemented and tested
- [ ] Worker functions mirror CLI command flow exactly
- [ ] mapper.py progress_callback is backwards-compatible
- [ ] Documentation updated

## Risks
| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| textual API changes | Low | Medium | Pin >=1.0.0, use only stable core widgets |
| Long operations block event loop | Medium | High | All heavy work in textual Worker threads |
| File browser terminal compatibility | Low | Low | Path inputs also accept direct text entry |
| Progress callback overhead | Low | Low | Call every 100 messages, not per-message |

## Notes
- The TUI depends on v1 import being implemented first (for the "Import v1" mode option)
- If v1 import isn't ready when TUI ships, disable that radio option with a "coming soon" note
- textual's pilot framework enables headless testing in CI without a terminal
- The only change to existing code is the optional progress_callback on map_desktop_to_frames
