# signal-ark: UI & Distribution Plan

## License

**AGPL-3.0-only.** Rationale:
- Signal itself is AGPL — community expectation for ecosystem tools
- We use Signal's protobuf schemas directly
- AGPL ensures any hosted version must share source
- Prevents someone wrapping this as a paid SaaS without contributing back

## Distribution

### Tier 1: PyPI (immediate)

```bash
pip install signal-ark
signal-ark decrypt --seed-dir ./backup --passphrase "..."
signal-ark build --seed-dir ./backup --desktop-db ./db.sqlite ...
```

- Publish as `signal-ark` on PyPI
- Requires Python 3.12+
- All deps (`cryptography`, `protobuf`, `click`) have wheels for all platforms
- Zero native compilation needed

### Tier 2: Standalone binaries (Phase 5)

- **PyInstaller** or **Nuitka** to produce single-file executables
- GitHub Releases with binaries for:
  - Linux x86_64 (AppImage)
  - Linux aarch64
  - macOS Apple Silicon (universal2)
  - macOS Intel
  - Windows x64 (.exe)
- CI matrix builds on GitHub Actions

### Tier 3: Package managers (Phase 6+)

- **Homebrew** tap for macOS/Linux: `brew install bearyjd/tap/signal-ark`
- **Flatpak** for Linux desktop (matches Signal Desktop Flatpak)
- **AUR** for Arch Linux
- **Scoop** or **winget** for Windows
- **Docker** image for headless/server use

## UI Architecture

### Phase A: TUI (Textual)

**Framework:** [Textual](https://textual.textualize.io/) — rich terminal UI, runs everywhere Python runs, no browser needed.

```
┌─ signal-ark ──────────────────────────────────────────────┐
│                                                           │
│  ┌─ Step 1: Seed Backup ──────────────────────────────┐   │
│  │  Path: [/sdcard/BackupMolly/.../signal-backup-...] │   │
│  │  Status: ✓ Found (main: 198K, metadata: 36B)       │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌─ Step 2: Account Entropy Pool ─────────────────────┐   │
│  │  AEP:  [________________________________]          │   │
│  │  Status: ✓ Valid (64 chars, BackupKey derived)      │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌─ Step 3: Desktop Data ─────────────────────────────┐   │
│  │  DB:   [/home/user/.../sql/db.sqlite]              │   │
│  │  Dir:  [/home/user/.../Signal/]                    │   │
│  │  Status: ✓ 78,403 messages, 2,470 conversations    │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌─ Step 4: Options ──────────────────────────────────┐   │
│  │  [x] 1:1 conversations                             │   │
│  │  [ ] Group conversations                            │   │
│  │  [x] Image attachments                              │   │
│  │  [ ] All attachment types                           │   │
│  │  [ ] Reactions & quotes                             │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌─ Step 5: Preview ──────────────────────────────────┐   │
│  │  Conversations to import:          240              │   │
│  │  Messages:                      36,657              │   │
│  │  Attachments:                    4,956              │   │
│  │  Estimated backup size:          ~580 MB            │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  [ Build Backup ]                      [ Cancel ]         │
│                                                           │
│  ┌─ Progress ─────────────────────────────────────────┐   │
│  │  ████████████████░░░░░░░░░░  62%  Encrypting...    │   │
│  │  Messages: 22,700 / 36,657                          │   │
│  │  Attachments: 3,100 / 4,956                         │   │
│  └────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
```

**Screens:**
1. **Welcome** — detect environment (adb connected? Desktop data found?)
2. **Setup** — wizard steps above (seed, AEP, desktop data, options)
3. **Preview** — conversation list with message counts, select which to include
4. **Build** — progress bars, live log
5. **Deploy** — offer to push to phone via adb, show restore instructions

**Key features:**
- Auto-detect Signal Desktop paths (Linux Flatpak, Linux native, macOS, Windows)
- Auto-detect seed backup on connected phone via adb
- Conversation browser — scroll through chats, preview messages before import
- Persistent config — remember paths between runs

### Phase B: Web UI (local-only)

**Framework:** FastAPI backend + vanilla HTML/CSS/JS frontend. No React/Vue — keep it simple and auditable.

**Architecture:**
```
signal-ark serve --port 8420
  → FastAPI app, binds to 127.0.0.1 ONLY
  → Static HTML/JS served from package
  → REST API for all operations
  → WebSocket for progress streaming
```

**Why local-only web UI?**
- Cross-platform without native UI frameworks
- Users can inspect network tab to verify no data leaves their machine
- Can be packaged as Tauri app later for native feel
- Accessible to non-technical users (no terminal needed)

**Screens:**
1. **Landing** — drag-and-drop zones for seed backup dir and Desktop data dir
2. **Auth** — paste AEP, derive keys, show confirmation (your name, profile)
3. **Browse** — conversation list with avatars, message counts, date ranges
4. **Select** — checkboxes for what to import, attachment options
5. **Build** — real-time progress with WebSocket updates
6. **Download** — download rebuilt backup as zip, or push to phone instructions

**Security measures:**
- Bind to `127.0.0.1` only — not `0.0.0.0`
- No telemetry, no analytics, no external requests
- AEP never sent to backend in URL params — always POST body
- Session-scoped keys, zeroed on exit
- CSP headers blocking all external resources

### Phase C: Desktop app (Tauri)

- Wrap the web UI in [Tauri](https://tauri.app/) for native distribution
- ~5MB download vs ~150MB for Electron
- Native file picker dialogs
- System tray for background operations
- Auto-update via GitHub Releases
- Signed binaries for macOS/Windows

## Conversation browser mockup (Web UI)

```
┌──────────────────────────────────────────────────────────────┐
│  signal-ark                              [Settings] [About]  │
├──────────────────┬───────────────────────────────────────────┤
│  Search...       │  Bryn Beary                               │
│                  │  ─────────────────────────────────────     │
│  ☑ Bryn Beary    │  Apr 19, 2026                             │
│    1,247 msgs    │                                           │
│    342 images    │  You: my phone just died                   │
│                  │                                 2:17 PM    │
│  ☑ Rob G         │                                           │
│    893 msgs      │  Bryn: oh no! what happened?               │
│    128 images    │                                 2:18 PM    │
│                  │                                           │
│  ☑ Jerry (Tank)  │  You: bricked itself during update         │
│    456 msgs      │                                 2:19 PM    │
│    67 images     │                                           │
│                  │  Bryn: Home on jam                         │
│  □ (select all)  │                                 2:35 PM    │
│                  │                                           │
│  ────────────    │                                           │
│  Selected: 3     │                                           │
│  Messages: 2,596 │                                           │
│  Attachments: 537│                                           │
├──────────────────┴───────────────────────────────────────────┤
│  [ ← Back ]                              [ Build Backup → ] │
└──────────────────────────────────────────────────────────────┘
```

## Implementation order

1. **Now:** CLI works, ship it (PyPI)
2. **Phase 5:** Cross-platform testing, standalone binaries, GitHub Releases
3. **Phase A:** TUI with Textual (2-3 days of work)
4. **Phase B:** Local web UI with FastAPI (1 week)
5. **Phase C:** Tauri wrapper (2-3 days once web UI exists)
6. **Tier 3:** Package manager submissions
