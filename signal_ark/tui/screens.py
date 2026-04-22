"""Wizard screens for the signal-ark TUI."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Input, Label, RadioSet, RadioButton, RichLog, Static
from textual.worker import Worker, WorkerState

from signal_ark.tui.app import WizardState
from signal_ark.tui.widgets import PassphraseInput, PathBrowserModal


class WelcomeScreen(Screen):
    """Mode selection: build, inspect, or import v1."""

    def compose(self) -> ComposeResult:
        with Vertical(id="welcome-container"):
            yield Static("signal-ark", id="welcome-title")
            yield Static("Backup wizard", id="welcome-subtitle")
            with RadioSet(id="mode-select"):
                yield RadioButton("Build backup from Desktop", value=True)
                yield RadioButton("Decrypt and inspect backup")
                yield RadioButton("Import v1 backup (coming soon)", disabled=True)
            with Horizontal(classes="button-row"):
                yield Button("Next", variant="primary", id="welcome-next")
                yield Button("Quit", id="welcome-quit")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "welcome-quit":
            self.app.exit()
        elif event.button.id == "welcome-next":
            radio = self.query_one(RadioSet)
            idx = radio.pressed_index
            state: WizardState = self.app.wizard_state
            if idx == 0:
                state.mode = "build"
            elif idx == 1:
                state.mode = "inspect"
            else:
                state.mode = "import_v1"
            self.app.push_screen(InputScreen())


class InputScreen(Screen):
    """Collect paths and credentials based on selected mode."""

    def compose(self) -> ComposeResult:
        state: WizardState = self.app.wizard_state
        with Vertical(id="input-container"):
            yield Static(f"Mode: {state.mode}", id="input-title")
            yield Label("Seed backup directory:", classes="field-label")
            yield Input(placeholder="/path/to/seed", id="input-seed-dir")
            yield Button("Browse...", id="browse-seed-dir", variant="default")

            yield Label("Passphrase (64-char AEP):", classes="field-label")
            yield PassphraseInput(
                placeholder="Enter your 64-character passphrase",
                max_length=64,
                id="input-passphrase",
            )

            if state.mode == "build":
                yield Label("Desktop database:", classes="field-label")
                yield Input(placeholder="/path/to/db.sqlite", id="input-desktop-db")
                yield Button("Browse...", id="browse-desktop-db", variant="default")

                yield Label("Attachments directory:", classes="field-label")
                yield Input(placeholder="/path/to/attachments.noindex", id="input-attachments-dir")
                yield Button("Browse...", id="browse-attachments-dir", variant="default")

                yield Label("Your ACI UUID:", classes="field-label")
                yield Input(placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", id="input-self-aci")

                yield Label("Output directory:", classes="field-label")
                yield Input(placeholder="/path/to/output", id="input-output-dir")
                yield Button("Browse...", id="browse-output-dir", variant="default")

            yield Static("", id="input-error", classes="field-error")
            with Horizontal(classes="button-row"):
                yield Button("Back", id="input-back")
                yield Button("Next", variant="primary", id="input-next")

    def _browse(self, target_input_id: str, is_file: bool = False) -> None:
        current = self.query_one(f"#{target_input_id}", Input).value or "."

        def _on_result(path: Path | None) -> None:
            if path is not None:
                self.query_one(f"#{target_input_id}", Input).value = str(path)

        self.app.push_screen(PathBrowserModal(initial=current, is_file=is_file), _on_result)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "input-back":
            self.app.pop_screen()
        elif bid == "browse-seed-dir":
            self._browse("input-seed-dir")
        elif bid == "browse-desktop-db":
            self._browse("input-desktop-db", is_file=True)
        elif bid == "browse-attachments-dir":
            self._browse("input-attachments-dir")
        elif bid == "browse-output-dir":
            self._browse("input-output-dir")
        elif bid == "input-next":
            self._validate_and_proceed()

    def _validate_and_proceed(self) -> None:
        state: WizardState = self.app.wizard_state
        error_widget = self.query_one("#input-error", Static)
        error_widget.update("")

        seed_dir_str = self.query_one("#input-seed-dir", Input).value.strip()
        if not seed_dir_str:
            error_widget.update("Seed directory is required.")
            return
        seed_dir = Path(seed_dir_str)
        if not seed_dir.is_dir():
            error_widget.update(f"Seed directory not found: {seed_dir}")
            return

        passphrase = self.query_one(PassphraseInput).value.strip()
        if not passphrase:
            error_widget.update("Passphrase is required.")
            return

        try:
            from signal_ark.kdf import validate_aep
            validate_aep(passphrase)
        except (ValueError, SystemExit) as e:
            error_widget.update(f"Invalid passphrase: {e}")
            return

        state.seed_dir = seed_dir
        state.passphrase = passphrase

        if state.mode == "build":
            db_str = self.query_one("#input-desktop-db", Input).value.strip()
            if not db_str:
                error_widget.update("Desktop database path is required.")
                return
            db_path = Path(db_str)
            if not db_path.is_file():
                error_widget.update(f"Database not found: {db_path}")
                return

            att_str = self.query_one("#input-attachments-dir", Input).value.strip()
            if not att_str:
                error_widget.update("Attachments directory is required.")
                return
            att_path = Path(att_str)
            if not att_path.is_dir():
                error_widget.update(f"Attachments directory not found: {att_path}")
                return

            aci = self.query_one("#input-self-aci", Input).value.strip()
            if not aci:
                error_widget.update("ACI UUID is required.")
                return

            out_str = self.query_one("#input-output-dir", Input).value.strip()
            if not out_str:
                error_widget.update("Output directory is required.")
                return

            state.desktop_db = db_path
            state.attachments_dir = att_path
            state.self_aci = aci
            state.output_dir = Path(out_str)

        self.app.push_screen(PreviewScreen())


class PreviewScreen(Screen):
    """Show read-only preview stats before executing."""

    def compose(self) -> ComposeResult:
        with Vertical(id="preview-container"):
            yield Static("Preview", id="preview-title")
            yield Static("Validating inputs...", id="preview-stats")
            yield Static("", id="preview-error", classes="field-error")
            with Horizontal(classes="button-row"):
                yield Button("Back", id="preview-back")
                yield Button("Start", variant="primary", id="preview-start", disabled=True)

    def on_mount(self) -> None:
        self.run_worker(self._load_preview, thread=True)

    def _load_preview(self) -> dict[str, int]:
        from signal_ark.tui.worker import run_preview
        return run_preview(self.app.wizard_state)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state == WorkerState.SUCCESS:
            stats = event.worker.result
            state: WizardState = self.app.wizard_state
            state.preview_stats = stats

            lines = []
            for k, v in stats.items():
                lines.append(f"  {k}: {v}")
            summary = "\n".join(lines) if lines else "  (no stats available)"

            self.query_one("#preview-stats", Static).update(
                f"Mode: {state.mode}\n"
                f"Seed: {state.seed_dir}\n"
                + (f"Desktop DB: {state.desktop_db}\n" if state.desktop_db else "")
                + f"\n{summary}"
            )
            self.query_one("#preview-start", Button).disabled = False
        elif event.state == WorkerState.ERROR:
            err = str(event.worker.error) if event.worker.error else "Unknown error"
            self.query_one("#preview-error", Static).update(f"Error: {err}")
            self.query_one("#preview-stats", Static).update("Preview failed.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "preview-back":
            self.app.pop_screen()
        elif event.button.id == "preview-start":
            self.app.push_screen(ProgressScreen())


class ProgressScreen(Screen):
    """Execute the build/inspect and show live progress."""

    def compose(self) -> ComposeResult:
        with Vertical(id="progress-container"):
            yield Static("Running...", id="progress-title")
            yield RichLog(id="progress-log", wrap=True, markup=True)
            with Horizontal(classes="button-row"):
                yield Button("Cancel", id="progress-cancel", disabled=True)

    def on_mount(self) -> None:
        state: WizardState = self.app.wizard_state
        if state.mode == "build":
            self.run_worker(self._run_build, thread=True)
        elif state.mode == "inspect":
            self.run_worker(self._run_inspect, thread=True)

    def _log(self, msg: str) -> None:
        self.app.call_from_thread(self._append_log, msg)

    def _append_log(self, msg: str) -> None:
        self.query_one("#progress-log", RichLog).write(msg)

    def _run_build(self) -> dict[str, int]:
        from signal_ark.tui.worker import run_build
        return run_build(self.app.wizard_state, on_log=self._log)

    def _run_inspect(self) -> dict[str, int]:
        from signal_ark.tui.worker import run_inspect
        return run_inspect(self.app.wizard_state, on_log=self._log)

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state == WorkerState.SUCCESS:
            self.app.push_screen(ResultsScreen())
        elif event.state == WorkerState.ERROR:
            err = str(event.worker.error) if event.worker.error else "Unknown error"
            self._append_log(f"[bold red]ERROR:[/bold red] {err}")
            self.query_one("#progress-title", Static).update("Failed")


class ResultsScreen(Screen):
    """Show final results and next steps."""

    def compose(self) -> ComposeResult:
        state: WizardState = self.app.wizard_state
        with Vertical(id="results-container"):
            yield Static("Results", id="results-title")
            yield Static("Complete!", id="results-success")

            stats_lines = []
            for k, v in state.result_stats.items():
                stats_lines.append(f"  {k}: {v}")
            stats_text = "\n".join(stats_lines) if stats_lines else "  (no stats)"
            yield Static(f"Stats:\n{stats_text}", id="results-stats")

            if state.result_output_dir:
                yield Static(
                    f"\nOutput: {state.result_output_dir}\n"
                    f"Files:  {state.result_files_dir}\n"
                    f"\nadb push {state.result_output_dir} /sdcard/SignalBackups/\n"
                    f"adb push {state.result_files_dir} /sdcard/SignalBackups/files/",
                    id="results-paths",
                )

            with Horizontal(classes="button-row"):
                yield Button("New Wizard", variant="primary", id="results-new")
                yield Button("Quit", id="results-quit")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "results-quit":
            self.app.exit()
        elif event.button.id == "results-new":
            self.app.wizard_state = WizardState()
            self.app.pop_screen()
            self.app.pop_screen()
            self.app.pop_screen()
            self.app.pop_screen()
            self.app.push_screen(WelcomeScreen())
