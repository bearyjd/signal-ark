"""Main TUI application and wizard state."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding


@dataclass
class WizardState:
    mode: str = ""
    seed_dir: Path | None = None
    passphrase: str = ""
    desktop_db: Path | None = None
    attachments_dir: Path | None = None
    self_aci: str = ""
    output_dir: Path | None = None
    v1_backup_path: Path | None = None
    v1_passphrase: str = ""
    preview_stats: dict[str, int] = field(default_factory=dict)
    result_stats: dict[str, int] = field(default_factory=dict)
    result_output_dir: Path | None = None
    result_files_dir: Path | None = None
    error: str = ""


class SignalArkApp(App):
    CSS_PATH = "signal_ark.tcss"
    TITLE = "signal-ark"
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.wizard_state = WizardState()

    def on_mount(self) -> None:
        from signal_ark.tui.screens import WelcomeScreen

        self.push_screen(WelcomeScreen())
