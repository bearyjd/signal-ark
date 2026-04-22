"""Custom TUI widgets for signal-ark."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, DirectoryTree, Input, Static


class PassphraseInput(Static):
    """Masked input with a show/hide toggle."""

    def __init__(
        self,
        placeholder: str = "",
        max_length: int = 0,
        *,
        id: str | None = None,
    ) -> None:
        super().__init__(id=id)
        self._placeholder = placeholder
        self._max_length = max_length

    def compose(self) -> ComposeResult:
        yield Input(
            placeholder=self._placeholder,
            password=True,
            max_length=self._max_length or 0,
            id=f"{self.id}-input" if self.id else None,
        )
        yield Button("Show", id=f"{self.id}-toggle" if self.id else None, variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        toggle_id = f"{self.id}-toggle" if self.id else None
        if toggle_id and event.button.id == toggle_id:
            inp = self.query_one(Input)
            inp.password = not inp.password
            event.button.label = "Hide" if not inp.password else "Show"
            event.stop()

    @property
    def value(self) -> str:
        return self.query_one(Input).value


class PathBrowserModal(ModalScreen[Path | None]):
    """File/directory browser modal."""

    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, initial: str = ".", is_file: bool = False) -> None:
        super().__init__()
        self._initial = initial
        self._is_file = is_file

    def compose(self) -> ComposeResult:
        yield Static("Select a path:", id="browser-title")
        yield Input(value=self._initial, id="browser-path")
        yield DirectoryTree(self._initial, id="browser-tree")
        with Horizontal(classes="button-row"):
            yield Button("Select", variant="primary", id="browser-select")
            yield Button("Cancel", variant="default", id="browser-cancel")

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self.query_one("#browser-path", Input).value = str(event.path)

    def on_directory_tree_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        if not self._is_file:
            self.query_one("#browser-path", Input).value = str(event.path)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "browser-select":
            path_str = self.query_one("#browser-path", Input).value
            self.dismiss(Path(path_str) if path_str else None)
        elif event.button.id == "browser-cancel":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
