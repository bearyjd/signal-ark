"""TUI wizard for signal-ark. Requires the [tui] extra: pip install signal-ark[tui]."""

from __future__ import annotations


def launch() -> None:
    """Launch the TUI wizard."""
    try:
        from signal_ark.tui.app import SignalArkApp
    except ImportError:
        raise SystemExit(
            "The TUI requires the [tui] extra. Install with: pip install signal-ark[tui]"
        )
    app = SignalArkApp()
    app.run()
