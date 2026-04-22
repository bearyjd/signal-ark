"""Tests for the TUI wizard using textual's pilot framework."""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from textual.widgets import Button, Input, RadioSet

from signal_ark.tui.app import SignalArkApp, WizardState
from signal_ark.tui.widgets import PassphraseInput


@pytest.fixture
def wizard_state() -> WizardState:
    return WizardState()


class TestWizardState:
    def test_defaults(self, wizard_state: WizardState) -> None:
        assert wizard_state.mode == ""
        assert wizard_state.seed_dir is None
        assert wizard_state.passphrase == ""
        assert wizard_state.desktop_db is None
        assert wizard_state.preview_stats == {}
        assert wizard_state.result_stats == {}

    def test_mutable(self, wizard_state: WizardState) -> None:
        wizard_state.mode = "build"
        assert wizard_state.mode == "build"


@pytest.mark.asyncio
async def test_app_launches() -> None:
    app = SignalArkApp()
    async with app.run_test() as pilot:
        assert app.title == "signal-ark"
        assert app.wizard_state.mode == ""


@pytest.mark.asyncio
async def test_welcome_screen_has_radio_options() -> None:
    app = SignalArkApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        radio = app.screen.query_one(RadioSet)
        assert radio is not None
        buttons = list(radio.query("RadioButton"))
        assert len(buttons) == 3


@pytest.mark.asyncio
async def test_welcome_next_sets_build_mode() -> None:
    app = SignalArkApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#welcome-next")
        assert app.wizard_state.mode == "build"


@pytest.mark.asyncio
async def test_welcome_quit_exits() -> None:
    app = SignalArkApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#welcome-quit")


@pytest.mark.asyncio
async def test_input_screen_build_mode_fields() -> None:
    app = SignalArkApp()
    async with app.run_test(size=(100, 60)) as pilot:
        await pilot.pause()
        await pilot.click("#welcome-next")
        await pilot.pause()
        inputs = list(app.screen.query(Input))
        input_ids = [i.id for i in inputs if i.id]
        assert "input-seed-dir" in input_ids
        assert "input-desktop-db" in input_ids
        assert "input-attachments-dir" in input_ids
        assert "input-self-aci" in input_ids
        assert "input-output-dir" in input_ids


@pytest.mark.asyncio
async def test_input_screen_inspect_mode_fields() -> None:
    app = SignalArkApp()
    async with app.run_test(size=(100, 60)) as pilot:
        await pilot.pause()
        radio = app.screen.query_one(RadioSet)
        buttons = list(radio.query("RadioButton"))
        buttons[1].toggle()
        await pilot.pause()
        await pilot.click("#welcome-next")
        await pilot.pause()
        assert app.wizard_state.mode == "inspect"
        input_ids = [i.id for i in app.screen.query(Input) if i.id]
        assert "input-seed-dir" in input_ids
        assert "input-desktop-db" not in input_ids


@pytest.mark.asyncio
async def test_input_validation_empty_seed_dir() -> None:
    app = SignalArkApp()
    async with app.run_test(size=(100, 60)) as pilot:
        await pilot.pause()
        await pilot.click("#welcome-next")
        await pilot.pause()
        await pilot.click("#input-next")
        await pilot.pause()
        from signal_ark.tui.screens import InputScreen
        assert isinstance(app.screen, InputScreen)


@pytest.mark.asyncio
async def test_passphrase_input_toggle() -> None:
    app = SignalArkApp()
    async with app.run_test(size=(100, 60)) as pilot:
        await pilot.pause()
        await pilot.click("#welcome-next")
        await pilot.pause()
        pp = app.screen.query_one(PassphraseInput)
        inner_input = pp.query_one(Input)
        assert inner_input.password is True
        toggle = pp.query_one(Button)
        await pilot.click(toggle)
        await pilot.pause()
        assert inner_input.password is False


@pytest.mark.asyncio
async def test_input_back_returns_to_welcome() -> None:
    app = SignalArkApp()
    async with app.run_test(size=(100, 60)) as pilot:
        await pilot.pause()
        await pilot.click("#welcome-next")
        await pilot.pause()
        await pilot.click("#input-back")
        await pilot.pause()
        radio = app.screen.query_one(RadioSet)
        assert radio is not None
