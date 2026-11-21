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
async def test_welcome_import_v1_radio_enabled() -> None:
    app = SignalArkApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        buttons = list(app.screen.query_one(RadioSet).query("RadioButton"))
        assert not buttons[2].disabled


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


# --- Cancel button on the progress screen ---


def test_run_build_cancelled_before_start_writes_nothing(tmp_path) -> None:
    import threading

    from signal_ark.tui.worker import Cancelled, run_build

    out = tmp_path / "out"
    out.mkdir()
    state = WizardState(mode="build", output_dir=out)
    cancel = threading.Event()
    cancel.set()

    with pytest.raises(Cancelled):
        run_build(state, on_log=lambda _m: None, cancel=cancel)

    assert list(out.iterdir()) == []


def test_run_inspect_cancelled_raises(tmp_path) -> None:
    import threading

    from signal_ark.tui.worker import Cancelled, run_inspect

    cancel = threading.Event()
    cancel.set()
    with pytest.raises(Cancelled):
        run_inspect(WizardState(mode="inspect"), on_log=lambda _m: None, cancel=cancel)


@pytest.mark.asyncio
async def test_progress_cancel_button_enabled_and_sets_flag() -> None:
    from signal_ark.tui.screens import ProgressScreen

    app = SignalArkApp()
    async with app.run_test() as pilot:
        screen = ProgressScreen()
        # mode unset: no worker is started, so only the button/flag are exercised
        await app.push_screen(screen)
        await pilot.pause()
        button = screen.query_one("#progress-cancel", Button)
        assert button.disabled is False
        assert not screen.cancel_event.is_set()
        await pilot.click("#progress-cancel")
        await pilot.pause()
        assert screen.cancel_event.is_set()


def _build_state(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    seed = tmp_path / "seed"
    seed.mkdir()
    return WizardState(
        mode="build",
        output_dir=out,
        seed_dir=seed,
        passphrase="x",
        desktop_db=tmp_path / "db.sqlite",
        attachments_dir=tmp_path / "att",
    )


def _patch_build_deps(monkeypatch, map_fn):
    """Stub the crypto/seed steps so run_build reaches the mapping stage."""
    import types

    from signal_ark import decrypt, kdf, metadata
    from signal_ark import encrypt
    from signal_ark.mapping import map_desktop_to_frames as _real  # noqa: F401
    import signal_ark.mapping as mapping_pkg

    class _Frame:
        def HasField(self, _name):
            return True

    seed = types.SimpleNamespace(frames=[_Frame()], backup_info=object())
    monkeypatch.setattr(kdf, "validate_aep", lambda p: p)
    monkeypatch.setattr(kdf, "aep_to_backup_key", lambda a: b"k")
    monkeypatch.setattr(kdf, "backup_key_to_message_backup_key", lambda k, i: (b"h", b"a"))
    monkeypatch.setattr(
        metadata, "decrypt_metadata", lambda *_a: types.SimpleNamespace(backup_id=b"i", version=1)
    )
    monkeypatch.setattr(decrypt, "decrypt_main", lambda *_a: b"")
    monkeypatch.setattr(decrypt, "parse_frames", lambda _p: seed)
    monkeypatch.setattr(mapping_pkg, "map_desktop_to_frames", map_fn)
    written = []
    monkeypatch.setattr(encrypt, "write_backup_directory", lambda **kw: written.append(kw))
    return written


def test_run_build_cancel_during_mapping_removes_new_files_dir(tmp_path, monkeypatch) -> None:
    import threading
    import types

    from signal_ark.tui.worker import Cancelled, run_build

    state = _build_state(tmp_path)
    (state.seed_dir / "main").write_bytes(b"")
    cancel = threading.Event()

    def fake_map(**kw):
        d = kw["output_files_dir"]
        d.mkdir(parents=True)
        (d / "new.bin").write_bytes(b"1")
        cancel.set()  # cancel arrives while mapping runs
        return types.SimpleNamespace(stats={}, media_names=[], backup_info=None, frames=[])

    written = _patch_build_deps(monkeypatch, fake_map)
    with pytest.raises(Cancelled):
        run_build(state, on_log=lambda _m: None, cancel=cancel)

    assert not (state.output_dir / "files").exists()
    assert written == []  # checkpoint after mapping: nothing written


def test_run_build_cancel_keeps_preexisting_attachments(tmp_path, monkeypatch) -> None:
    import threading
    import types

    from signal_ark.tui.worker import Cancelled, run_build

    state = _build_state(tmp_path)
    (state.seed_dir / "main").write_bytes(b"")
    files = state.output_dir / "files"
    files.mkdir()
    (files / "old.bin").write_bytes(b"old")
    cancel = threading.Event()

    def fake_map(**kw):
        d = kw["output_files_dir"]
        (d / "new.bin").write_bytes(b"1")
        cancel.set()
        return types.SimpleNamespace(stats={}, media_names=[], backup_info=None, frames=[])

    _patch_build_deps(monkeypatch, fake_map)
    with pytest.raises(Cancelled):
        run_build(state, on_log=lambda _m: None, cancel=cancel)

    assert (files / "old.bin").read_bytes() == b"old"
    assert not (files / "new.bin").exists()


def test_run_build_not_cancelled_writes_backup(tmp_path, monkeypatch) -> None:
    import threading
    import types

    from signal_ark.tui.worker import run_build

    state = _build_state(tmp_path)
    (state.seed_dir / "main").write_bytes(b"")

    def fake_map(**kw):
        return types.SimpleNamespace(stats={"a": 1}, media_names=[], backup_info=None, frames=[])

    written = _patch_build_deps(monkeypatch, fake_map)
    run_build(state, on_log=lambda _m: None, cancel=threading.Event())
    assert len(written) == 1


def test_run_inspect_cancel_between_steps(tmp_path, monkeypatch) -> None:
    import threading
    import types

    from signal_ark import decrypt, kdf, metadata
    from signal_ark.tui.worker import Cancelled, run_inspect

    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "main").write_bytes(b"")
    cancel = threading.Event()
    monkeypatch.setattr(kdf, "validate_aep", lambda p: p)
    monkeypatch.setattr(kdf, "aep_to_backup_key", lambda a: b"k")
    monkeypatch.setattr(kdf, "backup_key_to_message_backup_key", lambda k, i: (b"h", b"a"))

    def fake_meta(*_a):
        cancel.set()  # user cancels during the metadata step
        return types.SimpleNamespace(backup_id=b"i", version=1)

    monkeypatch.setattr(metadata, "decrypt_metadata", fake_meta)
    parsed = []
    monkeypatch.setattr(decrypt, "decrypt_main", lambda *_a: parsed.append(1) or b"")
    with pytest.raises(Cancelled):
        run_inspect(
            WizardState(mode="inspect", seed_dir=seed, passphrase="x"),
            on_log=lambda _m: None,
            cancel=cancel,
        )
    assert parsed == []  # stopped before the seed decrypt step


async def _run_progress(monkeypatch, fake_run_build):
    import signal_ark.tui.worker as worker
    from signal_ark.tui.screens import ProgressScreen

    monkeypatch.setattr(worker, "run_build", fake_run_build)
    app = SignalArkApp()
    app.wizard_state.mode = "build"
    return app, ProgressScreen()


@pytest.mark.asyncio
async def test_worker_cancel_does_not_crash_app(monkeypatch) -> None:
    from textual.widgets import Static

    from signal_ark.tui.worker import Cancelled

    def fake(state, on_log, cancel=None):
        assert cancel.wait(5)
        raise Cancelled("Cancelled by user")

    app, screen = await _run_progress(monkeypatch, fake)
    async with app.run_test() as pilot:
        await app.push_screen(screen)
        await pilot.pause()
        await pilot.click("#progress-cancel")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert app.is_running
        assert str(screen.query_one("#progress-title", Static).render()) == "Cancelled"
        assert screen.query_one("#progress-quit", Button).disabled is False


@pytest.mark.asyncio
async def test_worker_real_error_after_cancel_is_shown(monkeypatch) -> None:
    from textual.widgets import Static

    def fake(state, on_log, cancel=None):
        assert cancel.wait(5)
        raise RuntimeError("disk exploded")

    app, screen = await _run_progress(monkeypatch, fake)
    async with app.run_test() as pilot:
        await app.push_screen(screen)
        await pilot.pause()
        await pilot.click("#progress-cancel")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert str(screen.query_one("#progress-title", Static).render()) == "Failed"
        log = "\n".join(str(line) for line in screen.query_one("#progress-log").lines)
        assert "disk exploded" in log
        assert "No backup was written" not in log


@pytest.mark.asyncio
async def test_worker_success_despite_cancel_pushes_results(monkeypatch) -> None:
    from signal_ark.tui.screens import ResultsScreen

    def fake(state, on_log, cancel=None):
        assert cancel.wait(5)
        return {"a": 1}  # build had already passed its last checkpoint

    app, screen = await _run_progress(monkeypatch, fake)
    async with app.run_test() as pilot:
        await app.push_screen(screen)
        await pilot.pause()
        await pilot.click("#progress-cancel")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert isinstance(app.screen, ResultsScreen)
        log = "\n".join(str(line) for line in screen.query_one("#progress-log").lines)
        assert "completed before it could be cancelled" in log


def test_run_build_cancel_before_mapping_never_maps(tmp_path, monkeypatch) -> None:
    import threading

    from signal_ark import decrypt
    from signal_ark.tui.worker import Cancelled, run_build

    state = _build_state(tmp_path)
    (state.seed_dir / "main").write_bytes(b"")
    cancel = threading.Event()
    mapped = []
    _patch_build_deps(monkeypatch, lambda **kw: mapped.append(1))
    orig = decrypt.parse_frames

    def parse_then_cancel(p):
        cancel.set()  # user cancels while the seed is being parsed
        return orig(p)

    monkeypatch.setattr(decrypt, "parse_frames", parse_then_cancel)
    with pytest.raises(Cancelled):
        run_build(state, on_log=lambda _m: None, cancel=cancel)
    assert mapped == []
    assert list(state.output_dir.iterdir()) == []


def test_run_inspect_cancel_after_decrypt_skips_parse(tmp_path, monkeypatch) -> None:
    import threading
    import types

    from signal_ark import decrypt, kdf, metadata
    from signal_ark.tui.worker import Cancelled, run_inspect

    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "main").write_bytes(b"")
    cancel = threading.Event()
    monkeypatch.setattr(kdf, "validate_aep", lambda p: p)
    monkeypatch.setattr(kdf, "aep_to_backup_key", lambda a: b"k")
    monkeypatch.setattr(kdf, "backup_key_to_message_backup_key", lambda k, i: (b"h", b"a"))
    monkeypatch.setattr(
        metadata, "decrypt_metadata", lambda *_a: types.SimpleNamespace(backup_id=b"i", version=1)
    )
    monkeypatch.setattr(decrypt, "decrypt_main", lambda *_a: cancel.set() or b"")
    parsed = []
    monkeypatch.setattr(decrypt, "parse_frames", lambda _p: parsed.append(1))
    with pytest.raises(Cancelled):
        run_inspect(
            WizardState(mode="inspect", seed_dir=seed, passphrase="x"),
            on_log=lambda _m: None,
            cancel=cancel,
        )
    assert parsed == []


def test_run_build_cancel_after_metadata_skips_decrypt_main(tmp_path, monkeypatch) -> None:
    import threading

    from signal_ark import decrypt, kdf
    from signal_ark.tui.worker import Cancelled, run_build

    state = _build_state(tmp_path)
    (state.seed_dir / "main").write_bytes(b"")
    cancel = threading.Event()
    _patch_build_deps(monkeypatch, lambda **kw: None)
    # cancel arrives while the metadata step is finishing
    monkeypatch.setattr(
        kdf, "backup_key_to_message_backup_key", lambda k, i: cancel.set() or (b"h", b"a")
    )
    decrypted = []
    monkeypatch.setattr(decrypt, "decrypt_main", lambda *_a: decrypted.append(1) or b"")
    with pytest.raises(Cancelled):
        run_build(state, on_log=lambda _m: None, cancel=cancel)
    assert decrypted == []


def test_run_build_cancel_removes_new_symlink(tmp_path, monkeypatch) -> None:
    import threading
    import types

    from signal_ark.tui.worker import Cancelled, run_build

    state = _build_state(tmp_path)
    (state.seed_dir / "main").write_bytes(b"")
    files = state.output_dir / "files"
    files.mkdir()
    (files / "old.bin").write_bytes(b"old")
    target = tmp_path / "target_dir"
    target.mkdir()
    cancel = threading.Event()

    def fake_map(**kw):
        (kw["output_files_dir"] / "link").symlink_to(target)
        cancel.set()
        return types.SimpleNamespace(stats={}, media_names=[], backup_info=None, frames=[])

    _patch_build_deps(monkeypatch, fake_map)
    with pytest.raises(Cancelled):
        run_build(state, on_log=lambda _m: None, cancel=cancel)
    assert not (files / "link").is_symlink()
    assert target.exists()


# --- import_v1 -------------------------------------------------------------

_VALID_AEP = "a" * 64
_VALID_V1_PASS = "123456789012345678901234567890"


async def _open_v1_input(pilot, app):
    await pilot.pause()
    buttons = list(app.screen.query_one(RadioSet).query("RadioButton"))
    buttons[2].toggle()
    await pilot.pause()
    await pilot.click("#welcome-next")
    await pilot.pause()


def _fill_v1(app, tmp_path, **overrides):
    seed = tmp_path / "seed"
    seed.mkdir(exist_ok=True)
    v1 = tmp_path / "x.backup"
    v1.write_bytes(b"")
    values = {
        "#input-seed-dir": str(seed),
        "#input-v1-backup": str(v1),
        "#input-v1-passphrase-input": _VALID_V1_PASS,
        "#input-self-aci": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "#input-output-dir": str(tmp_path / "out"),
    }
    values.update(overrides)
    for sel, val in values.items():
        app.screen.query_one(sel, Input).value = val
    app.screen.query_one("#input-passphrase-input", Input).value = _VALID_AEP


@pytest.mark.asyncio
async def test_input_screen_import_v1_fields() -> None:
    app = SignalArkApp()
    async with app.run_test(size=(100, 80)) as pilot:
        await _open_v1_input(pilot, app)
        assert app.wizard_state.mode == "import_v1"
        ids = [i.id for i in app.screen.query(Input) if i.id]
        for want in ("input-seed-dir", "input-v1-backup", "input-v1-passphrase-input",
                     "input-self-aci", "input-output-dir"):
            assert want in ids
        assert "input-desktop-db" not in ids


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "override,message",
    [
        ({"#input-v1-backup": ""}, "v1 backup"),
        ({"#input-v1-backup": "/nonexistent/x.backup"}, "not found"),
        ({"#input-v1-passphrase-input": "123"}, "30 digits"),
        ({"#input-v1-passphrase-input": "x" * 30}, "digits"),
        ({"#input-self-aci": ""}, "ACI"),
        ({"#input-output-dir": ""}, "Output"),
    ],
)
async def test_import_v1_validation_errors(tmp_path, override, message) -> None:
    from textual.widgets import Static

    from signal_ark.tui.screens import InputScreen

    app = SignalArkApp()
    async with app.run_test(size=(100, 80)) as pilot:
        await _open_v1_input(pilot, app)
        _fill_v1(app, tmp_path, **override)
        app.screen._validate_and_proceed()
        await pilot.pause()
        assert isinstance(app.screen, InputScreen)
        assert message in str(app.screen.query_one("#input-error", Static).render())


@pytest.mark.asyncio
async def test_import_v1_valid_input_populates_state(tmp_path, monkeypatch) -> None:
    import signal_ark.tui.worker as worker
    from signal_ark.tui.screens import PreviewScreen

    monkeypatch.setattr(worker, "run_preview", lambda _s: {})

    app = SignalArkApp()
    async with app.run_test(size=(100, 80)) as pilot:
        await _open_v1_input(pilot, app)
        _fill_v1(app, tmp_path)
        app.screen._validate_and_proceed()
        await pilot.pause()
        assert isinstance(app.screen, PreviewScreen)
        st = app.wizard_state
        assert st.v1_backup_path == tmp_path / "x.backup"
        assert st.v1_passphrase == _VALID_V1_PASS
        assert st.output_dir == tmp_path / "out"


def _patch_v1_convert(monkeypatch, convert_fn):
    import signal_ark.v1_to_v2 as v1_to_v2

    written = _patch_build_deps(monkeypatch, lambda **kw: None)
    monkeypatch.setattr(v1_to_v2, "convert_v1_to_v2", convert_fn)
    return written


def _v1_state(tmp_path):
    state = _build_state(tmp_path)
    state.mode = "import_v1"
    state.v1_backup_path = tmp_path / "x.backup"
    state.v1_passphrase = _VALID_V1_PASS
    state.self_aci = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    (state.seed_dir / "main").write_bytes(b"")
    return state


def test_run_import_v1_writes_backup(tmp_path, monkeypatch) -> None:
    import threading
    import types

    from signal_ark.tui.worker import run_import_v1

    seen = {}

    def fake_convert(**kw):
        seen.update(kw)
        kw["progress_callback"]("messages", 3, 1)
        return types.SimpleNamespace(stats={"messages": 3}, media_names=[], backup_info=None, frames=[])

    written = _patch_v1_convert(monkeypatch, fake_convert)
    state = _v1_state(tmp_path)
    logs: list[str] = []
    stats = run_import_v1(state, on_log=logs.append, cancel=threading.Event())
    assert stats == {"messages": 3}
    assert len(written) == 1
    assert seen["v1_path"] == state.v1_backup_path
    assert seen["v1_passphrase"] == _VALID_V1_PASS
    assert seen["output_files_dir"] == state.output_dir / "files"
    assert any("messages" in m and "processed=3" in m for m in logs)
    assert state.result_output_dir == state.output_dir / "signal-backup-rebuilt"
    assert state.result_stats == {"messages": 3}


def test_run_import_v1_cancelled_before_start(tmp_path, monkeypatch) -> None:
    import threading

    from signal_ark.tui.worker import Cancelled, run_import_v1

    called = []
    _patch_v1_convert(monkeypatch, lambda **kw: called.append(1))
    state = _v1_state(tmp_path)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(Cancelled):
        run_import_v1(state, on_log=lambda _m: None, cancel=cancel)
    assert not called
    assert not (state.output_dir / "files").exists()


def test_run_import_v1_cancel_during_convert_discards_new_files(tmp_path, monkeypatch) -> None:
    import threading
    import types

    from signal_ark.tui.worker import Cancelled, run_import_v1

    state = _v1_state(tmp_path)
    cancel = threading.Event()
    files = state.output_dir / "files"

    def fake_convert(**kw):
        files.mkdir()
        (files / "new.bin").write_bytes(b"x")
        cancel.set()
        return types.SimpleNamespace(stats={}, media_names=[], backup_info=None, frames=[])

    written = _patch_v1_convert(monkeypatch, fake_convert)
    with pytest.raises(Cancelled):
        run_import_v1(state, on_log=lambda _m: None, cancel=cancel)
    assert not files.exists()
    assert not written


def test_run_build_forwards_mapping_progress_to_log(tmp_path, monkeypatch) -> None:
    import threading
    import types

    from signal_ark.tui.worker import run_build

    state = _build_state(tmp_path)
    (state.seed_dir / "main").write_bytes(b"")

    def fake_map(**kw):
        kw["progress_callback"]("messages mapped", 5, 1)
        return types.SimpleNamespace(stats={}, media_names=[], backup_info=None, frames=[])

    _patch_build_deps(monkeypatch, fake_map)
    logs: list[str] = []
    run_build(state, on_log=logs.append, cancel=threading.Event())

    assert "  [messages mapped] processed=5 skipped=1" in logs
