"""The gateway must stop Electron's Crashpad handler from following it into children."""

from __future__ import annotations

import ctypes
import sys

import pytest

from kiro_crew import crashpad_inherit
from kiro_crew.crashpad_inherit import (
    CRASHPAD_MASKS,
    EXC_MASK_CRASH,
    EXC_MASK_RESOURCE,
    MACH_PORT_NULL,
    detach_inherited_crash_handler,
)


class _FakeLibc:
    """Records the Mach call instead of making it."""

    def __init__(self, kern_return: int = 0) -> None:
        self.calls: list[tuple] = []
        self._kr = kern_return
        self.mach_task_self = _Fn(lambda: 0x103)
        self.task_set_exception_ports = _Fn(self._set)

    def _set(self, task, mask, port, behavior, flavor):
        self.calls.append((task, mask, port, behavior, flavor))
        return self._kr


class _Fn:
    def __init__(self, fn):
        self._fn = fn
        self.restype = None
        self.argtypes = None

    def __call__(self, *a):
        return self._fn(*a)


def test_noop_off_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    loaded = []
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: loaded.append(a) or _FakeLibc())
    assert detach_inherited_crash_handler(platform="linux") is False
    assert detach_inherited_crash_handler(platform="win32") is False
    assert loaded == []


def test_clears_exactly_the_crashpad_masks_to_the_null_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    libc = _FakeLibc()
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: libc)
    assert detach_inherited_crash_handler(platform="darwin") is True
    assert len(libc.calls) == 1
    task, mask, port, behavior, flavor = libc.calls[0]
    assert task == 0x103
    assert mask == CRASHPAD_MASKS == EXC_MASK_CRASH | EXC_MASK_RESOURCE
    # Only the two masks Crashpad registers; a wider mask would also wipe any
    # port a debugger or the runtime itself installed.
    assert mask & ~(EXC_MASK_CRASH | EXC_MASK_RESOURCE) == 0
    assert port == MACH_PORT_NULL
    assert behavior == crashpad_inherit.EXCEPTION_DEFAULT
    assert flavor == crashpad_inherit.THREAD_STATE_NONE


def test_reports_failure_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: _FakeLibc(kern_return=4))
    assert detach_inherited_crash_handler(platform="darwin") is False

    def _boom(*a, **k):
        raise OSError("no libSystem")

    monkeypatch.setattr(ctypes, "CDLL", _boom)
    assert detach_inherited_crash_handler(platform="darwin") is False


@pytest.mark.skipif(sys.platform != "darwin", reason="reads this task's real Mach exception ports")
def test_real_task_ports_are_null_afterwards() -> None:
    libc = ctypes.CDLL("/usr/lib/libSystem.dylib", use_errno=True)
    libc.mach_task_self.restype = ctypes.c_uint32
    assert detach_inherited_crash_handler() is True
    masks = (ctypes.c_uint32 * 32)()
    ports = (ctypes.c_uint32 * 32)()
    behaviors = (ctypes.c_int32 * 32)()
    flavors = (ctypes.c_int32 * 32)()
    count = ctypes.c_uint32(32)
    kr = libc.task_get_exception_ports(
        libc.mach_task_self(), CRASHPAD_MASKS, masks, ctypes.byref(count), ports, behaviors, flavors
    )
    assert kr == 0
    for i in range(count.value):
        if masks[i] & CRASHPAD_MASKS:
            assert ports[i] == MACH_PORT_NULL
