"""The two Windows-only ``kiro_crew.hooks`` imports refuse rather than crash.

Both sit inside an ``os.name == "nt"`` branch, so the crash they would cause is reachable
only on Windows in the standalone venv the module documents -- the one environment where
``kiro_crew`` is not importable. A ``ModuleNotFoundError`` there escapes as an uncaught
traceback mid-build, past every handler that would have cleaned up.

Fail closed rather than skip, which is the opposite of the agent-spec fence. The difference
is what each question is for: the spec fence asks "is this path sensitive", which a coarse
local list can answer well enough to be worth asking. These ask "would resolving this path
reach a host over SMB", and an unanswerable version of that is not permission to resolve it
anyway.
"""

from __future__ import annotations

import builtins
import os
import pathlib

import pytest

from .test_producer import load_build


def _hide_hooks(monkeypatch) -> None:
    """Make ``kiro_crew.hooks`` unimportable without touching the rest of ``kiro_crew``.

    Narrower than clearing ``sys.modules``: the module under test also imports
    ``kiro_crew.security``, and hiding both would not distinguish which guard fired.
    """
    real_import = builtins.__import__

    def _fail(name, *args, **kwargs):
        if name == "kiro_crew.hooks" or name.endswith(".hooks"):
            raise ImportError("no module named 'kiro_crew.hooks' (simulated standalone venv)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fail)


def test_the_unc_gate_refuses_when_hooks_is_unimportable(
    tmp_path: pathlib.Path, monkeypatch
) -> None:
    """A ``file://`` prompt on Windows without ``kiro_crew.hooks`` is refused, not crashed."""
    mod = load_build()
    agents = tmp_path / "agents"
    agents.mkdir()
    (agents / "persona.md").write_text("You are the front desk.\n", encoding="utf-8")
    monkeypatch.setattr(mod.os, "name", "nt")
    _hide_hooks(monkeypatch)

    with pytest.raises(mod.ExportRefused) as caught:
        mod._resolve_prompt_path("file://persona.md", agents)
    message = str(caught.value)
    assert "kiro_crew.hooks is not importable" in message
    assert "UNC" in message


def test_the_refusal_names_what_the_operator_can_do(tmp_path: pathlib.Path, monkeypatch) -> None:
    """The message has to carry the way out, or it is a dead end with a nicer traceback."""
    mod = load_build()
    agents = tmp_path / "agents"
    agents.mkdir()
    (agents / "persona.md").write_text("You are the front desk.\n", encoding="utf-8")
    monkeypatch.setattr(mod.os, "name", "nt")
    _hide_hooks(monkeypatch)

    with pytest.raises(mod.ExportRefused) as caught:
        mod._resolve_prompt_path("file://persona.md", agents)
    message = str(caught.value)
    assert "Copy the persona next to the agent spec" in message
    assert "kiro_crew is installed" in message


def test_posix_never_reaches_the_import(tmp_path: pathlib.Path, monkeypatch) -> None:
    """The guard is inside the nt branch, so POSIX resolves normally without hooks.

    Without this, a guard that refused on every platform would pass the two tests above
    while breaking the standalone mode the module exists for.
    """
    mod = load_build()
    agents = tmp_path / "agents"
    agents.mkdir()
    (agents / "persona.md").write_text("You are the front desk.\n", encoding="utf-8")
    _hide_hooks(monkeypatch)

    resolved = mod._resolve_prompt_path("file://persona.md", agents)
    assert resolved.name == "persona.md"


def test_the_guard_only_covers_the_import_failure(tmp_path: pathlib.Path) -> None:
    """With ``kiro_crew.hooks`` present, an ordinary relative persona resolves.

    Left on POSIX deliberately. Forcing ``os.name = "nt"`` with the real hooks module in
    play sends it looking for a Windows home directory and it raises for that reason
    instead, so the assertion would be about the fixture rather than the guard.
    """
    mod = load_build()
    agents = tmp_path / "agents"
    agents.mkdir()
    (agents / "persona.md").write_text("You are the front desk.\n", encoding="utf-8")

    resolved = mod._resolve_prompt_path("file://persona.md", agents)
    assert resolved.name == "persona.md"
    assert resolved.parent == agents


def test_the_persona_bytes_are_read_through_the_guarded_path(tmp_path: pathlib.Path) -> None:
    """The resolved path is readable by the module's own reader, so the guards do not block it.

    Uses ``_read_text_nofollow`` rather than a plain ``read_text`` because that is the reader
    the prompt path actually uses -- checking the file with a different reader would say
    nothing about whether this one still reaches it.
    """
    mod = load_build()
    agents = tmp_path / "agents"
    agents.mkdir()
    (agents / "persona.md").write_text("You are the front desk.\n", encoding="utf-8")

    resolved = mod._resolve_prompt_path("file://persona.md", agents)
    assert "front desk" in mod._read_text_nofollow(resolved, agents)


def test_the_absolute_branch_is_covered_by_the_first_guard(
    tmp_path: pathlib.Path, monkeypatch
) -> None:
    """An absolute persona is refused too, by the gate at the top rather than a second guard.

    ``_resolve_prompt_path`` reaches ``kiro_crew.hooks`` twice on nt: the UNC gate for every
    prompt, and the redirect-chain walk for an ABSOLUTE path. Only the first needs a guard,
    because it runs unconditionally and refuses, so no call reaches the second with the
    import still failing. A guard was written there and removed: mutating it away left every
    test passing, which is what an unreachable guard looks like.

    This test is what keeps that reasoning honest. If someone moves the chain walk above the
    UNC gate, the absolute case stops being covered and this reddens.
    """
    mod = load_build()
    agents = tmp_path / "agents"
    agents.mkdir()
    persona = tmp_path / "personas" / "frontdesk.md"
    persona.parent.mkdir(parents=True)
    persona.write_text("You are the front desk.\n", encoding="utf-8")
    monkeypatch.setattr(mod.os, "name", "nt")
    _hide_hooks(monkeypatch)

    with pytest.raises(mod.ExportRefused) as caught:
        mod._resolve_prompt_path(f"file://{persona}", agents)
    assert "kiro_crew.hooks is not importable" in str(caught.value)


def test_only_one_hooks_import_needs_a_guard(tmp_path: pathlib.Path) -> None:
    """A source rule: exactly one guarded hooks import, and the bare one says why.

    No runtime test can show the second import is unreachable -- that is the point of it
    being unreachable -- so the fact is pinned by reading the source instead.
    """
    # Read the file by path rather than through ``mod.__file__``, which mypy types as
    # ``str | None`` -- and the sibling source-rule tests in this directory read it the
    # same way, so the two cannot drift.
    source = (pathlib.Path(__file__).parent.parent / "build.py").read_text(encoding="utf-8")
    assert source.count("from kiro_crew.hooks import") == 2, "the import count changed"
    assert source.count("except ImportError as exc:") == 1, (
        "a second ImportError guard appeared; if the chain walk can now be reached with the "
        "import failing, it needs a test that reddens, and if it cannot, it needs no guard"
    )
    assert "Imported bare, and that is deliberate" in source


def test_a_missing_agent_spec_is_not_reported_as_a_missing_prompt(
    tmp_path: pathlib.Path,
) -> None:
    """The shared reader has TWO consumers, and its refusals reach the operator verbatim.

    ``_read_text_nofollow`` serves the prompt path and the agent-spec read. Its refusals
    are worded for the caller, so a spec that is absent must say "agent spec": telling an
    operator a "prompt file" is missing sends them looking for a persona they never
    referenced, in a crew that has no prompt reference at all.

    This is the check a change to a shared function needs and that a direct unit test of
    that function does not give -- the wording only matters at the call sites.
    """
    mod = load_build()
    home = tmp_path / "home"
    (home / "agents").mkdir(parents=True)
    crew = mod.resolve_crew("frontdesk", home)

    with pytest.raises(mod.ExportRefused) as caught:
        mod.read_agent_spec(crew)
    message = str(caught.value)
    assert "prompt file" not in message, "the spec read borrowed the prompt path's wording"


def test_the_prompt_path_still_says_prompt_file(tmp_path: pathlib.Path) -> None:
    """The other consumer keeps its own wording, which is what makes the parameter useful.

    A default that said "agent spec" everywhere would pass the test above and move the
    confusion to the prompt path instead.
    """
    mod = load_build()
    agents = tmp_path / "agents"
    agents.mkdir()

    with pytest.raises(mod.ExportRefused) as caught:
        mod._read_text_nofollow(agents / "absent.md")
    assert "prompt file" in str(caught.value)


@pytest.mark.skipif(os.name != "posix", reason="needs symlink cycle semantics")
def test_a_symlink_cycle_is_refused_by_the_chain_walk(tmp_path: pathlib.Path) -> None:
    """A cycle never reaches ``resolve()``, so ``resolve()`` needs no try/except.

    ``_refuse_redirects_in_chain`` judges each component with ``lstat`` and refuses the
    FIRST redirect, so a -> b -> a is rejected at ``a`` with a message naming the link. A
    guard was added around ``resolve()`` for ELOOP and removed: this test showed the refusal
    already comes from the chain walk, which makes the ELOOP branch unreachable.

    Kept as the pin for that ordering. If the chain walk is ever moved below ``resolve()``,
    the cycle reaches it, this assertion fails, and the guard is warranted again.
    """
    mod = load_build()
    agents = tmp_path / "agents"
    agents.mkdir()
    a, b = agents / "a.md", agents / "b.md"
    a.symlink_to(b)
    b.symlink_to(a)

    with pytest.raises(mod.ExportRefused) as caught:
        mod._resolve_prompt_path("file://a.md", agents)
    message = str(caught.value)
    assert "is a link or junction" in message, (
        "the cycle was not caught by the chain walk; resolve() may now be reached with a "
        "cycle in the path, which needs its own refusal"
    )


def test_an_ordinary_prompt_still_resolves(tmp_path: pathlib.Path) -> None:
    """The chain walk must not refuse a path with no redirects in it."""
    mod = load_build()
    agents = tmp_path / "agents"
    agents.mkdir()
    (agents / "persona.md").write_text("You are the front desk.\n", encoding="utf-8")
    assert mod._resolve_prompt_path("file://persona.md", agents).name == "persona.md"
