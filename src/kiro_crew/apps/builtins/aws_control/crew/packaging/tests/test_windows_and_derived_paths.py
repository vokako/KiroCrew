"""The four findings on the head that carried the previous round's security fixes.

Two of them were introduced BY those fixes, which is the part worth recording: hardening a
path-handling site with ``dir_fd`` and ``O_NOFOLLOW`` moved the failure rather than removing
it, and neither the suite nor I noticed until the review read the new code.

R1 ``_dir_fd_supported`` -- ``_write_marker_exclusive``, ``_marker_is_ours`` and
   ``_open_root_nofollow`` all reached ``os.O_DIRECTORY`` unconditionally. The attribute
   does not exist on Windows, so every Windows build raised ``AttributeError`` before doing
   any work. ``_open_nofollow_under`` had asked the platform question inline since before
   this round; the three new functions did not ask at all.

R2 the directory case -- ``os.unlink`` cannot remove a directory, so a pre-existing
   ``<out>.staging.owned/`` raised ``IsADirectoryError``. It raised AFTER ``staging.mkdir``,
   leaving a traceback and a staging tree nothing cleaned up.

F3 ``_write_nofollow`` -- the marker got the no-follow write last round and the
   machine-readable report did not, though both are paths derived from ``--out`` in a
   directory this build does not own. One shared function now, so the two cannot drift.

F4 the shared fence -- when ``kiro_crew.security`` is not importable the code falls back to a
   local denylist. It refuses the external-prompt reference outright rather than judging it
   by the weaker check.
"""

from __future__ import annotations

import ast
import os
import pathlib

import pytest

from .test_producer import BUILD_PY, load_build, make_crew, sign_plan


def _build(mod, home: pathlib.Path, work: pathlib.Path, select=None):
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    cands = mod.enumerate_all(crew, spec)
    work.mkdir(parents=True, exist_ok=True)
    plan_path = sign_plan(mod, crew, spec, work, select=select or {})
    plan = mod.merge_plans([plan_path], "frontdesk")
    mod.verify(plan, "frontdesk", cands)
    return mod.build_bundle(crew, spec, cands, plan, work / "bundle")


# ---------------------------------------------------------------------------
# R1: the platform question must be asked wherever O_DIRECTORY is used
# ---------------------------------------------------------------------------
def test_every_o_directory_use_is_behind_the_platform_guard() -> None:
    """A source rule, because the crash it prevents cannot be reproduced on POSIX.

    ``os.O_DIRECTORY`` simply exists here, so no behavioural test on this platform can fail
    when a function forgets to check for it -- which is exactly how three functions shipped
    without the check. The rule is that any function naming ``O_DIRECTORY`` also consults
    ``_dir_fd_supported``, which is the one predicate all of them now share.
    """
    tree = ast.parse(BUILD_PY.read_text(encoding="utf-8"), str(BUILD_PY))
    offenders: list[str] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        names = {node.attr for node in ast.walk(fn) if isinstance(node, ast.Attribute)}
        if "O_DIRECTORY" not in names:
            continue
        guarded = any(
            isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_dir_fd_supported"
            for node in ast.walk(fn)
        )
        if not guarded:
            offenders.append(f"{fn.name}:{fn.lineno}")

    assert not offenders, (
        "these functions use os.O_DIRECTORY without asking _dir_fd_supported() first, "
        f"so they raise AttributeError on Windows before doing any work: {offenders}"
    )


def test_the_o_directory_rule_is_scanning_real_functions() -> None:
    """Non-vacuity: a rule over an empty set would pass while the crash came back."""
    tree = ast.parse(BUILD_PY.read_text(encoding="utf-8"), str(BUILD_PY))
    users = [
        fn.name
        for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(isinstance(n, ast.Attribute) and n.attr == "O_DIRECTORY" for n in ast.walk(fn))
    ]
    assert len(users) >= 3, f"expected the dir_fd users to be in scope, found {users}"


def test_the_guard_reports_this_platform_honestly() -> None:
    """The predicate must answer for the platform it runs on, not a constant.

    A predicate hardcoded either way would satisfy the source rule above while making the
    branches it guards unreachable on one platform or the other.
    """
    mod = load_build()
    expected = os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY")
    assert mod._dir_fd_supported() is expected


# ---------------------------------------------------------------------------
# R2: a directory where a file belongs must refuse, not crash
# ---------------------------------------------------------------------------
def test_a_directory_at_the_marker_path_is_refused_without_residue(tmp_path) -> None:
    """``ExportRefused`` naming the path, and no staging tree left behind.

    Both halves matter and the second is the one the first version got wrong: it raised
    after ``staging.mkdir`` had run, so the operator got a traceback AND a directory they
    then had to clean up by hand before retrying.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home")
    work = tmp_path / "work"
    work.mkdir()
    (work / "bundle.staging.owned").mkdir()

    with pytest.raises(mod.ExportRefused) as caught:
        _build(mod, home, work)
    assert "is a directory" in str(caught.value)
    assert not (work / "bundle.staging").exists(), "the refusal stranded a staging tree"


def test_a_directory_at_the_report_path_is_refused(tmp_path) -> None:
    """The shared writer means the report path answers the same way the marker does."""
    mod = load_build()
    marker = tmp_path / "report.json"
    marker.mkdir()
    with pytest.raises(mod.ExportRefused) as caught:
        mod._write_nofollow(marker, "{}\n")
    assert "is a directory" in str(caught.value)


# ---------------------------------------------------------------------------
# F3: the report write must not follow a link either
# ---------------------------------------------------------------------------
@pytest.mark.skipif(os.name != "posix", reason="needs symlink semantics the fix relies on")
def test_a_planted_report_symlink_is_refused_and_the_target_survives(tmp_path) -> None:
    """A link at the report path stops the build, and the victim keeps its bytes.

    Driven through ``_cmd_build`` rather than the helper, because the point of the finding
    was that this call site had been missed while its sibling was fixed. The refusal is the
    same answer the marker path gives, from the same shared writer: this build does not
    write through a link to somewhere the operator did not name.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home")
    work = tmp_path / "work"
    work.mkdir()
    victim = tmp_path / "precious.txt"
    victim.write_bytes(b"do not truncate me\n")
    (work / "bundle.smc-bundle.json").symlink_to(victim)

    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    plan_path = sign_plan(mod, crew, spec, work, select={})

    with pytest.raises(mod.ExportRefused) as caught:
        mod._cmd_build("frontdesk", work / "bundle", [plan_path], home)
    assert "symlink" in str(caught.value).lower(), str(caught.value)
    assert victim.read_bytes() == b"do not truncate me\n", "the planted link was followed"


def test_rebuilding_over_our_own_report_still_works(tmp_path) -> None:
    """A regular file at the report path is replaced, not refused.

    This is the half the second version of the fix got wrong: refusing every existing path
    broke building twice over the same ``--out``, which is the ordinary case, because the
    report from the previous run legitimately sits there. The rule is about SHAPE -- a link
    or a directory is refused, a regular file is truncated -- so nothing has to guess whose
    file it is.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home")
    work = tmp_path / "work"
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    work.mkdir(parents=True, exist_ok=True)
    plan_path = sign_plan(mod, crew, spec, work, select={})

    assert mod._cmd_build("frontdesk", work / "bundle", [plan_path], home) == 0
    first = (work / "bundle.smc-bundle.json").read_text(encoding="utf-8")
    assert mod._cmd_build("frontdesk", work / "bundle", [plan_path], home) == 0
    assert (work / "bundle.smc-bundle.json").read_text(encoding="utf-8")
    assert first  # the first run really did write one


def test_both_derived_paths_go_through_one_writer() -> None:
    """The marker and the report must share the implementation, not resemble each other.

    The finding existed because they did not: one call site was hardened and the other kept
    its plain ``write_text``. A source assertion is the cheap way to keep that from
    recurring, since a second spelling is what has to be prevented.
    """
    tree = ast.parse(BUILD_PY.read_text(encoding="utf-8"), str(BUILD_PY))
    callers = {
        fn.name
        for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_write_nofollow"
            for n in ast.walk(fn)
        )
    }
    assert {
        "_write_marker_exclusive",
        # ``build_bundle``, not ``_cmd_build``: the report moved inside the build so it is
        # written BEFORE the swap. Written after, a failure landed once the previous bundle had
        # already been renamed aside and deleted -- a failure that had already replaced what it
        # was going to replace. The rule is about which WRITER is used; the function named here
        # follows wherever the write lives.
        "build_bundle",
    } <= callers, f"both derived-path writes must use _write_nofollow; found {sorted(callers)}"


# ---------------------------------------------------------------------------
# F4: no fence, no external prompt
# ---------------------------------------------------------------------------
def test_an_external_prompt_is_refused_when_the_shared_fence_is_missing(tmp_path) -> None:
    """Fail closed, and say which check was unavailable.

    The import is mutated to fail so the fallback path is the one under test. Refusing
    costs the external-reference feature and nothing else: an inline prompt is unaffected,
    which is what makes fail-closed the affordable direction here.
    """
    mod = load_build(
        mutate=(
            "        from kiro_crew.security import is_sensitive_path",
            "        raise ImportError('simulated standalone environment')",
        )
    )
    persona = tmp_path / "persona.md"
    persona.write_text("a persona\n", encoding="utf-8")
    home = make_crew(tmp_path / "home", prompt=f"file://{persona}")
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)

    with pytest.raises(mod.ExportRefused) as caught:
        mod.build_spec(crew, spec, set(), crew.agent_spec_path.parent)
    assert "is_sensitive_path" in str(caught.value)


def test_an_external_prompt_still_inlines_when_the_fence_is_present(tmp_path) -> None:
    """Non-vacuity: refusing unconditionally would satisfy the test above.

    ``kiro_crew.security`` is importable in this repo's own environment, so this is the path
    every real build takes and it has to keep working.
    """
    mod = load_build()
    persona = tmp_path / "persona.md"
    persona.write_text("a persona\n", encoding="utf-8")
    home = make_crew(tmp_path / "home", prompt=f"file://{persona}")
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    result = mod.build_spec(crew, spec, set(), crew.agent_spec_path.parent)
    assert "a persona" in result.spec["prompt"]
