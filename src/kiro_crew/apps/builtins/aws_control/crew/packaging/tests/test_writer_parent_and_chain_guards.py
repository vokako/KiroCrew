"""The writer's parent check, and the chain walk to the spec.

W1 the marker read opened its parent OUTSIDE the guard, so ``--out new/nested/bundle`` -- a
   path whose parent does not exist yet -- raised an unhandled ``FileNotFoundError`` out of a
   function whose entire job is to answer yes or no. No parent means no marker, which is False.

W2 the empty-directory check exempted all of ``_STAGING_OWNED_TOP_LEVEL``, and four of those
   five entries are FILE names. So an operator's own empty directory called ``agent.json`` or
   ``manifest.json`` was exempted and then removed by the recursive delete -- the exemption
   for the one directory this build leaves empty was written wide enough to cover four names
   it should never have covered.
"""

from __future__ import annotations

import pathlib

import pytest

from .test_producer import load_build, make_crew, sign_plan


def _build(mod, home: pathlib.Path, out: pathlib.Path, select):
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    cands = mod.enumerate_all(crew, spec)
    work = out.parent
    work.mkdir(parents=True, exist_ok=True)
    plan_path = sign_plan(mod, crew, spec, work, select=select)
    plan = mod.merge_plans([plan_path], "frontdesk")
    mod.verify(plan, "frontdesk", cands)
    return mod.build_bundle(crew, spec, cands, plan, out)


# ---------------------------------------------------------------------------
# W1
# ---------------------------------------------------------------------------
def test_the_marker_check_answers_false_for_an_absent_parent(tmp_path: pathlib.Path) -> None:
    """No parent means no marker. It must not raise."""
    mod = load_build()
    assert (
        mod._marker_is_ours(tmp_path / "does" / "not" / "exist" / "bundle.staging.owned") is False
    )


def test_the_marker_check_answers_false_for_a_file_where_the_parent_should_be(
    tmp_path: pathlib.Path,
) -> None:
    """NotADirectoryError gets the same answer for the same reason."""
    mod = load_build()
    blocker = tmp_path / "not-a-dir"
    blocker.write_bytes(b"x")
    assert mod._marker_is_ours(blocker / "bundle.staging.owned") is False


def test_a_build_into_a_nested_new_path_works(tmp_path: pathlib.Path) -> None:
    """The case the crash came from, driven through the real build.

    A unit test of the predicate would have stayed green under the old code for the wrong
    reason -- it raises rather than returning -- but only building shows that an operator
    naming a fresh nested --out gets a bundle instead of a traceback.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    report = _build(mod, home, tmp_path / "new" / "nested" / "bundle", {"skills": {"faq"}})
    assert report.digest.startswith("sha256:")
    assert (tmp_path / "new" / "nested" / "bundle" / "manifest.json").is_file()


def test_a_write_into_an_absent_directory_refuses_cleanly(tmp_path: pathlib.Path) -> None:
    """The writer's own parent open is guarded too, and refuses rather than raising.

    Different answer from the reader on purpose: the reader is asking a question and "no" is a
    valid answer, while the writer cannot proceed and has to say why.
    """
    mod = load_build()
    with pytest.raises(mod.ExportRefused) as caught:
        mod._write_nofollow(tmp_path / "absent" / "report.json", "{}\n")
    assert "is not there" in str(caught.value)


# ---------------------------------------------------------------------------
# W2
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["agent.json", "mcp.json", "manifest.json", "curation-plan.json"])
def test_an_empty_directory_named_after_a_file_entry_is_refused(
    tmp_path: pathlib.Path, name: str
) -> None:
    """Each of the four names the old exemption covered by accident.

    Parametrised rather than one representative case, because the bug was a SET being too wide
    and a single name would not show that every one of the four was exempt.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    out = tmp_path / "work" / "bundle"
    _build(mod, home, out, {"skills": {"faq"}})

    # The operator's own empty directory, using a name this build writes as a FILE.
    (out / name).unlink(missing_ok=True)
    (out / name).mkdir()

    with pytest.raises(mod.ExportRefused) as caught:
        _build(mod, home, out, {"skills": {"faq"}})
    assert (out / name).is_dir(), "the operator's directory was deleted"
    assert name in str(caught.value) or "no file this build would have written" in str(caught.value)


def test_the_empty_skills_directory_is_still_exempt(tmp_path: pathlib.Path) -> None:
    """Non-vacuity: narrowing the set must not break the one case it exists for.

    A bundle with no skills selected leaves ``skills/`` empty, and rebuilding over it has to
    work -- the first version of this guard refused it and reddened 13 tests.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    out = tmp_path / "work" / "bundle"
    _build(mod, home, out, {"skills": set()})
    assert (out / "skills").is_dir()
    assert not any((out / "skills").iterdir())
    _build(mod, home, out, {"skills": set()})


def test_the_two_sets_are_not_the_same_set() -> None:
    """A source-level pin, because the bug was one name list standing in for another.

    They overlap, so a future edit that "tidies" them back together would reintroduce exactly
    this finding. Stated as an inequality so the intent survives the tidying impulse.
    """
    mod = load_build()
    assert mod._BUILD_WRITES_EMPTY == {"skills"}
    assert mod._BUILD_WRITES_EMPTY < mod._STAGING_OWNED_TOP_LEVEL
    assert "agent.json" in mod._STAGING_OWNED_TOP_LEVEL
    assert "agent.json" not in mod._BUILD_WRITES_EMPTY
