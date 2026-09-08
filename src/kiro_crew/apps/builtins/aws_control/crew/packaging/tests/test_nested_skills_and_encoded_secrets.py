"""Three findings about what the bundle carries and what the scanner can see.

Each is the same kind of gap: a rule that was true of the shape in front of it and silent
about a shape one step away.

N1 nested skills -- ``_copy_skill`` walked the selected skill with ``rglob`` and shipped
   everything under it. Skill ids nest (``aws`` and ``aws/ec2`` are both skills, each with a
   ``SKILL.md``), so selecting the parent shipped the child the plan had excluded, and the
   printed notes said nothing about it. Deny-by-default is the whole premise of the plan, so
   an implicit inclusion is not a smaller version of the same thing.

N2 encoded credentials -- every pattern in the scanner matches a credential written
   literally, so a base64 of the same bytes matched none of them. The repo's own
   ``redact_credentials`` already decodes base64 chunks, so it is imported rather than
   restated; a local pattern per shape is what this file keeps needing, and that
   is the shape being retired.

N3 the Windows read -- ``_open_nofollow_under`` fell back to a single ``O_NOFOLLOW`` open
   where ``dir_fd`` is unavailable. That rejects only a FINAL-component link, so a parent
   replaced by a junction was traversed: the fallback protected the case that needs no
   protection and missed the one the function exists for. It now refuses.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib

import pytest

from .test_producer import load_build, make_crew, sign_plan

# From AWS's own documentation, so nothing here is a real credential.
_DOC_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def _build(mod, home: pathlib.Path, work: pathlib.Path, select):
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    cands = mod.enumerate_all(crew, spec)
    work.mkdir(parents=True, exist_ok=True)
    plan_path = sign_plan(mod, crew, spec, work, select=select)
    plan = mod.merge_plans([plan_path], "frontdesk")
    mod.verify(plan, "frontdesk", cands)
    return mod.build_bundle(crew, spec, cands, plan, work / "bundle")


# ---------------------------------------------------------------------------
# N1: selecting a parent must not ship an excluded child
# ---------------------------------------------------------------------------
def _nested_crew(tmp_path: pathlib.Path) -> pathlib.Path:
    return make_crew(
        tmp_path / "home",
        skills={
            "aws": {"SKILL.md": "# AWS\nparent\n"},
            "aws/ec2": {"SKILL.md": "# EC2\nchild\n"},
            "aws/s3": {"SKILL.md": "# S3\nother child\n"},
        },
    )


def test_selecting_only_the_parent_ships_only_the_parent(tmp_path: pathlib.Path) -> None:
    """The excluded children must be absent, and the count must agree.

    Both, because the count is what an operator reads and the files are what a customer
    gets. A bundle that ships three skills while reporting one is worse than either error
    alone.
    """
    mod = load_build()
    home = _nested_crew(tmp_path)
    work = tmp_path / "work"
    report = _build(mod, home, work, {"skills": {"aws"}})
    out = work / "bundle"

    assert (out / "skills" / "aws" / "SKILL.md").is_file()
    assert not (out / "skills" / "aws" / "ec2").exists(), "an excluded child skill shipped"
    assert not (out / "skills" / "aws" / "s3").exists(), "an excluded child skill shipped"
    assert report.skill_count == 1


def test_selecting_parent_and_one_child_ships_exactly_those(tmp_path: pathlib.Path) -> None:
    """The child comes back when the plan selects it, and the sibling stays out.

    Non-vacuity for the skip: a copy that simply stopped at every nested root would satisfy
    the test above while making a selected child unshippable.
    """
    mod = load_build()
    home = _nested_crew(tmp_path)
    work = tmp_path / "work"
    report = _build(mod, home, work, {"skills": {"aws", "aws/ec2"}})
    out = work / "bundle"

    assert (out / "skills" / "aws" / "SKILL.md").is_file()
    assert (out / "skills" / "aws" / "ec2" / "SKILL.md").is_file()
    assert not (out / "skills" / "aws" / "s3").exists()
    assert report.skill_count == 2


def test_a_parents_own_files_beside_a_child_still_ship(tmp_path: pathlib.Path) -> None:
    """The skip is scoped to the CHILD's subtree, not to everything below the parent.

    A parent legitimately has its own files at any depth. Skipping by "is under some nested
    root" rather than "is under an EXCLUDED nested root" would silently drop them.
    """
    mod = load_build()
    home = make_crew(
        tmp_path / "home",
        skills={"aws": {"SKILL.md": "# AWS\n"}, "aws/ec2": {"SKILL.md": "# EC2\n"}},
    )
    # Written here rather than through ``make_crew``: its writer does not create parent
    # directories for a nested filename, so a nested entry would fail on the write rather
    # than testing anything. The directory is called "reference" and not "docs", because the
    # docs lint reads a "docs/<name>.md" string appearing in source as a citation of a real
    # repository document and fails on the missing file.
    own = home / "skills" / "aws" / "reference"
    own.mkdir(parents=True)
    (own / "notes.md").write_text("parent's own file\n", encoding="utf-8")

    work = tmp_path / "work"
    _build(mod, home, work, {"skills": {"aws"}})
    out = work / "bundle"

    assert (out / "skills" / "aws" / "reference" / "notes.md").is_file()
    assert not (out / "skills" / "aws" / "ec2").exists()


# ---------------------------------------------------------------------------
# N2: a credential the scanner cannot read literally
# ---------------------------------------------------------------------------
def test_a_base64_encoded_labelled_secret_is_found() -> None:
    """The encoded form must be a finding, as the literal form already was.

    Asserted on both spellings in one test so the comparison is the assertion: if the
    encoded case ever stops being found, this fails while the literal case still passes,
    which is exactly the state the finding described.
    """
    mod = load_build()
    literal = f"aws_secret_access_key = {_DOC_SECRET}"
    encoded = base64.b64encode(literal.encode()).decode()

    assert mod.scan_text(literal, "t"), "the literal form must still be found"
    assert mod.scan_text(encoded, "t"), "the encoded form ships past every literal pattern"


def test_ordinary_skill_text_is_still_clean() -> None:
    """Non-vacuity: a scanner that flagged everything would pass the test above.

    The strings here are the kind of thing a real SKILL.md holds, including base64-looking
    words, because a detector that cannot tell those apart makes the build unusable.
    """
    mod = load_build()
    for text in (
        "# FAQ\nStore hours are 9 to 6.\n",
        "# Deploy\nRun `make release` and check the output.\n",
        "# Encoding\nUse base64 for binary payloads.\n",
    ):
        assert not mod.scan_text(text, "t"), text


def test_an_encoded_credential_blocks_the_skill_that_carries_it(tmp_path: pathlib.Path) -> None:
    """End to end: the candidate is blocked, so the plan cannot select it."""
    mod = load_build()
    encoded = base64.b64encode(f"aws_secret_access_key = {_DOC_SECRET}".encode()).decode()
    home = make_crew(tmp_path / "home", skills={"leaky": {"SKILL.md": f"# L\n{encoded}\n"}})
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    leaky = next(c for c in mod.enumerate_all(crew, spec)["skills"] if c.id == "leaky")
    assert leaky.blocked


# ---------------------------------------------------------------------------
# N3: no per-component fence, no read
# ---------------------------------------------------------------------------
def _no_dir_fd(mod_loader):
    return mod_loader(
        mutate=(
            '    return os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY")',
            "    return False",
        )
    )


def test_the_read_uses_an_attribute_walk_where_dir_fd_is_unavailable(
    tmp_path: pathlib.Path,
) -> None:
    """An ordinary external prompt must still be READABLE where no descriptor walk exists.

    An earlier version of this test asserted the opposite -- that the read refuses -- and
    both it and the code under it were wrong. External prompts are a supported feature with
    their own suite, so refusing on a platform without ``dir_fd`` deleted the feature from
    Windows instead of hardening it. The Windows CI job said so by reddening six tests,
    ``test_external_prompt_supported.py`` among them.

    The platform is simulated by mutating the predicate, because the branch cannot be
    reached on a POSIX host. That is also why the earlier mistake survived every local run:
    all of them took the strong path.
    """
    mod = _no_dir_fd(load_build)
    root = tmp_path / "agents"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "persona.md").write_bytes(b"content\n")

    fd = mod._open_attr_checked_under(root / "sub" / "persona.md", root)
    try:
        assert os.read(fd, 64) == b"content\n"
    finally:
        os.close(fd)


def test_a_link_above_the_prompt_is_refused_by_the_attribute_walk(
    tmp_path: pathlib.Path,
) -> None:
    """Non-vacuity: the fallback must still refuse what the descriptor walk refuses.

    A parent replaced by a link is the case a single ``O_NOFOLLOW`` open misses, so it is
    the case that decides whether this fallback is worth having at all. Planted at a PARENT
    and not at the leaf for exactly that reason.
    """
    mod = _no_dir_fd(load_build)
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    (secret_dir / "persona.md").write_text("private key material\n", encoding="utf-8")

    root = tmp_path / "agents"
    root.mkdir()
    (root / "sub").symlink_to(secret_dir, target_is_directory=True)

    with pytest.raises(mod.ExportRefused) as caught:
        mod._open_attr_checked_under(root / "sub" / "persona.md", root)
    assert "link or junction" in str(caught.value)


def test_a_link_at_the_anchor_is_refused_by_the_attribute_walk(tmp_path: pathlib.Path) -> None:
    """The anchor is judged by the same rule, which the POSIX walk had to learn separately."""
    mod = _no_dir_fd(load_build)
    real = tmp_path / "real"
    (real / "sub").mkdir(parents=True)
    (real / "sub" / "persona.md").write_bytes(b"content\n")
    link = tmp_path / "agents"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(mod.ExportRefused) as caught:
        mod._open_attr_checked_under(link / "sub" / "persona.md", link)
    assert "anchor" in str(caught.value)


def test_an_external_prompt_inlines_end_to_end_without_dir_fd(tmp_path: pathlib.Path) -> None:
    """The feature the refusal broke, driven through the real build rather than the opener.

    A unit test of the opener would have stayed green under the refusal too, because the
    refusal was correct at that level. What it broke was the build, which is what this
    asserts.
    """
    mod = _no_dir_fd(load_build)
    home = make_crew(tmp_path / "home", prompt="file://persona.md")
    (home / "agents" / "persona.md").write_bytes(b"an external persona\n")
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    result = mod.build_spec(crew, spec, set(), crew.agent_spec_path.parent)
    assert result.spec["prompt"] == "an external persona\n"


def test_skills_still_ship_where_dir_fd_is_unavailable(tmp_path: pathlib.Path) -> None:
    """Skill files do not go through the anchored opener, so they are unaffected."""
    mod = _no_dir_fd(load_build)
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    work = tmp_path / "work"
    _build(mod, home, work, {"skills": {"faq"}})
    assert (work / "bundle" / "skills" / "faq" / "SKILL.md").is_file()
    assert json.loads((work / "bundle" / "manifest.json").read_text(encoding="utf-8"))["digest"]
