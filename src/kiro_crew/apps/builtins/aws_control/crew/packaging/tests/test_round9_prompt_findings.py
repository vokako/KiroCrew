"""Two findings on the prompt reader, both raised by GPT and Opus independently.

V1 the pre-resolution walk ran only on the RELATIVE branch, so ``file:///abs/path`` reached
   ``resolve()`` with nothing having looked at its components. What that costs is Windows-only
   and narrow: resolving a reparse point that names a SHARE is the outbound SMB probe with its
   NTLM exchange, and the UNC gate above only sees a share written literally in the target.

   The first attempt walked the absolute path and refused every redirect. That reddened
   ``test_a_symlink_to_a_legitimate_persona_still_works`` and four more, because a symlink at
   the prompt path is a SUPPORTED case -- the design permits a persona outside the agents
   directory and protects it by checking the RESOLVED target against the sensitive-path fence.
   So the refusal is scoped to the one thing the target check cannot catch: a redirect that
   names a share, read with ``readlink``, which does not traverse.

V2 the read was unbounded. The prompt is inlined into ``agent.json``, so its bytes are held in
   memory, hashed and shipped -- and the path comes from the crew's agent spec, which makes the
   size someone else's choice.
"""

from __future__ import annotations

import pathlib

import pytest

from .test_producer import load_build, make_crew


# ---------------------------------------------------------------------------
# V1
# ---------------------------------------------------------------------------
def test_a_symlinked_persona_outside_the_agents_dir_still_works(tmp_path: pathlib.Path) -> None:
    """The supported case, pinned again here because a fix already broke it once.

    Kept beside the new refusal rather than left in its own file: the two are one decision, and
    a reader deciding whether to tighten the absolute branch needs to see the cost in the same
    place as the benefit.
    """
    mod = load_build()
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    persona = tmp_path / "shared" / "persona.md"
    persona.parent.mkdir(parents=True)
    persona.write_bytes(b"You are the front desk.\n")
    link = agents_dir / "linked.md"
    link.symlink_to(persona)

    assert mod._resolve_prompt_path(f"file://{link}", agents_dir) == link


def test_the_absolute_branch_refuses_a_redirect_naming_a_share(tmp_path: pathlib.Path) -> None:
    """The gap the walk was added for, tested through the nt branch.

    ``os.name`` is mutated rather than the test being skipped, because the branch cannot be
    reached on this host and skipping it would leave the fix with no test at all -- which is
    how the previous version of this fence shipped ineffective.
    """
    mod = load_build(mutate=('    elif os.name == "nt":', "    elif True:"))
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    # A link whose TARGET has UNC shape. The target need not exist: refusing before resolution
    # is the point, and a dangling link proves nothing was resolved.
    link = agents_dir / "persona.md"
    link.symlink_to("//attacker-host/share/persona.md")

    with pytest.raises(mod.ExportRefused) as caught:
        mod._resolve_prompt_path(f"file://{link}", agents_dir)
    assert "network share" in str(caught.value)
    assert "attacker-host" in str(caught.value)


def test_an_ordinary_absolute_link_is_not_refused_by_that_check(tmp_path: pathlib.Path) -> None:
    """Non-vacuity: on the same branch, a link to a local file must pass.

    Without this the refusal above would be satisfied by banning every link, which is exactly
    the over-broad version that had to be backed out.
    """
    mod = load_build(mutate=('    elif os.name == "nt":', "    elif True:"))
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    persona = tmp_path / "shared" / "persona.md"
    persona.parent.mkdir(parents=True)
    persona.write_bytes(b"a local persona\n")
    link = agents_dir / "persona.md"
    link.symlink_to(persona)

    assert mod._resolve_prompt_path(f"file://{link}", agents_dir) == link


# ---------------------------------------------------------------------------
# V2
# ---------------------------------------------------------------------------
def test_an_oversized_prompt_is_refused(tmp_path: pathlib.Path) -> None:
    """Refused rather than read, because the read is what allocates."""
    mod = load_build()
    home = make_crew(tmp_path / "home", prompt="file://persona.md")
    big = home / "agents" / "persona.md"
    big.write_bytes(b"x" * (mod._MAX_PROMPT_BYTES + 1))

    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    with pytest.raises(mod.ExportRefused) as caught:
        mod.build_spec(crew, spec, set(), crew.agent_spec_path.parent)
    assert "larger than" in str(caught.value)


def test_a_prompt_at_the_ceiling_is_read(tmp_path: pathlib.Path) -> None:
    """The bound is inclusive, so the ceiling is a size and not an off-by-one."""
    mod = load_build()
    home = make_crew(tmp_path / "home", prompt="file://persona.md")
    body = b"y" * mod._MAX_PROMPT_BYTES
    (home / "agents" / "persona.md").write_bytes(body)

    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    result = mod.build_spec(crew, spec, set(), crew.agent_spec_path.parent)
    assert result.spec["prompt"] == body.decode("utf-8")


def test_the_bound_is_applied_at_the_read(tmp_path: pathlib.Path, monkeypatch) -> None:
    """A stat-then-read pair would leave the bound advisory, so the read must carry it.

    Learned in the sidecar's copy of this fix: replacing the bounded read with an unbounded one
    left every behavioural test green, because the size comparison below it still raised. The
    allocation is what kills the process and it happens before any comparison, so the size the
    reader ASKS for is the only place the property is visible.
    """
    mod = load_build()
    requested: list[int] = []
    real_fdopen = mod.os.fdopen

    class _Recording:
        def __init__(self, inner):
            self._inner = inner

        def read(self, size=-1):
            requested.append(size)
            return self._inner.read(size)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return self._inner.__exit__(*exc)

    monkeypatch.setattr(mod.os, "fdopen", lambda *a, **k: _Recording(real_fdopen(*a, **k)))

    home = make_crew(tmp_path / "home", prompt="file://persona.md")
    (home / "agents" / "persona.md").write_bytes(b"z" * (mod._MAX_PROMPT_BYTES + 4096))
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    with pytest.raises(mod.ExportRefused):
        mod.build_spec(crew, spec, set(), crew.agent_spec_path.parent)

    assert requested, "the read did not go through fdopen, so this test proves nothing"
    assert all(
        0 < size <= mod._MAX_PROMPT_BYTES + 1 for size in requested
    ), f"the read was not bounded: asked for {requested}"


def test_an_ordinary_prompt_is_unaffected_by_the_ceiling(tmp_path: pathlib.Path) -> None:
    """Non-vacuity: a persona is prose, and prose must still read verbatim."""
    mod = load_build()
    home = make_crew(tmp_path / "home", prompt="file://persona.md")
    (home / "agents" / "persona.md").write_bytes(b"You are the front desk.\nBe brief.\n")
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    result = mod.build_spec(crew, spec, set(), crew.agent_spec_path.parent)
    assert result.spec["prompt"] == "You are the front desk.\nBe brief.\n"
