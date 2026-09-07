"""A sensitive --source, and what identifies a report as ours.

Each was real, and the first was mine: the comment above it argued the fail-open was a
deliberate accommodation for standalone mode. That argument holds for refusing outright and
does not hold for skipping the check, which is what the code did -- so standalone was the one
mode where a sensitive ``--source`` was read and bundled.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib

import pytest

from .test_producer import load_build, make_crew, sign_plan


def _build(mod, home: pathlib.Path, out: pathlib.Path, select):
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    cands = mod.enumerate_all(crew, spec)
    out.parent.mkdir(parents=True, exist_ok=True)
    plan_path = sign_plan(mod, crew, spec, out.parent, select=select)
    plan = mod.merge_plans([plan_path], "frontdesk")
    mod.verify(plan, "frontdesk", cands)
    return mod.build_bundle(crew, spec, cands, plan, out)


def test_a_sensitive_source_is_refused_even_without_the_shared_validator() -> None:
    """The standalone fence answers the question the shared one cannot be asked.

    Drives the predicate directly for the paths, and the fence's placement is pinned by the
    build-level test below -- a predicate that is never consulted passes this and does
    nothing.
    """
    mod = load_build()
    for sensitive in (
        "/home/someone/.aws/credentials",
        "/home/someone/.ssh/id_rsa",
        "/home/someone/.config/gcloud/application_default_credentials.json",
        "/home/someone/.kube/config",
        "/home/someone/.kiro/crew-auth-staging/thing.json",
    ):
        assert mod._looks_sensitive_standalone(sensitive), sensitive


def test_the_standalone_fence_matches_components_not_substrings() -> None:
    """``~/projects/sshconfig-notes`` is not ``~/.ssh``.

    A substring test would refuse an operator's ordinary directory, and a fence that fires on
    innocent paths gets deleted rather than fixed.
    """
    mod = load_build()
    for innocent in (
        "/home/someone/projects/sshconfig-notes/agents/a.json",
        "/home/someone/awsnotes/agents/a.json",
        "/home/someone/my.ssh.backup.txt",
        "/home/someone/gnupg-docs/agents/a.json",
    ):
        assert not mod._looks_sensitive_standalone(innocent), innocent


def test_the_two_part_entries_need_consecutive_components() -> None:
    """``.config/gcloud`` is two components in order, not two names anywhere."""
    mod = load_build()
    assert mod._looks_sensitive_standalone("/home/x/.config/gcloud/creds.json")
    assert not mod._looks_sensitive_standalone("/home/x/.config/other/gcloud-notes/a.json")


def test_the_build_consults_the_standalone_fence_on_the_spec_path(
    tmp_path: pathlib.Path,
) -> None:
    """Driven through the real build, so the guard's PLACEMENT is what is tested.

    The lesson this pins: a fence proven only by calling its predicate says nothing about
    whether the read path reaches it. No hook is needed to simulate standalone mode, because
    the local fence now runs unconditionally -- which is the fix. Under the old code this
    same crew was read and bundled whenever the shared validator was unimportable.
    """
    mod = load_build()
    home = make_crew(tmp_path / ".aws" / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})

    with pytest.raises(mod.ExportRefused) as caught:
        _build(mod, home, tmp_path / "out", {"skills": {"faq"}})
    assert "sensitive" in str(caught.value)


def test_a_foreign_json_carrying_the_version_key_is_still_refused(
    tmp_path: pathlib.Path,
) -> None:
    """``report_version`` alone authorised truncating unrelated data.

    It is a generic key. Any document that happens to carry ``"report_version": 1`` read as
    this tool's own output, and the build then replaced it.
    """
    mod = load_build()
    out = tmp_path / "work" / "bundle"
    out.parent.mkdir(parents=True)
    foreign = out.parent / f"{out.name}.smc-bundle.json"
    foreign.write_text(
        json.dumps({"report_version": mod.REPORT_VERSION, "notes": "someone else's file"}),
        encoding="utf-8",
    )

    with pytest.raises(mod.ExportRefused) as caught:
        mod._refuse_unless_our_report(foreign, out)
    assert "did not write it" in str(caught.value)
    assert json.loads(foreign.read_text(encoding="utf-8"))["notes"] == "someone else's file"


def test_our_own_report_naming_this_bundle_is_accepted(tmp_path: pathlib.Path) -> None:
    """The other half: a rebuild over this tool's own report is the ordinary case.

    Without this the fix would read as "refuse everything", which no test above would catch.
    """
    mod = load_build()
    out = tmp_path / "work" / "bundle"
    out.parent.mkdir(parents=True)
    ours = out.parent / f"{out.name}.smc-bundle.json"
    ours.write_text(
        json.dumps({"report_version": mod.REPORT_VERSION, "bundle_dir": str(out)}),
        encoding="utf-8",
    )
    mod._refuse_unless_our_report(ours, out)


def test_a_report_naming_a_different_bundle_is_refused(tmp_path: pathlib.Path) -> None:
    """Same version, different destination: not the report this build would replace."""
    mod = load_build()
    out = tmp_path / "work" / "bundle"
    out.parent.mkdir(parents=True)
    stale = out.parent / f"{out.name}.smc-bundle.json"
    stale.write_text(
        json.dumps(
            {"report_version": mod.REPORT_VERSION, "bundle_dir": str(tmp_path / "elsewhere")}
        ),
        encoding="utf-8",
    )
    with pytest.raises(mod.ExportRefused):
        mod._refuse_unless_our_report(stale, out)


def test_a_failed_promotion_leaves_no_report_behind(tmp_path: pathlib.Path, monkeypatch) -> None:
    """A rename failure rolls the report back with the bundle.

    The report is written before the swap on purpose, so a report failure cannot land after
    the previous bundle is gone. That ordering left the other hole: the swap failed, the
    previous bundle came back, and the report still described the bundle that never landed.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    out = tmp_path / "work" / "bundle"

    real_rename = pathlib.Path.rename

    def _fail_the_promotion(self, target):
        if str(target) == str(out):
            raise OSError(13, "promotion refused")
        return real_rename(self, target)

    monkeypatch.setattr(pathlib.Path, "rename", _fail_the_promotion)
    with pytest.raises(OSError):
        _build(mod, home, out, {"skills": {"faq"}})

    report = out.parent / f"{out.name}.smc-bundle.json"
    assert not report.exists(), "the report describes a bundle that never landed"
    assert not out.exists(), "no bundle was installed"


def test_a_failed_promotion_restores_a_previous_report_verbatim(
    tmp_path: pathlib.Path, monkeypatch
) -> None:
    """The rollback puts the earlier bytes back rather than deleting them.

    Distinguishes the two branches: deleting unconditionally would pass the test above and
    destroy the previous build's report here.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    out = tmp_path / "work" / "bundle"
    _build(mod, home, out, {"skills": {"faq"}})

    report = out.parent / f"{out.name}.smc-bundle.json"
    first = report.read_bytes()
    assert json.loads(first.decode("utf-8"))["bundle_dir"] == str(out)

    real_rename = pathlib.Path.rename

    def _fail_the_promotion(self, target):
        if str(target) == str(out):
            raise OSError(13, "promotion refused")
        return real_rename(self, target)

    monkeypatch.setattr(pathlib.Path, "rename", _fail_the_promotion)
    with pytest.raises(OSError):
        _build(mod, home, out, {"skills": {"faq"}})

    assert report.read_bytes() == first, "the previous build's report was not restored"


# ---------------------------------------------------------------------------
# Round-12 GPT F1: a short encoded credential must not slip under the b64 floor
#
# The standalone decoder is the packager's REAL scan path (the canonical redactor
# is not importable in the deployment venv), and a credential shorter than an AWS
# secret access key still base64-encodes to a run under 40 chars.
# ---------------------------------------------------------------------------
def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii").rstrip("=")


def test_a_short_encoded_credential_is_caught_by_the_decoder() -> None:
    """A ``sk-`` vendor key encodes to a ~32-char base64 run, well under the old 40 floor.

    Drives ``_scan_decoded_runs`` directly: that is the standalone-mode scan path the
    finding is about (in a deployment venv the canonical redactor is not importable, so
    this decoder is the real scan), and it is the unit the floor governs.
    """
    mod = load_build()
    secret = "sk-" + "A" * 22  # matches _HARD_PATTERNS vendor-key (sk-[A-Za-z0-9]{20,})
    run = _b64(secret)
    assert 20 <= len(run) < 40, f"run must sit in the newly-covered band, got {len(run)}"
    leaks = mod._scan_decoded_runs(f"note: {run}", "spec.json")
    assert any("encoded-vendor-key" in leak.kind for leak in leaks), [leak.kind for leak in leaks]


def test_MUTATION_the_old_40_char_floor_would_skip_the_short_run() -> None:
    """Restore the 40-char floor and the same short run goes unscanned by the decoder."""
    mod = load_build(mutate=("[A-Za-z0-9+/]{20,}={0,2}", "[A-Za-z0-9+/]{40,}={0,2}"))
    secret = "sk-" + "A" * 22
    run = _b64(secret)
    leaks = mod._scan_decoded_runs(f"note: {run}", "spec.json")
    assert not any("encoded-vendor-key" in leak.kind for leak in leaks), (
        "floor reverted to 40: the short encoded credential should slip through, "
        "proving the lowered floor is what catches it"
    )


# ---------------------------------------------------------------------------
# Round-12 GPT F2: a credential-store filename must be refused by name
#
# A ``.git-credentials`` file carries a generic ``user:password@host`` that the
# content patterns do not reliably match, so the name gate is the real defense.
# ---------------------------------------------------------------------------
def test_a_git_credentials_file_is_refused_by_name() -> None:
    """The name alone refuses it, before any content read."""
    mod = load_build()
    assert mod.refused_by_name(pathlib.Path(".git-credentials"))
    assert mod.refused_by_name(pathlib.Path(".pypirc"))


def test_MUTATION_git_credentials_would_pass_the_name_gate_without_the_entry() -> None:
    """Drop the ``.git-credentials`` entry and the name gate lets it through."""
    mod = load_build(mutate=("      | \\.git-credentials\n", ""))
    assert not mod.refused_by_name(pathlib.Path(".git-credentials")), (
        "entry removed: the name gate should no longer refuse it, proving the entry "
        "is what closes the gap"
    )


# ---------------------------------------------------------------------------
# Round-12 GPT F3: the agent-spec read must not follow a replacement symlink
#
# ``is_file()`` then ``_read_text`` was a check/read window a concurrent writer
# could win by swapping the spec for a symlink between the two. The read is now a
# single ``O_NOFOLLOW`` open, so the link is refused at open time with no window.
# The chain-walk guard also refuses a pre-planted link, so the nofollow read is
# tested at its own unit -- that is the part that closes the RACE the chain guard
# cannot, since a swap after the walk still lands on this open.
# ---------------------------------------------------------------------------
@pytest.mark.skipif(os.name != "posix", reason="needs symlink semantics the fix relies on")
def test_the_nofollow_reader_refuses_a_symlink(tmp_path: pathlib.Path) -> None:
    """A link at the read path returns None (refused) rather than its target's bytes."""
    mod = load_build()
    real = tmp_path / "real.json"
    real.write_text("secret from elsewhere\n", encoding="utf-8")
    link = tmp_path / "spec.json"
    os.symlink(real, link)

    assert mod._read_text_nofollow(real) == "secret from elsewhere\n", "a real file still reads"
    assert mod._read_text_nofollow(link) is None, "a symlink must be refused at the open"


@pytest.mark.skipif(os.name != "posix", reason="needs symlink semantics the fix relies on")
def test_MUTATION_a_following_reader_would_read_through_the_link(tmp_path: pathlib.Path) -> None:
    """Give the nofollow reader an ordinary following open and the link is read through."""
    mod = load_build(
        mutate=(
            "fd = os.open(path, os.O_RDONLY | _NOFOLLOW_READ_FLAGS)",
            "fd = os.open(path, os.O_RDONLY)",
        )
    )
    real = tmp_path / "real.json"
    real.write_text("secret from elsewhere\n", encoding="utf-8")
    link = tmp_path / "spec.json"
    os.symlink(real, link)

    assert mod._read_text_nofollow(link) == "secret from elsewhere\n", (
        "O_NOFOLLOW removed: the reader follows the link to its target, proving the "
        "flag is what refuses it"
    )


def test_the_local_fence_is_never_stricter_than_the_shared_one() -> None:
    """Every entry in the local list must be one the shared validator also refuses.

    The local list exists for the mode where the shared validator is unimportable, so it may
    be COARSER -- catch less -- but never stricter. A stricter entry refuses a path the rest
    of the tree considers ordinary, and one did: ``.kiro/agents`` is upstream's
    ``_WRITE_PROTECTED_HOME_PATHS``, protecting against WRITING a spec whose
    ``mcpServers.command`` the gateway execs. ``is_sensitive_path`` returns False for it, and
    ``~/.kiro`` is the DEFAULT source, so every run without ``--source`` refused its own crew.

    No local test caught that, because every test builds its crew under ``tmp_path`` and none
    exercises the default path. This test compares the two lists instead of the behaviour.
    """
    from kiro_crew.security.paths import is_sensitive_path

    mod = load_build()
    home = str(pathlib.Path.home())
    stricter = []
    for entry in mod._SENSITIVE_RELATIVE_DIRS:
        probe = f"{home}/{entry}"
        if "." not in pathlib.PurePosixPath(entry).name:
            probe += "/probe"
        if not is_sensitive_path(probe):
            stricter.append(entry)
    assert not stricter, (
        f"these local entries are refused here but not by the shared validator: {stricter}. "
        f"A read-only build must not invent a read fence the rest of the tree does not have."
    )


def test_the_default_agent_spec_path_is_not_refused() -> None:
    """The regression stated directly: the default source must remain usable.

    Named separately from the list comparison because this is the SYMPTOM an operator hits,
    and it should be the failure a future reader sees first.
    """
    mod = load_build()
    home = str(pathlib.Path.home())
    assert not mod._looks_sensitive_standalone(f"{home}/.kiro/agents/frontdesk.json")
    assert not mod._looks_sensitive_standalone(f"{home}/.kiro/crew/skills/faq/SKILL.md")


def test_a_plan_written_under_a_file_refuses_instead_of_crashing(
    tmp_path: pathlib.Path,
) -> None:
    """``mkdir(parents=True)`` under an existing FILE raises a bare OSError.

    Every other refusal in this CLI is an ``ExportRefused`` naming the flag at fault, so a
    traceback here sends the operator to read a stack instead of moving --out.
    """
    mod = load_build()
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("I am a file\n", encoding="utf-8")

    with pytest.raises(mod.ExportRefused) as caught:
        mod._refuse_unusable_parent(blocker / "sub" / "plan.json", what="the plan")
    message = str(caught.value)
    assert "is not a directory" in message
    assert "--out" in message, "the refusal must name the flag the operator can change"


def test_an_ordinary_missing_directory_is_still_created(tmp_path: pathlib.Path) -> None:
    """The guard must not refuse the ordinary case: --out naming a directory not yet there.

    Without this, a guard that refused whenever the parent was absent would pass the test
    above and break every first build.
    """
    mod = load_build()
    mod._refuse_unusable_parent(tmp_path / "fresh" / "deeper" / "plan.json", what="the plan")


def test_the_output_parent_is_judged_before_any_derived_path(tmp_path: pathlib.Path) -> None:
    """One check on the shared component, not three on the paths derived from it.

    The staging tree, its marker and the report are all ``out_dir.parent / <something>``, so
    a junction at that parent relocates all three together and each per-path check then
    validates a name that already points elsewhere.
    """
    mod = load_build()
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("file\n", encoding="utf-8")

    with pytest.raises(mod.ExportRefused) as caught:
        mod._refuse_unusable_parent(blocker / "bundle", what="the bundle")
    assert "is not a directory" in str(caught.value)


def test_build_bundle_calls_the_parent_guard_first() -> None:
    """A source rule: the call must precede the first derived name.

    A guard placed after ``staging = out_dir.parent / ...`` would pass a direct test of the
    guard while the derived paths were already built from an unvalidated parent.
    """
    src = (pathlib.Path(__file__).parent.parent / "build.py").read_text(encoding="utf-8")
    body = src[src.index("def build_bundle(") :]
    guard = body.index('_refuse_unusable_parent(out_dir, what="the bundle")')
    first_derived = body.index('staging = out_dir.parent / (out_dir.name + ".staging")')
    assert guard < first_derived, "the parent is validated after a path is derived from it"


def test_the_report_is_replaced_atomically(tmp_path: pathlib.Path) -> None:
    """A source rule for the write shape, since a partial write cannot be staged in a test.

    ``_write_nofollow`` opens with ``O_TRUNC``, so an in-place write that fails partway has
    already emptied the previous report while ``report_written`` is still False -- the one
    shape the rollback cannot see. Writing a temp and renaming means the destination holds
    either the old bytes or the complete new ones.
    """
    src = (pathlib.Path(__file__).parent.parent / "build.py").read_text(encoding="utf-8")
    assert "os.replace(report_tmp, report_path)" in src, "the report write is not atomic"
    assert "report_tmp.unlink(missing_ok=True)" in src, "the temp is not cleaned up"


def test_the_atomic_replace_still_refuses_a_planted_link() -> None:
    """Atomicity must not cost the no-follow refusal, and it nearly did.

    ``os.replace`` overwrites a symlink rather than following it. That is safe for the
    link's target, but it succeeds where an in-place ``O_NOFOLLOW`` open refused -- so the
    shape check has to be made explicitly before the rename. Two existing tests caught the
    regression when the rename was added without it.
    """
    src = (pathlib.Path(__file__).parent.parent / "build.py").read_text(encoding="utf-8")
    replace_at = src.index("os.replace(report_tmp, report_path)")
    window = src[replace_at - 900 : replace_at]
    assert "_is_redirecting_entry(report_path)" in window, (
        "the destination's shape is not judged before the rename, so a planted link at the "
        "report path is overwritten instead of refused"
    )


# ---------------------------------------------------------------------------
# Round-13 GPT F1: a nested directory reached through a link/junction must block
# the skill -- rglob descends into it and is_symlink() misses a junction.
# ---------------------------------------------------------------------------
@pytest.mark.skipif(os.name != "posix", reason="needs symlink semantics the fix relies on")
def test_a_skill_reaching_outside_through_a_linked_dir_is_blocked(tmp_path: pathlib.Path) -> None:
    """A skill whose subdirectory is a symlink to an out-of-source tree is blocked, not shipped."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "stolen.txt").write_text("secret from elsewhere\n", encoding="utf-8")

    home = make_crew(tmp_path / "home", skills={"leaky": {"SKILL.md": "# ok\n"}})
    skill_dir = home / "skills" / "leaky"
    os.symlink(outside, skill_dir / "nested")

    mod = load_build()
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    leaky = next(c for c in mod.enumerate_all(crew, spec)["skills"] if c.id == "leaky")
    assert leaky.blocked, "a skill reaching outside the source through a link must be blocked"
    assert "link or junction" in leaky.blocked


@pytest.mark.skipif(os.name != "posix", reason="needs symlink semantics the fix relies on")
def test_MUTATION_a_linked_dir_would_not_block_without_the_redirect_check(
    tmp_path: pathlib.Path,
) -> None:
    """With the redirect check dropped, the skill with a linked-out subdir passes unblocked."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "stolen.txt").write_text("secret from elsewhere\n", encoding="utf-8")

    home = make_crew(tmp_path / "home", skills={"leaky": {"SKILL.md": "# ok\n"}})
    skill_dir = home / "skills" / "leaky"
    os.symlink(outside, skill_dir / "nested")

    mod = load_build(
        mutate=(
            '(p for p in sorted(skill_dir.rglob("*")) if _is_redirecting_entry(p)),',
            '(p for p in sorted(skill_dir.rglob("*")) if False),',
        )
    )
    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    leaky = next(c for c in mod.enumerate_all(crew, spec)["skills"] if c.id == "leaky")
    assert not (leaky.blocked and "link or junction" in leaky.blocked), (
        "redirect check removed: the link-reaching skill should no longer be blocked by it, "
        "proving the check is what blocks it"
    )


# ---------------------------------------------------------------------------
# Round-13 GPT F2: the spec read must refuse a redirect at an INTERMEDIATE parent,
# not only the final component (O_NOFOLLOW guards only the last name).
# ---------------------------------------------------------------------------
@pytest.mark.skipif(os.name != "posix", reason="needs symlink semantics the fix relies on")
def test_the_openat_reader_refuses_a_redirected_parent(tmp_path: pathlib.Path) -> None:
    """A symlinked intermediate directory on the read path returns None (refused)."""
    mod = load_build()
    root = tmp_path / "root"
    real_parent = tmp_path / "elsewhere"
    real_parent.mkdir()
    (real_parent / "frontdesk.json").write_text('{"prompt": "elsewhere"}', encoding="utf-8")
    root.mkdir()
    os.symlink(real_parent, root / "agents")  # the intermediate parent is a link

    assert (
        mod._read_text_openat(root, pathlib.Path("agents/frontdesk.json")) is None
    ), "a redirected intermediate parent must be refused by the per-component O_NOFOLLOW walk"


@pytest.mark.skipif(os.name != "posix", reason="needs symlink semantics the fix relies on")
def test_MUTATION_a_final_only_nofollow_would_follow_the_parent(tmp_path: pathlib.Path) -> None:
    """Strip O_NOFOLLOW from the intermediate dir open and the reader follows the parent link."""
    mod = load_build(
        mutate=(
            '    dir_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)',
            "    dir_flags = os.O_RDONLY | os.O_DIRECTORY",
        )
    )
    root = tmp_path / "root"
    real_parent = tmp_path / "elsewhere"
    real_parent.mkdir()
    (real_parent / "frontdesk.json").write_text('{"prompt": "elsewhere"}', encoding="utf-8")
    root.mkdir()
    os.symlink(real_parent, root / "agents")  # the intermediate parent is a link

    text = mod._read_text_openat(root, pathlib.Path("agents/frontdesk.json"))
    assert text is not None and "elsewhere" in text, (
        "O_NOFOLLOW removed from the intermediate dir open: the walk follows the parent link "
        "to its target, proving the per-component O_NOFOLLOW is what refuses it"
    )


def test_the_local_fence_casefolds_rather_than_lowercasing() -> None:
    """Windows paths are case-insensitive, so ``~/.AWS`` names the same directory.

    And casefold is what the shared validator uses, so ``lower()`` here would be a second,
    weaker rule for one question. The two differ on real input: the German sharp s folds to
    ``ss`` where ``lower()`` leaves it alone.
    """
    mod = load_build()
    for variant in (".aws", ".AWS", ".Aws", ".aWs"):
        assert mod._looks_sensitive_standalone(f"/home/someone/{variant}/credentials"), variant


def test_the_predicate_uses_casefold_in_source() -> None:
    """A source rule, because no ASCII input distinguishes the two functions.

    ``.AWS`` is caught by either, so a behaviour test cannot tell casefold from lower. The
    difference only shows on non-ASCII, which no credential directory name has -- yet the
    shared validator casefolds, and matching it is the point.
    """
    src = (pathlib.Path(__file__).parent.parent / "build.py").read_text(encoding="utf-8")
    fn = src[src.index("def _looks_sensitive_standalone(") :]
    body = fn[: fn.index("\ndef ")]
    assert ".casefold()" in body, "the predicate stopped casefolding"
    assert ".lower()" not in body, "the predicate went back to lower(), which folds less"


def test_a_plan_edited_during_the_build_is_refused_not_overwritten(
    tmp_path: pathlib.Path, monkeypatch
) -> None:
    """The carried plan is the operator's signed file, so a stale copy must not replace it.

    The bytes are read before the build runs and written back at the end. An operator who
    edits and re-signs in between had that edit replaced with no message -- and a signature
    is the one thing they cannot reproduce from the build's output.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    out = tmp_path / "work" / "bundle"
    _build(mod, home, out, {"skills": {"faq"}})

    plan_file = out / mod.PLAN_FILENAME
    plan_file.write_text(json.dumps({"plan_version": mod.PLAN_VERSION}), encoding="utf-8")

    edited = json.dumps({"plan_version": mod.PLAN_VERSION, "signed_by": "the operator"})
    real_read = pathlib.Path.read_bytes
    fired: list[str] = []

    def _edit_after_the_plan_is_read(self, *args, **kwargs):
        data = real_read(self, *args, **kwargs)
        # The operator saves over the plan just after the build has taken its copy, which
        # is exactly the window the fix closes. Fires once, so the re-read at the end sees
        # the edited bytes rather than being edited again underneath it.
        if self.name == mod.PLAN_FILENAME and not fired:
            fired.append(self.name)
            plan_file.write_text(edited, encoding="utf-8")
        return data

    monkeypatch.setattr(pathlib.Path, "read_bytes", _edit_after_the_plan_is_read)
    with pytest.raises(mod.ExportRefused) as caught:
        _build(mod, home, out, {"skills": {"faq"}})

    assert "changed while this build was running" in str(caught.value)
    assert plan_file.read_text(encoding="utf-8") == edited, "the operator's edit was lost"


def test_an_unchanged_plan_is_still_carried(tmp_path: pathlib.Path) -> None:
    """The ordinary case: nobody edits it, and the plan is carried forward as before.

    Without this, a check that refused whenever a plan existed would pass the test above and
    break the documented plan-sign-build flow.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    out = tmp_path / "work" / "bundle"
    _build(mod, home, out, {"skills": {"faq"}})

    plan_file = out / mod.PLAN_FILENAME
    body = json.dumps({"plan_version": mod.PLAN_VERSION, "signed_by": "the operator"})
    plan_file.write_text(body, encoding="utf-8")

    _build(mod, home, out, {"skills": {"faq"}})
    assert plan_file.read_text(encoding="utf-8") == body, "the carried plan was not preserved"
