"""Two ways the bundle builder could reach past its own fences.

* A UNC prompt path was resolved before any check ran. On Windows resolving a UNC path IS
  the outbound SMB probe, so `file:////attacker/share/persona.md` touched the attacker's
  host -- and a Windows SMB touch carries an NTLM exchange. This repo already owns the
  rule (`hooks.is_unc_shape` + `hooks.unc_probe_allowed`, gated before resolution by
  `hooks.validate_file_path`); the builder simply did not consult it.

* Promotion was `rmtree(out_dir)` then `staging.rename(out_dir)`. A failure BETWEEN the two
  left nothing: the previous bundle was already deleted, and the `except BaseException`
  handler then removed staging as well, so the new bundle and the carried signed plan went
  with it. The comment above the swap called it "the last thing that happens", which was
  true of the ordering and false of the atomicity.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from .test_producer import load_build, make_crew


def _crew(mod, tmp_path):
    src = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\nhours"}})
    return mod.resolve_crew("frontdesk", src)


def _build(mod, crew, out):
    spec = mod.read_agent_spec(crew)
    return mod.build_bundle(crew, spec, mod.enumerate_all(crew, spec), None, out)


# --- the UNC gate ------------------------------------------------------------


class _OsThatSaysWindows:
    """`os` as build.py sees it, reporting nt.

    Patching the real ``os.name`` is too blunt: ``pathlib`` reads it to choose its flavour
    and then refuses with "cannot instantiate 'WindowsPath' on your system", and
    ``Path.home()`` stops working. Replacing only the module-global keeps pathlib real
    while the platform branch takes the Windows path, which is the branch under test.
    """

    name = "nt"

    def __getattr__(self, attr):  # everything else is the genuine module
        return getattr(os, attr)


def _as_windows(monkeypatch, mod):
    monkeypatch.setattr(mod, "os", _OsThatSaysWindows())


# --- promotion keeps one bundle at all times ---------------------------------


def test_a_failed_promotion_keeps_the_previous_bundle(monkeypatch, tmp_path):
    mod = load_build()
    crew = _crew(mod, tmp_path)
    out = tmp_path / "bundle"
    _build(mod, crew, out)
    first = (out / "manifest.json").read_text(encoding="utf-8")

    real_rename = pathlib.Path.rename

    def _fail_the_promotion(self, target):
        if str(self).endswith(".staging"):
            raise OSError("the promotion failed here")
        return real_rename(self, target)

    monkeypatch.setattr(pathlib.Path, "rename", _fail_the_promotion)
    with pytest.raises(OSError):
        _build(mod, crew, out)

    assert (out / "manifest.json").is_file(), "the previous bundle was destroyed"
    assert (out / "manifest.json").read_text(encoding="utf-8") == first
    assert not (out.parent / (out.name + ".previous")).exists(), "aside copy left behind"


def test_a_failed_promotion_keeps_the_carried_plan(monkeypatch, tmp_path):
    """The signed plan is the part that cannot be rebuilt from the crew."""
    mod = load_build()
    crew = _crew(mod, tmp_path)
    out = tmp_path / "bundle"
    _build(mod, crew, out)
    (out / mod.PLAN_FILENAME).write_bytes(b'{"signed": "plan"}')

    real_rename = pathlib.Path.rename

    def _fail_the_promotion(self, target):
        if str(self).endswith(".staging"):
            raise OSError("the promotion failed here")
        return real_rename(self, target)

    monkeypatch.setattr(pathlib.Path, "rename", _fail_the_promotion)
    with pytest.raises(OSError):
        _build(mod, crew, out)

    assert (out / mod.PLAN_FILENAME).read_bytes() == b'{"signed": "plan"}'


def test_a_successful_build_leaves_no_aside_copy(tmp_path):
    mod = load_build()
    crew = _crew(mod, tmp_path)
    out = tmp_path / "bundle"
    _build(mod, crew, out)
    _build(mod, crew, out)
    assert (out / "manifest.json").is_file()
    assert not (out.parent / (out.name + ".previous")).exists()
    assert not (out.parent / (out.name + ".staging")).exists()


def test_a_leftover_bundle_at_the_aside_path_does_not_block_a_build(tmp_path):
    """A crash between the two renames leaves a REAL bundle there; the next build proceeds.

    The leftover is produced by the build rather than hand-written, because the aside path
    is verified against its manifest's own digest now: a directory with a hand-made
    ``manifest.json`` is correctly refused, since that is what an operator's own directory
    using bundle names looks like.
    """
    mod = load_build()
    crew = _crew(mod, tmp_path)
    out = tmp_path / "bundle"
    _build(mod, crew, out)
    # A genuine bundle, built and then moved to where a crash would have left it.
    spare = tmp_path / "spare"
    _build(mod, crew, spare)
    stale = out.parent / (out.name + ".previous")
    spare.rename(stale)
    _build(mod, crew, out)
    assert (out / "manifest.json").is_file()
    assert not stale.exists()


def test_a_hand_written_manifest_at_the_aside_path_is_refused(tmp_path):
    """Owned names and plain shapes are both satisfied by a directory someone else made."""
    mod = load_build()
    crew = _crew(mod, tmp_path)
    out = tmp_path / "bundle"
    _build(mod, crew, out)
    theirs = out.parent / (out.name + ".previous")
    theirs.mkdir()
    (theirs / "manifest.json").write_text('{"notes": "mine"}\n', encoding="utf-8")
    (theirs / "agent.json").write_text('{"mine": true}\n', encoding="utf-8")
    with pytest.raises(mod.ExportRefused, match="does not match the bundle"):
        _build(mod, crew, out)
    assert (theirs / "manifest.json").read_text(encoding="utf-8") == '{"notes": "mine"}\n'


def test_the_aside_path_holding_someone_elses_files_is_refused(tmp_path):
    """The name is derived from --out, so that directory can be the operator's own."""
    mod = load_build()
    crew = _crew(mod, tmp_path)
    out = tmp_path / "bundle"
    _build(mod, crew, out)
    theirs = out.parent / (out.name + ".previous")
    theirs.mkdir()
    (theirs / "quarterly-report.xlsx").write_bytes(b"not mine to delete")
    with pytest.raises(mod.ExportRefused, match="does not own"):
        _build(mod, crew, out)
    assert (theirs / "quarterly-report.xlsx").read_bytes() == b"not mine to delete"
    assert (out / "manifest.json").is_file(), "the refusal must not disturb --out either"


def test_a_shape_this_build_never_writes_at_the_aside_path_is_refused(tmp_path):
    """An owned NAME is not enough: the delete is recursive."""
    mod = load_build()
    crew = _crew(mod, tmp_path)
    out = tmp_path / "bundle"
    _build(mod, crew, out)
    theirs = out.parent / (out.name + ".previous")
    (theirs / "skills").mkdir(parents=True)
    os.symlink(tmp_path / "elsewhere", theirs / "skills" / "link")
    with pytest.raises(mod.ExportRefused, match="shape this build never writes"):
        _build(mod, crew, out)
    assert (theirs / "skills" / "link").is_symlink()


def test_a_file_at_the_aside_path_is_refused_not_crashed_on(tmp_path):
    """`exists()` is true for a file and `iterdir()` would raise NotADirectoryError."""
    mod = load_build()
    crew = _crew(mod, tmp_path)
    out = tmp_path / "bundle"
    _build(mod, crew, out)
    stray = out.parent / (out.name + ".previous")
    stray.write_text("someone's note\n", encoding="utf-8")
    with pytest.raises(mod.ExportRefused, match="not a directory"):
        _build(mod, crew, out)
    assert stray.read_text(encoding="utf-8") == "someone's note\n"
