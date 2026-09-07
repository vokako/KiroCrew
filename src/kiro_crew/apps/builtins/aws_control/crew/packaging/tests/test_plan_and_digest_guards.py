"""Guards on the curation plan and the manifest digest.

``is_dir()`` and ``is_file()`` follow links, so they answer about the TARGET when what
matters is the ENTRY. ``_is_shape_this_build_never_writes`` answers about shape when what
matters is origin. The reparse walk ran after ``resolve()``, so it answered about the
resolved path when what matters is the one that was written down. And the encoded-credential
detector answered "nothing found" when the truth was "nothing looked".

R1 the chain check ran too late -- ``_resolve_prompt_path`` resolved before checking, and
   resolve IS the traversal: on Windows following a reparse point that names a share is the
   outbound SMB probe with its NTLM exchange, and resolve also COLLAPSES the links, so a walk
   placed after it can never see one. The previous version passed its own tests only because
   they called it directly with an unresolved path, which is not what the call site passes.

R2 the redactor fallback -- encoded detection vanished silently when ``kiro_crew`` was not
   importable, which is the documented standalone mode.

R3 empty directories -- verified by neither the top-level name check, the shape check, nor
   the file digest, then removed by the recursive delete.

R4 a symlinked output root -- ``is_dir()`` accepted a link to a directory, so the build
   created and deleted inside the link's target.

R5 the report write -- truncated whatever was at ``<out>.smc-bundle.json``.

R6 (Opus) ``read_plan`` -- ``UnicodeDecodeError`` is a ``ValueError``, neither an ``OSError``
   nor a ``JSONDecodeError``, so a plan that is not valid UTF-8 escaped the handler.
"""

from __future__ import annotations

import base64
import pathlib

import pytest

from .test_producer import load_build, make_crew, sign_plan

_DOC_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
_NO_REDACTOR = (
    "    _CANONICAL_REDACTOR: Callable[[str], tuple[str, list[str]]] | None = redact_credentials",
    "    _CANONICAL_REDACTOR = None",
)


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
# R1
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# R2
# ---------------------------------------------------------------------------
def test_encoded_credentials_are_found_without_the_canonical_redactor() -> None:
    """Standalone mode must not silently stop looking."""
    mod = load_build(mutate=_NO_REDACTOR)
    assert mod._CANONICAL_REDACTOR is None, "the mutation did not take"
    encoded = base64.b64encode(f"aws_secret_access_key = {_DOC_SECRET}".encode()).decode()
    kinds = [leak.kind for leak in mod.scan_text(encoded, "t")]
    assert kinds, "the standalone fallback found nothing"
    assert any(k.startswith("encoded-") for k in kinds), kinds


def test_the_standalone_fallback_does_not_flag_ordinary_text() -> None:
    """Non-vacuity: a decoder that reported everything would pass the test above.

    The long alphanumeric strings here are the false positives that matter -- a digest, a
    token-shaped id -- because a scanner that refuses those makes the build unusable.
    """
    mod = load_build(mutate=_NO_REDACTOR)
    for text in (
        "# FAQ\nStore hours are 9 to 6.\n",
        "digest: 9f8c2b1e4a7d6f3b8e2c5a9d1f4b7e0c3a6d9f2b5e8c1a4d7f0b3e6c9a2d5f8b\n",
        "# Encoding\nUse base64 for binary payloads.\n",
    ):
        assert not mod.scan_text(text, "t"), text


def test_the_literal_pass_is_unaffected_by_the_fallback() -> None:
    """A literal credential is still found, with or without the redactor."""
    mod = load_build(mutate=_NO_REDACTOR)
    assert mod.scan_text(f"aws_secret_access_key = {_DOC_SECRET}", "t")


# ---------------------------------------------------------------------------
# R3
# ---------------------------------------------------------------------------
def test_the_empty_directory_guard_names_the_directory(tmp_path: pathlib.Path) -> None:
    """Rebuilding over a bundle with an extra empty directory refuses and says which."""
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    work = tmp_path / "work"
    _build(mod, home, work, {"skills": {"faq"}})
    (work / "bundle" / "skills" / "notes").mkdir()

    crew = mod.resolve_crew("frontdesk", home)
    spec = mod.read_agent_spec(crew)
    cands = mod.enumerate_all(crew, spec)
    plan = mod.merge_plans(
        [sign_plan(mod, crew, spec, tmp_path / "w2", select={"skills": {"faq"}})], "frontdesk"
    )
    mod.verify(plan, "frontdesk", cands)
    with pytest.raises(mod.ExportRefused) as caught:
        mod.build_bundle(crew, spec, cands, plan, work / "bundle")
    assert "no file this build would have written" in str(caught.value)
    assert "skills/notes" in str(caught.value)


def test_the_builders_own_empty_skills_directory_is_accepted(tmp_path: pathlib.Path) -> None:
    """A bundle with no skills selected leaves an empty ``skills/``, and must rebuild.

    Measured, not assumed: the first version of this guard refused it and reddened 13 tests.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    work = tmp_path / "work"
    _build(mod, home, work, {"skills": set()})
    assert (work / "bundle" / "skills").is_dir()
    assert not any((work / "bundle" / "skills").iterdir())
    _build(mod, home, work, {"skills": set()})


# ---------------------------------------------------------------------------
# R4
# ---------------------------------------------------------------------------
def test_a_symlinked_output_root_is_refused(tmp_path: pathlib.Path) -> None:
    """``is_dir()`` follows the link, so the entry has to be judged first.

    The target is EMPTY on purpose. A target holding the operator's own files trips the older
    "holds files this build does not own" check, which would make this test pass with the new
    guard removed -- measured: it did. Empty, and a valid previous bundle, are the cases only
    this guard covers, and they are the ordinary ones for a deliberately placed link.
    """
    mod = load_build()
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    real = tmp_path / "somewhere-else"
    real.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    (work / "bundle").symlink_to(real, target_is_directory=True)

    with pytest.raises(mod.ExportRefused) as caught:
        _build(mod, home, work, {"skills": {"faq"}})
    assert "symlink" in str(caught.value)
    assert (work / "bundle").is_symlink(), "the operator's link was replaced"


def test_what_the_symlinked_root_guard_prevents(tmp_path: pathlib.Path) -> None:
    """The harm is stated as a test so the refusal is not defended by a guess.

    With the guard mutated off, the build succeeds and the link at ``--out`` is gone: the
    promotion replaced it with a real directory. That is the loss -- not a write into the
    target, which is what an earlier version of this comment claimed without measuring.
    """
    mod = load_build(mutate=("        if _is_redirecting_entry(candidate):", "        if False:"))
    home = make_crew(tmp_path / "home", skills={"faq": {"SKILL.md": "# FAQ\n"}})
    real = tmp_path / "somewhere-else"
    real.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    (work / "bundle").symlink_to(real, target_is_directory=True)

    _build(mod, home, work, {"skills": {"faq"}})
    assert not (work / "bundle").is_symlink(), "the link survived, so the guard is unnecessary"
    assert not (real / "manifest.json").exists(), "the bundle did land in the target after all"


# ---------------------------------------------------------------------------
# R6
# ---------------------------------------------------------------------------
def test_a_plan_that_is_not_utf8_is_refused_cleanly(tmp_path: pathlib.Path) -> None:
    """``UnicodeDecodeError`` is a ``ValueError``, so the narrower tuple let it escape."""
    mod = load_build()
    bad = tmp_path / "curation-plan.json"
    bad.write_bytes(b'{"plan_version": 1, "note": "\xff\xfe not utf-8"}')
    with pytest.raises(mod.ExportRefused) as caught:
        mod.read_plan(bad)
    assert "not valid JSON" in str(caught.value)


def test_a_plan_that_is_valid_utf8_but_bad_json_is_still_refused(tmp_path: pathlib.Path) -> None:
    """Non-vacuity: the wider tuple must still cover what the narrower one did."""
    mod = load_build()
    bad = tmp_path / "curation-plan.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(mod.ExportRefused):
        mod.read_plan(bad)
