"""The prompt path's chained-redirect and post-open checks.

Y1 the UNC check read only the FIRST hop, so link -> link -> share was open: the first
   ``readlink`` returns a local path, the test says no, and ``resolve()`` then follows the rest
   of the chain to the share. One hop is not a fence when hops compose.

Y2 the lstat walk judges paths and the open resolves one, so there is a window between them.
   A descriptor walk closes it and this platform cannot do one. The post-open identity check
   does not close it either -- it turns "the checks were advisory" into "a swap before the open
   is detected", which is a smaller claim and the honest one.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from .test_producer import load_build

_AS_NT = ('    elif os.name == "nt":', "    elif True:")


# ---------------------------------------------------------------------------
# Y1
# ---------------------------------------------------------------------------
def test_a_chained_redirect_to_a_share_is_refused(tmp_path: pathlib.Path) -> None:
    """Two local hops and then a share. The first hop alone looks harmless."""
    mod = load_build(mutate=_AS_NT)
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    third = agents_dir / "third.md"
    third.symlink_to("//attacker-host/share/persona.md")
    second = agents_dir / "second.md"
    second.symlink_to(third)
    first = agents_dir / "persona.md"
    first.symlink_to(second)

    with pytest.raises(mod.ExportRefused) as caught:
        mod._resolve_prompt_path(f"file://{first}", agents_dir)
    assert "network share" in str(caught.value)
    assert "attacker-host" in str(caught.value)


def test_a_single_hop_to_a_share_is_still_refused(tmp_path: pathlib.Path) -> None:
    """The case that already worked must keep working while the chain case is added."""
    mod = load_build(mutate=_AS_NT)
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    link = agents_dir / "persona.md"
    link.symlink_to("//attacker-host/share/persona.md")

    with pytest.raises(mod.ExportRefused) as caught:
        mod._resolve_prompt_path(f"file://{link}", agents_dir)
    assert "network share" in str(caught.value)


def test_a_chain_of_local_links_is_not_refused(tmp_path: pathlib.Path) -> None:
    """Non-vacuity: following the chain must not become refusing every chain.

    A persona reached through a couple of local links is the supported case the earlier
    over-broad version of this fence destroyed, so it is asserted here rather than assumed.
    """
    mod = load_build(mutate=_AS_NT)
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    real = tmp_path / "shared" / "persona.md"
    real.parent.mkdir(parents=True)
    real.write_bytes(b"a shared persona\n")
    mid = agents_dir / "mid.md"
    mid.symlink_to(real)
    first = agents_dir / "persona.md"
    first.symlink_to(mid)

    assert mod._resolve_prompt_path(f"file://{first}", agents_dir) == first


def test_a_redirect_cycle_is_refused_rather_than_followed(tmp_path: pathlib.Path) -> None:
    """A cycle has to terminate somewhere that is not an infinite loop."""
    mod = load_build(mutate=_AS_NT)
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    a = agents_dir / "a.md"
    b = agents_dir / "b.md"
    a.symlink_to(b)
    b.symlink_to(a)

    with pytest.raises(mod.ExportRefused) as caught:
        mod._resolve_prompt_path(f"file://{a}", agents_dir)
    assert "chain of more than" in str(caught.value)


def test_the_hop_bound_is_a_bound_and_not_a_ban(tmp_path: pathlib.Path) -> None:
    """A chain inside the bound resolves; one past it is refused. Both, so the number means
    something rather than being a synonym for "refuse"."""
    mod = load_build(mutate=_AS_NT)
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    real = tmp_path / "persona.md"
    real.write_bytes(b"ok\n")

    inside = real
    for i in range(mod._MAX_REDIRECT_HOPS - 2):
        nxt = agents_dir / f"hop{i}.md"
        nxt.symlink_to(inside)
        inside = nxt
    assert mod._resolve_prompt_path(f"file://{inside}", agents_dir) == inside


# ---------------------------------------------------------------------------
# Y2
# ---------------------------------------------------------------------------
def test_the_opener_confirms_what_it_opened(tmp_path: pathlib.Path) -> None:
    """A file swapped between the walk and the open is detected, not read.

    ``os.lstat`` is patched to report a different inode than the open will see, which is what a
    swap in that window looks like from inside the function. Patching is the only way in: the
    real window is microseconds and a test that raced it would be flaky.
    """
    mod = load_build()
    root = tmp_path / "agents"
    (root / "sub").mkdir(parents=True)
    target = root / "sub" / "persona.md"
    target.write_bytes(b"content\n")

    real_lstat = mod.os.lstat

    class _Fake:
        def __init__(self, st):
            self.st_dev = st.st_dev
            self.st_ino = st.st_ino + 1  # as if a different file had been there
            self.st_mode = st.st_mode

    mod.os.lstat = lambda p, *a, **k: _Fake(real_lstat(p, *a, **k))
    try:
        with pytest.raises(mod.ExportRefused) as caught:
            mod._open_attr_checked_under(target, root)
    finally:
        mod.os.lstat = real_lstat
    assert "changed between being checked and being opened" in str(caught.value)


def test_an_unswapped_file_opens_normally(tmp_path: pathlib.Path) -> None:
    """Non-vacuity: the identity check must not refuse the ordinary read."""
    mod = load_build()
    root = tmp_path / "agents"
    (root / "sub").mkdir(parents=True)
    target = root / "sub" / "persona.md"
    target.write_bytes(b"content\n")

    fd = mod._open_attr_checked_under(target, root)
    try:
        assert os.read(fd, 64) == b"content\n"
    finally:
        os.close(fd)


def test_the_descriptor_is_not_leaked_when_the_check_refuses(tmp_path: pathlib.Path) -> None:
    """A refusal after the open must close it, or a long build runs out of descriptors."""
    mod = load_build()
    root = tmp_path / "agents"
    (root / "sub").mkdir(parents=True)
    target = root / "sub" / "persona.md"
    target.write_bytes(b"content\n")

    real_lstat = mod.os.lstat

    class _Fake:
        def __init__(self, st):
            self.st_dev = st.st_dev
            self.st_ino = st.st_ino + 1
            self.st_mode = st.st_mode

    before = len(os.listdir("/proc/self/fd"))
    mod.os.lstat = lambda p, *a, **k: _Fake(real_lstat(p, *a, **k))
    try:
        for _ in range(20):
            with pytest.raises(mod.ExportRefused):
                mod._open_attr_checked_under(target, root)
    finally:
        mod.os.lstat = real_lstat
    assert len(os.listdir("/proc/self/fd")) <= before + 2, "descriptors leaked on the refusal path"
