"""A backup ROOT replaced with a symlink was followed, and everything under it uploaded.

Every per-entry guard in ``iter_backup_files`` was already careful: ``os.walk`` runs with
``followlinks=False``, symlinked subdirectories are pruned from ``dirnames``, symlinked
files are skipped, and each target must resolve inside the root. All of it assumed the root
itself was trustworthy.

``os.walk(top, followlinks=False)`` refuses to DESCEND into a symlinked subdirectory but
always follows the ``top`` argument. Measured before this suite existed: with the root
replaced by a link to ``/proc/self``, the walk listed 45 entries, ``environ`` passed
``os.path.isfile``, was not itself a link, and passed containment -- because ``real_root``
was derived from the followed link too. Every guard agreed to upload the task's own
credentials to the owner's bucket.

``artifacts_dir`` is one of these roots and the agent writes into that tree by design, with
a backend that auto-approves every tool, so the swap is a reachable input rather than a
theoretical one.
"""

from __future__ import annotations

import os
import pathlib
import shutil

import pytest
from container.backup import layout


class _Settings:
    """The parts of Settings that layout reads."""

    def __init__(self, home: pathlib.Path) -> None:
        self.data_home = home
        self.sessions_dir = home / "sessions"
        self.archive_dir = home / "sessions" / "archive"
        self.artifacts_dir = home / "artifacts"
        self.session_map_path = home / "session_map.json"
        self.open_slots_path = home / "open_slots.json"

    def backup_unit(self) -> list[pathlib.Path]:
        return [
            self.sessions_dir,
            self.archive_dir,
            self.session_map_path,
            self.open_slots_path,
            self.artifacts_dir,
        ]


def _home(tmp_path: pathlib.Path) -> _Settings:
    s = _Settings(tmp_path / "home")
    s.sessions_dir.mkdir(parents=True)
    (s.sessions_dir / "conversation.json").write_text("{}", encoding="utf-8")
    return s


def test_a_root_symlinked_to_proc_yields_nothing_from_it(tmp_path):
    s = _home(tmp_path)
    os.symlink("/proc/self", s.artifacts_dir)
    got = list(layout.iter_backup_files(s))
    assert not any("/proc" in os.path.realpath(p) for p, _, _ in got)
    assert not any(p.name == "environ" for p, _, _ in got)


def test_the_legitimate_roots_are_unaffected_by_one_bad_root(tmp_path):
    """A refused root must not stop the backup: the rest of the unit still uploads."""
    s = _home(tmp_path)
    os.symlink("/proc/self", s.artifacts_dir)
    got = list(layout.iter_backup_files(s))
    assert any(p.name == "conversation.json" for p, _, _ in got)


def test_a_root_symlinked_inside_the_home_is_still_refused(tmp_path):
    """The rule is "a root must be a real directory", not "must not point at /proc"."""
    s = _home(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "planted.json").write_text("{}", encoding="utf-8")
    os.symlink(elsewhere, s.artifacts_dir)
    got = list(layout.iter_backup_files(s))
    assert not any(p.name == "planted.json" for p, _, _ in got)


def test_a_file_where_a_root_should_be_is_reported_not_silently_empty(tmp_path, caplog):
    """O_DIRECTORY turns this into a logged ENOTDIR instead of a walk that finds nothing.

    Without it the open succeeds -- a regular file is not a link -- and ``os.walk`` on a
    file yields nothing while swallowing the error, so the root vanishes from the backup
    with no record. A backup that silently loses a root looks exactly like a root that was
    legitimately empty, which is the failure mode that hides data loss until a restore.
    """
    s = _home(tmp_path)
    s.artifacts_dir.write_text("not a directory\n", encoding="utf-8")
    with caplog.at_level("WARNING"):
        got = list(layout.iter_backup_files(s))
    assert any(p.name == "conversation.json" for p, _, _ in got)
    assert not any(p.name == "artifacts" for p, _, _ in got)
    assert any(
        "artifacts" in r.getMessage() for r in caplog.records
    ), "the skipped root was not reported"


def test_a_real_root_is_walked_normally(tmp_path):
    s = _home(tmp_path)
    s.artifacts_dir.mkdir()
    (s.artifacts_dir / "chart.png").write_bytes(b"\x89PNG")
    nested = s.artifacts_dir / "sub"
    nested.mkdir()
    (nested / "deep.txt").write_text("x", encoding="utf-8")
    got = list(layout.iter_backup_files(s))
    names = {p.name for p, _, _ in got}
    assert {"chart.png", "deep.txt", "conversation.json"} <= names


def test_a_swap_landing_after_the_open_reaches_nothing(tmp_path, monkeypatch):
    """A root that becomes a link AFTER it was opened must not redirect the walk.

    The O_NOFOLLOW open refuses a root that is ALREADY a link; it cannot refuse one that
    changes afterwards. What covers that now is WHERE the walk starts: ``os.fwalk`` descends
    from the descriptor, so nothing looks the root's name up a second time and renaming it
    has no effect at all. The previous version walked by path and would have followed it.

    Made deterministic by performing the swap at the moment enumeration begins.
    """
    s = _home(tmp_path)
    s.artifacts_dir.mkdir()
    (s.artifacts_dir / "chart.png").write_bytes(b"\x89PNG")
    real_fwalk = os.fwalk
    swapped: list[str] = []

    def _swap_then_fwalk(*a, **kw):
        if not swapped:
            swapped.append("done")
            shutil.rmtree(s.artifacts_dir)
            os.symlink("/proc/self", s.artifacts_dir)
        return real_fwalk(*a, **kw)

    monkeypatch.setattr(layout.os, "fwalk", _swap_then_fwalk)
    got = list(layout.iter_backup_files(s))
    assert swapped, "the test did not exercise the swap"
    assert not any(p.name == "environ" for p, _, _ in got)
    assert not any("/proc" in os.path.realpath(p) for p, _, _ in got)
    assert any(p.name == "conversation.json" for p, _, _ in got)


def test_the_reader_refuses_a_symlinked_root(tmp_path):
    """The other half of the same gap: enumeration is one side, reading is the other.

    ``iter_backup_files`` hands back a PATH, because that is what the uploader takes, so
    the reader is where a swap landing between enumeration and read has to fail.
    ``_open_nofollow_under`` walked every component under the root with ``O_NOFOLLOW`` and
    opened the ROOT normally, justified in its own docstring by "it is the container's own
    data home, fixed by the task definition, not something the agent names" -- true of the
    name, false of its destination, since ``artifacts_dir`` is one of these roots and the
    agent writes there by design.
    """
    from container.backup import sidecar

    real = tmp_path / "real"
    real.mkdir()
    (real / "secret.json").write_text("not to be read through a link\n", encoding="utf-8")
    link = tmp_path / "artifacts"
    os.symlink(real, link)

    with pytest.raises(OSError):
        sidecar._read_nofollow(link / "secret.json", link)


def test_the_reader_still_reads_through_a_real_root(tmp_path):
    from container.backup import sidecar

    root = tmp_path / "artifacts"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "chart.json").write_text("{}", encoding="utf-8")
    assert sidecar._read_nofollow(root / "sub" / "chart.json", root) == b"{}"


def test_a_symlinked_root_is_reported(tmp_path, caplog):
    """Silence would make a shrinking backup look like an empty directory."""
    s = _home(tmp_path)
    os.symlink("/proc/self", s.artifacts_dir)
    with caplog.at_level("WARNING"):
        list(layout.iter_backup_files(s))
    assert any("artifacts" in r.getMessage() for r in caplog.records)
