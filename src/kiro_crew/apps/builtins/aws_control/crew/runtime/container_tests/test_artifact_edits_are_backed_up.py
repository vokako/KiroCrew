"""An artifact edit must reach the bucket. "Artifact" was treated as "write-once".

``run_backup_cycle`` skipped any object under the artifact prefix once it had been uploaded
before, on a comment that said "artifacts are never rewritten". That is false, and the
gateway's own store says so: ``ArtifactStore._write_artifact`` rewrites ``current.html`` and
``meta.json`` at the SAME path on every update, and only ``versions/<n>.html`` is a new file
per version. So the skip dropped every edit after the first, permanently -- the bucket held
version 1 while the task served version 7, and a task replacement restored the stale one.

The skip is kept for the versions directory, which is what it was reasoning about and where
the volume is. The live pair is hashed like any other file.
"""

from __future__ import annotations

import os

from container.backup import layout, run_backup_cycle, run_sidecar
from container.backup.state import BackupState, state_path
from container.backup.store import InMemoryObjectStore

from .test_backup_sidecar import _fk, _write, make_settings


def test_an_edited_artifact_reaches_the_bucket(tmp_path) -> None:
    """The finding, stated as the property it broke."""
    s = make_settings(tmp_path)
    store = InMemoryObjectStore()
    state = BackupState()
    live = s.artifacts_dir / "slug1" / "current.html"
    key = _fk(s, "data/artifacts/slug1/current.html")

    _write(live, b"<p>version 1</p>")
    run_backup_cycle(s, store, state)
    assert store.get(key) == b"<p>version 1</p>"

    _write(live, b"<p>version 2, edited</p>")
    run_backup_cycle(s, store, state)
    assert store.get(key) == b"<p>version 2, edited</p>", "the edit never reached the bucket"


def test_an_unchanged_artifact_is_still_not_re_uploaded(tmp_path) -> None:
    """Non-vacuity: removing the skip entirely would pass the test above.

    What the write-once skip bought was avoiding a re-hash and a re-upload of content that
    cannot change. That still has to hold, or this trades a correctness bug for a cost one.
    """
    s = make_settings(tmp_path)
    store = InMemoryObjectStore()
    state = BackupState()
    live = s.artifacts_dir / "slug1" / "current.html"
    snap = s.artifacts_dir / "slug1" / "versions" / "1.html"
    _write(live, b"<p>v1</p>")
    _write(snap, b"<p>v1</p>")

    run_backup_cycle(s, store, state)
    second = run_backup_cycle(s, store, state)

    assert store.put_count[_fk(s, "data/artifacts/slug1/current.html")] == 1
    assert store.put_count[_fk(s, "data/artifacts/slug1/versions/1.html")] == 1
    # Both were spared, by different mechanisms: the snapshot by the write-once skip, the
    # unchanged live body by the hash. Asserted separately so a regression in either shows.
    assert second.skipped_artifact >= 1, "the snapshot did not take the write-once path"
    assert second.skipped_unchanged >= 1, "the live body did not take the hash path"


def test_a_version_snapshot_keeps_the_write_once_skip(tmp_path) -> None:
    """A snapshot is spared without hashing, which is what lets a restart stay cheap."""
    s = make_settings(tmp_path)
    store = InMemoryObjectStore()
    snap = s.artifacts_dir / "slug1" / "versions" / "1.html"
    live = s.artifacts_dir / "slug1" / "current.html"
    _write(snap, b"payload")
    _write(live, b"<p>live</p>")
    run_sidecar(s, store=store, max_cycles=1)

    os.unlink(state_path(s))  # a restart: local state gone, bucket intact
    run_sidecar(s, store=store, max_cycles=1)

    assert store.put_count[_fk(s, "data/artifacts/slug1/versions/1.html")] == 1
    # The live body IS re-uploaded, because seeding recovers sizes and not hashes. Pinned so
    # the cost is a recorded decision rather than something a later reader has to rediscover.
    assert store.put_count[_fk(s, "data/artifacts/slug1/current.html")] == 2


def test_the_write_once_predicate_reads_a_path_component(tmp_path) -> None:
    """A slug containing the word must not claim the exemption."""
    s = make_settings(tmp_path)
    prefix = layout.artifact_prefix(s)
    assert layout.is_write_once_artifact(s, prefix + "slug1/versions/3.html")
    assert not layout.is_write_once_artifact(s, prefix + "slug1/current.html")
    assert not layout.is_write_once_artifact(s, prefix + "slug1/meta.json")
    assert not layout.is_write_once_artifact(s, prefix + "my-versions-slug/current.html")
    assert not layout.is_write_once_artifact(s, "data/sessions/abc.jsonl")
