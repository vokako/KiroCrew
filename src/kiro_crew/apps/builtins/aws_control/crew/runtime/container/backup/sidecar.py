"""The asynchronous backup sidecar: the long-running copier.

One public seam, ``run_sidecar(settings)`` (see ``container/CONTRACT.md``). The
real work is factored into ``run_backup_cycle`` so a single pass can be tested
directly against a fake store and real temporary files.

Three on-disk facts shape the copier, each proven wrong-if-ignored by a test:

1. The transcript is atomically replaced, sometimes shorter. So we upload whole
   objects (``store.put`` has no offset/append). An incremental splice would be
   incorrect, not merely slow.
2. mtime is restored after every rewrite. So change detection is size PLUS a
   content hash, never mtime.
3. Writes hold a per-session advisory ``flock`` on ``<transcript>.lock``. So a
   read of a live transcript takes a shared ``flock`` on the same sidecar file
   and waits, rather than reading a half-replaced file.

Artifacts are write-once and heavy: an object already recorded in the state is
skipped without being re-hashed.
"""

from __future__ import annotations

import hashlib
import logging
import os
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..common import Settings
from . import layout
from .state import BackupState, ObjMeta, backup_status, state_path
from .store import ObjectStore, S3ObjectStore

logger = logging.getLogger("smc.backup.sidecar")

# How long a single file read will wait for the writer's lock before giving up
# for this cycle. Bounded so one wedged writer cannot stall the whole loop; the
# file is simply retried next cycle. The design accepts lag.
LOCK_WAIT_SECS = 5.0
_LOCK_POLL_SECS = 0.05

#: Largest file this cycle reads into memory as one ``bytes``, in bytes.
#:
#: A file at or below this is read whole and change-detected by size PLUS a content hash.
#: A file ABOVE it is not read into memory at all: it is streamed to the bucket through
#: ``ObjectStore.put_stream`` (boto3's ``upload_fileobj``, which transfers in bounded chunks
#: and negotiates multipart itself), and change-detected by size only. So this is the
#: threshold between the in-memory path and the streaming path, NOT a size above which a
#: file is dropped -- every regular file is made durable regardless of size, which matters
#: because the agent writes into ``artifacts_dir`` by design and nothing bounds what it
#: writes. Memory no longer scales with the largest file a cycle touches; it scales with the
#: hash buffer for small files and boto3's chunk size for large ones.
#:
#: 256 MiB because reading a file this small whole is cheaper than the multipart machinery,
#: while it stays far above any transcript or config file (kilobytes). Override with
#: ``SMC_MAX_BACKUP_FILE_BYTES`` to move the in-memory/streaming boundary; correctness does
#: not depend on where it sits, only cost does.
MAX_BACKUP_FILE_BYTES = 256 * 1024 * 1024

__all__ = ["run_sidecar", "run_backup_cycle", "CycleResult", "backup_status"]


@dataclass
class CycleResult:
    scanned: int = 0
    uploaded: int = 0
    skipped_unchanged: int = 0
    skipped_artifact: int = 0
    deferred_locked: int = 0
    skipped_too_large: int = 0
    uploaded_bytes: int = 0


#: Guarded because NEITHER constant exists on every platform; see the twin in
#: ``packaging/build.py``. They are separate on purpose -- this tree is the source
#: of a container image and cannot import that module -- and
#: ``test_backup_swap_race.py`` pins the two to the same value.
_NOFOLLOW_READ_FLAGS: int = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


class _Contended(Exception):
    """The writer's lock could not be taken within the wait budget."""


class _NotARegularFile(Exception):
    """What was opened is not a regular file, so it is not a backup candidate."""


class _TooLarge(Exception):
    """The file is past the memory ceiling, so it is not read into this process."""


def _open_nofollow_under(root: Path, path: Path) -> int:
    """Open ``path`` walking each component under ``root``, following no link at all.

    ``O_NOFOLLOW`` on a whole path constrains only the FINAL component, which this
    module said out loud it was not closing: an agent that controls a nested path can
    swap a PARENT directory for a link to ``/proc/self`` after validation, and the
    final-component check then happily opens ``environ``. The review asked for the
    real fix rather than the documented gap.

    So each component is opened relative to the previous descriptor with
    ``O_NOFOLLOW`` set, which makes a swapped directory fail at the component that
    was swapped instead of being traversed. ``root`` carries ``O_NOFOLLOW`` too.

    That last part is deliberately omitted, justified as "root itself is opened normally:
    it is the container's own data home, fixed by the task definition, not something the
    agent names". True of the PATH and false of what the path resolves to: the roots
    include ``artifacts_dir``, the agent writes into that tree by design, and replacing
    the directory with a link to ``/proc/self`` made this reader open the link's target.
    A claim about who controls a name is not a claim about who controls its destination.

    Falls back to a single ``O_NOFOLLOW`` open where ``dir_fd`` is unsupported
    (Windows). That is a real narrowing and is why it is spelled as a branch rather
    than hidden: the sidecar only runs inside the Linux image, so the fallback exists
    to keep the module importable and testable off-platform, not to be relied on.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_DIRECTORY"):
        return os.open(str(path), flags | (_NOFOLLOW_READ_FLAGS & ~getattr(os, "O_NOFOLLOW", 0)))

    rel = path.relative_to(root).parts
    dir_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in rel[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = nxt
        return os.open(rel[-1], flags | os.O_NONBLOCK, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)


def _read_nofollow(
    path: Path, root: Path | None = None, *, max_bytes: int = MAX_BACKUP_FILE_BYTES
) -> bytes:
    """Read ``path``, refusing a symlink AT OPEN TIME rather than before it.

    ``layout.enumerate_*`` already rejects a symlink it can see, but that check and
    this read are two separate moments, and the agent writes into this tree. Between
    them it can replace an enumerated regular file with a link to
    ``/proc/self/environ``, and the read would follow it and upload the task's own
    credentials to the owner's bucket. Checking harder beforehand cannot close that:
    the fix is to make the check and the read the same operation.

    ``O_NOFOLLOW`` fails with ``ELOOP`` when the final component is a link, and the
    ``fstat`` confirms that what was actually opened is a regular file -- so the bytes
    returned are the bytes of the thing that passed the test.

    EVERY component is checked, not just the last. When a ``root`` is given the path
    is walked one component at a time under it, each opened with ``O_NOFOLLOW``, so a
    swapped PARENT directory fails at the component that was swapped. Without a
    ``root`` this falls back to a single whole-path open, which constrains the final
    component only -- callers inside the backup tree always pass one.
    ``O_NONBLOCK`` is on the open for a reason found by test: a FIFO left in the tree
    makes a plain ``os.open`` block forever waiting for a writer, so the ``fstat``
    below never runs and every later backup cycle queues behind it. Opening
    non-blocking gets the descriptor first and lets the regular-file check do its job.
    It is cleared afterwards so the reads themselves are ordinary blocking reads.
    """
    if root is not None:
        fd = _open_nofollow_under(root, path)
    else:
        fd = os.open(str(path), os.O_RDONLY | _NOFOLLOW_READ_FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _NotARegularFile(str(path))
        # A regular file is confirmed, so restore blocking semantics before reading:
        # a non-blocking read on a regular file is fine, but clearing the flag keeps
        # the loop below identical to an ordinary read.
        # Only when O_NONBLOCK was actually applied. On Windows neither that flag
        # nor set_blocking() works on a regular-file descriptor -- it raises
        # WinError 87 -- and there is nothing to undo there anyway. Located by
        # reading the traceback: the previous attempt at this guessed os.read was
        # to blame and changed the wrong line.
        if getattr(os, "O_NONBLOCK", 0) and _NOFOLLOW_READ_FLAGS & os.O_NONBLOCK:
            os.set_blocking(fd, True)
        # Read through a file object rather than a raw os.read loop. A 1 MiB os.read
        # on Windows raises WinError 87 (invalid parameter), which reddened this on
        # the Windows shard; fdopen sizes its own buffers per platform. The
        # descriptor has already passed O_NOFOLLOW and the regular-file check, and
        # wrapping it changes neither -- closefd=False keeps the close in the
        # caller's finally, so there is exactly one close.
        with os.fdopen(fd, "rb", closefd=False) as fh:
            # Bounded at the READ, not by an earlier stat. A stat-then-read pair leaves the
            # bound advisory: the agent writes into this tree, so a file that measured small
            # can be extended before the read, and it is the read that allocates. Asking for
            # one byte past the ceiling is what makes "too large" observable without holding
            # a second copy -- if that byte arrives, the file is over and nothing more of it
            # is read.
            data = fh.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise _TooLarge(str(path))
        return data
    finally:
        os.close(fd)


def _stream_upload_nofollow(
    path: Path,
    store: "ObjectStore",
    key: str,
    root: Path | None = None,
    *,
    prev: "ObjMeta | None" = None,
) -> int | None:
    """Stream ``path`` to ``store`` under ``key`` without holding it in memory.

    The large-file counterpart to ``_read_nofollow``. It opens ``path`` under the
    same ``O_NOFOLLOW`` guard and confirms a regular file with ``fstat`` on the
    OPENED descriptor, then hands THAT open file object to ``store.put_stream`` --
    which streams it to the bucket in bounded chunks (boto3 owns the multipart
    negotiation). Passing the open object, not the path, is what keeps the pin:
    the descriptor uploaded is the one that passed the symlink and regular-file
    checks, so there is no window in which the name could be swapped for a link to
    ``/proc/self/environ`` between the check and the upload -- the same reason
    ``_read_nofollow`` reads the fd it fstat'd rather than re-opening by name.

    Change detection for a streamed file is SIZE ONLY, because hashing would need
    the read into memory this path exists to avoid. When ``prev`` is a prior
    streamed entry (``hash == ""``) whose size equals the size on the OPENED
    descriptor, the object is unchanged and nothing is uploaded: returns ``None``.
    The size is read from the same ``fstat`` that validated the file, so the
    comparison is against the descriptor that would have been uploaded, not a
    by-name stat that could disagree. Otherwise streams and returns the byte count.
    """
    if root is not None:
        fd = _open_nofollow_under(root, path)
    else:
        fd = os.open(str(path), os.O_RDONLY | _NOFOLLOW_READ_FLAGS)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _NotARegularFile(str(path))
        if prev is not None and prev.hash == "" and prev.size == st.st_size:
            return None
        if getattr(os, "O_NONBLOCK", 0) and _NOFOLLOW_READ_FLAGS & os.O_NONBLOCK:
            os.set_blocking(fd, True)
        with os.fdopen(fd, "rb", closefd=False) as fh:
            store.put_stream(key, fh)
        return st.st_size
    finally:
        os.close(fd)


def _read_locked(
    path: Path,
    lock_path: Path,
    wait_secs: float,
    root: Path | None = None,
    *,
    max_bytes: int = MAX_BACKUP_FILE_BYTES,
) -> bytes:
    """Read ``path`` while holding a shared ``flock`` on ``lock_path``.

    Polls ``LOCK_SH | LOCK_NB`` to a deadline instead of a bare blocking
    ``flock``, so the wait is bounded. The exclusive writer blocks us and we
    block no writer for longer than the read itself (a few milliseconds on a
    small transcript). Raises ``_Contended`` on timeout rather than reading
    through the lock.
    """
    fd = None
    try:
        # Imported HERE, not at module scope. ``fcntl`` is POSIX-only and this is
        # the one function that uses it, while the module around it is imported on
        # Windows by two things that have nothing to do with locking: this suite's
        # own collection, and an upstream repo-wide test that walks every module.
        # A module-level import made both fail with ModuleNotFoundError on Windows
        # even though the sidecar only ever runs inside the Linux image. Same
        # convention as this tree's boto3 imports: keep the package importable
        # where the capability is absent, and fail at the call instead.
        import fcntl

        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
        deadline = time.monotonic() + wait_secs
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise _Contended(str(path))
                time.sleep(_LOCK_POLL_SECS)
        try:
            return _read_nofollow(path, root, max_bytes=max_bytes)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        if fd is not None:
            os.close(fd)


def run_backup_cycle(
    settings: Settings,
    store: ObjectStore,
    state: BackupState,
    *,
    lock_wait_secs: float = LOCK_WAIT_SECS,
    max_file_bytes: int = MAX_BACKUP_FILE_BYTES,
) -> CycleResult:
    """One backup pass over the whole unit. Mutates ``state`` in place.

    Whole-object upload; size+hash change detection; write-once artifact skip;
    lock-respecting reads of live transcripts.
    """
    result = CycleResult()

    for local_path, rel_key, root in layout.iter_backup_files(settings):
        result.scanned += 1
        prev = state.objects.get(rel_key)

        # Write-once artifacts: skip the re-hash and re-upload only for a path that really
        # is written once.
        #
        # Note that "artifacts are never rewritten" would be false here.
        # ``ArtifactStore._write_artifact`` rewrites ``current.html`` and ``meta.json`` at the
        # SAME path on every update, and only ``versions/<n>.html`` is a new file each time.
        # So a presence-only skip over the whole artifact prefix dropped every edit after the
        # first, permanently and silently: the object in the bucket stayed at version 1 while
        # the task served version 7, and a task replacement restored the stale one.
        #
        # The skip is kept for the versions directory, which is what it was actually reasoning
        # about, and that is where the volume is -- a long-lived artifact accumulates snapshots
        # and none of them changes after it is written. The live pair is hashed like any other
        # file, which costs two small files per artifact per cycle.
        # ``prev is not None`` only, deliberately, and the trade is stated because a review
        # asked for the opposite. Requiring ``prev.hash`` would refuse a SEEDED entry, and
        # seeding is all a task restart has: ``store.list()`` returns sizes and no etag, so
        # every entry recovered from the bucket has ``hash == ""``. Demanding a hash there
        # does not add a hash -- it re-reads and re-hashes every historical snapshot on
        # every restart, which is the cost this skip exists to avoid and grows with the
        # artifact's whole history.
        #
        # What the skip gives up in exchange: a snapshot replaced by different bytes of the
        # SAME length, at a path nothing is supposed to rewrite, stays stale. Detecting that
        # needs a hash in the bucket listing, which is a change to the store interface, not
        # to this condition. Pinned by test_a_version_snapshot_keeps_the_write_once_skip.
        if prev is not None and layout.is_write_once_artifact(settings, rel_key):
            result.skipped_artifact += 1
            continue

        try:
            if layout.needs_lock(settings, local_path):
                lock_path = local_path.parent / (local_path.name + ".lock")
                data = _read_locked(
                    local_path, lock_path, lock_wait_secs, root, max_bytes=max_file_bytes
                )
            else:
                data = _read_nofollow(local_path, root, max_bytes=max_file_bytes)
        except _TooLarge:
            # Too large to hold in memory as one bytes object, so stream it to the
            # bucket instead of reading it. boto3's upload_fileobj (via
            # store.put_stream) transfers in bounded chunks and negotiates multipart
            # itself, so memory does not scale with the file size and the only copy
            # is NOT lost on task replacement. The agent can write an artifact of any
            # size into this tree, so this path is reachable in ordinary operation,
            # not an edge case.
            #
            # Change detection for a streamed file is SIZE ONLY: hashing would
            # require reading it into memory, which is the cost this path exists to
            # avoid. A size-only ObjMeta (hash == "") matches the shape a seeded
            # entry already has, so a subsequent cycle re-streams only when the size
            # changes. A same-size in-place rewrite of an oversized file is not
            # re-detected -- the same accepted limit the write-once artifact skip
            # documents, and artifacts above the ceiling are versioned files that are
            # not rewritten in place.
            try:
                streamed = _stream_upload_nofollow(
                    local_path,
                    store,
                    layout.full_key(settings, rel_key),
                    root,
                    prev=prev,
                )
            except _Contended:
                result.deferred_locked += 1
                logger.debug("backup: %s locked, deferring to next cycle", rel_key)
                continue
            except (_NotARegularFile, OSError) as exc:
                if isinstance(exc, FileNotFoundError):
                    continue
                logger.warning(
                    "backup: skipping %s, it is no longer the regular file it was "
                    "enumerated as (%s). Nothing is uploaded for it this cycle.",
                    rel_key,
                    exc,
                )
                continue
            if streamed is None:
                result.skipped_unchanged += 1
                continue
            state.objects[rel_key] = ObjMeta(streamed, "")
            result.uploaded += 1
            result.uploaded_bytes += streamed
            continue
        except _Contended:
            result.deferred_locked += 1
            logger.debug("backup: %s locked, deferring to next cycle", rel_key)
            continue
        except (_NotARegularFile, OSError) as exc:
            # OSError covers ELOOP from O_NOFOLLOW: the file that was enumerated as a
            # regular file is now a symlink. That is the race this reader exists to
            # lose safely, so skip the entry and say so -- FileNotFoundError keeps its
            # own quiet branch below because rotation is routine, while this is not.
            if isinstance(exc, FileNotFoundError):
                continue
            logger.warning(
                "backup: skipping %s, it is no longer the regular file it was "
                "enumerated as (%s). Nothing is uploaded for it this cycle.",
                rel_key,
                exc,
            )
            continue

        size = len(data)
        digest = hashlib.sha256(data).hexdigest()
        if prev is not None and prev.size == size and prev.hash == digest:
            result.skipped_unchanged += 1
            continue

        store.put(layout.full_key(settings, rel_key), data)
        state.objects[rel_key] = ObjMeta(size, digest)
        result.uploaded += 1
        result.uploaded_bytes += size

    return result


def _build_store(settings: Settings) -> ObjectStore | None:
    if not settings.backup_bucket:
        return None
    return S3ObjectStore(settings.backup_bucket)


def run_sidecar(
    settings: Settings,
    *,
    store: ObjectStore | None = None,
    stop: "threading.Event | None" = None,
    max_cycles: int | None = None,
) -> None:
    """Run the copier until ``stop`` is set (the container's normal case).

    ``store``/``stop``/``max_cycles`` exist for tests; the container calls this
    with only ``settings``. If no bucket is configured the sidecar logs and
    returns rather than crashing the task -- backup is then disabled, which is a
    degraded state the owner can see, not a dead container.
    """
    if store is None:
        store = _build_store(settings)
    if store is None:
        logger.warning(
            "backup: SMC_BACKUP_BUCKET is not set; backup is DISABLED for this "
            "task. Conversations will not survive the container."
        )
        return

    stop = stop or threading.Event()
    spath = state_path(settings)
    state = BackupState.load(spath)

    # Seed the object index from what is already in the bucket so a task restart
    # does not re-upload every write-once artifact.
    try:
        existing = store.list(layout.object_prefix(settings))
        seed: dict[str, ObjMeta | int] = {}
        for full, size in existing.items():
            rel = layout.rel_from_full(settings, full)
            if rel is not None:
                seed[rel] = size
        state.seed_sizes(seed)
    except Exception:  # noqa: BLE001 - seeding is an optimisation, never fatal
        logger.warning("backup: could not seed state from bucket", exc_info=True)

    n = 0
    while not stop.is_set():
        started = time.time()
        try:
            res = run_backup_cycle(
                settings, store, state, max_file_bytes=settings.max_backup_file_bytes
            )
            state.cycles += 1
            state.last_cycle_ts = time.time()
            state.last_success_ts = state.last_cycle_ts
            state.save(spath)
            logger.info(
                "backup cycle=%d scanned=%d uploaded=%d (%d B) unchanged=%d "
                "artifacts_skipped=%d deferred_locked=%d lag=0.0s",
                state.cycles,
                res.scanned,
                res.uploaded,
                res.uploaded_bytes,
                res.skipped_unchanged,
                res.skipped_artifact,
                res.deferred_locked,
            )
        except Exception:  # noqa: BLE001 - one bad cycle must not kill the loop
            logger.exception("backup: cycle failed; will retry next interval")

        n += 1
        if max_cycles is not None and n >= max_cycles:
            break
        elapsed = time.time() - started
        stop.wait(max(0.0, settings.backup_interval_secs - elapsed))
