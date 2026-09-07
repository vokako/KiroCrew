"""The sidecar's on-disk memory of what it has already uploaded.

Two reasons this is persisted rather than kept in RAM:

* Cost. Re-hashing every artifact on every cycle would make single-cycle work
  grow with total history. The state lets the sidecar skip write-once artifacts
  it has already seen and re-hash only the small, mutable transcripts.
* Visibility. The design accepts that backup lags live conversation, but
  requires the lag to be *readable* by the owner. The last-cycle timestamp is
  recorded here so ``sidecar.backup_status`` can report the exposure window.

The state file lives beside the data home but OUTSIDE the backup unit, so it is
never itself uploaded or restored.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeGuard

from ..common import Settings

STATE_FILENAME = ".smc_backup_state.json"


def _finite_number(value: object) -> TypeGuard[int | float]:
    """A real, usable number: not a bool, not NaN, not an infinity.

    Declared as a ``TypeGuard`` rather than ``bool`` so the ``int(...)`` calls that follow
    narrow correctly; with a plain ``bool`` return mypy still saw ``Any | None`` at the
    conversion and rejected it.

    ``isinstance(x, (int, float))`` alone is not enough, and the gap is reachable by the
    agent. ``json.loads`` turns ``1e999`` into ``float('inf')`` and ``NaN`` into
    ``float('nan')`` -- both genuine ``float`` instances -- and ``int()`` then raises
    ``OverflowError`` / ``ValueError``. Measured on all four spellings, each of which broke
    ``BackupState.load``'s "NEVER raise" contract and so killed the sidecar; the supervisor
    treats a dead sidecar as a dead task, which on ECS is a boot loop.

    An infinity also has to be refused where it does NOT raise. ``last_cycle_ts`` accepted
    it happily, and a timestamp of ``inf`` makes every elapsed-time comparison in
    ``backup_status`` meaningless while looking like a valid reading.

    ``bool`` is excluded because ``isinstance(True, int)`` is True.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value)


def state_path(settings: Settings) -> Path:
    return settings.data_home / STATE_FILENAME


@dataclass
class ObjMeta:
    size: int
    hash: str  # sha256 hex, or "" when only the size is known (seeded from S3)


@dataclass
class BackupState:
    objects: dict[str, ObjMeta] = field(default_factory=dict)
    cycles: int = 0
    last_cycle_ts: float | None = None
    last_success_ts: float | None = None

    # --- persistence -------------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "BackupState":
        """Read the state, or start fresh. NEVER raise: a crash here ends the task.

        The parse was already guarded, but everything after it assumed the decoded
        shape. This file sits in the crew's own data home, which the agent can write,
        so the shape is attacker-controlled in the only sense that matters here -- an
        unattended crew with an auto-approved shell. Each of these ended the sidecar
        process, and the supervisor treats a dead sidecar as a dead task:

        * ``{"objects": []}``   -> ``.items()`` on a list -> AttributeError
        * ``[]`` or ``"x"``     -> ``.get`` on a list or str -> AttributeError
        * ``{"objects": {"a": {"size": "big"}}}`` -> ``int("big")`` -> ValueError
        * ``{"objects": {"a": {"size": {}}}}``    -> ``int({})``    -> TypeError
        * ``{"cycles": "many"}``                  -> ``int("many")`` -> ValueError
        * ``{"last_cycle_ts": "soon"}``           -> passes here, then breaks the
          arithmetic in ``backup_status`` a cycle later, which is worse than failing
          now because the traceback names the wrong module.

        Falling back to a fresh state is the behaviour the parse failure already had.
        It costs a re-hash of the backup unit, which is the cheap direction: the
        alternative on this path is the task dying.
        """
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError):
            return cls()
        if not isinstance(raw, dict):
            return cls()

        raw_objects = raw.get("objects")
        objects: dict[str, ObjMeta] = {}
        if isinstance(raw_objects, dict):
            for k, v in raw_objects.items():
                if not isinstance(k, str) or not isinstance(v, dict):
                    continue
                size = v.get("size")
                if not _finite_number(size):
                    continue
                digest = v.get("hash", "")
                objects[k] = ObjMeta(int(size), digest if isinstance(digest, str) else "")

        cycles = raw.get("cycles", 0)
        if not _finite_number(cycles):
            cycles = 0

        def _ts(value: object) -> float | None:
            # A string here survived the old load and broke backup_status's arithmetic
            # one cycle later, in a module that had done nothing wrong. Infinity is the
            # same defect wearing a number: it passes every isinstance check and then
            # makes every elapsed-time comparison meaningless.
            if not _finite_number(value):
                return None
            return float(value)

        return cls(
            objects=objects,
            cycles=int(cycles),
            last_cycle_ts=_ts(raw.get("last_cycle_ts")),
            last_success_ts=_ts(raw.get("last_success_ts")),
        )

    def save(self, path: Path) -> None:
        payload = {
            "objects": {k: {"size": m.size, "hash": m.hash} for k, m in self.objects.items()},
            "cycles": self.cycles,
            "last_cycle_ts": self.last_cycle_ts,
            "last_success_ts": self.last_success_ts,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # --- seeding -----------------------------------------------------------

    def seed_sizes(self, sizes: dict[str, ObjMeta | int]) -> None:
        """Prime the index from an S3 listing after a fresh task start.

        Only sizes are known from a listing, so hashes stay ``""``. That is
        enough for the write-once artifact skip (which checks presence), while
        mutable transcripts are safely re-hashed once because ``""`` never
        equals a real hash.
        """
        for key, meta in sizes.items():
            if key in self.objects:
                continue
            size = meta.size if isinstance(meta, ObjMeta) else int(meta)
            self.objects[key] = ObjMeta(size, "")


def backup_status(settings: Settings, *, now: float | None = None) -> dict:
    """The owner-readable backup metric: how stale is the backup, right now.

    ``lag_secs`` is the age of the last completed cycle. ``None`` means no cycle
    has completed yet (the exposure is the whole conversation, not a bounded
    window) -- reported as such rather than as zero.
    """
    st = BackupState.load(state_path(settings))
    now = time.time() if now is None else now
    lag = None if st.last_success_ts is None else max(0.0, now - st.last_success_ts)
    return {
        "lag_secs": lag,
        "last_success_ts": st.last_success_ts,
        "last_cycle_ts": st.last_cycle_ts,
        "cycles": st.cycles,
        "objects": len(st.objects),
    }
