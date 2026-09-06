"""The crew appearance library — the dashboard's OWN pack store.

Crews can wear an appearance pack (``agents.*.avatar = {"kind": "pack", "id":
...}``). The pack FORMAT is the one Crew Companion defined — a manifest plus
animation files — and ``AppearanceStore`` already reads and writes it, so this
module reuses that class rather than writing a second reader for the same files.

What it does NOT do is share Crew Companion's library. That app is independent:
it owns its own packs under its own data directory, gated on the app being
enabled, and nothing here reads or moves them. Crews get a second, separate
library rooted at the data home. Two stores of the same class, two directories,
no migration between them and no cross-reach in either direction. A user who
wants a Companion pack on a crew exports it from the gallery and imports it here
through ``POST /api/appearances/import`` — the bundle format is the same.

Why separate rather than shared: the two surfaces have different lifetimes (a
crew's face must render while the Companion app is disabled), different owners
(a dashboard route vs an app route), and different deletion rules (a crew may
still be wearing a pack). Every attempt to make one store serve both produced a
new hazard at the seam — a migration that could strand a pack, a gallery delete
that could blank a crew, an import cycle between the app package and the
dashboard. Keeping them apart removes the seam.

**Shape.** A lazily-built process-wide instance behind a ``threading.Lock``, the
same shape ``artifacts.get_default_store`` uses for the artifact store and for
the same reason: the first caller may be a request handler or a test, and neither
is a natural owner of construction. It is rooted per call through
``data_home()`` so a pod or a test with a ``KIROCREW_HOME`` override never
reaches the real install.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from kiro_crew.appearance_packs import safe_pack_id
from kiro_crew.config.paths import data_home
from kiro_crew.loop_lock import LoopBoundLock

if TYPE_CHECKING:
    from kiro_crew.apps.builtins.crew_companion.appearances import AppearanceStore

#: The crew library's directory under the data home. A directory of its own
#: rather than a bare ``appearances/`` at the top level, because the store keeps
#: its colour maps beside the packs and both belong to the same library.
LIBRARY_DIRNAME = "appearance-library"

_store: "AppearanceStore | None" = None
_store_lock = threading.Lock()

#: Serializes every MUTATION of the crew library (import, delete). ``LoopBoundLock``
#: rather than a bare ``asyncio.Lock``: it rebinds per running loop, which is the
#: repo-wide rule ``scripts/check_loop_bound_locks.py`` enforces. Ordering when
#: both are held: the agents config lock first, this one second.
_library_mutation_lock = LoopBoundLock()


def _library_lock() -> LoopBoundLock:
    return _library_mutation_lock


def library_dir() -> Path:
    """Where the crew library lives.

    Resolved per call, never bound at import: ``data_home()`` honours a
    ``KIROCREW_HOME`` override set after this module was imported, which is what
    keeps a pod, a dev backend and a test from reaching into the real install.
    """
    return data_home() / LIBRARY_DIRNAME


def get_appearance_store() -> "AppearanceStore":
    """The process-wide crew appearance store, built on first use."""
    # boot path: the store class lives inside the Crew Companion app package,
    # whose initializer imports its routes and, through them, `pack_transfer`
    # (which builds a urllib opener at module scope). The dashboard route table
    # imports this module before the socket binds, so importing the app here at
    # module scope would put that work on every gateway launch. First request
    # instead -- the same deferral `import_pack` below already applies.
    from kiro_crew.apps.builtins.crew_companion.appearances import AppearanceStore

    global _store
    with _store_lock:
        if _store is None:
            store = AppearanceStore(library_dir())
            store.load()
            _store = store
        return _store


async def crews_wearing(pack_id: str) -> list[str]:
    """The crews whose ``avatar`` names *pack_id*, sorted.

    Compared CASEFOLDED. A pack id is a directory name, and on macOS and Windows
    the filesystem treats ``Aurora`` and ``aurora`` as one directory — so a crew
    wearing ``Aurora`` is wearing whatever ``DELETE .../aurora`` would remove
    there, and an exact comparison found no wearer and let the delete through.
    The store already refuses case-colliding FILENAMES inside a pack on the same
    reasoning (``save_pack``'s ``seen_casefolded``); this is the same rule one
    level up. On a case-sensitive filesystem the fold can only over-report a
    wearer (refusing a delete of ``aurora`` because ``Aurora`` is worn), which
    costs one ``?force=1`` and never a pack.

    Read under the agents routes' config lock by the caller — see
    :func:`delete_pack_if_unworn`.
    """
    # circular import: config.loader reaches back into this package through the
    # dashboard handler tree, so the config model is imported at call time.
    from kiro_crew.config.loader import KiroCrewConfig

    wanted = pack_id.casefold()
    cfg = await asyncio.to_thread(KiroCrewConfig.load)
    return sorted(
        name
        for name, agent in cfg.agents.items()
        if agent.avatar.get("kind") == "pack"
        and isinstance(agent.avatar.get("id"), str)
        and agent.avatar["id"].casefold() == wanted
    )


async def delete_pack_if_unworn(pack_id: str, *, force: bool = False) -> tuple[bool, list[str]]:
    """Delete a custom pack unless a crew still wears it.

    Returns ``(deleted, wearers)``. ``wearers`` is non-empty only when the delete
    was REFUSED, so a caller distinguishes "still worn" from "no such pack" by
    that list rather than by re-deriving it.

    Three mechanics carry the guarantee:

    * The in-use read and the delete run under the agents routes' own config
      lock. Without it a crew save landing between them would leave exactly the
      reference the check exists to find.
    * The delete goes through ``_drained_to_thread``, so a cancelled request
      cannot release that lock with a directory removal still in flight.
    * The pack id is CANONICALIZED once, and the same canonical value drives both
      the wearer lookup and the delete. The store normalizes through
      ``safe_pack_id`` (which strips whitespace) while a raw comparison against
      the config does not, so ``"aurora "`` would find no wearer and then delete
      ``aurora`` — the guard bypassed by a trailing space. An id the store would
      refuse outright is answered as "no such pack" without touching the config.
      Case is the other variant of the same bypass and is handled inside
      :func:`crews_wearing`, which compares casefolded.
    """
    # circular import: handlers.agents imports this module for the store and the
    # guard, so the lock and the drained-worker helper it owns can only be
    # reached at call time.
    from kiro_crew.dashboard.handlers.agents import _drained_to_thread, _get_config_lock

    ident = safe_pack_id(pack_id)
    if ident is None:
        return False, []
    store = await asyncio.to_thread(get_appearance_store)
    async with _get_config_lock():
        if not force:
            wearers = await crews_wearing(ident)
            if wearers:
                return False, wearers
        # Library lock INSIDE the config lock, always in that order, so the delete
        # cannot interleave with an import of the same id (see ``import_pack``).
        async with _library_lock():
            deleted = await _drained_to_thread(store.delete_pack, ident)
    return bool(deleted), []


async def import_pack(payload: object) -> dict:
    """Install a bundle into the crew library, serialized with every other mutation.

    ``import_bundle`` checks ``pack_exists`` and then writes through a staging
    directory named ``.tmp-<id>-<pid>`` — the SAME name for two requests in one
    process. Two concurrent imports of one id therefore both passed the collision
    check and then interleaved inside that one staging directory, so a
    "successful" response could install one request's manifest over the other's
    art. Holding the library lock across check-and-write makes the pair atomic,
    and running under ``_drained_to_thread`` means a cancelled request cannot
    release the lock with the write still in flight.
    """
    # boot path: pack_transfer builds a urllib opener at module scope, and this
    # module is imported by the dashboard's route table before the socket binds;
    # importing it here means the first import request pays that, not the launch.
    from kiro_crew.apps.builtins.crew_companion.pack_transfer import import_bundle
    from kiro_crew.dashboard.handlers.agents import _drained_to_thread

    store = await asyncio.to_thread(get_appearance_store)
    async with _library_lock():
        return await _drained_to_thread(import_bundle, store, payload)


def _reset_for_tests() -> None:
    """Drop the process-global store so the next call rebuilds it. Tests only."""
    global _store
    _store = None
