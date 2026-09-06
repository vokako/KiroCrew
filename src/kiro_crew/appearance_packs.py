"""What a legal appearance-pack id is, shared by the config and the pack store.

A pack id is two things at once. On disk it is a DIRECTORY NAME under the
appearance library, so it is the boundary that stops ``../`` escaping the
library. In ``config.json`` it is a VALUE — ``agents.*.avatar.id`` — naming
which pack a crew wears. Both sides have to agree on what is legal, or a crew
could persist a reference the store is obliged to refuse.

The two sides cannot share the store's own copy of the rule.
``config/sections.py`` is deliberately one-way ("it must not import the loader,
schema, or validation modules") and reaching into an app package from it would
invert the dependency and pull that app's tree into every config load. So the
rule lives here, in a module that imports nothing but ``typing``, and both
sides read it.

The character class is what the pack store has always enforced, unchanged:
``str.isalnum`` plus dash and underscore. ``isalnum`` is Unicode-aware, so the
class is wider than ASCII — deliberately kept that way, because narrowing it
here would make an already-installed pack whose directory carries a non-ASCII
letter stop listing, which loses the user's art from the gallery for no
security gain (the name still cannot contain a separator, a dot, a drive
prefix or a NUL).
"""

from __future__ import annotations

from typing import Any

#: The pack every install has: its art ships inside the frontend bundle, so it
#: has no directory on disk and is never imported, exported or deleted. Lives
#: here rather than in the Companion store module so the dashboard can name it
#: without importing the app package (whose initializer pulls in its routes).
DEFAULT_PACK = "kiro-ghost"

#: Cap on a pack id. Long enough for a descriptive name, short enough that the
#: resulting path stays well inside every platform's limit.
MAX_PACK_ID_LEN = 64


def safe_pack_id(raw: Any) -> str | None:
    """Validate a pack id as a single safe path segment, or ``None``.

    Rejecting is correct here rather than sanitising: a caller sending a
    traversal is not making a typo, and silently rewriting it would hide that.
    """
    if not isinstance(raw, str):
        return None
    ident = raw.strip()
    if not ident or len(ident) > MAX_PACK_ID_LEN:
        return None
    if ident in (".", ".."):
        return None
    # Letters, digits, dash and underscore only — no separators, no dots.
    if not all(c.isalnum() or c in "-_" for c in ident):
        return None
    return ident
