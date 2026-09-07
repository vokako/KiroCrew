"""Two comments that had drifted from the code beside them, and a guard against a third.

Both were flagged by review, and both had the same history: they described an earlier
version of the line under them and stopped being true when that line changed. A comment
that contradicts its own code is worse than no comment, because a reader who trusts it
reasons from a premise the program does not hold.

* ``front/app.py`` said the control header's name was "not pinned by the shared base",
  directly above ``CONTROL_SECRET_HEADER = common.CONTROL_SECRET_HEADER``.
* ``front/transcript.py`` said the backup layout was "not ours to import", eleven lines
  below ``from ..backup.layout import full_key, sessions_prefix``.

Neither code line was wrong. Both are the better choice than what the comment described:
one definition for the header, and an import instead of a second copy of a key scheme,
whose failure mode is silently missing every object. So the comments were corrected to the
code rather than the other way round.

These tests are the cheap half of keeping them honest. They cannot check that prose is
accurate, only that the specific claims which HAD drifted cannot come back while the code
they contradict is still there.

The guard is a plain substring match and it caught the first attempt at this file: the
replacement comments explained their own history by QUOTING the retired phrase, which the
match cannot tell from asserting it. The comments were reworded to describe the old claim
instead of repeating it, rather than teaching the guard to allow a quoted form -- an
exception for "in quotes" is an exception a future edit can sit inside.
"""

from __future__ import annotations

import pathlib

from container import common
from container.front import app as app_mod
from container.front import transcript as transcript_mod

APP_SOURCE = pathlib.Path(app_mod.__file__)
TRANSCRIPT_SOURCE = pathlib.Path(transcript_mod.__file__)


def test_the_control_header_has_one_definition() -> None:
    """The alias must stay an alias, so the deploy integration has one name to match."""
    assert app_mod.CONTROL_SECRET_HEADER is common.CONTROL_SECRET_HEADER


def test_the_header_comment_does_not_deny_the_shared_definition() -> None:
    """The retired claim must not return while the line below it is an alias.

    Keyed on the phrase that was wrong rather than on the whole comment: pinning the exact
    prose would make every rewording a test failure, which trains people to edit the test.
    """
    text = APP_SOURCE.read_text(encoding="utf-8")
    assert "not pinned by the shared base" not in text, (
        "the comment denies the shared definition again, but CONTROL_SECRET_HEADER is "
        "still an alias for common.CONTROL_SECRET_HEADER"
    )


def test_the_transcript_key_comes_from_the_backup_layout() -> None:
    """The import is what keeps the two key schemes from drifting apart.

    Asserted as an identity against the layout module's own functions, so replacing the
    import with a local reimplementation fails here even if it happens to agree today.
    """
    from container.backup import layout

    assert transcript_mod.full_key is layout.full_key
    assert transcript_mod.sessions_prefix is layout.sessions_prefix


def test_the_transcript_comment_does_not_deny_the_import() -> None:
    """The retired claim must not return while the import is right there."""
    text = TRANSCRIPT_SOURCE.read_text(encoding="utf-8")
    assert "from ..backup.layout import" in text, "the import this comment describes is gone"
    assert (
        "not ours to import" not in text
    ), "the comment says the layout is not ours to import, directly above an import of it"
