"""Two inputs that pass an ``isinstance`` check and then raise anyway.

Both are reachable by the party the design treats as untrusted, and both turn a refusal into
a crash, which is the worst direction for the failure to go.

* ``BackupState.load`` promises it NEVER raises, because the supervisor treats a dead
  sidecar as a dead task and on ECS that is a boot loop. Its guards used
  ``isinstance(x, (int, float))``, but ``json.loads`` produces ``float('inf')`` for
  ``1e999`` and ``float('nan')`` for ``NaN`` -- both genuine floats -- and ``int()`` then
  raises ``OverflowError`` / ``ValueError``. The agent writes that file.
* ``_control_authorized`` compared with ``hmac.compare_digest`` on ``str``, which raises
  ``TypeError`` for any non-ASCII character. One accented letter in the header turned a
  clean 403 into an unhandled 500.
"""

from __future__ import annotations

import pathlib

import pytest
from container.backup.state import BackupState, ObjMeta


def _write(tmp_path: pathlib.Path, raw: str) -> pathlib.Path:
    p = tmp_path / ".smc_backup_state.json"
    p.write_text(raw, encoding="utf-8")
    return p


@pytest.mark.parametrize(
    "raw",
    [
        '{"objects":{"k":{"size":1e999}}}',  # int(inf)  -> OverflowError
        '{"objects":{"k":{"size":-1e999}}}',
        '{"objects":{"k":{"size":NaN}}}',  # int(nan)  -> ValueError
        '{"objects":{"k":{"size":Infinity}}}',
        '{"objects":{"k":{"size":-Infinity}}}',
        '{"cycles":1e999}',
        '{"cycles":NaN}',
        '{"last_cycle_ts":Infinity}',
        '{"last_cycle_ts":NaN}',
        '{"last_success_ts":-Infinity}',
    ],
)
def test_a_non_finite_number_does_not_raise(tmp_path, raw):
    state = BackupState.load(_write(tmp_path, raw))
    assert isinstance(state, BackupState)
    assert isinstance(state.cycles, int)
    for v in state.objects.values():
        assert isinstance(v.size, int)
    # A non-finite timestamp must be dropped, not stored: it does not raise, but it makes
    # every elapsed-time comparison in backup_status meaningless while looking valid.
    for ts in (state.last_cycle_ts, state.last_success_ts):
        assert ts is None or (isinstance(ts, float) and ts == ts and abs(ts) != float("inf"))


def test_a_valid_state_still_round_trips(tmp_path):
    """The rejection must not have widened into the ordinary case."""
    original = BackupState(
        objects={"transcripts/a.json": ObjMeta(12, "ab" * 32)},
        cycles=7,
        last_cycle_ts=1000.5,
        last_success_ts=999.0,
    )
    p = tmp_path / ".smc_backup_state.json"
    original.save(p)
    back = BackupState.load(p)
    assert back.objects == original.objects
    assert (back.cycles, back.last_cycle_ts, back.last_success_ts) == (7, 1000.5, 999.0)


def test_a_finite_float_size_is_still_accepted(tmp_path):
    state = BackupState.load(_write(tmp_path, '{"objects":{"k":{"size":12.0}}}'))
    assert state.objects["k"].size == 12


# --- the control header ------------------------------------------------------


@pytest.mark.parametrize("provided", ["ab\u00e9", "a\U0001f600", "\u00ff" * 4, "caf\u00e9"])
def test_a_non_ascii_control_header_is_refused_not_a_crash(provided):
    """`hmac.compare_digest` on str raises TypeError for non-ASCII; bytes do not."""
    from container.front import app as front_app

    class _Req:
        def __init__(self, value):
            self.headers = {front_app.CONTROL_SECRET_HEADER: value}

    class _Settings:
        control_secret = "the-real-secret"

    assert front_app._control_authorized(_Req(provided), _Settings()) is False


def test_the_matching_secret_still_authorizes():
    from container.front import app as front_app

    class _Req:
        def __init__(self, value):
            self.headers = {front_app.CONTROL_SECRET_HEADER: value}

    class _Settings:
        control_secret = "the-real-secret"

    assert front_app._control_authorized(_Req("the-real-secret"), _Settings()) is True
    assert front_app._control_authorized(_Req("wrong"), _Settings()) is False
