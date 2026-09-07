"""A malformed backup-state file must not end the task.

``BackupState.load`` guarded the JSON parse and then assumed the decoded shape. The file
lives in the crew's own data home, which the agent can write, and the crew runs its
backend with every tool auto-approved -- so a wrong type here is reachable in normal
operation, not only under attack. Each case below raised out of ``load``, killed the
sidecar process, and the supervisor treats a dead sidecar as a dead task.

Falling back to a fresh state costs one re-hash of the backup unit. The alternative on
this path is the crew dying, so every case is asserted to RETURN rather than raise.
"""

from __future__ import annotations

import json

import pytest
from container.backup.state import BackupState, ObjMeta


def _write(tmp_path, payload, raw: str | None = None):
    p = tmp_path / ".smc_backup_state.json"
    p.write_text(raw if raw is not None else json.dumps(payload), encoding="utf-8")
    return p


@pytest.mark.parametrize(
    "payload",
    [
        {"objects": []},  # .items() on a list
        [],  # .get on a list
        "a string",  # .get on a str
        42,  # .get on an int
        None,  # .get on None
        {"objects": {"a": {"size": "big"}}},  # int("big")
        {"objects": {"a": {"size": {}}}},  # int({})
        {"objects": {"a": {"size": None}}},
        {"objects": {"a": "not a dict"}},
        {"objects": {"a": {}}},  # no size at all
        {"cycles": "many"},  # int("many")
        {"cycles": {}},
        {"last_cycle_ts": "soon"},  # breaks arithmetic a cycle later
        {"last_success_ts": []},
        {"objects": {"a": {"size": 1, "hash": 7}}},  # non-str hash
    ],
)
def test_a_malformed_state_returns_instead_of_raising(tmp_path, payload):
    state = BackupState.load(_write(tmp_path, payload))
    assert isinstance(state, BackupState)
    # Whatever survived must be usable by the caller without another type check.
    assert isinstance(state.objects, dict)
    assert isinstance(state.cycles, int)
    for k, v in state.objects.items():
        assert isinstance(k, str)
        assert isinstance(v.size, int)
        assert isinstance(v.hash, str)
    for ts in (state.last_cycle_ts, state.last_success_ts):
        assert ts is None or isinstance(ts, float)


def test_truncated_json_still_returns_a_fresh_state(tmp_path):
    state = BackupState.load(_write(tmp_path, None, raw='{"objects": {"a": '))
    assert state.objects == {}
    assert state.cycles == 0


def test_a_missing_file_returns_a_fresh_state(tmp_path):
    assert BackupState.load(tmp_path / "absent.json").objects == {}


def test_a_wellformed_state_still_round_trips(tmp_path):
    """The hardening must not quietly discard a legitimate state."""
    original = BackupState(
        objects={"transcripts/a.json": ObjMeta(12, "ab" * 32)},
        cycles=7,
        last_cycle_ts=1000.5,
        last_success_ts=999.0,
    )
    p = tmp_path / ".smc_backup_state.json"
    original.save(p)
    back = BackupState.load(p)
    assert back.objects == original.objects, "a valid state was dropped"
    assert back.cycles == 7
    assert back.last_cycle_ts == 1000.5
    assert back.last_success_ts == 999.0


def test_a_valid_entry_survives_beside_a_broken_one(tmp_path):
    """Per-entry skipping, not all-or-nothing: one bad row must not lose the rest."""
    p = _write(
        tmp_path,
        {
            "objects": {
                "good.json": {"size": 5, "hash": "cd" * 32},
                "bad.json": {"size": "enormous"},
            },
            "cycles": 3,
        },
    )
    state = BackupState.load(p)
    assert "good.json" in state.objects, "the valid entry was discarded with the broken one"
    assert "bad.json" not in state.objects
    assert state.cycles == 3


def test_a_bool_is_not_accepted_as_a_number(tmp_path):
    """``isinstance(True, int)`` is True, so bools need naming explicitly."""
    state = BackupState.load(_write(tmp_path, {"cycles": True, "last_cycle_ts": False}))
    assert state.cycles == 0
    assert state.last_cycle_ts is None
