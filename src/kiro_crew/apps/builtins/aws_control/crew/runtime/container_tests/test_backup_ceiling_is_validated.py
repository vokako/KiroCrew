"""A size ceiling below 1 excludes every file, so it is refused at load.

``SMC_MAX_BACKUP_FILE_BYTES=0`` made every file exceed the ceiling. The sidecar skipped all
of them -- ``session_map.json`` and ``open_slots.json`` included -- logged a warning per file,
and left the bucket empty while the task answered its port and looked healthy. Measured
before the fix: 0 uploaded, 3 skipped, 0 objects in the bucket.

Refused where the value ENTERS rather than where it is used. The two callers both pass
``settings.max_backup_file_bytes``, so once the boundary is closed a non-positive value cannot
reach the cycle from anything but a direct call in this repo's own code, and a second guard
there would be one no test could redden without inventing the caller it guards against.
"""

from __future__ import annotations

import pytest
from container.common import ConfigError
from container.common.config import load


def _base_env(tmp_path):
    """The minimum a load needs, so the ceiling is the only thing under test."""
    return {
        "SMC_DATA_HOME": str(tmp_path / "data"),
        "SMC_CONFIG_DIR": str(tmp_path / "data" / "config"),
        "SMC_CREW_NAME": "crew1",
        "SMC_SINGLE_PRINCIPAL": "1",
    }


@pytest.mark.parametrize("bad", ["0", "-1", "-268435456"])
def test_a_ceiling_below_one_is_refused(monkeypatch, tmp_path, bad) -> None:
    """Zero and negative both exclude everything, so both are refused."""
    for key, value in _base_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SMC_MAX_BACKUP_FILE_BYTES", bad)
    with pytest.raises(ConfigError) as caught:
        load()
    assert "SMC_MAX_BACKUP_FILE_BYTES" in str(caught.value)
    assert "at least 1" in str(caught.value)


def test_an_ordinary_ceiling_loads(monkeypatch, tmp_path) -> None:
    """Non-vacuity: a real ceiling must still load, and so must an unset one."""
    for key, value in _base_env(tmp_path).items():
        monkeypatch.setenv(key, value)

    monkeypatch.setenv("SMC_MAX_BACKUP_FILE_BYTES", "1048576")
    assert load().max_backup_file_bytes == 1048576

    monkeypatch.delenv("SMC_MAX_BACKUP_FILE_BYTES", raising=False)
    assert load().max_backup_file_bytes == 256 * 1024 * 1024


def test_a_ceiling_of_one_loads(monkeypatch, tmp_path) -> None:
    """The bound is "at least 1", so 1 is accepted rather than being an off-by-one."""
    for key, value in _base_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SMC_MAX_BACKUP_FILE_BYTES", "1")
    assert load().max_backup_file_bytes == 1


def test_a_non_integer_ceiling_is_still_refused(monkeypatch, tmp_path) -> None:
    """The positive check must not have replaced the integer check."""
    for key, value in _base_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("SMC_MAX_BACKUP_FILE_BYTES", "plenty")
    with pytest.raises(ConfigError) as caught:
        load()
    assert "must be an integer" in str(caught.value)
