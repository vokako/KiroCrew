"""A malformed authority object must not be reported as a complete restore.

``restore`` wrote whatever bytes the bucket held and counted them restored. So a truncated
``open_slots.json`` -- a partial multipart upload, a clipped object -- made the restore report
COMPLETE. The supervisor then started the backend, which read nothing usable, and the sidecar
backed that empty state up over the real one. The refusal that exists to prevent exactly this
loss was bypassed by the path that reports success.

Not writing it is what makes the completeness check see it as missing, which turns the restore
PARTIAL and refuses the boot. A truncated upload and a lost object are the same situation for
the boot that follows, so they get the same verdict.
"""

from __future__ import annotations

import json

import pytest
from container.backup import layout
from container.backup import restore as restore_mod
from container.backup.store import InMemoryObjectStore

from .test_backup_sidecar import make_settings

# Every one of these is accepted by ``json.loads`` or not, but none is a mapping -- which is
# what both readers require (``SessionMap._load`` returns {} for a non-dict; the slot table is
# persisted as one).
_NOT_OBJECTS = (
    pytest.param(b'{"a": {"sid":', id="truncated-mid-object"),
    pytest.param(b"[]", id="json-array"),
    pytest.param(b'"a string"', id="json-string"),
    pytest.param(b"", id="empty-object"),
    pytest.param(b"\xff\xfe not utf-8", id="not-utf8"),
    pytest.param(b"null", id="json-null"),
)


def _bucket_with(settings, session_map: bytes, open_slots: bytes) -> InMemoryObjectStore:
    keys = layout.config_keys(settings)
    store = InMemoryObjectStore()
    store.put(layout.full_key(settings, keys["session_map"]), session_map)
    store.put(layout.full_key(settings, keys["open_slots"]), open_slots)
    return store


@pytest.mark.parametrize("payload", _NOT_OBJECTS)
def test_a_malformed_authority_object_makes_the_restore_partial(tmp_path, payload) -> None:
    """PARTIAL, which is what the supervisor refuses to boot on."""
    settings = make_settings(tmp_path)
    store = _bucket_with(settings, b'{"a": {"sid": "x"}}', payload)

    result = restore_mod.run_restore(settings, store=store)

    assert result.partial is True, f"reported complete for {payload!r}"
    assert result.missing == ["open_slots"]


@pytest.mark.parametrize("payload", _NOT_OBJECTS)
def test_the_malformed_bytes_are_not_written_to_disk(tmp_path, payload) -> None:
    """The local file must stay ABSENT, which is what the completeness check reads.

    Writing it and then refusing would leave the bad bytes where the next boot finds them, and
    a boot that got past the refusal for any reason would read them.
    """
    settings = make_settings(tmp_path)
    store = _bucket_with(settings, b'{"a": {"sid": "x"}}', payload)

    restore_mod.run_restore(settings, store=store)

    assert not settings.open_slots_path.exists(), f"{payload!r} was written to disk"


def test_a_well_formed_pair_still_restores(tmp_path) -> None:
    """Non-vacuity: the check must not refuse the ordinary restore.

    An empty object is included on purpose -- it is exactly what a clean first boot seeds, so
    a check that rejected it would brick every second boot.
    """
    settings = make_settings(tmp_path)
    store = _bucket_with(settings, b"{}\n", b'{"slot-1": {"title": "hi"}}')

    result = restore_mod.run_restore(settings, store=store)

    assert not result.partial
    assert result.restored == 2
    assert json.loads(settings.session_map_path.read_text(encoding="utf-8")) == {}
    assert json.loads(settings.open_slots_path.read_text(encoding="utf-8")) == {
        "slot-1": {"title": "hi"}
    }


def test_a_good_object_still_lands_when_its_sibling_is_malformed(tmp_path) -> None:
    """One bad object must not cost the other one.

    The restore is partial either way, but an owner reading the logs after fixing the bucket
    should not find that the good half was discarded too.
    """
    settings = make_settings(tmp_path)
    store = _bucket_with(settings, b'{"a": {"sid": "x"}}', b"[]")

    result = restore_mod.run_restore(settings, store=store)

    assert result.partial is True
    assert settings.session_map_path.is_file()
    assert json.loads(settings.session_map_path.read_text(encoding="utf-8")) == {"a": {"sid": "x"}}


def test_the_shape_predicate_answers_only_the_loadable_question() -> None:
    """It is deliberately shallow: contents are the backend's business, not the restore's."""
    assert restore_mod._is_authority_object(b"{}")
    assert restore_mod._is_authority_object(b'{"anything": ["at", "all"]}')
    assert not restore_mod._is_authority_object(b"[]")
    assert not restore_mod._is_authority_object(b"")
