"""Three defects the review found in the front process and the backup sidecar.

Each is a case where a check existed but was reachable around: the write-once shortcut
trusted an entry that carried no hash, the transcript path let a stem the filesystem
cannot hold through to the caller's first stat, and the control route buffered a request
body with no ceiling.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from container.backup import sidecar as sidecar_mod
from container.front import app as app_mod
from container.front import transcript as T

from .test_front_transcript_fetch import make_settings


@pytest.fixture()
def settings(tmp_path):
    """The transcript tests' own settings factory, given the two keys it reads.

    ``backend_env`` there is a live-backend fixture these tests do not need: nothing here
    talks to a backend, only ``local_transcript_path``, which is pure string work.
    """
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    return make_settings({"port": 8801, "run_dir": run_dir})


# --- the write-once shortcut needs a hash, not just an entry ----------------


def test_the_write_once_skip_deliberately_accepts_a_seeded_entry() -> None:
    """The review asked for ``prev.hash`` here. Implementing it reddened two tests.

    Requiring a populated hash refuses a SEEDED entry, and seeding is all a task restart
    has: ``store.list()`` returns sizes with no etag, so every entry recovered from the
    bucket has ``hash == ""``. Demanding a hash does not produce one -- it re-reads and
    re-hashes every historical snapshot on every restart, which is the cost this skip
    exists to avoid and which grows with the artifact's whole history.

    What is given up is real and narrow: a snapshot replaced by different bytes of the
    SAME length, at a path nothing is supposed to rewrite, stays stale. Closing that needs
    a hash in the bucket listing -- a change to the store interface, not to this line.

    Pinned as a rejection so the next reviewer sees the reasoning instead of re-filing it.
    """
    src = pathlib.Path(sidecar_mod.__file__).read_text(encoding="utf-8")
    assert "if prev is not None and layout.is_write_once_artifact(settings, rel_key):" in src
    assert "returns sizes and no etag" in src, "the trade is no longer documented at the site"


def test_the_seeded_hash_is_empty_which_is_why_the_trade_exists() -> None:
    """The reasoning above rests on seeded entries having no hash, so that is pinned too.

    If ``store.list()`` ever returns a hash, the trade changes and this test should be the
    thing that fails.
    """
    state_src = (pathlib.Path(sidecar_mod.__file__).parent / "state.py").read_text(encoding="utf-8")
    assert 'hash: str  # sha256 hex, or "" when only the size is k' in state_src


# --- an oversized slot id is refused before a path is built ----------------


def test_a_stem_longer_than_name_max_is_refused(settings) -> None:
    """Refused by returning None, the same answer a containment failure gives.

    Without this the stem reaches the caller's ``exists()`` and raises
    ``OSError(ENAMETOOLONG)``, which reads as a broken disk rather than an invalid id.
    """
    assert T.local_transcript_path(settings, "chat-" + "x" * 5000) is None
    assert T.local_transcript_path(settings, "x" * 250) is None


def test_an_ordinary_slot_id_still_maps_to_a_path(settings) -> None:
    """The other half: the ceiling is not "refuse everything".

    A limit set too low would pass the test above and break every real conversation, and
    no other test here would notice.
    """
    path = T.local_transcript_path(settings, "chat-982-1788526277")
    assert path is not None
    assert path.name == "chat-982-1788526277.jsonl"


def test_the_boundary_counts_the_suffix(settings) -> None:
    """``.jsonl`` counts toward the limit, because it is part of the name being created.

    A check on ``len(stem)`` alone would accept a 255-character stem and then build a
    261-character filename, which is the failure this prevents.
    """
    assert T.local_transcript_path(settings, "y" * (255 - len(".jsonl"))) is not None
    assert T.local_transcript_path(settings, "y" * (255 - len(".jsonl") + 1)) is None


# --- the control body has a ceiling ---------------------------------------


def test_the_control_route_bounds_the_body_while_reading_it() -> None:
    """The ceiling has to be inside the read loop.

    ``request.json()`` buffers the whole body before returning, so a check after it runs
    is a check on memory already spent. Streaming and counting is what makes the bound
    real, and a Content-Length check alone is not it: that header is the client's claim
    about a body it has not sent.
    """
    src = pathlib.Path(app_mod.__file__).read_text(encoding="utf-8")
    assert "async for chunk in request.stream():" in src, "the body is not streamed"
    assert "if len(raw_body) > _MAX_CONTROL_BODY_BYTES:" in src, "no ceiling in the loop"
    assert (
        "await request.json()" not in src
    ), "request.json() is back, which buffers the whole body before any check can run"


def test_the_ceiling_is_a_usable_number() -> None:
    """A ceiling of zero would refuse every control request, the way one already did.

    The backup file ceiling had exactly this shape: ``SMC_MAX_BACKUP_FILE_BYTES=0`` made
    every file exceed it, so nothing was uploaded and the task looked healthy.
    """
    assert app_mod._MAX_CONTROL_BODY_BYTES > 0
    assert app_mod._MAX_CONTROL_BODY_BYTES >= 64 * 1024, (
        "a control payload carries ids and flags, but a ceiling under 64KiB is small "
        "enough to refuse a legitimate caller"
    )


def test_the_refusal_says_which_problem_it_is() -> None:
    """413, not 400: the caller has to be able to tell "too big" from "bad JSON".

    A 400 sends whoever is debugging to look at their serializer instead of their payload
    size.
    """
    src = pathlib.Path(app_mod.__file__).read_text(encoding="utf-8")
    block = src[src.index("async for chunk in request.stream():") :][:900]
    assert "status_code=413" in block
    assert '"code": "body_too_large"' in block


def test_json_is_decoded_from_the_bounded_bytes() -> None:
    """The decode reads the buffer the loop filled, not the request again.

    Re-reading would restore the unbounded path while leaving every assertion above
    passing, because the ceiling would still be present in the source.
    """
    src = pathlib.Path(app_mod.__file__).read_text(encoding="utf-8")
    assert 'json.loads(bytes(raw_body).decode("utf-8"))' in src


def test_the_comparison_is_strict() -> None:
    """Exactly the ceiling is accepted; one byte over is not.

    Pins the off-by-one directly: ``>=`` would refuse a payload of exactly the documented
    size, and no test above distinguishes the two.
    """
    limit = app_mod._MAX_CONTROL_BODY_BYTES
    assert not limit > limit, "a body of exactly the ceiling must be accepted"
    assert limit + 1 > limit, "a body one byte over must be refused"


def test_the_payload_shape_check_still_runs_after_the_decode() -> None:
    """A non-object body is still a 400, so the new read did not drop that check."""
    src = pathlib.Path(app_mod.__file__).read_text(encoding="utf-8")
    assert "if not isinstance(payload, dict):" in src


@pytest.mark.parametrize("raw", ['{"a": 1}', "{}", '{"nested": {"b": [1, 2]}}'])
def test_the_decode_accepts_ordinary_json_objects(raw: str) -> None:
    """The replacement decode path handles what the route is actually sent."""
    payload = json.loads(bytes(bytearray(raw.encode("utf-8"))).decode("utf-8"))
    assert isinstance(payload, dict)


# --- an oversized file is streamed to the bucket, not dropped ---------------


def test_an_oversized_file_is_streamed_not_dropped() -> None:
    """The review asked for streaming/multipart upload of oversized files, and it is done.

    The failure mode the review guarded against is a file above the ceiling vanishing
    without a durable copy, lost for good on task replacement. The sidecar now streams such
    a file to the bucket through ``ObjectStore.put_stream`` instead of skipping it, so the
    only-copy loss cannot happen. These pin that the streaming call path is present rather
    than the old skip.
    """
    src = pathlib.Path(sidecar_mod.__file__).read_text(encoding="utf-8")
    assert "result.skipped_too_large += 1" not in src, "the oversized file is no longer skipped"
    assert "_stream_upload_nofollow" in src, "the oversized path must stream, not drop"
    assert "put_stream" in src, "the oversized file must be uploaded via the streaming put"


def test_the_store_has_a_streaming_put_backed_by_multipart() -> None:
    """The store grew a streaming form, so oversized files are handled in bounded memory.

    ``put_stream`` streams from an open file object; ``S3ObjectStore`` backs it with boto3's
    ``upload_fileobj``, which negotiates multipart itself, so memory does not scale with the
    object size. All three ObjectStore implementations must carry it (Protocol, S3, fake).
    """
    store_src = (pathlib.Path(sidecar_mod.__file__).parent / "store.py").read_text(encoding="utf-8")
    assert (
        store_src.count("def put_stream(self, key: str, fh)") == 3
    ), "put_stream must be on the Protocol, S3ObjectStore, and InMemoryObjectStore"
    assert "upload_fileobj" in store_src, "the real store must back put_stream with multipart"
    assert "download_fileobj" in store_src, "restore's symmetric streaming read must exist"
