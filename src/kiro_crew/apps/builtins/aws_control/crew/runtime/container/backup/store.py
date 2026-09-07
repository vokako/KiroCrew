"""The object store the sidecar and restore talk to.

Everything above this module works against the :class:`ObjectStore` protocol,
never against boto3 directly, so the same code runs against S3 in the container
and against :class:`InMemoryObjectStore` under pytest with no AWS and no moto.

Keys handled here are FULL keys (``<prefix>/<crew>/<namespace>/<path>``); the
prefixing lives in ``layout`` and the callers.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ObjectStore(Protocol):
    """The minimal surface backup and restore need.

    Whole objects only. There is deliberately no partial/append/range write:
    the transcript is atomically replaced on the write side (sometimes shorter),
    so an offset write would splice two unrelated versions together.
    """

    def put(self, key: str, data: bytes) -> None: ...

    def get(self, key: str) -> bytes: ...

    def put_stream(self, key: str, fh) -> None:
        """Upload the object by streaming from an open binary file object.

        For an object too large to hold in memory as one ``bytes``. ``fh`` is a
        readable binary file object positioned at the start; the store reads it in
        bounded chunks, so memory does not scale with the object size. The caller
        keeps ownership of ``fh`` and closes it. Whole-object semantics, same as
        ``put``.
        """
        ...

    def get_stream(self, key: str, fh) -> None:
        """Download the object by streaming into an open binary file object.

        The mirror of ``put_stream`` for restore: ``fh`` is a writable binary file
        object, and the store writes the object into it in bounded chunks.
        """
        ...

    def list(self, prefix: str) -> dict[str, int]:
        """Map every key under ``prefix`` to its size in bytes."""
        ...


class ObjectNotFound(KeyError):
    """Raised by ``get`` when a key is absent."""


class InMemoryObjectStore:
    """A fake S3 for tests. Whole-object semantics, no network.

    ``put`` replaces the object wholesale, mirroring ``PutObject``: this is the
    property that makes the shorter-file trap testable -- there is no way to
    express a splice.
    """

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}
        # Observable history, so a test can assert an object was written once
        # (write-once artifacts) rather than every cycle.
        self.put_count: dict[str, int] = {}

    def put(self, key: str, data: bytes) -> None:
        self._objects[key] = bytes(data)
        self.put_count[key] = self.put_count.get(key, 0) + 1

    def put_stream(self, key: str, fh) -> None:
        # Read the whole object from the file object, mirroring the real store's
        # streaming upload. The fake holds it in memory (it is a test double), but
        # it consumes ``fh`` the same way ``upload_fileobj`` does, so a test that
        # streams a large file exercises the same call path the container uses.
        self._objects[key] = fh.read()
        self.put_count[key] = self.put_count.get(key, 0) + 1

    def get(self, key: str) -> bytes:
        try:
            return self._objects[key]
        except KeyError as exc:
            raise ObjectNotFound(key) from exc

    def get_stream(self, key: str, fh) -> None:
        try:
            fh.write(self._objects[key])
        except KeyError as exc:
            raise ObjectNotFound(key) from exc

    def list(self, prefix: str) -> dict[str, int]:
        return {k: len(v) for k, v in self._objects.items() if k.startswith(prefix)}


class S3ObjectStore:
    """The real store, backed by boto3. Not exercised by the unit tests.

    Constructed lazily so importing the backup package never requires AWS
    credentials or network. All access to the bucket in the whole container
    funnels through this one object.
    """

    def __init__(self, bucket: str, *, client=None) -> None:
        self._bucket = bucket
        if client is None:
            import boto3  # local import: keep the package importable without AWS

            client = boto3.client("s3")
        self._client = client

    def put(self, key: str, data: bytes) -> None:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=data)

    def put_stream(self, key: str, fh) -> None:
        # boto3 owns the multipart negotiation: upload_fileobj reads ``fh`` in
        # bounded chunks and switches to multipart above its threshold, so memory
        # does not scale with the object size. ``fh`` is the descriptor the caller
        # already opened and validated (O_NOFOLLOW + regular-file fstat); passing
        # the open object rather than a path keeps that pin -- a path would let
        # upload re-open by name and reintroduce the TOCTOU the reader exists to
        # lose safely.
        self._client.upload_fileobj(fh, self._bucket, key)

    def get(self, key: str) -> bytes:
        try:
            resp = self._client.get_object(Bucket=self._bucket, Key=key)
        except self._client.exceptions.NoSuchKey as exc:
            raise ObjectNotFound(key) from exc
        return resp["Body"].read()

    def get_stream(self, key: str, fh) -> None:
        try:
            self._client.download_fileobj(self._bucket, key, fh)
        except self._client.exceptions.NoSuchKey as exc:
            raise ObjectNotFound(key) from exc

    def list(self, prefix: str) -> dict[str, int]:
        out: dict[str, int] = {}
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                out[obj["Key"]] = int(obj["Size"])
        return out
