"""The crew appearance library: its own store, its own routes.

Crews wear appearance packs from a library the dashboard owns. It is a SEPARATE
library from Crew Companion's -- that app is independent and keeps its own packs
under its own data directory behind its own enabled-gated routes -- so the two
share only the pack format and the ``AppearanceStore`` class.

These tests hold:

* the crew store is rooted at the data home and never at the Companion's dir;
* the dashboard routes work with the Companion app disabled or absent;
* every route is owner-gated, and the audit never decides the request;
* untrusted SVG is served inert;
* deleting a pack a crew still wears is refused, by name, unless forced.
"""

from __future__ import annotations

import base64
import json
import types
import unittest.mock
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from kiro_crew.apps.builtins.crew_companion import appearances as ap
from kiro_crew.config.loader import KiroCrewAgentConfig, KiroCrewConfig
from kiro_crew.dashboard import appearances as shared

_PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@pytest.fixture(autouse=True)
def _fresh_store():
    """No test may inherit another's process-global store."""
    shared._reset_for_tests()
    yield
    shared._reset_for_tests()


@pytest.fixture(autouse=True)
def _owner_caller(monkeypatch):
    monkeypatch.setattr(
        "kiro_crew.dashboard.handlers.source_providers.is_owner_dashboard_request",
        lambda request: True,
    )


def _seed_pack(root: Path, ident="aurora", *, extra=None, states=None):
    """A minimal pack under *root* (a store's data dir), returning its directory."""
    pack = root / ap.PACKS_DIRNAME / ident
    pack.mkdir(parents=True, exist_ok=True)
    manifest: dict = {
        "meta": {"id": ident, "name": ident.title(), "format": "svg"},
        "states": states if states is not None else {"idle": "idle.svg"},
    }
    (pack / "manifest.json").write_text(json.dumps(manifest), "utf-8")
    for name in (manifest["states"] or {}).values():
        (pack / name).write_text(f"<svg id='{name}'/>", "utf-8")
    for name, content in (extra or {}).items():
        (pack / name).write_text(content, "utf-8")
    return pack


def _app() -> web.Application:
    from kiro_crew.dashboard import handlers
    from kiro_crew.dashboard.routes import agents as agents_routes

    app = web.Application()
    app["state"] = types.SimpleNamespace(conversation_log=None)
    agents_routes.register(app)
    assert handlers.api_appearances_list is not None
    return app


class TestTheCrewLibraryIsItsOwn:
    """Two libraries, two directories, no reach between them.

    An earlier design shared one store between this surface and the Companion
    app and migrated the app's packs into it. Every hazard that design produced
    lived at the seam -- a migration that could strand a pack, a gallery delete
    that could blank a crew, an import cycle between the app package and the
    dashboard. Keeping the libraries apart removes the seam, so these tests pin
    the separation itself.
    """

    def test_the_store_is_rooted_at_the_data_home(self):
        from kiro_crew.config.paths import data_home

        assert shared.library_dir() == data_home() / shared.LIBRARY_DIRNAME
        shared.get_appearance_store()
        assert (shared.library_dir() / ap.PACKS_DIRNAME).exists()

    def test_the_library_is_masked_from_sandboxed_agents(self):
        """A sandboxed agent must not be able to delete the user's packs.

        Every leaf under the data home is writable inside the sandbox unless
        ``sandbox._CREW_HIDDEN_LEAVES`` names it; the library is written only
        by the gateway's owner-gated routes, so nothing in-sandbox loses access
        by hiding it, and leaving it visible let an agent-issued ``rm -rf``
        permanently destroy imported packs. Pinned by the SAME constant the
        store roots itself at, so a rename cannot silently unmask it.
        """
        from kiro_crew import sandbox

        assert shared.LIBRARY_DIRNAME in sandbox._CREW_HIDDEN_LEAVES

    def test_the_library_is_created_before_the_sandbox_spawns(self):
        """Hidden is not enough when the directory does not exist yet.

        The launcher's mask loop is guarded on ``isdir``, and this store builds its
        root on FIRST USE -- so on an install that has never imported a pack the
        mask has nothing to bind over, and the first import creates the library in
        full view of every sandbox already running. Pre-creating it (empty, 0o700)
        before each spawn is what closes that; the store's own ``mkdir`` is
        ``exist_ok`` so it tolerates finding the root already there.
        """
        from kiro_crew import sandbox

        assert shared.LIBRARY_DIRNAME in sandbox._CREW_PRECREATE_HIDDEN_DIR_LEAVES

    def test_the_store_accepts_a_pre_created_empty_root(self):
        shared.library_dir().mkdir(parents=True, mode=0o700)
        store = shared.get_appearance_store()
        assert store.list_packs()[0]["id"] == ap.DEFAULT_PACK

    def test_repeated_calls_return_the_same_object(self):
        assert shared.get_appearance_store() is shared.get_appearance_store()

    def test_the_companions_packs_are_not_read(self):
        """A pack that exists only in the Companion's directory is invisible here."""
        from kiro_crew.apps.manager import app_dir

        _seed_pack(app_dir("crew-companion") / "data", "companion-only")
        assert [p["id"] for p in shared.get_appearance_store().list_packs()] == [ap.DEFAULT_PACK]

    def test_the_companions_directory_is_never_created_or_touched(self):
        from kiro_crew.apps.manager import app_dir

        legacy = app_dir("crew-companion")
        assert not legacy.exists()
        _seed_pack(shared.library_dir(), "aurora")
        store = shared.get_appearance_store()
        store.list_packs()
        store.pack_detail("aurora")
        assert store.delete_pack("aurora") is True
        assert not legacy.exists()

    def test_the_store_module_has_no_migration_and_no_app_reach(self):
        """Pinned structurally: the seam must not grow back.

        The store module may import the Companion's STORE CLASS (the pack format
        is shared) and nothing else from that app -- not its hooks, not its
        routes, not its data directory.
        """
        source = Path(shared.__file__).read_text(encoding="utf-8")
        # Identifiers, not prose: the docstring is allowed to SAY why there is
        # no migration; the code is not allowed to have one.
        import ast

        tree = ast.parse(source)
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        assert not any("migrat" in n.lower() or "legacy" in n.lower() for n in names), names
        assert "crew_companion.hooks" not in source
        assert "crew_companion.backend" not in source
        assert "app_dir(" not in source and "app_data_dir(" not in source

    def test_the_companion_app_does_not_import_the_dashboard_store(self):
        """And the other direction: the app stays independent of this module."""
        from kiro_crew.apps.builtins.crew_companion import hooks
        from kiro_crew.apps.builtins.crew_companion.backend import routes

        for mod in (hooks, routes):
            source = Path(mod.__file__).read_text(encoding="utf-8")
            assert "kiro_crew.dashboard" not in source, mod.__name__


class TestRoutesDoNotDependOnTheApp:
    @pytest.mark.asyncio
    async def test_the_library_lists_while_the_companion_is_disabled(self, monkeypatch):
        """A crew's face must render while the Companion app is off."""
        monkeypatch.setattr(
            "kiro_crew.apps.builtins.crew_companion.backend.routes.is_app_enabled",
            lambda _name: False,
        )
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get("/api/appearances")
            assert resp.status == 200
            assert [p["id"] for p in (await resp.json())["packs"]] == [
                ap.DEFAULT_PACK,
                "aurora",
            ]


class TestListAndDetail:
    @pytest.mark.asyncio
    async def test_the_builtin_is_listed_first(self):
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            body = await (await client.get("/api/appearances")).json()
        assert body["packs"][0]["id"] == ap.DEFAULT_PACK

    @pytest.mark.asyncio
    async def test_detail_inlines_the_art(self):
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            body = await (await client.get("/api/appearances/aurora")).json()
        assert body["animations"]["idle"]["content"] == "<svg id='idle.svg'/>"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("ident", ["gone", "dots.are.out", "x" * 70])
    async def test_a_miss_or_a_bad_id_is_the_same_404(self, ident):
        """Telling the two apart would hand a caller probing for traversal a
        signal it does not need, and a deleted pack is the ordinary case."""
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get(f"/api/appearances/{ident}")
            assert resp.status == 404
            assert (await resp.json())["code"] == "pack_not_found"


class TestSlotRoute:
    @pytest.mark.asyncio
    async def test_a_present_slot_is_served_as_svg(self):
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get("/api/appearances/aurora/slot/idle")
            assert resp.status == 200
            assert resp.headers["Content-Type"].startswith("image/svg+xml")
            assert resp.headers["X-Resolved-Slot"] == "idle"
            assert await resp.text() == "<svg id='idle.svg'/>"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("asked", "present", "expected"),
        [
            ("working", {"idle": "idle.svg", "working": "working.svg"}, "working"),
            ("working", {"idle": "idle.svg", "loading": "loading.svg"}, "loading"),
            ("working", {"idle": "idle.svg", "thinking": "thinking.svg"}, "thinking"),
            ("working", {"idle": "idle.svg"}, "idle"),
            ("done", {"idle": "idle.svg", "done": "done.svg"}, "done"),
            ("done", {"idle": "idle.svg"}, "idle"),
            ("error", {"idle": "idle.svg", "error": "error.svg"}, "error"),
            ("error", {"idle": "idle.svg"}, "idle"),
        ],
    )
    async def test_the_fallback_chain_is_resolved_server_side(self, asked, present, expected):
        """A client probing four names would spend four requests learning what
        the manifest already says -- and the legacy desktop-era slot names
        (``loading``, ``thinking``) keep such a pack animating."""
        _seed_pack(shared.library_dir(), "aurora", states=present)
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get(f"/api/appearances/aurora/slot/{asked}")
            assert resp.status == 200
            assert resp.headers["X-Resolved-Slot"] == expected

    @pytest.mark.asyncio
    async def test_an_open_ended_random_clip_resolves_to_itself(self):
        """A pack's random clips are named by their author.

        A fixed slot vocabulary would make them unfetchable, so "unknown" means
        "not in this pack, even after fallback".
        """
        pack = shared.library_dir() / ap.PACKS_DIRNAME / "aurora"
        pack.mkdir(parents=True)
        (pack / "manifest.json").write_text(
            json.dumps(
                {
                    "meta": {"id": "aurora", "name": "Aurora"},
                    "states": {"idle": "idle.svg"},
                    "random": {"cartwheel": "cartwheel.svg"},
                }
            ),
            "utf-8",
        )
        (pack / "idle.svg").write_text("<svg/>", "utf-8")
        (pack / "cartwheel.svg").write_text("<svg id='cw'/>", "utf-8")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get("/api/appearances/aurora/slot/cartwheel")
            assert resp.status == 200
            assert resp.headers["X-Resolved-Slot"] == "cartwheel"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("slot", ["nope", "x" * 65])
    async def test_an_unknown_slot_is_a_404(self, slot):
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get(f"/api/appearances/aurora/slot/{slot}")
            assert resp.status == 404
            assert (await resp.json())["code"] == "slot_not_found"

    @pytest.mark.asyncio
    async def test_the_builtin_says_the_client_draws_it_itself(self):
        """A distinct code, because "this pack has no files" is not "missing"."""
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get(f"/api/appearances/{ap.DEFAULT_PACK}/slot/idle")
            assert resp.status == 404
            assert (await resp.json())["code"] == "builtin_no_content"

    @pytest.mark.asyncio
    async def test_a_lottie_slot_is_served_as_json(self):
        _seed_pack(shared.library_dir(), "aurora", states={"idle": "idle.json"})
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get("/api/appearances/aurora/slot/idle")
            assert resp.headers["Content-Type"].startswith("application/json")

    @pytest.mark.asyncio
    async def test_a_sprite_slot_is_decoded_so_an_img_tag_can_use_it(self):
        """The route exists to be an ``<img src>``.

        The store keeps a sheet base64-encoded because its write path is
        text-only; base64 text under an image content type is not an image.
        """
        _seed_pack(shared.library_dir(), "aurora", states={"idle": "idle.png"})
        pack = shared.library_dir() / ap.PACKS_DIRNAME / "aurora"
        (pack / "idle.png").write_text(_b64(_PNG), "utf-8")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get("/api/appearances/aurora/slot/idle")
            assert resp.status == 200
            assert resp.headers["Content-Type"] == "image/png"
            assert await resp.read() == _PNG

    @pytest.mark.asyncio
    async def test_an_etag_match_answers_304(self):
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            first = await client.get("/api/appearances/aurora/slot/idle")
            etag = first.headers["ETag"]
            second = await client.get(
                "/api/appearances/aurora/slot/idle", headers={"If-None-Match": etag}
            )
            assert second.status == 304
            assert second.headers["X-Resolved-Slot"] == "idle"


class TestImport:
    @staticmethod
    def _bundle(ident="imported"):
        return {
            "kind": "crew-companion-pack",
            "version": 1,
            "id": ident,
            "manifest": {
                "meta": {"id": ident, "name": "Imported"},
                "states": {"idle": "idle.svg"},
            },
            "files": {"idle.svg": "<svg/>"},
        }

    @pytest.mark.asyncio
    async def test_json_body_matches_the_companions_request_shape(self):
        """Same ``{"bundle": ...}`` envelope, so the frontend reuses its client."""
        async with TestClient(TestServer(_app())) as client:
            resp = await client.post("/api/appearances/import", json={"bundle": self._bundle()})
            assert resp.status == 200, await resp.json()
            assert (await resp.json())["id"] == "imported"
        assert shared.get_appearance_store().pack_exists("imported")

    @pytest.mark.asyncio
    async def test_a_multipart_upload_is_accepted(self):
        from aiohttp import FormData

        form = FormData()
        form.add_field(
            "file",
            json.dumps(self._bundle("from-file")).encode("utf-8"),
            filename="pack.json",
            content_type="application/json",
        )
        async with TestClient(TestServer(_app())) as client:
            resp = await client.post("/api/appearances/import", data=form)
            assert resp.status == 200, await resp.text()
        assert shared.get_appearance_store().pack_exists("from-file")

    @pytest.mark.asyncio
    async def test_a_colliding_id_is_refused_rather_than_clobbered(self):
        _seed_pack(shared.library_dir(), "imported")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.post("/api/appearances/import", json={"bundle": self._bundle()})
            assert resp.status == 400
            assert (await resp.json())["code"] == "invalid_bundle"

    @pytest.mark.asyncio
    async def test_a_traversal_id_is_refused(self):
        async with TestClient(TestServer(_app())) as client:
            resp = await client.post(
                "/api/appearances/import", json={"bundle": self._bundle("../../evil")}
            )
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_a_body_that_is_not_a_bundle_is_a_400(self):
        async with TestClient(TestServer(_app())) as client:
            assert (await client.post("/api/appearances/import", data=b"not json")).status == 400


class TestDelete:
    @pytest.fixture()
    def worn(self):
        _seed_pack(shared.library_dir(), "aurora")
        cfg = KiroCrewConfig.load()
        cfg.agents["nova"] = KiroCrewAgentConfig(
            kiro_agent="kirocrew", avatar={"kind": "pack", "id": "aurora"}
        )
        cfg.agents["comet"] = KiroCrewAgentConfig(
            kiro_agent="kirocrew", avatar={"kind": "pack", "id": "aurora"}
        )
        cfg.agents["plain"] = KiroCrewAgentConfig(kiro_agent="kirocrew")
        cfg.save()

    @pytest.mark.asyncio
    async def test_a_pack_nobody_wears_is_deleted(self):
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.delete("/api/appearances/aurora")
            assert resp.status == 200, await resp.json()
        assert not shared.get_appearance_store().pack_exists("aurora")

    @pytest.mark.asyncio
    async def test_a_worn_pack_is_refused_and_the_crews_are_named(self, worn):
        """A roster of blank faces the user cannot explain is the alternative."""
        async with TestClient(TestServer(_app())) as client:
            resp = await client.delete("/api/appearances/aurora")
            assert resp.status == 409
            body = await resp.json()
            assert body["code"] == "pack_in_use"
            assert body["crews"] == ["comet", "nova"]
        assert shared.get_appearance_store().pack_exists("aurora")

    @pytest.mark.asyncio
    async def test_force_deletes_it_anyway(self, worn):
        """The crews keep a dangling reference and fall back to the ghost, which
        is what an absent pack already means."""
        async with TestClient(TestServer(_app())) as client:
            resp = await client.delete("/api/appearances/aurora?force=1")
            assert resp.status == 200, await resp.json()
        assert not shared.get_appearance_store().pack_exists("aurora")
        assert KiroCrewConfig.load().agents["nova"].avatar == {
            "kind": "pack",
            "id": "aurora",
        }

    @pytest.mark.asyncio
    async def test_the_builtin_cannot_be_deleted(self):
        async with TestClient(TestServer(_app())) as client:
            resp = await client.delete(f"/api/appearances/{ap.DEFAULT_PACK}")
            assert resp.status == 400
            assert (await resp.json())["code"] == "builtin_pack"

    @pytest.mark.asyncio
    async def test_the_builtin_cannot_be_forced_either(self):
        async with TestClient(TestServer(_app())) as client:
            resp = await client.delete(f"/api/appearances/{ap.DEFAULT_PACK}?force=1")
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_a_pack_that_is_not_there_is_a_404(self):
        async with TestClient(TestServer(_app())) as client:
            resp = await client.delete("/api/appearances/gone")
            assert resp.status == 404
            assert (await resp.json())["code"] == "pack_not_found"

    @pytest.mark.asyncio
    async def test_a_crew_wearing_a_DIFFERENT_pack_does_not_block(self):
        _seed_pack(shared.library_dir(), "aurora")
        cfg = KiroCrewConfig.load()
        cfg.agents["nova"] = KiroCrewAgentConfig(
            kiro_agent="kirocrew", avatar={"kind": "pack", "id": "nebula"}
        )
        cfg.save()
        async with TestClient(TestServer(_app())) as client:
            assert (await client.delete("/api/appearances/aurora")).status == 200


class TestOwnerGate:
    """Every route is owner-gated, reads included.

    A pack is user-authored content served back verbatim, and the library
    decides what the roster draws — so a non-owner dashboard session must not be
    able to read it, import into it, or delete from it.
    """

    @pytest.fixture(autouse=True)
    def _not_the_owner(self, monkeypatch):
        monkeypatch.setattr(
            "kiro_crew.dashboard.handlers.source_providers.is_owner_dashboard_request",
            lambda request: False,
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("get", "/api/appearances"),
            ("get", "/api/appearances/aurora"),
            ("get", "/api/appearances/aurora/slot/idle"),
            ("post", "/api/appearances/import"),
            ("post", "/api/appearances/petdex/fetch"),
            ("delete", "/api/appearances/aurora"),
        ],
    )
    async def test_a_non_owner_is_refused(self, method, path):
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            resp = await getattr(client, method)(path, json={})
            assert resp.status == 403


class TestPetdexRoute:
    @pytest.mark.asyncio
    async def test_a_hit_is_handed_back(self, monkeypatch):
        monkeypatch.setattr(
            "kiro_crew.apps.builtins.crew_companion.pack_transfer.fetch_petdex_pet",
            lambda raw: {"ok": True, "slug": "kirby", "spriteBase64": _b64(_PNG)},
        )
        async with TestClient(TestServer(_app())) as client:
            resp = await client.post(
                "/api/appearances/petdex/fetch", json={"input": "petdex.dev/pets/kirby"}
            )
            assert resp.status == 200
            assert (await resp.json())["slug"] == "kirby"

    @pytest.mark.asyncio
    async def test_a_miss_is_a_200_carrying_ok_false(self, monkeypatch):
        """A miss or an unreachable registry is what the import dialog shows,
        not a client error — the same contract the app's own route has."""
        monkeypatch.setattr(
            "kiro_crew.apps.builtins.crew_companion.pack_transfer.fetch_petdex_pet",
            lambda raw: {"ok": False, "error": "Could not reach PetDex"},
        )
        async with TestClient(TestServer(_app())) as client:
            resp = await client.post("/api/appearances/petdex/fetch", json={"input": "x"})
            assert resp.status == 200
            assert (await resp.json())["ok"] is False

    @pytest.mark.asyncio
    async def test_a_body_that_is_not_an_object_is_treated_as_empty(self, monkeypatch):
        seen: list[object] = []
        monkeypatch.setattr(
            "kiro_crew.apps.builtins.crew_companion.pack_transfer.fetch_petdex_pet",
            lambda raw: seen.append(raw) or {"ok": False, "error": "no"},
        )
        async with TestClient(TestServer(_app())) as client:
            assert (await client.post("/api/appearances/petdex/fetch", json=["nope"])).status == 200
            assert (
                await client.post("/api/appearances/petdex/fetch", data=b"not json")
            ).status == 200
        assert seen == ["", ""]


class TestMalformedRequests:
    @pytest.mark.asyncio
    async def test_a_json_array_body_is_not_a_bundle(self):
        async with TestClient(TestServer(_app())) as client:
            resp = await client.post("/api/appearances/import", json=["nope"])
            assert resp.status == 400
            assert (await resp.json())["code"] == "invalid_bundle"

    @pytest.mark.asyncio
    async def test_a_multipart_upload_with_no_parts_is_a_400(self):
        from aiohttp import FormData

        async with TestClient(TestServer(_app())) as client:
            resp = await client.post(
                "/api/appearances/import",
                data=FormData()(),
                headers={"Content-Type": "multipart/form-data; boundary=x"},
            )
            assert resp.status == 400
            assert (await resp.json())["code"] == "invalid_bundle"

    @pytest.mark.asyncio
    async def test_a_multipart_part_that_is_not_json_is_a_400(self):
        from aiohttp import FormData

        form = FormData()
        form.add_field("file", b"not json at all", filename="pack.json")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.post("/api/appearances/import", data=form)
            assert resp.status == 400
            assert (await resp.json())["code"] == "invalid_bundle"

    @pytest.mark.asyncio
    async def test_a_sprite_slot_that_will_not_decode_reads_as_absent(self):
        """The pack lists the slot but there is nothing renderable behind it.

        Which is the same answer as the slot not being there, and a better one
        than handing the browser bytes that are not a PNG.
        """
        _seed_pack(shared.library_dir(), "aurora", states={"idle": "idle.png"})
        pack = shared.library_dir() / ap.PACKS_DIRNAME / "aurora"
        (pack / "idle.png").write_text("not base64 !!", "utf-8")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get("/api/appearances/aurora/slot/idle")
            assert resp.status == 404
            assert (await resp.json())["code"] == "slot_not_found"


class TestUntrustedSvgIsServedInert:
    """A pack's SVG is third-party markup on the dashboard's OWN origin.

    An SVG is XML, not a bitmap: it can carry a `<script>` element. An `<img
    src>` will not run it, but navigating straight to the slot URL renders it as
    a DOCUMENT on an origin that already holds the dashboard's session — and a
    pack arrives by import or PetDex fetch, so its author is not necessarily the
    user. The picture tier already refuses SVG outright for this reason; a pack's
    art has to be SVG, so it is served inert instead.
    """

    @pytest.mark.asyncio
    async def test_svg_carries_the_script_none_policy(self):
        _seed_pack(shared.library_dir(), "aurora")
        pack = shared.library_dir() / ap.PACKS_DIRNAME / "aurora"
        (pack / "idle.svg").write_text(
            "<svg xmlns='http://www.w3.org/2000/svg'><script>fetch('/api/agents')</script></svg>",
            "utf-8",
        )
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get("/api/appearances/aurora/slot/idle")
            assert resp.status == 200
            assert (
                resp.headers["Content-Security-Policy"]
                == "script-src 'none'; style-src 'unsafe-inline'"
            )
            assert resp.headers["X-Content-Type-Options"] == "nosniff"

    @pytest.mark.asyncio
    async def test_the_policy_matches_the_one_untrusted_file_reads_use(self):
        """Two policies for one class of content is a drift waiting to happen."""
        from kiro_crew.dashboard.handlers import appearances as handlers_mod

        source = Path(
            Path(handlers_mod.__file__).resolve().parents[1] / "handlers" / "files.py"
        ).read_text(encoding="utf-8")
        assert f'"{handlers_mod._SVG_CSP}"' in source

    @pytest.mark.asyncio
    async def test_the_policy_rides_the_304_too(self):
        """A revalidated response is still the one the browser renders."""
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            first = await client.get("/api/appearances/aurora/slot/idle")
            second = await client.get(
                "/api/appearances/aurora/slot/idle",
                headers={"If-None-Match": first.headers["ETag"]},
            )
            assert second.status == 304
            assert second.headers["Content-Security-Policy"] == handlers_svg_csp()

    @pytest.mark.asyncio
    async def test_inert_formats_get_nosniff_without_the_svg_policy(self):
        """`nosniff` is what stops a browser re-deciding what a lottie really is."""
        _seed_pack(shared.library_dir(), "aurora", states={"idle": "idle.json"})
        async with TestClient(TestServer(_app())) as client:
            resp = await client.get("/api/appearances/aurora/slot/idle")
            assert resp.headers["X-Content-Type-Options"] == "nosniff"
            assert "Content-Security-Policy" not in resp.headers


def handlers_svg_csp() -> str:
    from kiro_crew.dashboard.handlers import appearances as handlers_mod

    return handlers_mod._SVG_CSP


class TestTheDeleteGuardCannotBeBypassedByAnIdVariant:
    """The guard and the store have to agree on what the id IS.

    The store normalizes through `safe_pack_id`, which strips whitespace; a raw
    comparison against the config does not. So a delete for `"aurora "` found no
    wearer and then removed `aurora` — the guard walked past by a trailing space.
    """

    @pytest.fixture()
    def worn(self):
        _seed_pack(shared.library_dir(), "aurora")
        cfg = KiroCrewConfig.load()
        cfg.agents["nova"] = KiroCrewAgentConfig(
            kiro_agent="kirocrew", avatar={"kind": "pack", "id": "aurora"}
        )
        cfg.save()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("variant", ["aurora ", " aurora", "  aurora  "])
    async def test_a_whitespace_variant_still_finds_the_wearer(self, worn, variant):
        deleted, wearers = await shared.delete_pack_if_unworn(variant)
        assert (deleted, wearers) == (False, ["nova"])
        assert shared.get_appearance_store().pack_exists("aurora")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("variant", ["Aurora", "AURORA", "aUrOrA"])
    async def test_a_case_variant_still_finds_the_wearer(self, variant):
        """`Aurora` worn, `aurora` deleted: one directory on macOS and Windows.

        The guard cannot know which filesystem it is on, and it does not need to:
        comparing casefolded refuses the delete on every platform, and on a
        case-sensitive one that refusal costs `?force=1` rather than a pack. The
        store's own `save_pack` already refuses case-colliding filenames inside a
        pack for the same reason -- this is the same rule for the pack name.
        """
        _seed_pack(shared.library_dir(), variant)
        cfg = KiroCrewConfig.load()
        cfg.agents["nova"] = KiroCrewAgentConfig(
            kiro_agent="kirocrew", avatar={"kind": "pack", "id": variant}
        )
        cfg.save()

        deleted, wearers = await shared.delete_pack_if_unworn("aurora")
        assert (deleted, wearers) == (False, ["nova"])
        assert shared.get_appearance_store().pack_exists(variant)

    @pytest.mark.asyncio
    async def test_the_route_reports_the_case_variant_wearer(self):
        _seed_pack(shared.library_dir(), "Aurora")
        cfg = KiroCrewConfig.load()
        cfg.agents["nova"] = KiroCrewAgentConfig(
            kiro_agent="kirocrew", avatar={"kind": "pack", "id": "Aurora"}
        )
        cfg.save()
        async with TestClient(TestServer(_app())) as client:
            resp = await client.delete("/api/appearances/aurora")
            assert resp.status == 409
            body = await resp.json()
            assert body["code"] == "pack_in_use"
            assert body["crews"] == ["nova"]
        assert shared.get_appearance_store().pack_exists("Aurora")

    @pytest.mark.asyncio
    async def test_an_id_the_store_would_refuse_never_reaches_the_config(self):
        """No pack can exist under it, so there is nothing to look up."""
        with unittest.mock.patch.object(
            KiroCrewConfig,
            "load",
            side_effect=AssertionError("config read for an impossible id"),
        ):
            assert await shared.delete_pack_if_unworn("../../etc") == (False, [])


class TestAcceptedOwnerDecisionsAreAudited:
    """Half a permission decision in the log is not an audit trail.

    The shared gate records a DENIAL and returns None on success, so an accepted
    decision left no record: a reader could see who was turned away and not who
    got in. The nearest sibling — the owner-gated `GET /api/agents/{name}/avatar`,
    also user-supplied media on this origin — audits its success, so this module
    does too, reads included.
    """

    @pytest.fixture()
    def audited(self, monkeypatch):
        seen: list[dict] = []
        recorder = types.SimpleNamespace(log_api_access=lambda **kw: seen.append(kw))
        monkeypatch.setattr("kiro_crew.dashboard.handlers.appearances._sel", lambda: recorder)
        return seen

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("method", "path", "operation"),
        [
            ("get", "/api/appearances", "appearances.list"),
            ("get", "/api/appearances/aurora", "appearances.detail"),
            ("get", "/api/appearances/aurora/slot/idle", "appearances.slot"),
            ("delete", "/api/appearances/aurora", "appearances.delete"),
        ],
    )
    async def test_a_successful_owner_read_or_write_is_recorded(
        self, audited, method, path, operation
    ):
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            resp = await getattr(client, method)(path)
            assert resp.status == 200, await resp.text()
        accepted = [e for e in audited if e.get("outcome") == "success"]
        assert operation in {e["operation"] for e in accepted}

    @pytest.mark.asyncio
    async def test_a_failing_audit_never_changes_the_response(self, monkeypatch):
        """An audit must not break the request it describes."""
        _seed_pack(shared.library_dir(), "aurora")
        boom = types.SimpleNamespace(
            log_api_access=lambda **kw: (_ for _ in ()).throw(RuntimeError("sel down"))
        )
        monkeypatch.setattr("kiro_crew.dashboard.handlers.appearances._sel", lambda: boom)
        async with TestClient(TestServer(_app())) as client:
            assert (await client.get("/api/appearances")).status == 200


class TestAnAuditNeverDecidesTheOperation:
    """An audit describes an operation; it must never decide it.

    A write that audits AFTER its mutation and lets the audit raise turns a
    completed delete into a 500 — the pack is gone and the client is told the
    request failed, so the user retries and is told there is no such pack.
    """

    @pytest.fixture()
    def sel_is_down(self, monkeypatch):
        boom = types.SimpleNamespace(
            log_api_access=lambda **kw: (_ for _ in ()).throw(RuntimeError("sel down"))
        )
        monkeypatch.setattr("kiro_crew.dashboard.handlers.appearances._sel", lambda: boom)

    @pytest.mark.asyncio
    async def test_a_delete_that_succeeded_is_not_reported_as_a_failure(self, sel_is_down):
        _seed_pack(shared.library_dir(), "aurora")
        async with TestClient(TestServer(_app())) as client:
            resp = await client.delete("/api/appearances/aurora")
            assert resp.status == 200, await resp.text()
        assert not shared.get_appearance_store().pack_exists("aurora")

    @pytest.mark.asyncio
    async def test_an_import_that_succeeded_is_not_reported_as_a_failure(self, sel_is_down):
        bundle = {
            "kind": "crew-companion-pack",
            "version": 1,
            "id": "imported",
            "manifest": {
                "meta": {"id": "imported", "name": "Imported"},
                "states": {"idle": "idle.svg"},
            },
            "files": {"idle.svg": "<svg/>"},
        }
        async with TestClient(TestServer(_app())) as client:
            resp = await client.post("/api/appearances/import", json={"bundle": bundle})
            assert resp.status == 200, await resp.text()
        assert shared.get_appearance_store().pack_exists("imported")

    @pytest.mark.asyncio
    async def test_a_petdex_fetch_still_answers(self, sel_is_down, monkeypatch):
        monkeypatch.setattr(
            "kiro_crew.apps.builtins.crew_companion.pack_transfer.fetch_petdex_pet",
            lambda raw: {"ok": False, "error": "no"},
        )
        async with TestClient(TestServer(_app())) as client:
            assert (
                await client.post("/api/appearances/petdex/fetch", json={"input": "x"})
            ).status == 200

    @pytest.mark.asyncio
    async def test_every_audit_on_this_surface_goes_through_the_one_chokepoint(self):
        """Pinned structurally, because the defect was one call site out of four.

        Three review rounds each found a different obligation missing from these
        routes, every time because the surface re-derived it by hand. A direct
        ``_sel().log_api_access`` here is that mistake reappearing.
        """
        from kiro_crew.dashboard.handlers import appearances as handlers_mod

        source = Path(handlers_mod.__file__).read_text(encoding="utf-8")
        direct = [line for line in source.splitlines() if "_sel().log_api_access" in line]
        # Exactly one: the call inside `_audit` itself.
        assert len(direct) == 1, direct


class TestLibraryMutationsAreSerialized:
    """Two same-id imports cannot interleave inside one staging directory.

    `import_bundle` checks `pack_exists` and then writes through `.tmp-<id>-<pid>`
    -- the same name for two requests in one process. Unserialized, both passed
    the collision check and interleaved in that one directory, so a "successful"
    response could install one request's manifest over the other's art.
    """

    @staticmethod
    def _bundle(ident, art):
        return {
            "kind": "crew-companion-pack",
            "version": 1,
            "id": ident,
            "manifest": {
                "meta": {"id": ident, "name": art},
                "states": {"idle": "idle.svg"},
            },
            "files": {"idle.svg": f"<svg id='{art}'/>"},
        }

    @pytest.mark.asyncio
    async def test_concurrent_same_id_imports_yield_one_winner_and_one_refusal(self, monkeypatch):
        """The loser sees the winner's pack and is refused, never merged into it."""
        import asyncio
        import time

        real_save = ap.AppearanceStore.save_pack

        def _slow_save(self, ident, manifest, files):
            # Widen the check-then-write window so an unserialized pair WOULD
            # overlap; the lock is what keeps them from doing so.
            time.sleep(0.05)
            return real_save(self, ident, manifest, files)

        monkeypatch.setattr(ap.AppearanceStore, "save_pack", _slow_save)
        results = await asyncio.gather(
            shared.import_pack(self._bundle("dup", "first")),
            shared.import_pack(self._bundle("dup", "second")),
        )
        oks = sorted(r["ok"] for r in results)
        assert oks == [False, True], results
        detail = shared.get_appearance_store().pack_detail("dup")
        assert detail is not None
        # Whole-pack integrity: the manifest name and the art agree.
        name = detail["meta"]["name"]
        assert detail["animations"]["idle"]["content"] == f"<svg id='{name}'/>"

    @pytest.mark.asyncio
    async def test_import_and_delete_hold_the_same_lock(self):
        """Pinned structurally: a second lock would not serialize against the first."""
        source = Path(shared.__file__).read_text(encoding="utf-8")
        body_import = source[source.index("async def import_pack") :]
        body_delete = source[
            source.index("async def delete_pack_if_unworn") : source.index("async def import_pack")
        ]
        assert "async with _library_lock():" in body_import
        assert "async with _library_lock():" in body_delete

    def test_the_lock_is_loop_bound_not_a_bare_asyncio_lock(self):
        from kiro_crew.loop_lock import LoopBoundLock

        assert isinstance(shared._library_lock(), LoopBoundLock)


class TestTheDashboardAddsNoBootPathImportOfPackTransfer:
    """This module and its handler defer `pack_transfer` to call time.

    `pack_transfer` builds a urllib opener at module scope, and the dashboard
    route table imports the handler module before the socket binds. What THIS
    PR controls is its own two modules: neither may import `pack_transfer` at
    module scope. That includes the store class itself: it lives inside the
    Companion app package, whose initializer imports its routes and, through
    them, `pack_transfer` -- so a module-scope import of ANYTHING under the app
    package reaches the opener. Both dashboard modules therefore import from the
    neutral `appearance_packs` leaf at module scope and the app package only
    inside the functions that need it.
    """

    @pytest.mark.parametrize(
        "module",
        ["kiro_crew.dashboard.appearances", "kiro_crew.dashboard.handlers.appearances"],
    )
    def test_no_module_scope_app_package_import(self, module):
        import importlib

        source = Path(importlib.import_module(module).__file__).read_text(encoding="utf-8")
        offenders = [
            line
            for line in source.splitlines()
            if line.startswith(("from ", "import ")) and "crew_companion" in line
        ]
        assert offenders == [], offenders

    def test_importing_the_dashboard_modules_does_not_load_the_app_package(self):
        """Proved in a fresh interpreter, not by reading source.

        A `TYPE_CHECKING` guard or a function-local import that is wrong in
        some other way still passes the line scan above; only an interpreter
        that imported the module and then looked at `sys.modules` settles it.
        """
        import subprocess
        import sys

        code = (
            "import sys\n"
            "import kiro_crew.dashboard.appearances\n"
            "import kiro_crew.dashboard.handlers.appearances\n"
            "loaded = sorted(m for m in sys.modules if 'crew_companion' in m)\n"
            "print(loaded)\n"
        )
        out = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=True,
        )
        assert out.stdout.strip() == "[]", out.stdout
