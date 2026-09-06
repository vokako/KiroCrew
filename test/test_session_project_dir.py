"""Tests for the opt-in per-session project directory.

`session_project_dir` runs on the slot-creation path, so its contract is as much
about what it REFUSES as what it returns: every rejection has to come back as
``""`` (the caller's "no per-session directory") rather than as an exception,
because an exception there stops a session from opening.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import tempfile
import time
import unittest.mock
from pathlib import Path

import pytest

from kiro_crew.config.loader import KiroCrewConfig, session_project_dir
from kiro_crew.config.sections import DashboardConfig


def _load_from_dict(data: object) -> KiroCrewConfig:
    """Write *data* to a temp config file and load via ``KiroCrewConfig.load()``.

    Same mechanism as ``test_config_loader._load_from_dict`` -- loading through
    the real entry point is what makes the parse wiring observable.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        tmp = Path(f.name)
    try:
        with unittest.mock.patch("kiro_crew.config.loader.config_path", return_value=tmp):
            return KiroCrewConfig.load()
    finally:
        tmp.unlink(missing_ok=True)


class TestSessionProjectDirHappyPath:
    def test_creates_directory_under_root_and_returns_realpath(self, tmp_path):
        root = tmp_path / "sessions"
        root.mkdir()

        got = session_project_dir("chat-7", str(root))

        assert got == os.path.realpath(str(root / "chat-7"))
        assert Path(got).is_dir()

    def test_an_existing_directory_is_refused_not_adopted(self, tmp_path):
        """A second derivation of one key must REFUSE, not hand over the first.

        `slot.project` is persisted on the transcript's metadata line and
        rehydrated from there, so a restored session is served from metadata and
        never re-derives. A path that already exists here therefore belongs to an
        EARLIER session whose key was reused, and adopting it would leak that
        session's files into a fresh one.
        """
        root = tmp_path / "sessions"
        root.mkdir()

        first = session_project_dir("chat-7", str(root))
        second = session_project_dir("chat-7", str(root))

        assert first == os.path.realpath(str(root / "chat-7"))
        assert second == "", "an existing directory must never be adopted"
        assert [p.name for p in root.iterdir()] == ["chat-7"]

    def test_a_sensitive_candidate_is_refused_before_the_directory_exists(
        self, tmp_path, monkeypatch
    ):
        """A sensitive candidate must be rejected BEFORE `mkdir`, not after.

        The post-`mkdir` sensitive check cannot undo a side effect, and nothing
        here deletes, so creating first leaves a DIRECTORY squatting on a path
        meant to hold a file. For a governance leaf such as
        `<data_home>/security_policy.json` that blocks policy loading outright.

        The load-bearing assertion is the second one: returning `""` was already
        true before the fix, because the post-check caught it. What was wrong was
        that the directory existed by then.
        """
        import kiro_crew.security as security

        root = tmp_path / "sessions"
        root.mkdir()
        target = os.path.realpath(str(root / "security_policy.json"))
        real = security.is_sensitive_path
        monkeypatch.setattr(
            security,
            "is_sensitive_path",
            lambda p: os.path.realpath(str(p)) == target or real(p),
        )

        assert session_project_dir("security_policy.json", str(root)) == ""
        assert list(root.iterdir()) == [], "created the sensitive path before rejecting it"

    def test_a_pre_existing_directory_is_never_handed_over(self, tmp_path):
        """Same refusal when the directory was not created by this function."""
        root = tmp_path / "sessions"
        root.mkdir()
        stale = root / "chat-9"
        stale.mkdir()
        (stale / "previous-session-notes.md").write_text("secret", encoding="utf-8")

        assert session_project_dir("chat-9", str(root)) == ""
        # And the earlier session's file is untouched: nothing here deletes.
        assert (stale / "previous-session-notes.md").read_text(encoding="utf-8") == "secret"

    def test_distinct_keys_get_distinct_directories(self, tmp_path):
        root = tmp_path / "sessions"
        root.mkdir()

        a = session_project_dir("chat-1", str(root))
        b = session_project_dir("chat-2", str(root))

        assert a != b
        assert sorted(p.name for p in root.iterdir()) == ["chat-1", "chat-2"]


class TestSessionProjectDirRefusals:
    def test_parent_traversal_key_is_refused(self, tmp_path):
        """`_safe_dir_name` is a sanitizer, not a validator.

        It maps separators to ``_`` but does NOT reject ``..``, so the
        containment assertion is what actually stops an escape. Without it this
        would resolve to the root's parent.
        """
        root = tmp_path / "sessions"
        root.mkdir()

        assert session_project_dir("..", str(root)) == ""
        assert session_project_dir(".", str(root)) == ""

    def test_separators_in_key_stay_one_level_down(self, tmp_path):
        root = tmp_path / "sessions"
        root.mkdir()

        got = session_project_dir("a/b:c d", str(root))

        assert got == os.path.realpath(str(root / "a_b_c_d"))
        assert Path(got).parent == root.resolve()

    def test_missing_root_returns_empty(self, tmp_path):
        assert session_project_dir("chat-7", str(tmp_path / "absent")) == ""

    @pytest.mark.parametrize("bad_key", [None, "", 0, 17, b"chat-7"])
    def test_a_key_that_is_not_a_non_empty_string_returns_empty(self, bad_key, tmp_path):
        """Pins the guard that a caller bug must not reach `_safe_dir_name`.

        A `None` key reaching the broad `except` reports the caller's mistake as
        "no per-session directory" -- indistinguishable from the feature being
        off. The guard makes it explicit, and this test fails
        if anyone removes it AND the broad except is ever narrowed.
        """
        root = tmp_path / "sessions"
        root.mkdir()

        assert session_project_dir(bad_key, str(root)) == ""
        assert list(root.iterdir()) == []

    def test_root_that_is_a_file_returns_empty(self, tmp_path):
        f = tmp_path / "not-a-dir"
        f.write_text("x", encoding="utf-8")

        assert session_project_dir("chat-7", str(f)) == ""

    def test_symlink_child_pointing_outside_root_is_refused(self, tmp_path):
        """An existing child that is a symlink out of the root must not be used."""
        root = tmp_path / "sessions"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (root / "chat-7").symlink_to(outside, target_is_directory=True)

        assert session_project_dir("chat-7", str(root)) == ""

    def test_dangling_symlink_child_cannot_create_outside_the_root(self, tmp_path):
        """A symlink to a MISSING target outside the root must create nothing.

        Measured, and not what I first assumed: `mkdir` does NOT follow a symlink
        at the final component. Dangling or not, it raises `FileExistsError`, so
        exclusive creation is what refuses this - the containment assertions are
        not what this test exercises. It is kept because the property it pins is a
        security property worth stating outright: no directory appears outside
        the configured root. The second assertion is the load-bearing one.
        """
        root = tmp_path / "sessions"
        root.mkdir()
        outside = tmp_path / "outside"  # deliberately NOT created
        (root / "chat-7").symlink_to(outside, target_is_directory=True)

        assert session_project_dir("chat-7", str(root)) == ""
        assert not outside.exists(), "followed a dangling symlink and created outside the root"

    def test_root_swapped_for_a_symlink_after_validation_creates_nothing_outside(self, tmp_path):
        """The ROOT going symlink mid-call must not redirect the create.

        The child is created relative to a descriptor opened on the root that
        passed validation, so the create cannot be steered by a later change to
        what that PATH resolves to. Without that, the create re-resolves the root
        at call time: an attacker who can replace the root directory -- it is
        writable by the gateway's own user, and the caller steers the child's
        name through the session key -- gets a directory of their choosing
        created wherever the replacement symlink points.

        The swap is timed off the last validation call before the create, which
        is the sensitive-path check on the candidate, so the interleaving is
        deterministic rather than a race the test hopes to hit.
        """
        import kiro_crew.security as security

        root = tmp_path / "sessions"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        real_check = security.is_sensitive_path
        swapped = []

        def _swap_root_then_check(path: str) -> bool:
            # Runs for the root first, then for the candidate. Swap on the
            # candidate call: validation of the root is done by then, so this is
            # the window the fix has to close.
            if str(path).startswith(str(root / "chat-9")) and not swapped:
                swapped.append(True)
                root.rmdir()
                root.symlink_to(outside, target_is_directory=True)
            return real_check(path)

        with unittest.mock.patch.object(security, "is_sensitive_path", _swap_root_then_check):
            result = session_project_dir("chat-9", str(root))

        assert swapped, "the swap never ran, so this test proves nothing"
        assert result == ""
        assert list(outside.iterdir()) == [], "created a directory outside the configured root"

    def test_an_ancestor_swapped_for_a_symlink_creates_nothing_outside(self, tmp_path):
        """An ANCESTOR of the root going symlink mid-call must be refused too.

        Distinct from the test above, and the reason a single `O_NOFOLLOW` open of
        the root is not enough: that flag guards the LAST component only, so a
        directory ABOVE the root swapped for a link is followed silently and the
        open then pins the link's target. Re-resolving the root afterwards to
        check it cannot see this either -- that resolution walks the swapped
        ancestor as well, so it agrees with itself and the escape looks contained.

        Closed by walking the already-resolved root one component at a time, each
        open carrying `O_NOFOLLOW`, so the swapped ancestor is refused at the
        component it sits on.
        """
        import kiro_crew.security as security

        tree = tmp_path / "tree"
        (tree / "sessions").mkdir(parents=True)
        outside = tmp_path / "outside"
        (outside / "sessions").mkdir(parents=True)
        root = tree / "sessions"
        real_check = security.is_sensitive_path
        swapped = []

        def _swap_ancestor_then_check(path: str) -> bool:
            # Swap `tree`, the root's PARENT, once the root itself has passed
            # validation -- the window a leaf-only guard leaves open.
            if str(path).startswith(str(root / "chat-11")) and not swapped:
                swapped.append(True)
                (tree / "sessions").rmdir()
                tree.rmdir()
                tree.symlink_to(outside, target_is_directory=True)
            return real_check(path)

        with unittest.mock.patch.object(security, "is_sensitive_path", _swap_ancestor_then_check):
            result = session_project_dir("chat-11", str(root))

        assert swapped, "the swap never ran, so this test proves nothing"
        assert result == ""
        assert list((outside / "sessions").iterdir()) == [], "created through a swapped ancestor"

    def test_the_directory_is_still_created_without_the_posix_open_flags(
        self, tmp_path, monkeypatch
    ):
        """Windows has no `O_DIRECTORY`/`O_NOFOLLOW`, and must still get a directory.

        Naming either flag on Windows raises `AttributeError`, and this function's
        catch-all turns that into `""` -- so an earlier revision silently disabled
        the whole opt-in on every Windows session while looking correct on POSIX.
        Every assertion in this file passed, because they all run on POSIX.

        Simulated the way the repo's other Windows tests do it, by DELETING the
        two attributes rather than by faking a capability flag: deleting them is
        what reproduces the `AttributeError`, and a test that only cleared
        `os.supports_dir_fd` would have passed against the broken code. What the
        non-pinned branch does on real Windows is hold the root open in a share
        mode that forbids renaming or deleting it, or anything above it, which is
        why creating by name there is safe; on POSIX the same call degrades to an
        ordinary directory open, so what this pins is the part that was broken --
        that the feature still produces a directory at all.
        """
        monkeypatch.delattr(os, "O_DIRECTORY", raising=False)
        monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
        monkeypatch.setattr(os, "supports_dir_fd", set())
        root = tmp_path / "sessions"
        root.mkdir()

        result = session_project_dir("chat-13", str(root))

        assert result == os.path.realpath(str(root / "chat-13"))
        assert Path(result).is_dir()

    def test_an_ancestor_swap_is_refused_without_the_posix_open_flags(self, tmp_path, monkeypatch):
        """The non-pinned branch must refuse an ancestor swap, not just create safely.

        The branch taken where a platform cannot create relative to a descriptor
        needs its REFUSALS tested, not only its happy path. Holding the root open
        stops it being renamed from that moment on and refuses a reparse point at
        its own name, but an ancestor swapped before the pin is traversed, so the
        pin lands on whatever that ancestor points at -- the same escape the
        component walk refuses on POSIX, arriving by a different route. Pinning
        the happy path alone leaves it open, and on POSIX nothing exercises this
        branch at all.

        Same swap and same timing as the POSIX ancestor test, with the two flags
        deleted so the platform capability reports False.
        """
        import kiro_crew.security as security

        monkeypatch.delattr(os, "O_DIRECTORY", raising=False)
        monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
        monkeypatch.setattr(os, "supports_dir_fd", set())
        tree = tmp_path / "tree"
        (tree / "sessions").mkdir(parents=True)
        outside = tmp_path / "outside"
        (outside / "sessions").mkdir(parents=True)
        root = tree / "sessions"
        real_check = security.is_sensitive_path
        swapped = []

        def _swap_ancestor_then_check(path: str) -> bool:
            if str(path).startswith(str(root / "chat-15")) and not swapped:
                swapped.append(True)
                (tree / "sessions").rmdir()
                tree.rmdir()
                tree.symlink_to(outside, target_is_directory=True)
            return real_check(path)

        with unittest.mock.patch.object(security, "is_sensitive_path", _swap_ancestor_then_check):
            result = session_project_dir("chat-15", str(root))

        assert swapped, "the swap never ran, so this test proves nothing"
        assert result == ""
        assert list((outside / "sessions").iterdir()) == [], "created through a swapped ancestor"

    @pytest.mark.skipif(
        os.name != "posix" or os.geteuid() == 0,
        reason="POSIX-only: root ignores directory permissions, and os.geteuid is absent on Windows",
    )
    def test_unwritable_root_degrades_to_empty(self, tmp_path):
        """A permissions failure must degrade, not raise.

        The caller treats "" as "use the shared default", so this is the path
        that keeps a session openable on a read-only or full disk.
        """
        root = tmp_path / "sessions"
        root.mkdir()
        original_mode = stat.S_IMODE(root.stat().st_mode)
        os.chmod(root, stat.S_IRUSR | stat.S_IXUSR)
        try:
            assert session_project_dir("chat-7", str(root)) == ""
        finally:
            # Restore what pytest created rather than a hardcoded mode: a literal
            # here is both less correct and flagged by the insecure-file-permissions
            # SAST rule.
            os.chmod(root, original_mode)


class TestSessionProjectDirRootFallback:
    def test_empty_root_falls_back_to_the_workspace_directory(self, tmp_path, monkeypatch):
        ws = tmp_path / "workspace"
        ws.mkdir()
        monkeypatch.setattr(
            "kiro_crew.config.loader.default_project_dir",
            lambda workspace=None: str(ws),
        )

        got = session_project_dir("chat-7", "")

        assert got == os.path.realpath(str(ws / "chat-7"))

    def test_empty_root_with_no_workspace_dir_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            "kiro_crew.config.loader.default_project_dir",
            lambda workspace=None: "",
        )

        assert session_project_dir("chat-7", "") == ""


class TestNamelessCreateThroughTheHandler:
    """The flow the setting exists for, driven through the real create handler.

    The dashboard's own "New chat" path sends no name, so the handler's local
    `name` is None there. An earlier revision derived the directory from that
    `name`, which meant the opt-in silently did nothing on precisely this path
    while looking correct on a named create. A unit test of the helper cannot
    catch that -- only driving the handler can, because the defect was in which
    argument the call site passed.
    """

    @staticmethod
    async def _create(
        tmp_path,
        monkeypatch,
        body,
        preseed=None,
        cfg_override=None,
        reopen=False,
        after_create=None,
    ):
        """POST to the real create handler with the setting on. Returns (state, root).

        ``preseed`` names a directory to create under the root BEFORE the POST,
        standing in for a session that was closed and whose key a later create
        reproduces. ``cfg_override`` replaces the config object entirely, for
        exercising a PARTIAL config whose dashboard lacks the new fields.
        ``reopen`` POSTs the same body twice. In between it clears every slot's
        project AND empties the root, so the second request is a reopen of an
        existing slot that has no directory of its own -- the shape a session
        first materialized by the send path leaves behind, and the only shape
        where the derivation would actually run. Leaving the first create's
        directory in place instead would let the never-adopt rule refuse the
        second derivation for a different reason and hide whether the gate works.
        """
        from unittest.mock import AsyncMock, MagicMock

        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from chat_test_helpers import _make_ready_kiro_prerequisite

        from kiro_crew.config.loader import KiroCrewConfig
        from kiro_crew.dashboard.chat import api_chat_slot_create
        from kiro_crew.dashboard.state import DashboardState
        from kiro_crew.history import ConversationLog

        root = tmp_path / "session-roots"
        root.mkdir()
        if preseed:
            stale = root / preseed
            stale.mkdir()
            (stale / "previous-session-notes.md").write_text("secret", encoding="utf-8")
        cfg = cfg_override or KiroCrewConfig(
            dashboard=DashboardConfig(
                new_project_per_session=True,
                session_project_root=str(root),
            )
        )
        monkeypatch.setattr(
            "kiro_crew.dashboard.chat_handlers.KiroCrewConfig.load",
            classmethod(lambda cls: cfg),
        )
        monkeypatch.setattr("kiro_crew.dashboard.state.config_dir", lambda: tmp_path)

        sessions = MagicMock(count=0)
        sessions.remove = AsyncMock()
        sessions.recycle_background = AsyncMock()
        sessions.get_pid = MagicMock(return_value=None)
        state = DashboardState(
            sessions=sessions,
            crons=MagicMock(
                list_jobs=MagicMock(return_value=[]), status=MagicMock(return_value={})
            ),
            lessons=MagicMock(load_all=MagicMock(return_value=[])),
            start_time=0.0,
            conversation_log=ConversationLog(base_dir=tmp_path),
        )
        state.kiro_prerequisite_service = _make_ready_kiro_prerequisite()

        app = web.Application()
        app["state"] = state
        app.router.add_post("/api/chat/slots", api_chat_slot_create)
        async with TestClient(TestServer(app)) as client:
            resp = await client.post("/api/chat/slots", json=body)
            assert resp.status == 200, f"slot create returned {resp.status}, not 200"
            if after_create is not None:
                # Handed the OPEN client so a test can drive a second request
                # against the same live state, which is what a reopen is.
                await after_create(state, root, client)
            if reopen:
                for existing in state._slots.values():
                    existing.project = ""
                for made in root.iterdir():
                    shutil.rmtree(made)
                resp = await client.post("/api/chat/slots", json=body)
                assert resp.status == 200, f"slot reopen returned {resp.status}, not 200"
        return state, root

    @pytest.mark.asyncio
    async def test_a_create_with_no_name_still_gets_its_own_directory(self, tmp_path, monkeypatch):
        state, root = await self._create(tmp_path, monkeypatch, {})

        assert len(state._slots) == 1
        slot = next(iter(state._slots.values()))
        # The directory must be named from the MINTED key, and must actually be
        # the slot's project rather than the shared workspace default.
        assert slot.project == os.path.realpath(str(root / slot.key))
        assert Path(slot.project).is_dir()
        assert Path(slot.project).parent == root.resolve()

    @pytest.mark.asyncio
    async def test_a_concurrent_explicit_selection_during_the_await_is_not_clobbered(
        self, tmp_path, monkeypatch
    ):
        """The helper must yield to a project set by a concurrent writer.

        The helper awaits twice and does not hold a lock across them, so a
        project POST can set an explicit selection while it waits. Committing the
        derived directory unconditionally would replace that selection with the
        weaker default. Simulated by having the conflict-scan await set
        `slot.project` mid-flight, standing in for the concurrent writer; the
        commit must then see a non-empty field and leave it alone.
        """
        from types import SimpleNamespace

        from kiro_crew.dashboard import chat_handlers

        root = tmp_path / "sessions"
        root.mkdir()
        slot = SimpleNamespace(
            project="",
            key="chat-1-1788689331",
            workspace="default",
            _project_init_lock=asyncio.Lock(),
        )
        explicit = "/some/explicit/project"

        def _scan_sets_project(_path):
            # Stand-in for a concurrent project POST landing during the await.
            slot.project = explicit
            return None

        monkeypatch.setattr(chat_handlers, "voice_runtime_workspace_conflict", _scan_sets_project)
        cfg = SimpleNamespace(
            dashboard=SimpleNamespace(new_project_per_session=True, session_project_root=str(root))
        )

        await chat_handlers._apply_per_session_project(slot, cfg, "default")

        assert slot.project == explicit, "clobbered a concurrent explicit selection"

    @pytest.mark.asyncio
    async def test_two_concurrent_creates_for_one_slot_derive_only_once(self, tmp_path):
        """A duplicate create must REUSE the winner's directory, not derive again.

        Two creates naming one slot key -- a double submit, a client retry -- both
        pass the "no project yet" check unless something serialises them, and both
        derive. The loser's
        exclusive create meets the winner's directory and gets nothing back, so it
        returns False and its caller falls through to the SHARED default; if that
        fallback commits first, the compare-and-set correctly declines to
        overwrite it and the slot ends on the shared directory with the winner's
        private one orphaned. A duplicate request silently costs the isolation the
        opt-in exists for.

        Pinned on the DERIVATION COUNT rather than the final project, because the
        final project looks identical either way in this unit -- the orphaning
        needs the caller's fallback to interleave. Exactly one derivation is the
        property that makes the follower a reuser instead of a second creator.
        """
        from types import SimpleNamespace

        from kiro_crew.config import loader as config_loader
        from kiro_crew.dashboard import chat_handlers

        root = tmp_path / "sessions"
        root.mkdir()
        slot = SimpleNamespace(
            project="",
            key="chat-9-1788689331",
            workspace="default",
            _project_init_lock=asyncio.Lock(),
        )
        cfg = SimpleNamespace(
            dashboard=SimpleNamespace(new_project_per_session=True, session_project_root=str(root))
        )
        calls = []
        real_derive = config_loader.session_project_dir

        def _counting_derive(session_key, root_arg="", workspace=None):
            # Slow enough that a second caller reaches the helper before the first
            # commits, so the interleaving is forced rather than hoped for.
            calls.append(session_key)
            time.sleep(0.05)
            return real_derive(session_key, root_arg, workspace)

        with unittest.mock.patch.object(chat_handlers, "session_project_dir", _counting_derive):
            results = await asyncio.gather(
                chat_handlers._apply_per_session_project(slot, cfg, "default"),
                chat_handlers._apply_per_session_project(slot, cfg, "default"),
            )

        assert len(calls) == 1, f"derived {len(calls)} times; the follower re-derived"
        assert sorted(results) == [False, True], "both calls claimed the assignment"
        assert slot.project == os.path.realpath(str(root / slot.key))
        assert [p.name for p in root.iterdir()] == [slot.key], "left an orphaned directory"

        """The send path must NOT derive, and must say why at the call site.

        Deriving there is circular: it needs the session's workspace, which for an
        auto-created slot comes from the requested agent's bindings, but
        `resolve_agent_bindings` requires the project directory it is given to be
        the one the session actually runs in. An earlier revision derived anyway
        and put the directory under the DEFAULT workspace root whenever the root
        was unconfigured and the request named a non-default agent.

        Pinned structurally because the harm is a wrong LOCATION chosen from stale
        inputs, which a status-code test cannot see. The reasoning is required to
        stay next to the code so a later reader does not "fix" the gap by
        reintroducing the bug.
        """
        import inspect

        from kiro_crew.dashboard import chat_handlers

        send_src = inspect.getsource(chat_handlers.api_chat)
        assert "_apply_per_session_project" not in send_src, "the send path derives again"
        assert "circular" in send_src, "the reason for not deriving is not recorded"
        # The create endpoint, which does have a resolved workspace, must apply it.
        create_src = inspect.getsource(chat_handlers.api_chat_slot_create)
        assert "_apply_per_session_project" in create_src

    @pytest.mark.asyncio
    async def test_a_config_without_a_dashboard_attribute_is_tolerated(self):
        """The whole access chain must be guarded, not just the leaf fields.

        Measured regression: hardening `new_project_per_session` alone left
        `cfg.dashboard` itself bare, and the send path sees config stand-ins with
        no `dashboard` attribute at all. That raised `AttributeError` inside the
        request handler and surfaced as a 500 on an endpoint contracted to fail
        closed with 400/409 - five tests across two files caught it, none of them
        in this file.
        """
        from types import SimpleNamespace

        from kiro_crew.dashboard.chat_handlers import _apply_per_session_project

        slot = SimpleNamespace(project="", key="chat-1-1788689331", workspace="default")
        # No `dashboard` attribute at all, and no exception may escape.
        await _apply_per_session_project(slot, SimpleNamespace(default_agent="x"), "default")

        assert slot.project == ""

    @pytest.mark.asyncio
    async def test_a_partial_config_object_does_not_break_slot_create(self, tmp_path, monkeypatch):
        """A config whose dashboard lacks the new fields must still create a slot.

        This is a regression pin for a real 500. `cfg.dashboard` reaching this
        handler is routinely a PARTIAL stand-in - 36 sites across 19 test files
        patch `KiroCrewConfig.load` with a minimal
        `dashboard=SimpleNamespace(default_project="")` - so reading a newly
        added field by bare attribute access raised `AttributeError` inside the
        request handler and returned 500 from `/api/chat/slots`. Three CI shards
        caught it while every test in this file passed, because this file always
        built a COMPLETE config.

        The pin is the response status, not the absence of an exception: the
        observable failure was a 500, and `_create` asserts 200.
        """
        from types import SimpleNamespace

        partial = SimpleNamespace(
            default_agent="local-only-crew",
            dashboard=SimpleNamespace(default_project=""),
        )
        state, root = await self._create(tmp_path, monkeypatch, {}, cfg_override=partial)

        # And a missing field must read as OFF, not as "on with a bad root".
        assert list(root.iterdir()) == [], "a missing field must default the feature OFF"
        slot = next(iter(state._slots.values()))
        assert slot.project != os.path.realpath(str(root / slot.key))

    @pytest.mark.asyncio
    @pytest.mark.parametrize("supplied_name", ["reused-name", "worker-1-stable"])
    async def test_a_create_whose_directory_already_exists_falls_back(
        self, supplied_name, tmp_path, monkeypatch
    ):
        """The blocking case: a reused key must not inherit the old directory.

        Driven through the handler because that is where the harm lands. The
        directory is pre-seeded with a file, standing in for a session that was
        closed and whose key a later create reproduces. `slot.project` must NOT
        become that directory, and the earlier file must survive - nothing in
        this change deletes.

        `worker-1-stable` is parametrized deliberately: an earlier revision gated
        on the key's SHAPE via `_slot_index_from_key`, which only checks that the
        second segment is a digit, so that name passed an "auto-minted only"
        guard while being entirely reusable. Refusing an existing directory
        covers it without classifying keys at all.
        """
        state, root = await self._create(
            tmp_path, monkeypatch, {"name": supplied_name}, preseed=supplied_name
        )

        slot = state._slots[supplied_name]
        stale = root / supplied_name
        assert slot.project != os.path.realpath(str(stale)), "adopted a reused key's directory"
        assert (stale / "previous-session-notes.md").read_text(encoding="utf-8") == "secret"

    @pytest.mark.asyncio
    async def test_the_assignment_is_saved_even_with_no_other_metadata(self, tmp_path, monkeypatch):
        """A derived directory must be durable at the moment it is assigned.

        The handler's durable save was conditional on the metadata the REQUEST
        supplied -- a folder, a pinned title, a peer binding -- and a plain
        create or reopen supplies none of those. So the assignment lived only in
        memory: a crash before the next periodic flush lost it, while the
        directory and anything the session had written into it stayed on disk
        with nothing pointing at it. Nothing re-derives the directory (a restored
        session is served its project from metadata), so the assignment IS the
        only record of the association.

        Asserted on the forced save rather than on file contents because the
        defect is that the write never happens, and `force=True` is what
        distinguishes it from the dirty-flag flush that may or may not follow.
        """
        from unittest.mock import AsyncMock

        from kiro_crew.dashboard import chat_handlers

        saves = AsyncMock(return_value=True)
        monkeypatch.setattr(chat_handlers, "save_slot_off_loop", saves)

        state, root = await self._create(tmp_path, monkeypatch, {})

        slot = next(iter(state._slots.values()))
        assert slot.project == os.path.realpath(str(root / slot.key))
        assert saves.await_count == 1, "the assignment was never persisted"
        assert saves.await_args.kwargs["force"] is True
        assert saves.await_args.args[1] is slot

    @pytest.mark.asyncio
    async def test_a_reopen_of_an_existing_slot_derives_nothing(self, tmp_path, monkeypatch):
        """Only a slot this request MINTS may be given a directory.

        This endpoint also serves a reopen, and a slot that already exists can
        have a live provider running in the shared directory. Assigning a project
        there changes in-memory metadata only: the provider keeps the cwd it
        started with, so the session advertises a private directory while its
        files keep landing in the shared one. Isolation is reported and not
        delivered, and the mixed files cannot be sorted out afterwards.

        The second POST reopens the slot with its project cleared and no
        directory of its own, which is what a session first materialized by the
        send path looks like -- that path deliberately does not derive. That is
        the only precondition where the derivation would run at all: leave the
        first create's directory in place and the never-adopt rule refuses for a
        different reason, which proves nothing about the gate.
        """
        state, root = await self._create(tmp_path, monkeypatch, {"name": "reopened"}, reopen=True)

        slot = state._slots["reopened"]
        assert list(root.iterdir()) == [], "the reopen derived a directory"
        assert slot.project != os.path.realpath(str(root / "reopened")), "reopen assigned a project"

    @pytest.mark.asyncio
    async def test_the_shared_fallback_waits_for_an_in_flight_project_decision(
        self, tmp_path, monkeypatch
    ):
        """The handler must not commit the shared default past a held decision.

        Two overlapping creates on one name split into a winner that mints the
        slot and a follower that finds it existing. Only the winner derives -- the
        follower is excluded so it cannot reassign a project under a live
        provider -- which takes the follower straight to the shared fallback. A
        fallback that commits while the winner's derivation is in flight wins the
        field, the winner's compare-and-set then correctly declines to overwrite
        it, and the slot runs in the shared directory with the private one it
        exclusively created orphaned.

        Driven by holding `_project_init_lock` with the project cleared, which is
        exactly the state a follower observes mid-derivation, and then issuing the
        follower's own request. Held that way the request must not finish; once
        the decision lands and the lock frees, it must accept that decision
        instead of replacing it. Two concurrent POSTs cannot express this -- over
        HTTP they observably serialise, so such a test passes whether or not the
        fallback locks anything.
        """
        outcome = {}

        async def _follower(state, root, client):
            slot = state._slots["raced"]
            derived = slot.project
            assert derived == os.path.realpath(str(root / "raced"))
            async with slot._project_init_lock:
                slot.project = ""
                task = asyncio.create_task(client.post("/api/chat/slots", json={"name": "raced"}))
                await asyncio.sleep(0.2)
                outcome["finished_while_held"] = task.done()
                # The winner's commit, landing while the follower waits.
                slot.project = derived
            resp = await task
            assert resp.status == 200
            outcome["project"] = slot.project
            outcome["derived"] = derived

        await self._create(tmp_path, monkeypatch, {"name": "raced"}, after_create=_follower)

        assert outcome["finished_while_held"] is False, "committed past a held project decision"
        assert outcome["project"] == outcome["derived"], "shared default replaced the derivation"


class TestOffByDefault:
    def test_toggle_defaults_to_false(self):
        """Installing this change must alter nothing until a user opts in."""
        assert DashboardConfig().new_project_per_session is False

    def test_root_defaults_to_empty(self):
        assert DashboardConfig().session_project_root == ""

    def test_config_that_never_mentions_the_keys_parses_to_the_old_behaviour(self):
        cfg = _load_from_dict({"dashboard": {}})

        assert cfg.dashboard.new_project_per_session is False
        assert cfg.dashboard.session_project_root == ""

    def test_config_that_sets_the_keys_is_actually_read(self, tmp_path):
        """Pins the loader wiring, which the default-only test cannot.

        A test that only asserts False-when-absent passes even if the parse were
        never wired at all, because the dataclass default is already False. This
        one fails unless `_load_resolved` reads both keys.
        """
        cfg = _load_from_dict(
            {
                "dashboard": {
                    "new_project_per_session": True,
                    "session_project_root": str(tmp_path / "roots"),
                }
            }
        )

        assert cfg.dashboard.new_project_per_session is True
        assert cfg.dashboard.session_project_root == str(tmp_path / "roots")

    def test_non_boolean_toggle_degrades_to_false(self):
        """`_safe_bool` keeps a hand-edited config from raising on load."""
        cfg = _load_from_dict({"dashboard": {"new_project_per_session": "yes please"}})

        assert cfg.dashboard.new_project_per_session is False
