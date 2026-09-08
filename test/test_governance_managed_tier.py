"""The MDM-managed tier, and the tighten-only composition rule beneath it.

Covers the top precedence tier added to ``load_security_policy`` and the
composition primitive every lower tier now goes through:

* the tier is **inert** with no managed file, so every standalone install is
  unaffected (this is the property that makes the tier free to ship);
* the trust checks on a *present* managed file -- regular file, root-owned, not
  group/world-writable, not a symlink, size-bounded -- and the fact that each
  failure **raises** instead of falling through to a lower, possibly permissive
  tier, which is the entire security property;
* both document encodings the tier accepts (macOS ``.plist``, JSON elsewhere);
* ``_intersect_ceilings``: a subordinate may add restrictions and may not remove
  one, and everything outside ``controls`` stays the authority's;
* that there is NO channel by which a lower tier outranks the authority.

**Nothing here touches a real managed path.** The autouse fixture points
``_managed_policy_path`` and ``_policy_home_path`` at nonexistent files under
``tmp_path`` before every test, so a dev machine that happens to have
``/etc/kirocrew/security_policy.json`` cannot make an assertion here read a
document this module never wrote. There is deliberately no environment override
for the managed path, so the function seam is the only way to aim it.
"""

from __future__ import annotations

import json
import os
import plistlib
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kiro_crew import platform_compat
from kiro_crew.platform import governance
from kiro_crew.platform import governance_health as health
from kiro_crew.platform import governance_profiles as gp
from kiro_crew.platform.context import PlatformCompositionError
from kiro_crew.platform.governance import (
    SIGNATURE_UNSIGNED,
    SIGNATURE_UNVERIFIED,
    TIER_CENTRAL,
    TIER_ENV,
    TIER_HOME,
    TIER_MANAGED,
    load_security_policy,
    resolve,
    resolve_ordinal,
)

_POLICY_ENV = "KIROCREW_SECURITY_POLICY"

#: The real path resolver, captured at import time -- BEFORE the autouse fixture
#: replaces the module attribute. The "no env override" test needs the genuine
#: function, and there is no other way back to it once the seam is patched.
_REAL_MANAGED_POLICY_PATH = governance._managed_policy_path


#: The uid check only runs on POSIX -- off POSIX ``_assert_managed_file_trusted``
#: returns early and documents that the ACL is the OS's to enforce. Tests whose
#: subject IS the uid comparison on a real file are therefore POSIX-only; the
#: faked-stat tests below force ``IS_POSIX`` so the mode-bit branch is exercised
#: on a Windows runner too, and no platform's answer is left untested.
_POSIX_ONLY = pytest.mark.skipif(
    not hasattr(os, "getuid"), reason="uid ownership semantics; os.getuid is POSIX-only"
)


#: A managed file under ``tmp_path`` is owned by whoever runs pytest, and a test
#: cannot chown to root -- so the "owned by a non-root uid" case is natural here
#: and needs no patching at all, which is why those tests exercise the real
#: ``os.fstat``. Unless the suite runs AS root, where the file would legitimately
#: pass the check.
_NOT_ROOT = pytest.mark.skipif(
    hasattr(os, "getuid") and os.getuid() == 0,
    reason="running as root makes a tmp_path file legitimately root-owned",
)


# ──────────────────────────────────────────────────────────────────────────
# Helpers -- same document-building idiom as test_governance_policy.py /
# test_governance_distribution.py: a minimal valid body, tagged by
# ``identity.issuer`` so a precedence assertion can name the document that won
# without parsing a control out of it.
# ──────────────────────────────────────────────────────────────────────────


def _doc(marker: str = "", **extra: object) -> dict:
    body: dict = {"version": 1, "boot": {"fail_closed": True}}
    if marker:
        body["identity"] = {"issuer": marker}
    body.update(extra)
    return body


def _write_policy(path: Path, marker: str = "", **extra: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_doc(marker, **extra)), encoding="utf-8")
    return path


def _write_plist_policy(path: Path, marker: str = "", **extra: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        plistlib.dump(_doc(marker, **extra), handle)
    return path


def _sized_policy_bytes(total: int) -> bytes:
    """JSON for a valid policy whose encoded length is EXACTLY *total* bytes.

    Padding rides on ``identity.issuer`` rather than a filler top-level key
    because ``parse_policy`` is fail-closed on an unknown top-level scope, so a
    filler key would be refused for the wrong reason.
    """
    body = _doc("x")
    pad = total - len(json.dumps(body).encode("utf-8"))
    assert pad >= 0, "requested size is below the minimum valid document"
    body["identity"]["issuer"] = "x" * (1 + pad)
    raw = json.dumps(body).encode("utf-8")
    assert len(raw) == total
    return raw


def _future(days: int = 7) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _point_managed(monkeypatch, path: object) -> None:
    monkeypatch.setattr(governance, "_managed_policy_path", lambda: path)


def _point_home(monkeypatch, path: Path) -> None:
    monkeypatch.setattr(governance, "_policy_home_path", lambda: path)


def _fake_managed_stat(monkeypatch, *, uid: int = 0, extra_mode: int = 0, perm: int = None) -> None:
    """Report a doctored ``os.fstat`` for the managed file's descriptor.

    Needed because a test cannot create a root-owned file: without this the uid
    check fires first and the mode-bit branch below it is unreachable. The fake
    delegates to the real ``os.fstat`` and rewrites only the fields under
    test, so ``S_ISREG`` and every other predicate still answer about the real
    file rather than about a hand-built tuple.

    ``perm`` REPLACES the permission bits (the file type is preserved, so
    ``S_ISREG`` is unaffected). Pass it whenever the assertion depends on the
    permissions being exactly something: ``extra_mode`` alone ORs onto whatever the
    filesystem reports, and Windows honours only the read-only bit, so a
    ``chmod(0o644)`` there leaves 0o666 behind and a "no group write" case would
    fail on the platform rather than on the code.
    """
    real_fstat = os.fstat

    def fake(fd: int) -> os.stat_result:
        st = real_fstat(fd)
        mode = st.st_mode
        if perm is not None:
            mode = stat.S_IFMT(mode) | perm
        return os.stat_result(
            (
                mode | extra_mode,
                st.st_ino,
                st.st_dev,
                st.st_nlink,
                uid,
                st.st_gid,
                st.st_size,
                int(st.st_atime),
                int(st.st_mtime),
                int(st.st_ctime),
            )
        )

    monkeypatch.setattr(os, "fstat", fake)
    # The mode-bit branch sits behind the POSIX gate, so the gate must be on for
    # the branch to be reachable at all on a Windows runner.
    monkeypatch.setattr(platform_compat, "IS_POSIX", True)


class _ExplodingPath(type(Path())):  # type: ignore[misc]
    """A path whose ``exists()`` raises OSError, as an unreadable parent would."""

    def exists(self, *args: object, **kwargs: object) -> bool:  # type: ignore[override]
        raise OSError("permission denied")


# ──────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _hermetic_governance_globals(monkeypatch, tmp_path):
    """Pin every process global and env var this module's subject reads.

    The two path seams are aimed at nonexistent files under ``tmp_path`` so the
    tier starts INERT in every test and a real ``/etc/kirocrew`` (or a developer's
    own home policy) can never be the document an assertion here reads. The env
    vars are deleted because each selects a tier: one left set by a CI image would
    make every precedence assertion read a file this module never wrote.
    ``governance_health`` and ``governance_profiles`` keep worker-lifetime state,
    so both are reset on the way in and on the way out.
    """
    # Every per-process latch and memo the ladder keeps (absence audit, env-inversion
    # warning, intersect pairs, last bundled document) lives in one holder and is
    # reset together, so a fixture cannot forget one -- that is how ``last_bundled``
    # leaked between tests when it was a separate global.
    governance.reset_process_state()
    for var in (
        _POLICY_ENV,
        "KIROCREW_ADMISSION_POLICY",
        "KIROCREW_POLICY_URL",
        "KIROCREW_POLICY_HEADERS",
        "KIROCREW_POLICY_CACHE_ONLY",
    ):
        monkeypatch.delenv(var, raising=False)
    _point_managed(monkeypatch, tmp_path / "absent" / "managed.json")
    _point_home(monkeypatch, tmp_path / "absent" / "home.json")
    health.reset()
    gp.reset_store()
    yield
    governance.reset_process_state()
    health.reset()
    gp.reset_store()


@pytest.fixture
def trusted_managed(monkeypatch):
    """Treat the managed file as trusted, for tests whose subject is NOT the guard.

    A test cannot create a root-owned file, so every happy-path assertion about
    the tier's PRECEDENCE would otherwise refuse for a reason it is not testing.
    The guard itself is exercised for real -- unpatched -- by
    ``TestManagedFileTrustIsChecked``.
    """
    monkeypatch.setattr(governance, "_assert_managed_file_trusted", lambda fd, path: None)


# ──────────────────────────────────────────────────────────────────────────
# (a) Inert with no managed file
# ──────────────────────────────────────────────────────────────────────────
class TestTheTierIsInertByDefault:
    def test_absent_managed_file_reads_as_none(self):
        assert governance._read_managed_policy() is None

    def test_unknown_platform_has_no_managed_path_and_stays_inert(self, monkeypatch):
        # ``_managed_policy_path`` answers None on a platform with no managed
        # channel; the reader must treat that as inert, not as an error.
        _point_managed(monkeypatch, None)
        assert governance._read_managed_policy() is None

    def test_standalone_home_policy_still_governs_with_no_managed_file(self, monkeypatch, tmp_path):
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        ceiling = load_security_policy()
        assert ceiling is not None
        assert ceiling.tier == TIER_HOME
        assert ceiling.identity_issuer == "operator"

    def test_no_policy_at_any_tier_is_still_ungoverned(self):
        assert load_security_policy() is None

    def test_an_unreadable_parent_directory_leaves_the_tier_inert(self, monkeypatch, tmp_path):
        # A permissions quirk on a path nobody configured is not a managed policy,
        # so the tier stays inert rather than aborting boot.
        _point_managed(monkeypatch, _ExplodingPath(tmp_path / "managed.json"))
        assert governance._read_managed_policy() is None

    def test_the_managed_path_is_not_environment_overridable(self, monkeypatch, tmp_path):
        # The absence of an override is the tier's whole trust claim: an env var is
        # per-process and redefinable by whoever launches the process, so an MDM
        # could set one but never pin one. Calls the REAL resolver (captured at
        # import) with plausible override names set, and asserts none of them wins.
        planted = tmp_path / "planted.json"
        for var in (
            "KIROCREW_MANAGED_POLICY",
            "KIROCREW_MANAGED_SECURITY_POLICY",
            "KIROCREW_MANAGED_POLICY_PATH",
        ):
            monkeypatch.setenv(var, str(planted))
        resolved = _REAL_MANAGED_POLICY_PATH()
        assert resolved is None or resolved != planted
        # Only two constants and None. Windows is deliberately None: the obvious
        # implementation there reads %ProgramData% from the environment, which is
        # exactly the per-process override this test exists to forbid, and the
        # ownership check that would catch a redirect cannot run without a uid.
        assert resolved in (
            None,
            governance._MANAGED_POLICY_MACOS,
            governance._MANAGED_POLICY_LINUX,
        )

    def test_the_managed_path_is_not_under_the_service_env_dir(self):
        """The Linux managed path must be a SIBLING of the service's env dir, not inside it.

        ``service.linux.ENV_DIR`` (``/etc/kirocrew``) is created by the service
        installer, and under a hardened umask it came out ``0750``/``0700`` root-owned.
        The managed reader fails closed on every open error but ENOENT -- which is
        right for a directory this tier owns -- so a managed path BENEATH the installer's
        directory turned a non-searchable env dir into a boot abort on a host no fleet
        ever provisioned: ``open()`` of a missing file under a directory the gateway
        cannot search is EACCES, not ENOENT. Keeping the two directories disjoint is what
        makes "present but unreadable" mean what it says.
        """
        from kiro_crew.service import linux as svc_linux

        managed = governance._MANAGED_POLICY_LINUX
        env_dir = svc_linux.ENV_DIR
        assert managed.parent != env_dir
        assert env_dir not in managed.parents
        assert managed.parent not in env_dir.parents

    def test_windows_has_no_managed_tier_rather_than_an_overridable_one(self, monkeypatch):
        """The tier must not advertise a guarantee it cannot enforce.

        A ``%ProgramData%``-derived path would be resolved from a variable the
        launching user controls, and ``_assert_managed_file_trusted`` returns early on
        non-POSIX with no ownership check -- so a standard user could install their own
        document as the TOP authority. Absent beats falsely authoritative.
        """
        import kiro_crew.platform_compat as pc

        monkeypatch.setattr(pc, "IS_MACOS", False, raising=False)
        monkeypatch.setattr(pc, "IS_LINUX", False, raising=False)
        monkeypatch.setattr(pc, "IS_WINDOWS", True, raising=False)
        monkeypatch.setenv("ProgramData", "C:\\Users\\me\\evil")
        assert _REAL_MANAGED_POLICY_PATH() is None


# ──────────────────────────────────────────────────────────────────────────
# (b) The managed document outranks every local channel
# ──────────────────────────────────────────────────────────────────────────
class TestTheManagedTierOutranksLocalChannels:
    def test_managed_outranks_the_env_tier(self, monkeypatch, tmp_path, trusted_managed):
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        monkeypatch.setenv(_POLICY_ENV, str(_write_policy(tmp_path / "env.json", "local-env")))
        ceiling = load_security_policy()
        assert ceiling is not None
        assert ceiling.tier == TIER_MANAGED
        assert ceiling.identity_issuer == "mdm"

    def test_managed_outranks_the_home_tier(self, monkeypatch, tmp_path, trusted_managed):
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        ceiling = load_security_policy()
        assert ceiling is not None
        assert ceiling.tier == TIER_MANAGED
        assert ceiling.identity_issuer == "mdm"

    def test_managed_outranks_the_bundled_tier(self, monkeypatch, tmp_path, trusted_managed):
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        ceiling = load_security_policy(bundled_loader=lambda: _doc("companion"))
        assert ceiling is not None
        assert ceiling.tier == TIER_MANAGED
        assert ceiling.identity_issuer == "mdm"

    def test_managed_outranks_env_and_home_together(self, monkeypatch, tmp_path, trusted_managed):
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        monkeypatch.setenv(_POLICY_ENV, str(_write_policy(tmp_path / "env.json", "local-env")))
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        ceiling = load_security_policy()
        assert ceiling is not None
        assert ceiling.tier == TIER_MANAGED
        assert ceiling.identity_issuer == "mdm"

    def test_a_lower_tier_cannot_undo_a_managed_denial(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        # The precedence claim only matters if it survives composition, so the env
        # document below governs the SAME scope and tries to open it up.
        _point_managed(
            monkeypatch,
            _write_policy(
                tmp_path / "managed.json",
                "mdm",
                commands={"mode": "deny", "deny": ["git push*"]},
            ),
        )
        monkeypatch.setenv(
            _POLICY_ENV,
            str(
                _write_policy(
                    tmp_path / "env.json", "local-env", commands={"mode": "deny", "deny": []}
                )
            ),
        )
        ceiling = load_security_policy()
        assert ceiling is not None
        assert not resolve(ceiling, None, "commands", "git push origin main").permitted
        assert ceiling.pinned_command_patterns() == ("git push*",)


# ──────────────────────────────────────────────────────────────────────────
# (c)-(g) Trust checks on a PRESENT managed file -- each one raises
# ──────────────────────────────────────────────────────────────────────────
class TestManagedFileTrustIsChecked:
    @_POSIX_ONLY
    @_NOT_ROOT
    def test_a_non_root_owned_managed_file_is_refused(self, monkeypatch, tmp_path):
        # Deliberately UNPATCHED: a file under tmp_path is owned by whoever runs
        # pytest, so this exercises the real uid comparison against a real fstat
        # rather than a hand-built stat result.
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        with pytest.raises(PlatformCompositionError, match="not root"):
            governance._read_managed_policy()

    @_POSIX_ONLY
    @_NOT_ROOT
    def test_a_non_root_managed_file_does_not_fall_through_to_the_home_tier(
        self, monkeypatch, tmp_path
    ):
        # THE security property. Falling through here would restore exactly the
        # override this tier exists to remove, so the load must raise -- not return
        # the permissive local ceiling.
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        with pytest.raises(PlatformCompositionError, match="not root"):
            load_security_policy()

    @_POSIX_ONLY
    @_NOT_ROOT
    def test_a_non_root_managed_file_does_not_fall_through_to_the_env_tier(
        self, monkeypatch, tmp_path
    ):
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        monkeypatch.setenv(_POLICY_ENV, str(_write_policy(tmp_path / "env.json", "local-env")))
        with pytest.raises(PlatformCompositionError, match="not root"):
            load_security_policy()

    @_POSIX_ONLY
    @_NOT_ROOT
    def test_a_non_root_managed_file_does_not_fall_through_to_ungoverned(
        self, monkeypatch, tmp_path
    ):
        # No lower tier at all: the answer is still a refusal, never the
        # editable-defaults None an ungoverned host gets.
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        with pytest.raises(PlatformCompositionError):
            load_security_policy()

    def test_a_group_writable_managed_file_is_refused(self, monkeypatch, tmp_path):
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _fake_managed_stat(monkeypatch, uid=0, extra_mode=stat.S_IWGRP)
        with pytest.raises(PlatformCompositionError, match="group- or world-writable"):
            governance._read_managed_policy()

    def test_a_world_writable_managed_file_is_refused(self, monkeypatch, tmp_path):
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _fake_managed_stat(monkeypatch, uid=0, extra_mode=stat.S_IWOTH)
        with pytest.raises(PlatformCompositionError, match="group- or world-writable"):
            governance._read_managed_policy()

    def test_a_group_writable_managed_file_does_not_fall_through(self, monkeypatch, tmp_path):
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        _fake_managed_stat(monkeypatch, uid=0, extra_mode=stat.S_IWGRP)
        with pytest.raises(PlatformCompositionError, match="group- or world-writable"):
            load_security_policy()

    def test_a_root_owned_unwritable_managed_file_is_accepted(self, monkeypatch, tmp_path):
        # Positive control for the two refusals above: with uid 0 and no
        # group/world write bits the same fake PASSES, so those tests are failing
        # on the bits under test and not on the fake itself.
        path = _write_policy(tmp_path / "managed.json", "mdm")
        # 0o644 is pinned in the FAKE, not via chmod: Windows would leave the real
        # mode at 0o666 and this control would fail on the platform, not the guard.
        #
        # The real mode is ALSO dropped to read-only, because the trust check now asks
        # the kernel for EFFECTIVE write access as well (that is what sees a POSIX ACL,
        # which never appears in st_mode). A faked root-owned stat over a file this
        # account can really rewrite is not a coherent fixture for a "trusted file"
        # control -- the guard would be right to refuse it. Harmless off POSIX, where
        # the effective-access branch does not run at all.
        path.chmod(0o444)
        _point_managed(monkeypatch, path)
        _fake_managed_stat(monkeypatch, uid=0, perm=0o644)
        data = governance._read_managed_policy()
        assert data is not None
        assert data["identity"] == {"issuer": "mdm"}

    def test_the_uid_check_is_skipped_off_posix(self, monkeypatch, tmp_path):
        # Off POSIX there is no uid to compare, so the ownership branch is skipped and
        # only the regular-file test survives. That is exactly why
        # ``_managed_policy_path`` returns None on Windows: a tier whose trust check
        # cannot run must not be reachable, or it would lend its authority to a
        # user-writable file. This test pins the skip itself, which any future
        # non-POSIX platform would also take.
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        monkeypatch.setattr(platform_compat, "IS_POSIX", False)
        data = governance._read_managed_policy()
        assert data is not None
        assert data["identity"] == {"issuer": "mdm"}

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo is POSIX-only")
    def test_a_fifo_at_the_managed_path_is_refused(self, monkeypatch, tmp_path):
        # A FIFO has no bounded size, so it is rejected before a byte is read.
        # O_NONBLOCK in the open is what keeps this from hanging with no writer.
        fifo = tmp_path / "managed.json"
        os.mkfifo(fifo)
        _point_managed(monkeypatch, fifo)
        with pytest.raises(PlatformCompositionError, match="not a regular file"):
            governance._read_managed_policy()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo is POSIX-only")
    def test_a_fifo_is_refused_before_the_ownership_check(self, monkeypatch, tmp_path):
        # Ordering matters: the regular-file test must come first, or a FIFO would
        # be reported as an ownership problem and an operator would chown it.
        fifo = tmp_path / "managed.json"
        os.mkfifo(fifo)
        _point_managed(monkeypatch, fifo)
        with pytest.raises(PlatformCompositionError) as excinfo:
            governance._read_managed_policy()
        assert "not root" not in str(excinfo.value)

    @pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="O_NOFOLLOW is POSIX-only")
    def test_a_symlink_at_the_managed_path_is_refused(self, monkeypatch, tmp_path):
        # The open carries O_NOFOLLOW, so a symlink planted at the managed path
        # cannot redirect the ceiling at a file the user does own. The target
        # EXISTS, so the earlier ``path.exists()`` probe does not short-circuit --
        # O_NOFOLLOW is what refuses it.
        target = _write_policy(tmp_path / "attacker.json", "attacker")
        link = tmp_path / "managed.json"
        link.symlink_to(target)
        _point_managed(monkeypatch, link)
        with pytest.raises(PlatformCompositionError, match="could not be opened"):
            governance._read_managed_policy()

    @pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="O_NOFOLLOW is POSIX-only")
    def test_a_symlinked_managed_path_does_not_fall_through(self, monkeypatch, tmp_path):
        target = _write_policy(tmp_path / "attacker.json", "attacker")
        link = tmp_path / "managed.json"
        link.symlink_to(target)
        _point_managed(monkeypatch, link)
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        with pytest.raises(PlatformCompositionError):
            load_security_policy()

    def test_an_oversize_managed_file_is_refused(self, monkeypatch, tmp_path, trusted_managed):
        path = tmp_path / "managed.json"
        path.write_bytes(_sized_policy_bytes(governance._MANAGED_POLICY_MAX_BYTES + 1))
        _point_managed(monkeypatch, path)
        with pytest.raises(PlatformCompositionError, match="exceeds"):
            governance._read_managed_policy()

    def test_a_managed_file_at_exactly_the_limit_is_accepted(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        # The bound is a bound, not a blanket refusal, so the boundary is asserted
        # from both sides.
        path = tmp_path / "managed.json"
        path.write_bytes(_sized_policy_bytes(governance._MANAGED_POLICY_MAX_BYTES))
        _point_managed(monkeypatch, path)
        data = governance._read_managed_policy()
        assert data is not None
        assert data["version"] == 1

    def test_an_oversize_managed_file_does_not_fall_through(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        path = tmp_path / "managed.json"
        path.write_bytes(_sized_policy_bytes(governance._MANAGED_POLICY_MAX_BYTES + 1))
        _point_managed(monkeypatch, path)
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        with pytest.raises(PlatformCompositionError, match="exceeds"):
            load_security_policy()

    def test_a_managed_file_that_is_not_an_object_is_refused(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        path = tmp_path / "managed.json"
        path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        _point_managed(monkeypatch, path)
        with pytest.raises(PlatformCompositionError, match="not a JSON/plist object"):
            governance._read_managed_policy()

    def test_unparseable_managed_json_is_refused(self, monkeypatch, tmp_path, trusted_managed):
        path = tmp_path / "managed.json"
        path.write_text("{not json", encoding="utf-8")
        _point_managed(monkeypatch, path)
        with pytest.raises(PlatformCompositionError, match="unreadable"):
            governance._read_managed_policy()

    def test_a_structurally_invalid_managed_document_raises_at_its_own_tier(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        # Readable bytes, refused by parse_policy: a fleet that placed a document
        # here meant it to govern, so a bad one aborts rather than degrading.
        path = tmp_path / "managed.json"
        path.write_text(json.dumps({"version": 99, "boot": {}}), encoding="utf-8")
        _point_managed(monkeypatch, path)
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        with pytest.raises(PlatformCompositionError, match="version"):
            load_security_policy()


# ──────────────────────────────────────────────────────────────────────────
# (h) Both document encodings
# ──────────────────────────────────────────────────────────────────────────
class TestManagedDocumentEncodings:
    def test_a_macos_plist_managed_document_parses(self, monkeypatch, tmp_path, trusted_managed):
        # macOS publishes a managed configuration profile as a plist in the
        # ``dev.kirocrew`` preference domain, so the reader keys on the suffix.
        _point_managed(monkeypatch, _write_plist_policy(tmp_path / "dev.kirocrew.plist", "mdm"))
        data = governance._read_managed_policy()
        assert data is not None
        assert data["version"] == 1
        assert data["identity"] == {"issuer": "mdm"}

    def test_a_binary_plist_managed_document_parses_the_same(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        """The file the MDM actually writes is BINARY, not XML.

        ``cfprefsd`` materialises ``/Library/Managed Preferences/*.plist`` as a binary
        property list. ``plistlib.loads(body)`` with no ``fmt`` auto-detects, so both
        parse today -- this test exists so a future ``fmt=plistlib.FMT_XML`` tightening
        cannot pass CI on the XML fixture while refusing every real managed Mac.
        """
        path = tmp_path / "dev.kirocrew.plist"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as handle:
            plistlib.dump(
                _doc("mdm", commands={"mode": "deny", "deny": ["git push*"]}),
                handle,
                fmt=plistlib.FMT_BINARY,
            )
        assert path.read_bytes().startswith(b"bplist"), "the fixture really is binary"
        _point_managed(monkeypatch, path)
        data = governance._read_managed_policy()
        assert data is not None
        assert data["identity"] == {"issuer": "mdm"}
        assert data["commands"] == {"mode": "deny", "deny": ["git push*"]}

    def test_a_plist_managed_document_governs(self, monkeypatch, tmp_path, trusted_managed):
        _point_managed(
            monkeypatch,
            _write_plist_policy(
                tmp_path / "dev.kirocrew.plist",
                "mdm",
                commands={"mode": "deny", "deny": ["git push*"]},
            ),
        )
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        ceiling = load_security_policy()
        assert ceiling is not None
        assert ceiling.tier == TIER_MANAGED
        assert ceiling.identity_issuer == "mdm"
        assert not resolve(ceiling, None, "commands", "git push origin").permitted

    def test_json_bytes_at_a_plist_path_are_refused(self, monkeypatch, tmp_path, trusted_managed):
        # The suffix picks the parser, so a mismatch fails closed instead of being
        # sniffed: a document whose encoding is ambiguous is not trusted.
        path = tmp_path / "dev.kirocrew.plist"
        path.write_text(json.dumps(_doc("mdm")), encoding="utf-8")
        _point_managed(monkeypatch, path)
        with pytest.raises(PlatformCompositionError, match="unreadable"):
            governance._read_managed_policy()

    def test_plist_bytes_at_a_json_path_are_refused(self, monkeypatch, tmp_path, trusted_managed):
        path = tmp_path / "managed.json"
        with path.open("wb") as handle:
            plistlib.dump(_doc("mdm"), handle)
        _point_managed(monkeypatch, path)
        with pytest.raises(PlatformCompositionError, match="unreadable"):
            governance._read_managed_policy()


# ──────────────────────────────────────────────────────────────────────────
# (i) + (j) Tighten-only composition
# ──────────────────────────────────────────────────────────────────────────
class TestASubordinateMayOnlyTighten:
    def _compose(self, monkeypatch, tmp_path, authority: dict, subordinate: dict):
        """Load with a managed *authority* and a home *subordinate*."""
        managed = tmp_path / "managed.json"
        managed.write_text(json.dumps({**_doc("mdm"), **authority}), encoding="utf-8")
        _point_managed(monkeypatch, managed)
        home = tmp_path / "home.json"
        home.write_text(json.dumps({**_doc("operator"), **subordinate}), encoding="utf-8")
        _point_home(monkeypatch, home)
        ceiling = load_security_policy()
        assert ceiling is not None
        return ceiling

    def test_a_subordinate_addition_to_a_governed_scope_is_applied(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"commands": {"mode": "deny", "deny": ["git push*"]}},
            subordinate={"commands": {"mode": "deny", "deny": ["rm -rf*"]}},
        )
        # deny∪ -- both denials bind.
        assert not resolve(ceiling, None, "commands", "git push origin").permitted
        assert not resolve(ceiling, None, "commands", "rm -rf /").permitted
        assert resolve(ceiling, None, "commands", "ls -la").permitted

    def test_a_subordinate_cannot_widen_a_deny_list_by_omission(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"commands": {"mode": "deny", "deny": ["git push*"]}},
            subordinate={"commands": {"mode": "deny", "deny": []}},
        )
        assert not resolve(ceiling, None, "commands", "git push origin").permitted

    def test_a_subordinate_cannot_widen_an_allowlist(self, monkeypatch, tmp_path, trusted_managed):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"tools": {"mode": "allow", "allow": ["read", "grep"]}},
            subordinate={"tools": {"mode": "allow", "allow": ["read", "grep", "execute_bash"]}},
        )
        # allow∩ -- the extra entry the subordinate added does not appear.
        assert resolve(ceiling, None, "tools", "read").permitted
        assert not resolve(ceiling, None, "tools", "execute_bash").permitted

    def test_a_subordinate_allowlist_narrows_when_it_is_smaller(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"tools": {"mode": "allow", "allow": ["read", "grep"]}},
            subordinate={"tools": {"mode": "allow", "allow": ["read"]}},
        )
        assert resolve(ceiling, None, "tools", "read").permitted
        assert not resolve(ceiling, None, "tools", "grep").permitted

    def test_a_subordinate_cannot_flip_a_deny_scope_open_with_allow_mode(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        # Rule 1 makes allow-mode ignore deny entirely WITHIN one ruleset, so a
        # subordinate switching mode is the obvious widening attempt. Composition
        # is an AND of the two rulesets, not a mode handover, so it fails.
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"commands": {"mode": "deny", "deny": ["git push*"]}},
            subordinate={"commands": {"mode": "allow", "allow": ["git push*", "ls*"]}},
        )
        assert not resolve(ceiling, None, "commands", "git push origin").permitted

    def test_a_subordinate_cannot_relax_an_ordinal(self, monkeypatch, tmp_path, trusted_managed):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"sandbox": {"min_level": "strict"}},
            subordinate={"sandbox": {"min_level": "off"}},
        )
        control = resolve_ordinal(ceiling, None, "sandbox.min_level")
        assert control is not None
        assert control.value == "strict"

    def test_a_subordinate_may_tighten_an_ordinal(self, monkeypatch, tmp_path, trusted_managed):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"sandbox": {"min_level": "standard"}},
            subordinate={"sandbox": {"min_level": "strict"}},
        )
        control = resolve_ordinal(ceiling, None, "sandbox.min_level")
        assert control is not None
        assert control.value == "strict"

    def test_a_subordinate_cannot_relax_an_approval_ordinal(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"approval_mode": "interactive"},
            subordinate={"approval_mode": "yolo"},
        )
        control = resolve_ordinal(ceiling, None, "approval_mode")
        assert control is not None
        assert control.value == "interactive"

    def test_a_subordinate_cannot_re_enable_a_disabled_capability(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"capabilities": {"script_hooks": {"enabled": False}}},
            subordinate={"capabilities": {"script_hooks": {"enabled": True}}},
        )
        gate = ceiling.get("capabilities.script_hooks")
        assert gate is not None
        assert gate.enabled is False  # type: ignore[attr-defined]

    def test_a_subordinate_may_disable_a_capability_the_authority_enabled(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"capabilities": {"script_hooks": {"enabled": True}}},
            subordinate={"capabilities": {"script_hooks": {"enabled": False}}},
        )
        gate = ceiling.get("capabilities.script_hooks")
        assert gate is not None
        assert gate.enabled is False  # type: ignore[attr-defined]

    def test_a_scope_only_the_subordinate_governs_carries_through(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        # An ungoverned scope is unrestricted, so ADDING governance to it is a
        # tightening, not an escape -- the subordinate's control survives whole.
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"commands": {"mode": "deny", "deny": ["git push*"]}},
            subordinate={"tools": {"mode": "allow", "allow": ["read"]}},
        )
        assert resolve(ceiling, None, "tools", "read").permitted
        assert not resolve(ceiling, None, "tools", "execute_bash").permitted
        assert not resolve(ceiling, None, "commands", "git push origin").permitted

    def test_a_scope_only_the_authority_governs_is_not_repealed_by_omission(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        ceiling = self._compose(
            monkeypatch,
            tmp_path,
            authority={"tools": {"mode": "allow", "allow": ["read"]}},
            subordinate={"commands": {"mode": "deny", "deny": ["rm -rf*"]}},
        )
        assert not resolve(ceiling, None, "tools", "execute_bash").permitted

    def test_composition_is_the_same_for_the_env_tier(self, monkeypatch, tmp_path, trusted_managed):
        # The subordinate's identity does not change the algebra: whichever of
        # tiers 3-5 is present composes the same way.
        _point_managed(
            monkeypatch,
            _write_policy(
                tmp_path / "managed.json", "mdm", tools={"mode": "allow", "allow": ["read"]}
            ),
        )
        monkeypatch.setenv(
            _POLICY_ENV,
            str(
                _write_policy(
                    tmp_path / "env.json",
                    "local-env",
                    tools={"mode": "allow", "allow": ["read", "execute_bash"]},
                )
            ),
        )
        ceiling = load_security_policy()
        assert ceiling is not None
        assert resolve(ceiling, None, "tools", "read").permitted
        assert not resolve(ceiling, None, "tools", "execute_bash").permitted


# ──────────────────────────────────────────────────────────────────────────
# (k) Boot flags compose strictest-wins
# ──────────────────────────────────────────────────────────────────────────
class TestAnEnvDocumentBeneathAnAuthorityIsAnnouncedOnce:
    """The precedence inversion is otherwise silent at the moment it bites.

    Before this change ``KIROCREW_SECURITY_POLICY`` outranked the central document and
    was the documented mid-incident rollback lever. Now it only tightens. A fleet whose
    runbook still says "set the env var to roll back" learns that mid-incident unless
    the host says so -- so the FIRST time the inverted shape composes, it warns once
    (log + SEL row), and then stays quiet: the shape is stable for the process lifetime.
    """

    @staticmethod
    def _recording_sel():
        class Stub:
            def __init__(self):
                self.calls = []

            def log_api_access(self, **kw):
                self.calls.append(kw)

        return Stub()

    @staticmethod
    def _rows(stub):
        return [c for c in stub.calls if c.get("operation") == "security_policy_env_tightens_only"]

    def test_env_beneath_managed_warns_once_and_audits(
        self, monkeypatch, tmp_path, trusted_managed, caplog
    ):
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        monkeypatch.setenv(_POLICY_ENV, str(_write_policy(tmp_path / "env.json", "local-env")))

        with caplog.at_level("WARNING", logger="kiro_crew.platform.governance"):
            load_security_policy()
            load_security_policy()

        rows = self._rows(stub)
        assert len(rows) == 1, "once per process, not once per compose"
        assert rows[0]["resources"] == f"{TIER_MANAGED}<-env"
        warned = [r for r in caplog.records if "can only tighten" in r.getMessage()]
        assert len(warned) == 1

    def test_env_alone_does_not_warn(self, monkeypatch, tmp_path):
        """A standalone host with only an env document is the old shape; nothing inverted."""
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        monkeypatch.setenv(_POLICY_ENV, str(_write_policy(tmp_path / "env.json", "local-env")))

        load_security_policy()

        assert self._rows(stub) == []

    def test_a_home_document_beneath_managed_does_not_warn(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        """Home never outranked anything, so there is no inversion to announce."""
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))

        load_security_policy()

        assert self._rows(stub) == []


class TestEveryCeilingFieldHasAComposeClass:
    """Every ``GovernanceCeiling`` field is placed in exactly one precedence class.

    ``_intersect_ceilings`` documents two classes for the fields outside ``controls``
    -- "absence means no choice" (a lower tier may supply it) and "absence means the
    fail-closed floor" (authority-only) -- and gets the second for free from
    ``replace(authority, ...)``. That default is exactly how a misclassification ships
    silently: a new field inherits authority-only whether or not that is right, and
    ``fallback_profile`` has already been through that once. This test makes the next
    field a deliberate decision: add it to one of the sets below, or fail here.
    """

    #: Folded field-by-field by ``_intersect_ceilings`` (tighten-only).
    COMPOSED = frozenset({"boot", "controls"})
    #: "Absence means no choice expressed": the highest tier that declared one wins,
    #: re-applied by ``compose_tier_ladder``.
    LOWER_MAY_SUPPLY = frozenset({"distribution"})
    #: "Absence means the fail-closed floor": always the authority's own value.
    AUTHORITY_ONLY = frozenset(
        {
            "version",
            "identity_issuer",
            "identity_signature",
            "signature_state",
            "updates",
            "fallback_profile",
            "agentcore_identity_posture",
            "agentcore_gateway_url",
            "agentcore_workload_name",
            "tier",
        }
    )

    def test_every_field_is_classified_exactly_once(self):
        from dataclasses import fields

        declared = {f.name for f in fields(governance.GovernanceCeiling)}
        classified = self.COMPOSED | self.LOWER_MAY_SUPPLY | self.AUTHORITY_ONLY
        assert not (self.COMPOSED & self.LOWER_MAY_SUPPLY & self.AUTHORITY_ONLY)
        assert declared - classified == set(), (
            "new GovernanceCeiling field(s) with no compose class -- decide whether a "
            "lower tier may supply each one and add it to the matching set above"
        )
        assert classified - declared == set(), "classified field(s) no longer exist"

    def test_authority_only_fields_keep_the_authority_value(self):
        """The classification is checked against the fold, not just against itself."""
        from dataclasses import replace

        authority = governance.parse_policy(_doc("authority"))
        subordinate = replace(
            governance.parse_policy(_doc("subordinate")),
            identity_signature="sub-sig",
            signature_state=SIGNATURE_UNVERIFIED,
            tier=TIER_HOME,
            agentcore_gateway_url="https://sub.example",
            agentcore_workload_name="sub-workload",
            agentcore_identity_posture="login",
        )

        merged = governance._intersect_ceilings(authority, subordinate)

        for name in self.AUTHORITY_ONLY:
            assert getattr(merged, name) == getattr(authority, name), name


class TestATierIntersectIsAuditedOncePerPairNotPerCompose:
    """``compose_tier_ladder`` runs per app callback, and the pairs it folds are fixed.

    An earlier revision wrote a ``security_policy_tier_intersect`` row on EVERY compose,
    so the flagship shape (managed + home present) appended one unchanging row to the
    append-only SEL per interaction, burying the one-time absence and env-inversion
    signals a fleet actually reads. The record is now keyed on the ``(authority, lower)``
    pair: the first compose of a pair writes one row, a repeat writes nothing, and a
    tier that appears later (an env document set after boot) is still recorded once.
    """

    @staticmethod
    def _recording_sel():
        class Stub:
            def __init__(self):
                self.calls = []

            def log_api_access(self, **kw):
                self.calls.append(kw)

        return Stub()

    @staticmethod
    def _rows(stub):
        return [
            c["resources"]
            for c in stub.calls
            if c.get("operation") == "security_policy_tier_intersect"
        ]

    def test_repeated_composes_of_the_same_shape_write_one_row(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))

        for _ in range(5):
            load_security_policy()

        assert self._rows(stub) == [f"{TIER_MANAGED}<-{TIER_HOME}"]

    def test_a_tier_that_appears_later_is_still_recorded_once(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))

        load_security_policy()
        monkeypatch.setenv(_POLICY_ENV, str(_write_policy(tmp_path / "env.json", "local-env")))
        load_security_policy()
        load_security_policy()

        rows = self._rows(stub)
        assert rows.count(f"{TIER_MANAGED}<-{TIER_HOME}") == 1
        assert rows.count(f"{TIER_MANAGED}<-{TIER_ENV}") == 1
        assert len(rows) == 2


class TestARefreshTagsTheCentralDocumentLikeBootDoes:
    """``compose_installed_ceiling`` must compose an untiered fetched document as CENTRAL.

    ``parse_distributed_policy`` returns a ceiling with no tier; boot tags it
    ``TIER_CENTRAL`` before folding. A refresh that passed it in untagged made
    ``compose_tier_ladder``'s ``ceiling.tier in (TIER_MANAGED, TIER_CENTRAL)`` guard
    False, so a host that reached the fleet document only on a later poll never got the
    env-tightens-only warning -- the exact host the warning targets -- and its intersect
    row read ``""<-env``.
    """

    @staticmethod
    def _recording_sel():
        class Stub:
            def __init__(self):
                self.calls = []

            def log_api_access(self, **kw):
                self.calls.append(kw)

        return Stub()

    def test_an_untagged_central_document_composes_as_the_central_tier(self, monkeypatch, tmp_path):
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        monkeypatch.setattr(governance, "_read_managed_policy", lambda: None)
        monkeypatch.setenv(_POLICY_ENV, str(_write_policy(tmp_path / "env.json", "local-env")))
        untagged = governance.parse_policy(_doc("fleet"))
        assert untagged.tier == ""

        composed = governance.compose_installed_ceiling(untagged)

        assert composed is not None
        assert composed.tier == TIER_CENTRAL
        rows = [c["resources"] for c in stub.calls]
        assert f"{TIER_CENTRAL}<-{TIER_ENV}" in rows
        assert any(c.get("operation") == "security_policy_env_tightens_only" for c in stub.calls)
        assert not any(r.startswith("<-") for r in rows), rows

    def test_an_already_tagged_document_alone_is_returned_by_identity(self, monkeypatch, tmp_path):
        # The standalone-host promise: the fetched document IS the installed one.
        monkeypatch.setattr(governance, "_read_managed_policy", lambda: None)
        from dataclasses import replace

        central = replace(governance.parse_policy(_doc("fleet")), tier=TIER_CENTRAL)
        assert governance.compose_installed_ceiling(central) is central


class TestTheLadderProcessStateResetsAsOneUnit:
    """Every per-process value the ladder keeps lives in one holder.

    Four separate module globals were reset by hand in two test fixtures, and the
    round-15 leak of the last bundled document was the fixture that reset three of the
    four. One dataclass, one ``reset_process_state()``.
    """

    def test_reset_clears_every_field(self, monkeypatch, tmp_path, trusted_managed):
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _point_home(monkeypatch, _write_policy(tmp_path / "home.json", "operator"))
        monkeypatch.setenv(_POLICY_ENV, str(_write_policy(tmp_path / "env.json", "local-env")))
        load_security_policy(bundled_loader=lambda: _doc("b"))
        st = governance._process_state
        assert st.last_bundled is not None
        assert st.env_beneath_central_warned is True
        assert st.tier_intersects_audited

        governance.reset_process_state()

        st = governance._process_state
        assert st == governance._TierProcessState()


class TestBootFlagsComposeStrictestWins:
    def _boot(self, monkeypatch, tmp_path, authority: dict, subordinate: dict):
        managed = tmp_path / "managed.json"
        managed.write_text(
            json.dumps({"version": 1, "boot": authority, "identity": {"issuer": "mdm"}}),
            encoding="utf-8",
        )
        _point_managed(monkeypatch, managed)
        home = tmp_path / "home.json"
        home.write_text(
            json.dumps({"version": 1, "boot": subordinate, "identity": {"issuer": "operator"}}),
            encoding="utf-8",
        )
        _point_home(monkeypatch, home)
        ceiling = load_security_policy()
        assert ceiling is not None
        return ceiling.boot

    def test_a_strict_subordinate_tightens_a_loose_authority(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        boot = self._boot(
            monkeypatch,
            tmp_path,
            authority={"require_sandbox": False, "allow_terminal": True, "fail_closed": False},
            subordinate={"require_sandbox": True, "allow_terminal": False, "fail_closed": True},
        )
        assert boot.require_sandbox is True  # OR
        assert boot.allow_terminal is False  # AND
        assert boot.fail_closed is True  # OR

    def test_a_loose_subordinate_cannot_relax_a_strict_authority(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        boot = self._boot(
            monkeypatch,
            tmp_path,
            authority={"require_sandbox": True, "allow_terminal": False, "fail_closed": True},
            subordinate={"require_sandbox": False, "allow_terminal": True, "fail_closed": False},
        )
        assert boot.require_sandbox is True
        assert boot.allow_terminal is False
        assert boot.fail_closed is True

    def test_allow_terminal_needs_both_tiers_to_agree(self, monkeypatch, tmp_path, trusted_managed):
        boot = self._boot(
            monkeypatch,
            tmp_path,
            authority={"allow_terminal": True},
            subordinate={"allow_terminal": True},
        )
        assert boot.allow_terminal is True


# ──────────────────────────────────────────────────────────────────────────
# (l) Everything outside ``controls`` stays the authority's
# ──────────────────────────────────────────────────────────────────────────
class TestNonControlFieldsStayWithTheAuthority:
    @pytest.fixture
    def composed(self, monkeypatch, tmp_path, trusted_managed):
        _point_managed(
            monkeypatch,
            _write_policy(
                tmp_path / "managed.json",
                "mdm",
                updates={"source": "git@fleet.example:kirocrew.git", "min_version": "9.9.9"},
            ),
        )
        home = tmp_path / "home.json"
        home.write_text(
            json.dumps(
                {
                    "version": 1,
                    "boot": {"fail_closed": True},
                    # A signed-but-unprovable identity, so the composed
                    # signature_state can be told apart from the authority's.
                    "identity": {"issuer": "operator", "signature": "deadbeef"},
                    "updates": {"source": "git@attacker.example:x.git", "min_version": "0.0.1"},
                }
            ),
            encoding="utf-8",
        )
        _point_home(monkeypatch, home)
        ceiling = load_security_policy()
        assert ceiling is not None
        return ceiling

    def test_identity_stays_the_authoritys(self, composed):
        assert composed.identity_issuer == "mdm"
        assert composed.identity_signature == ""

    def test_signature_state_stays_the_authoritys(self, composed):
        # The managed document carries no signature; the home one carries an
        # unprovable one. A subordinate must not relabel the ceiling's provenance
        # in either direction.
        assert composed.signature_state == SIGNATURE_UNSIGNED
        assert composed.signature_state != SIGNATURE_UNVERIFIED

    def test_update_pins_stay_the_authoritys(self, composed):
        assert composed.updates.source == "git@fleet.example:kirocrew.git"
        assert composed.updates.min_version == "9.9.9"

    def test_distribution_pins_stay_the_authoritys(self, composed):
        # Neither document declares a source (declaring one would make the central
        # tier fetch), so the assertion is that the composed value is the
        # authority's -- a subordinate cannot redirect where the NEXT document
        # comes from.
        assert composed.distribution == governance.PolicyDistribution()

    def test_a_managed_document_with_no_distribution_block_pins_nothing(self, composed):
        # Neither document here carries a ``distribution`` block at all, so there is
        # no fleet declaration to protect. Marking the ceiling ``managed`` anyway
        # refused the cadence variables on behalf of a choice nobody made -- it threw
        # away an operator's own KIROCREW_POLICY_REFRESH on a host whose profile is
        # silent about distribution.
        assert composed.distribution.managed is False

    def test_the_managed_marker_rides_on_a_declared_block(self):
        # ``managed`` is set by the LOADER, never parsed from a document, and it has
        # to survive composition: the background refresher reads the pins back off
        # the installed ceiling long after the managed tier is out of scope, and
        # that is where ``resolve_distribution`` decides whether an environment
        # override may redirect the source. A subordinate that could clear the flag
        # would hand the redirect back.
        #
        # Asserted at the seam that sets it. Going through ``load_security_policy``
        # would drag in a real fetch, because a declared block is only valid with a
        # source of its own or KIROCREW_POLICY_URL -- neither of which this is about.
        ceiling = governance._managed_ceiling(
            {
                "version": 1,
                "boot": {"fail_closed": True},
                "distribution": {"source": "https://mdm.corp.example/policy.json"},
            }
        )
        assert ceiling is not None
        assert ceiling.tier == TIER_MANAGED
        assert ceiling.distribution.managed is True
        assert ceiling.distribution.source == "https://mdm.corp.example/policy.json"

    def test_the_marker_is_absent_at_the_seam_when_the_document_declares_nothing(self):
        """The same seam, the other way, so the flag tracks the declaration."""
        ceiling = governance._managed_ceiling({"version": 1, "boot": {"fail_closed": True}})
        assert ceiling is not None
        assert ceiling.tier == TIER_MANAGED
        assert ceiling.distribution.managed is False
        # No parse route can set the flag, in either direction.
        assert governance.PolicyDistribution.from_dict({"source": "https://x"}).managed is False

    def test_the_tier_label_stays_the_authoritys(self, composed):
        assert composed.tier == TIER_MANAGED

    def test_a_subordinate_fallback_is_ignored_when_the_authority_declares_none(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        # An authority that declared no fallback means an unusable profile file
        # DENIES its surface (fail-closed). A subordinate supplying one would replace
        # that floor with something looser -- the escape hatch widened by the tier
        # that may only tighten. A subordinate that wants a fallback asks the fleet to
        # declare one.
        _point_managed(monkeypatch, _write_policy(tmp_path / "managed.json", "mdm"))
        _point_home(
            monkeypatch,
            _write_policy(
                tmp_path / "home.json",
                "operator",
                fallback={"tools": {"mode": "allow", "allow": ["read"]}},
            ),
        )
        ceiling = load_security_policy()
        assert ceiling is not None
        assert ceiling.tier == TIER_MANAGED
        assert ceiling.fallback_profile is None

    def test_the_authoritys_fallback_wins_when_both_declare_one(
        self, monkeypatch, tmp_path, trusted_managed
    ):
        _point_managed(
            monkeypatch,
            _write_policy(
                tmp_path / "managed.json",
                "mdm",
                fallback={"tools": {"mode": "allow", "allow": ["grep"]}},
            ),
        )
        _point_home(
            monkeypatch,
            _write_policy(
                tmp_path / "home.json",
                "operator",
                fallback={"tools": {"mode": "allow", "allow": ["read"]}},
            ),
        )
        ceiling = load_security_policy()
        assert ceiling is not None
        fallback = ceiling.fallback_profile
        assert fallback is not None
        assert resolve(None, fallback, "tools", "grep").permitted
        assert not resolve(None, fallback, "tools", "read").permitted


# ──────────────────────────────────────────────────────────────────────────
# (i) A PRESENT-but-unreadable managed document fails closed
#
# ``_read_managed_policy`` deliberately has no ``path.exists()`` pre-check. It
# looked harmless and was a downgrade path: ``exists()`` raises EACCES when the
# managed DIRECTORY is root-only -- which is exactly how a hardened fleet
# configures ``/etc/kirocrew`` -- and the old code caught that and returned
# ``None``. Hardening the directory therefore DISABLED the ceiling it was
# protecting, and governance silently fell through to whatever local tier was
# present. So ``FileNotFoundError`` is now the only error that means absent, and
# every other ``OSError`` raises.
# ──────────────────────────────────────────────────────────────────────────


def _deny_managed_open(monkeypatch, target: object, exc: OSError) -> None:
    """Raise *exc* from ``os.open`` for *target* only, delegating every other path.

    ``governance.os`` IS the ``os`` module, so this ``setattr`` is process-wide --
    hence the delegation. pytest's own machinery, the ``tmp_path`` factory and the
    home tier all keep opening files normally; only the managed path answers with
    the error under test. Patching the module attribute is also the ONLY seam that
    reaches this branch, because the branch is the bare ``os.open`` call itself.
    """
    real_open = os.open
    wanted = os.fspath(target)

    def fake(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        try:
            candidate = os.fspath(path)
        except TypeError:  # an int fd, which is never the managed path
            candidate = None
        if candidate == wanted:
            raise exc
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", fake)


class TestAPresentButUnreadableManagedDocumentDoesNotReadAsAbsent:
    """FileNotFoundError means absent; every other OSError must refuse.

    The distinction is the whole tier: "we could not read the fleet's ceiling" and
    "this host has no fleet ceiling" are opposite answers, and conflating them hands
    governance to a local account by way of a directory permission.
    """

    #: A home document that permits everything in a scope the managed tier does not
    #: mention -- i.e. strictly LOOSER than any managed ceiling. If the refusals
    #: below ever fell through, this is the ceiling the host would run under, so it
    #: is what makes the fall-through observable rather than merely asserted-absent.
    LOOSE_HOME = {"mode": "deny", "deny": []}

    def _point_both(self, monkeypatch, tmp_path):
        """Aim the managed path at a document, and the home tier at a looser one.

        The managed file is deliberately NOT written. That is not a shortcut, it is
        the case under test: when the managed DIRECTORY is root-only, a non-root
        process cannot see the document at all -- ``exists()`` raises EACCES -- while
        an actual open of the same path gets EACCES. A test that wrote the file would
        make ``exists()`` answer True, and the removed pre-check would then fall
        through to the same open and refuse identically, so the test could not tell
        the fix from the bug it replaced. Absent-to-``stat`` and unreadable-to-``open``
        is exactly the pairing the old code got wrong.
        """
        managed = tmp_path / "managed.json"
        _point_managed(monkeypatch, managed)
        _point_home(
            monkeypatch,
            _write_policy(tmp_path / "home.json", "operator", commands=self.LOOSE_HOME),
        )
        return managed

    # ── absent stays inert ────────────────────────────────────────────────

    def test_a_genuinely_absent_managed_path_is_still_inert(self, monkeypatch, tmp_path):
        # The pre-check's removal must not have cost the tier its "free on every
        # standalone install" property: the open itself is now the existence test.
        _point_managed(monkeypatch, tmp_path / "nowhere" / "managed.json")
        assert governance._read_managed_policy() is None

    def test_file_not_found_from_the_open_is_the_absence_signal(self, monkeypatch, tmp_path):
        # Asserted through the OPEN rather than through a missing file, because that
        # is the contract now: absence is one specific errno out of ``os.open``, not
        # a separate ``exists()`` question that could disagree with it.
        managed = self._point_both(monkeypatch, tmp_path)
        _deny_managed_open(monkeypatch, managed, FileNotFoundError(2, "No such file"))
        assert governance._read_managed_policy() is None

    def test_an_absent_managed_path_does_let_the_home_tier_govern(self, monkeypatch, tmp_path):
        # POSITIVE CONTROL for the refusals below. Without it, a test asserting "this
        # raises instead of returning the home ceiling" would still pass if the home
        # ceiling had never been loadable in the first place.
        managed = self._point_both(monkeypatch, tmp_path)
        _deny_managed_open(monkeypatch, managed, FileNotFoundError(2, "No such file"))
        ceiling = load_security_policy()
        assert ceiling is not None
        assert ceiling.tier == TIER_HOME
        assert ceiling.identity_issuer == "operator"

    # ── present-but-unreadable refuses ────────────────────────────────────

    def test_eacces_on_the_managed_path_raises_rather_than_reading_as_absent(
        self, monkeypatch, tmp_path
    ):
        managed = self._point_both(monkeypatch, tmp_path)
        _deny_managed_open(monkeypatch, managed, PermissionError(13, "Permission denied"))
        with pytest.raises(PlatformCompositionError) as excinfo:
            governance._read_managed_policy()
        # The operator has to be told WHICH document could not be read; a fleet has
        # more than one governance file and the message is the only pointer.
        assert str(managed) in str(excinfo.value)

    def test_the_refusal_does_not_fall_through_to_a_looser_home_tier(self, monkeypatch, tmp_path):
        """THE security property of this fix, stated as a whole-load assertion.

        A root-only ``/etc/kirocrew`` is the CORRECT way to install a managed
        ceiling, so this is the configuration the old pre-check punished: it read as
        "no managed policy" and the permissive home document below became the
        ceiling. The load must refuse instead -- not return this ceiling.
        """
        managed = self._point_both(monkeypatch, tmp_path)
        _deny_managed_open(monkeypatch, managed, PermissionError(13, "Permission denied"))
        with pytest.raises(PlatformCompositionError) as excinfo:
            load_security_policy()
        assert str(managed) in str(excinfo.value)

    def test_the_refusal_does_not_fall_through_to_a_looser_env_tier(self, monkeypatch, tmp_path):
        managed = self._point_both(monkeypatch, tmp_path)
        monkeypatch.setenv(
            _POLICY_ENV,
            str(_write_policy(tmp_path / "env.json", "local-env", commands=self.LOOSE_HOME)),
        )
        _deny_managed_open(monkeypatch, managed, PermissionError(13, "Permission denied"))
        with pytest.raises(PlatformCompositionError):
            load_security_policy()

    def test_the_refusal_does_not_fall_through_to_ungoverned(self, monkeypatch, tmp_path):
        # No lower tier at all: the answer is still a refusal, never the
        # editable-defaults ``None`` an ungoverned host gets.
        managed = tmp_path / "managed.json"
        _write_policy(managed, "mdm")
        _point_managed(monkeypatch, managed)
        _deny_managed_open(monkeypatch, managed, PermissionError(13, "Permission denied"))
        with pytest.raises(PlatformCompositionError):
            load_security_policy()

    @pytest.mark.parametrize(
        "exc",
        [
            PermissionError(13, "Permission denied"),
            OSError(21, "Is a directory"),
            OSError(40, "Too many levels of symbolic links"),
            # errno-LESS: ``OSError`` carries no errno when it was raised by hand, and
            # a branch that switched on ``exc.errno`` would compare against None and
            # fall into the wrong arm. Only the EXCEPTION TYPE may decide.
            OSError("no errno at all"),
        ],
    )
    def test_every_non_absent_open_error_refuses(self, monkeypatch, tmp_path, exc):
        managed = self._point_both(monkeypatch, tmp_path)
        _deny_managed_open(monkeypatch, managed, exc)
        with pytest.raises(PlatformCompositionError):
            load_security_policy()

    def test_an_errno_less_oserror_is_not_mistaken_for_absence(self, monkeypatch, tmp_path):
        # The same case as above, asserted at the READER so the failure names this
        # branch rather than the composed load.
        managed = self._point_both(monkeypatch, tmp_path)
        _deny_managed_open(monkeypatch, managed, OSError("no errno at all"))
        with pytest.raises(PlatformCompositionError) as excinfo:
            governance._read_managed_policy()
        assert str(managed) in str(excinfo.value)

    def test_a_path_whose_exists_raises_is_not_consulted_at_all(self, monkeypatch, tmp_path):
        """The hardened fleet, spelled out: ``exists()`` raises and ``open`` gets EACCES.

        This is the configuration the pre-check punished. ``_ExplodingPath.exists``
        raises ``OSError`` exactly as a root-only parent directory makes it, so a
        reader that still asked would take the answer it was given -- "not a managed
        policy" -- and hand the ceiling to the looser home document below. Nothing may
        consult it: the open IS the existence test, and it says EACCES.
        """
        managed = _ExplodingPath(tmp_path / "managed.json")
        _point_managed(monkeypatch, managed)
        _point_home(
            monkeypatch,
            _write_policy(tmp_path / "home.json", "operator", commands=self.LOOSE_HOME),
        )
        _deny_managed_open(monkeypatch, managed, PermissionError(13, "Permission denied"))
        with pytest.raises(PlatformCompositionError) as excinfo:
            load_security_policy()
        assert str(managed) in str(excinfo.value)


class TestAManagedPlistMustBeJsonNative:
    """A plist value JSON cannot represent is refused at READ time, fail-closed.

    ``plistlib`` decodes ``<date>`` to :class:`datetime` and ``<data>`` to ``bytes``, and
    the signature payload is canonical JSON over the RAW document. A SIGNED profile
    carrying a plist-native date therefore raised ``TypeError`` out of
    ``_verify_policy_signature``, which is documented never to raise, and
    ``context.safe_context_call`` degrades every non-``PlatformCompositionError`` to
    open-source defaults -- so the fleet ceiling was silently REMOVED. Signing a profile
    made the host LESS governed, inverting ``require_policy_signature``. A ``<date>`` for
    a timestamp is the idiomatic MDM spelling, so this was the ordinary
    authoring mistake rather than an exotic one.
    """

    @staticmethod
    def _identity() -> dict:
        """A signed identity: both fields non-empty, so the payload builder is reached."""
        return {"issuer": "mdm", "signature": "a" * 64}

    @pytest.fixture
    def trusting(self, monkeypatch):
        """A trust root holding a key for the issuer, so the SIGNED path is taken.

        Without a key ``_policy_signature_state`` returns before canonicalization and the
        crash these tests are about is unreachable.
        """
        monkeypatch.setattr(
            governance, "_policy_trust_settings", lambda: (False, {"mdm": "secret"})
        )

    def test_a_plist_date_is_refused_rather_than_crashing_the_loader(
        self, monkeypatch, tmp_path, trusted_managed, trusting
    ):
        """The reported case: a timestamp authored as a plist ``<date>``."""
        _point_managed(
            monkeypatch,
            _write_plist_policy(
                tmp_path / "dev.kirocrew.plist",
                identity=self._identity(),
                updates={"pinned_at": datetime.now(timezone.utc)},
            ),
        )
        with pytest.raises(PlatformCompositionError, match="JSON cannot represent"):
            load_security_policy()

    def test_a_plist_data_value_is_refused(self, monkeypatch, tmp_path, trusted_managed, trusting):
        """``<data>`` decodes to ``bytes``, which ``json.dumps`` also cannot serialize."""
        _point_managed(
            monkeypatch,
            _write_plist_policy(
                tmp_path / "dev.kirocrew.plist",
                identity={**self._identity(), "fingerprint": b"\x00\x01"},
            ),
        )
        with pytest.raises(PlatformCompositionError, match="JSON cannot represent"):
            load_security_policy()

    def test_a_nested_plist_date_is_refused(self, monkeypatch, tmp_path, trusted_managed, trusting):
        """The walk is recursive: a value one level down is just as unsignable."""
        _point_managed(
            monkeypatch,
            _write_plist_policy(
                tmp_path / "dev.kirocrew.plist",
                identity=self._identity(),
                updates={"pinned_at": [datetime.now(timezone.utc)]},
            ),
        )
        with pytest.raises(PlatformCompositionError, match="JSON cannot represent"):
            load_security_policy()

    def test_the_refusal_names_the_offending_key_path(
        self, monkeypatch, tmp_path, trusted_managed, trusting
    ):
        """An operator has to be told WHICH key to rewrite, not just that one is wrong."""
        _point_managed(
            monkeypatch,
            _write_plist_policy(
                tmp_path / "dev.kirocrew.plist",
                identity=self._identity(),
                updates={"pinned_at": datetime.now(timezone.utc)},
            ),
        )
        with pytest.raises(PlatformCompositionError) as excinfo:
            load_security_policy()
        detail = str(excinfo.value)
        assert "updates.pinned_at" in detail
        assert "<string>" in detail, "the message names the remedy"

    def test_an_unsigned_plist_date_is_also_refused(self, monkeypatch, tmp_path, trusted_managed):
        """Refused at READ time, so the guard does not depend on the signature.

        Deliberately pinned: a value with no canonical form cannot be signed later
        either, and asserting the unsigned case here stops a refactor from narrowing the
        guard back to the signed path alone. This is a behaviour change -- such a
        document loaded and governed before.
        """
        _point_managed(
            monkeypatch,
            _write_plist_policy(
                tmp_path / "dev.kirocrew.plist",
                "mdm",
                updates={"pinned_at": datetime.now(timezone.utc)},
            ),
        )
        with pytest.raises(PlatformCompositionError, match="JSON cannot represent"):
            governance._read_managed_policy()

    def test_a_json_native_plist_still_parses(
        self, monkeypatch, tmp_path, trusted_managed, trusting
    ):
        """The guard must not refuse the documented form: an ISO-8601 ``<string>``."""
        stamp = _future()
        _point_managed(
            monkeypatch,
            _write_plist_policy(
                tmp_path / "dev.kirocrew.plist",
                identity=self._identity(),
                updates={"pinned_at": stamp},
            ),
        )
        data = governance._read_managed_policy()
        assert data is not None
        assert data["updates"]["pinned_at"] == stamp


class TestAnAclGrantingWriteIsRefusedTooNotJustAModeBit:
    """``st_mode`` cannot see a POSIX ACL, so a mode-only check was not the claim.

    A named-user ACL entry (``user:me:w``) on a root-owned ``0644`` file does not appear
    in ``st_mode`` at all -- the group triple shows the ACL *mask*, not that entry -- so
    the file reads as "not writable" while this account can in fact rewrite it. The tier's
    whole claim is "a standard user cannot author this", and it would have been false
    while looking checked.

    The check reads the STORED ACL (``system.posix_acl_access``) and asks whether any
    named non-root user or group may write. It does not ask the kernel whether *this
    process* may write: an earlier revision did (``faccessat(AT_EACCESS)``), which root
    always may, so the check was skipped as root and a ``user:me:w`` grant on a root-run
    gateway went unchecked. Reading the file's own ACL gives the same answer whoever
    runs the process.

    The ACL itself is not constructed on disk: ``setfacl`` is not portable across the
    CI matrix (and absent on macOS runners, which use a different ACL model), so these
    pin the branch by feeding the accessor a real ``acl_ea`` blob of the shape the
    kernel stores. The mode-bit refusals in ``TestManagedFileTrustIsChecked`` remain
    the real-filesystem half.
    """

    @staticmethod
    def _acl_blob(*entries):
        """Build an ``acl_ea`` xattr blob: version header then (tag, perm, id) records."""
        out = (0x0002).to_bytes(2, "little") + b"\x00\x00"
        for tag, perm, principal in entries:
            out += tag.to_bytes(2, "little") + perm.to_bytes(2, "little")
            out += principal.to_bytes(4, "little")
        return out

    # Tags from posix_acl_xattr.h; the owner/group/other/mask triples ARE the mode bits.
    USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
    R, W = 0x04, 0x02

    @staticmethod
    def _point_at_a_clean_root_owned_file(monkeypatch, tmp_path):
        """A file whose stat is beyond reproach: root-owned, 0644, regular."""
        path = _write_policy(tmp_path / "managed.json", "mdm")
        path.chmod(0o444)
        _point_managed(monkeypatch, path)
        _fake_managed_stat(monkeypatch, uid=0, perm=0o644)
        return path

    def _install_acl(self, monkeypatch, blob):
        """Make ``os.getxattr`` return *blob* for the ACL attribute."""
        monkeypatch.setattr(governance.os, "getxattr", lambda p, name, **kw: blob, raising=False)

    @_POSIX_ONLY
    @pytest.mark.parametrize("uid", [1000, 0])
    def test_a_named_user_write_grant_is_refused_whoever_runs_the_process(
        self, monkeypatch, tmp_path, uid
    ):
        """``user:1000:rw`` on a root-owned 0644 file is refused as root AND as a user.

        The root case is the round-15 defect: the previous check asked "can *I* write
        this", which root always can, so it was skipped as root and the grant to uid
        1000 -- who CAN rewrite the fleet authority -- went unchecked on a root-run
        gateway. Reading the stored ACL gives the same answer under either uid.
        """
        self._point_at_a_clean_root_owned_file(monkeypatch, tmp_path)
        monkeypatch.setattr(os, "getuid", lambda: uid, raising=False)
        self._install_acl(
            monkeypatch,
            self._acl_blob(
                (self.USER_OBJ, self.R | self.W, 0xFFFFFFFF),
                (self.USER, self.R | self.W, 1000),
                (self.GROUP_OBJ, self.R, 0xFFFFFFFF),
                (self.MASK, self.R | self.W, 0xFFFFFFFF),
                (self.OTHER, self.R, 0xFFFFFFFF),
            ),
        )
        with pytest.raises(PlatformCompositionError, match="access-control entry"):
            governance._read_managed_policy()

    @_POSIX_ONLY
    def test_a_named_group_write_grant_is_refused(self, monkeypatch, tmp_path):
        self._point_at_a_clean_root_owned_file(monkeypatch, tmp_path)
        monkeypatch.setattr(os, "getuid", lambda: 0, raising=False)
        self._install_acl(monkeypatch, self._acl_blob((self.GROUP, self.W, 500)))
        with pytest.raises(PlatformCompositionError, match="access-control entry"):
            governance._read_managed_policy()

    @_POSIX_ONLY
    def test_a_read_only_named_grant_still_loads(self, monkeypatch, tmp_path):
        """The control: a named entry that grants only READ is not a rewrite path."""
        self._point_at_a_clean_root_owned_file(monkeypatch, tmp_path)
        self._install_acl(
            monkeypatch,
            self._acl_blob(
                (self.USER_OBJ, self.R | self.W, 0xFFFFFFFF),
                (self.USER, self.R, 1000),
                (self.MASK, self.R, 0xFFFFFFFF),
                (self.OTHER, self.R, 0xFFFFFFFF),
            ),
        )
        data = governance._read_managed_policy()
        assert data is not None
        assert data["identity"] == {"issuer": "mdm"}

    @_POSIX_ONLY
    def test_a_named_grant_to_root_is_not_a_grant(self, monkeypatch, tmp_path):
        """``user:0:rw`` gives root nothing it lacked; the fleet still owns the file."""
        self._point_at_a_clean_root_owned_file(monkeypatch, tmp_path)
        self._install_acl(monkeypatch, self._acl_blob((self.USER, self.R | self.W, 0)))
        data = governance._read_managed_policy()
        assert data is not None

    @_POSIX_ONLY
    def test_no_acl_set_still_loads(self, monkeypatch, tmp_path):
        """``ENODATA`` -- the ordinary file with no ACL -- is not evidence of anything."""
        self._point_at_a_clean_root_owned_file(monkeypatch, tmp_path)

        def enodata(p, name, **kw):
            raise OSError(61, "No data available")

        monkeypatch.setattr(governance.os, "getxattr", enodata, raising=False)
        data = governance._read_managed_policy()
        assert data is not None

    @_POSIX_ONLY
    def test_an_unqueryable_acl_is_not_evidence_of_write_access(self, monkeypatch, tmp_path):
        """A filesystem that cannot answer must not abort boot.

        The mode checks above already stand; refusing on an unanswerable query would turn
        an exotic filesystem (or macOS, whose ACL model has no such xattr) into a boot
        failure.
        """
        self._point_at_a_clean_root_owned_file(monkeypatch, tmp_path)

        def explode(*a, **kw):
            raise NotImplementedError("xattrs unsupported here")

        monkeypatch.setattr(governance.os, "getxattr", explode, raising=False)
        data = governance._read_managed_policy()
        assert data is not None

    @_POSIX_ONLY
    def test_a_malformed_acl_blob_is_not_evidence_of_write_access(self, monkeypatch, tmp_path):
        self._point_at_a_clean_root_owned_file(monkeypatch, tmp_path)
        self._install_acl(monkeypatch, b"\x02\x00\x00\x00\x01\x02\x03")
        data = governance._read_managed_policy()
        assert data is not None

    def test_a_mask_that_strips_write_makes_a_raw_rw_entry_read_only(self):
        """``user:alice:rw-,mask::r--`` -- alice can only read, so the file is trusted.

        ``acl(5)`` limits every named entry by ``ACL_MASK``. A walk that tested the raw
        write bit refused this file and aborted boot for an entry that grants nothing.
        Over-refusal is fail-closed, but a boot abort on a read-only grant is still a
        wrong answer; the effective permission is the one the kernel enforces.
        """
        blob = self._acl_blob(
            (self.USER_OBJ, self.R | self.W, 0),
            (self.USER, self.R | self.W, 1000),
            (self.GROUP_OBJ, self.R, 0),
            (self.MASK, self.R, 0),
            (self.OTHER, self.R, 0),
        )
        assert governance._posix_acl_blob_grants_write_to_non_root(blob) is False

    def test_a_mask_that_keeps_write_leaves_the_grant_refused(self):
        """The control: with ``mask::rw-`` the same entry is an effective write grant."""
        blob = self._acl_blob(
            (self.USER, self.R | self.W, 1000),
            (self.MASK, self.R | self.W, 0),
        )
        assert governance._posix_acl_blob_grants_write_to_non_root(blob) is True

    def test_a_mask_entry_after_the_named_entry_still_applies(self):
        """The kernel writes entries in tag order, but the walk must not depend on it."""
        blob = self._acl_blob(
            (self.MASK, self.R, 0),
            (self.GROUP, self.R | self.W, 50),
        )
        assert governance._posix_acl_blob_grants_write_to_non_root(blob) is False
        blob = self._acl_blob(
            (self.GROUP, self.R | self.W, 50),
            (self.MASK, self.R, 0),
        )
        assert governance._posix_acl_blob_grants_write_to_non_root(blob) is False

    def test_a_wrong_version_header_is_ignored(self):
        blob = (
            (0x0003).to_bytes(2, "little")
            + b"\x00\x00"
            + self._acl_blob((self.USER, self.W, 1000))[4:]
        )
        assert governance._posix_acl_blob_grants_write_to_non_root(blob) is False


class TestAnAbsentManagedTierIsAuditedNotRefused:
    """Absence hands governance to a local tier, and says so ONCE, in the audit trail.

    A predecessor of this class asserted the opposite -- that absence on a directory
    this account could write must ABORT BOOT. That guard was withdrawn: any root
    account defeats it by tightening the directory before unlinking, a correctly
    provisioned fleet host never reaches the interesting branch, and each revision
    aborted boot on a different honest host shape. The host cannot adjudicate the cause
    of an absence (deletion and never-provisioned are one syscall result), so it reports
    and the fleet decides. These tests pin the reporting, pin that it is NOT fatal, and
    pin that it happens at BOOT rather than on every read -- the first version audited
    from ``_read_managed_policy`` and wrote a row per refresh poll on every standalone
    host, which surfaced as three stray ``redact`` calls in an unrelated dashboard test.
    """

    @staticmethod
    def _recording_sel():
        class Stub:
            def __init__(self):
                self.calls = []

            def log_api_access(self, **kw):
                self.calls.append(kw)

        return Stub()

    @staticmethod
    def _absence_rows(stub):
        return [c for c in stub.calls if c.get("operation") == "security_policy_tier_absent"]

    def test_boot_emits_exactly_one_audit_record_naming_the_managed_tier(
        self, monkeypatch, tmp_path
    ):
        """The record is the whole mechanism, so its absence is the regression to catch."""
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        _point_managed(monkeypatch, tmp_path / "dev.kirocrew.plist")

        load_security_policy()

        absent = self._absence_rows(stub)
        assert len(absent) == 1, "exactly one absence record at boot"
        assert absent[0]["resources"] == f"{TIER_MANAGED}<-absent"
        assert not absent[0].get("critical"), "best-effort: absence must not gate boot"

    def test_a_second_load_in_the_same_process_does_not_audit_again(self, monkeypatch, tmp_path):
        """Once per PROCESS, not once per call of the loader.

        ``mcp_gateway.app_call`` re-runs ``load_security_policy`` on every app callback
        to compose that call's ceiling, so a per-call emit appended one SEL row per
        callback on a standalone host. The ``absence_audited`` latch is what makes the
        contract true.
        """
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        _point_managed(monkeypatch, tmp_path / "dev.kirocrew.plist")

        load_security_policy()
        load_security_policy()
        load_security_policy()

        assert len(self._absence_rows(stub)) == 1

    def test_the_reader_itself_does_not_audit(self, monkeypatch, tmp_path):
        """``_read_managed_policy`` runs per refresh and per recompose; it must stay silent.

        Auditing from the reader wrote one HMAC-chained SEL row per poll interval on
        every standalone host for a fact that never changes. Boot is the one place.
        """
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        _point_managed(monkeypatch, tmp_path / "dev.kirocrew.plist")

        assert governance._read_managed_policy() is None
        assert governance._read_managed_policy() is None

        assert self._absence_rows(stub) == []

    def test_a_platform_with_no_managed_tier_reports_nothing(self, monkeypatch):
        """Windows has no managed path at all; an absence it could never have had is not news."""
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        _point_managed(monkeypatch, None)

        load_security_policy()

        assert self._absence_rows(stub) == []

    def test_the_record_never_names_the_managed_path(self, monkeypatch, tmp_path):
        """Same rule as ``_audit_policy_tier``: the SEL is agent-readable.

        The managed path is fleet control-plane detail, so only the tier NAME is
        recorded. The operator gets the path from the gateway log instead.
        """
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        managed = tmp_path / "dev.kirocrew.plist"
        _point_managed(monkeypatch, managed)

        load_security_policy()

        blob = repr(stub.calls)
        assert str(managed) not in blob
        assert str(tmp_path) not in blob

    def test_an_unwritable_sel_does_not_refuse_boot(self, monkeypatch, tmp_path):
        """One unwritable audit file must not brick every standalone install.

        Absence is the common case -- every standalone install reaches it -- so making
        the governance decision contingent on an SEL write would convert a local
        filesystem problem into a fleet-wide outage. Contrast
        a record that GATES an action, which belongs only to a path where a local
        document could outrank the fleet ceiling -- no such path exists here.
        """

        class Exploding:
            def log_api_access(self, **kw):
                raise OSError("SEL append failed (disk full)")

        monkeypatch.setattr(governance, "sel", lambda: Exploding())
        _point_managed(monkeypatch, tmp_path / "dev.kirocrew.plist")

        assert load_security_policy() is None

    def test_a_user_writable_managed_directory_is_still_not_a_refusal(self, monkeypatch, tmp_path):
        """The withdrawn guard's exact scenario, pinned to the OPPOSITE outcome.

        ``tmp_path`` is genuinely writable by this account, which is what the old guard
        refused on. Keeping a test on this scenario is what stops the refusal being
        reintroduced quietly -- a reviewer proposing it has to delete a test that states
        the decision, rather than adding one to a gap.
        """
        stub = self._recording_sel()
        monkeypatch.setattr(governance, "sel", lambda: stub)
        _point_managed(monkeypatch, tmp_path / "absent.plist")

        assert governance._read_managed_policy() is None
        assert load_security_policy() is None

    def test_a_present_but_untrusted_document_is_still_refused(self, monkeypatch, tmp_path):
        """The coverage that did NOT move: a loose host is caught when the doc EXISTS.

        This is why dropping the absence guard costs less than it appears.
        ``_assert_managed_file_trusted`` rejects a document a local account could
        rewrite, so the sloppily provisioned host is already refused on the path where
        the fleet actually placed a document. Only the "loose host AND already deleted"
        cell was given up.
        """
        managed = tmp_path / "dev.kirocrew.plist"
        managed.write_text(json.dumps({"version": 1}), encoding="utf-8")
        _point_managed(monkeypatch, managed)
        monkeypatch.setattr(platform_compat, "IS_POSIX", True)
        _fake_managed_stat(monkeypatch, uid=0, extra_mode=stat.S_IWGRP)

        with pytest.raises(PlatformCompositionError):
            governance._read_managed_policy()
