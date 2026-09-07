"""Tests for the sandbox guard.

This container runs SANDBOXED-ONLY. kiro-cli runs the model subprocess inside an
unprivileged user namespace; without one, ``wrap_argv`` fails closed. There is no
opt-in to run unsandboxed, because the worker holds the model credential
(``KIRO_API_KEY``) and auto-approves every tool -- an unsandboxed worker on
untrusted prompt content would be a credential-exfiltration path. So on a host
without a user namespace the container refuses to start rather than run the model
subprocess exposed. These pin that: it refuses when the probe reports no
namespace, and only then.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from container.common import Settings
from container.common.config import ConfigError, _bool
from container.supervisor import __main__ as entry


def make_settings(tmp_path: Path) -> Settings:
    data_home = tmp_path / "data"
    data_home.mkdir(parents=True, exist_ok=True)
    return Settings(
        backend_port=8765,
        backend_run_dir=data_home / "run",
        front_port=8080,
        route_prefix="",
        control_secret=None,
        data_home=data_home,
        config_dir=data_home,
        crew_name="test-crew",
        backup_bucket=None,
        backup_prefix="",
        backup_interval_secs=30,
    )


def test_the_guard_refuses_when_no_user_namespace_is_available(tmp_path: Path) -> None:
    """No sandbox and no opt-in escape: the container must refuse to start.

    This is the whole point of the sandboxed-only posture. There is deliberately
    no config key or env var that lets a deployment run the model subprocess
    unsandboxed, so the only safe answer on a host without a user namespace
    (Fargate today) is to refuse.
    """
    settings = make_settings(tmp_path)
    with pytest.raises(ConfigError, match="sandboxed-only"):
        entry.verify_sandbox(settings, probe=lambda: False)


def test_the_refusal_names_the_missing_sandbox_not_a_missing_opt_in(tmp_path: Path) -> None:
    """The message must not point the operator at an opt-in that does not exist.

    An unsandboxed posture would tell operators to set
    ``agent.sandbox_allow_unsandboxed_exec``; a message still saying that would
    send them to a dead knob. It must name the missing user namespace instead.
    """
    settings = make_settings(tmp_path)
    with pytest.raises(ConfigError) as exc:
        entry.verify_sandbox(settings, probe=lambda: False)
    assert "sandbox_allow_unsandboxed_exec" not in str(exc.value)


def test_a_host_with_namespaces_starts(tmp_path: Path) -> None:
    entry.verify_sandbox(make_settings(tmp_path), probe=lambda: True)  # no raise


def test_an_unknown_probe_result_does_not_block(tmp_path: Path) -> None:
    """Non-Linux: the probe cannot run, so it must not be read as unavailable."""
    entry.verify_sandbox(make_settings(tmp_path), probe=lambda: None)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("off", False),
        (" true ", True),
    ],
)
def test_bool_accepts_the_spellings_a_template_may_produce(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
) -> None:
    monkeypatch.setenv("SMC_PROBE_BOOL", raw)
    assert _bool("SMC_PROBE_BOOL", False) is expected


@pytest.mark.parametrize("raw", ["ture", "${SinglePrincipal}", "maybe", "2"])
def test_bool_refuses_a_value_it_cannot_read(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    """Reading a typo as "no" is the safe direction but hides a broken deployment.

    An unresolved CloudFormation reference is the realistic case: it would leave
    the setting at its safe default with nothing pointing at the parameter that
    failed to resolve.
    """
    monkeypatch.setenv("SMC_PROBE_BOOL", raw)
    with pytest.raises(ConfigError, match="must be a boolean"):
        _bool("SMC_PROBE_BOOL", False)
