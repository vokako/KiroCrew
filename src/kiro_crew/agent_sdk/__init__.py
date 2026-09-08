"""The one import surface between application code and an agent backend.

Provider-neutral turn usage and stop-reason vocabulary live here first. The
boundary is enforced by ``scripts/check_agent_sdk_boundary.py`` and
``test/test_agent_sdk_boundary.py``, so application code cannot introduce new
direct dependencies on the backend packages while the rest of the SDK is built.

Machine-local backend readiness lives in :mod:`kiro_crew.agent_sdk.backend_install`.
Promptless structured command batches live in
:mod:`kiro_crew.agent_sdk.native_commands`; their ACP process lifecycle and
exception translation stay in the driver, and only plain data crosses upward.

Layering::

    consumers        dashboard/  slack/  discord/  telegram/  messaging/
                     session.py  subagent.py  apps/  cli_*.py  workflows/
                            |
                            |  import kiro_crew.agent_sdk for anything
                            |  provider-specific. A file ALREADY in the
                            |  boundary baseline keeps its direct ACP
                            |  imports; a file that is clean today is
                            |  REFUSED a new one by the gate
                            v
                     kiro_crew.agent_sdk          domain types, role protocols,
                                                  capabilities, supervisor
                            |
                            |  resolves drivers through a registry
                            v
                     kiro_crew.agent_sdk.drivers.acp
                                                  the only module INSIDE this
                                                  package that imports
                                                  kiro_crew.acp
                            v
                     kiro_crew.acp  (foundation)  wire, dialects, adapters,
                                                  session handles, worker pool

If the gate goes red you introduced a boundary violation: fix the import
direction rather than relaxing the rule, and never add or raise a line in
``.github/agent-sdk-boundary-baseline.txt`` to make it green.

Design of record, including what each later phase moves in here:
``docs/request-for-change/rfc-crew-agent-sdk-boundary.md``.
"""

from __future__ import annotations

from typing import Protocol

from kiro_crew.agent_sdk.backend_install import (
    CACHE_TTL_SECONDS,
    COMPONENT_CLAUDE_ACP_ADAPTER,
    COMPONENT_CLAUDE_CODE_CLI,
    COMPONENT_KIRO_CLI,
    INSTALLED,
    MISSING,
    UNKNOWN,
    BackendInstallState,
    clear_probe_cache,
    probe_backend,
    probe_backends,
)
from kiro_crew.agent_sdk.events import (
    ALL_EVENT_KINDS,
    EVENT_AGENT_SWITCHED,
    EVENT_CLEAR_STATUS,
    EVENT_COMPACTION_STATUS,
    EVENT_COMPLETE,
    EVENT_MCP_OAUTH_REQUEST,
    EVENT_MCP_SERVER_INIT_FAILURE,
    EVENT_MCP_SERVER_INITIALIZED,
    EVENT_PERMISSION_REQUEST,
    EVENT_STEER_CLEARED,
    EVENT_STEER_CONSUMED,
    EVENT_STEER_QUEUED,
    EVENT_SUBAGENT_ACTIVITY,
    EVENT_SUBAGENT_LIST,
    EVENT_TEXT_CHUNK,
    EVENT_THINKING_CHUNK,
    EVENT_TODO_UPDATE,
    EVENT_TOOL_CALL,
    EVENT_TOOL_CALL_UPDATE,
    EVENT_TOOL_RESULT,
    STOP_REASON_CANCELLED,
    STOP_REASON_COMPACTION_FAILED,
    STOP_REASON_END_TURN,
    STOP_REASON_REFUSAL,
    STOP_REASON_STALE_RECOVER,
    STOP_REASON_TOOL_STALL,
)
from kiro_crew.agent_sdk.native_commands import NativeCommandBatch, run_kiro_native_commands

#: Historical spellings of the two terminal reasons, kept because
#: ``monitoring/completion.py`` reads them. They are ALIASES, not a second
#: definition: one literal per reason lives in
#: :mod:`kiro_crew.agent_sdk.events`, so the two cannot drift apart.
TURN_STOP_REASON_CANCELLED = STOP_REASON_CANCELLED
TURN_STOP_REASON_END_TURN = STOP_REASON_END_TURN


class AgentTurnUsage(Protocol):
    """Provider-neutral token dimensions reported for one completed turn."""

    input_tokens: int
    output_tokens: int


__all__ = [
    "AgentTurnUsage",
    "ALL_EVENT_KINDS",
    "EVENT_AGENT_SWITCHED",
    "EVENT_CLEAR_STATUS",
    "EVENT_COMPACTION_STATUS",
    "EVENT_COMPLETE",
    "EVENT_MCP_OAUTH_REQUEST",
    "EVENT_MCP_SERVER_INITIALIZED",
    "EVENT_MCP_SERVER_INIT_FAILURE",
    "EVENT_PERMISSION_REQUEST",
    "EVENT_STEER_CLEARED",
    "EVENT_STEER_CONSUMED",
    "EVENT_STEER_QUEUED",
    "EVENT_SUBAGENT_ACTIVITY",
    "EVENT_SUBAGENT_LIST",
    "EVENT_TEXT_CHUNK",
    "EVENT_THINKING_CHUNK",
    "EVENT_TODO_UPDATE",
    "EVENT_TOOL_CALL",
    "EVENT_TOOL_CALL_UPDATE",
    "EVENT_TOOL_RESULT",
    "STOP_REASON_CANCELLED",
    "STOP_REASON_COMPACTION_FAILED",
    "STOP_REASON_END_TURN",
    "STOP_REASON_REFUSAL",
    "STOP_REASON_STALE_RECOVER",
    "STOP_REASON_TOOL_STALL",
    "CACHE_TTL_SECONDS",
    "COMPONENT_CLAUDE_ACP_ADAPTER",
    "COMPONENT_CLAUDE_CODE_CLI",
    "COMPONENT_KIRO_CLI",
    "INSTALLED",
    "MISSING",
    "UNKNOWN",
    "BackendInstallState",
    "NativeCommandBatch",
    "clear_probe_cache",
    "probe_backend",
    "probe_backends",
    "run_kiro_native_commands",
    "TURN_STOP_REASON_CANCELLED",
    "TURN_STOP_REASON_END_TURN",
]
