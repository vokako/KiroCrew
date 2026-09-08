"""The event-kind and stop-reason vocabulary every backend is described in.

These strings are what application code branches on: an event's ``kind`` and a
turn's ``stop_reason``. They are provider-neutral by construction -- no backend
puts them on the wire, the driver assigns them while translating a harness's own
frames -- so the SDK owns them and the ACP layer reads them from here.

``kiro_crew.acp.types`` re-exports every name below, so
``from kiro_crew.acp.types import EVENT_TOOL_CALL`` keeps working unchanged. The
re-export is the same *object*, not a copy of the literal: a test asserts
identity in both directions, because two modules each spelling ``"tool_call"``
would drift silently.

One stop reason deliberately stays behind in ``kiro_crew.acp.types``:
``STOP_REASON_CONTENT_FILTERED_WIRE`` is a harness's own spelling of a refusal,
normalised to :data:`STOP_REASON_REFUSAL` before it reaches any consumer. It is
a wire literal shared by the parser and its tests, not vocabulary application
code compares against.

This module imports nothing from ``kiro_crew.acp`` or ``kiro_crew.providers``,
and must not: it is the leaf the boundary points at. See
``docs/request-for-change/rfc-crew-agent-sdk-boundary.md`` §PR 2.
"""

from __future__ import annotations

# ── Event Kinds ──

EVENT_TEXT_CHUNK = "text_chunk"
EVENT_THINKING_CHUNK = "thinking_chunk"
EVENT_TOOL_CALL = "tool_call"
EVENT_TOOL_CALL_UPDATE = "tool_call_update"
EVENT_TOOL_RESULT = "tool_result"
EVENT_PERMISSION_REQUEST = "permission_request"
EVENT_COMPLETE = "complete"
EVENT_COMPACTION_STATUS = "compaction_status"
EVENT_CLEAR_STATUS = "clear_status"
EVENT_AGENT_SWITCHED = "agent_switched"
EVENT_MCP_OAUTH_REQUEST = "mcp_oauth_request"
# Agent's own task/TODO list snapshot, recovered from the `todo_list` tool's
# rawOutput. Not an ACP-native update kind — see KIRO_TOOL_TODO_LIST in
# `kiro_crew.acp.types`, which names that tool's wire spelling.
EVENT_TODO_UPDATE = "todo_update"
EVENT_MCP_SERVER_INITIALIZED = "mcp_server_initialized"
EVENT_MCP_SERVER_INIT_FAILURE = "mcp_server_init_failure"
EVENT_SUBAGENT_LIST = "subagent_list"
EVENT_SUBAGENT_ACTIVITY = "subagent_activity"
EVENT_STEER_QUEUED = "steer_queued"
EVENT_STEER_CONSUMED = "steer_consumed"
EVENT_STEER_CLEARED = "steer_cleared"

#: Every event kind the SDK defines. A dispatcher can assert an unknown kind
#: against this instead of hand-listing the constants it happens to know, which
#: is how a kind added here reaches an exhaustiveness check for free.
ALL_EVENT_KINDS = frozenset(
    {
        EVENT_TEXT_CHUNK,
        EVENT_THINKING_CHUNK,
        EVENT_TOOL_CALL,
        EVENT_TOOL_CALL_UPDATE,
        EVENT_TOOL_RESULT,
        EVENT_PERMISSION_REQUEST,
        EVENT_COMPLETE,
        EVENT_COMPACTION_STATUS,
        EVENT_CLEAR_STATUS,
        EVENT_AGENT_SWITCHED,
        EVENT_MCP_OAUTH_REQUEST,
        EVENT_TODO_UPDATE,
        EVENT_MCP_SERVER_INITIALIZED,
        EVENT_MCP_SERVER_INIT_FAILURE,
        EVENT_SUBAGENT_LIST,
        EVENT_SUBAGENT_ACTIVITY,
        EVENT_STEER_QUEUED,
        EVENT_STEER_CONSUMED,
        EVENT_STEER_CLEARED,
    }
)

# ── Stop Reasons ──

STOP_REASON_CANCELLED = "cancelled"
STOP_REASON_END_TURN = "end_turn"
# Model-side content refusal ("response declined by the model"). Non-retryable:
# retrying the same prompt hits the same refusal, so chat_runner surfaces an
# actionable message instead of churning the retry ladder.
STOP_REASON_REFUSAL = "refusal"
# Signalled by the ACP layer when a genuinely-wedged (stale) turn was probed via
# session/cancel and got no ack within the grace window — a confirmed wedge, not
# a done-but-missing-frame turn (which acks and completes normally). The
# dashboard routes this to reset+resume+continue-nudge auto-recovery.
STOP_REASON_STALE_RECOVER = "stale_recover"
# Signalled by the per-session watchdog when an in-flight tool was judged dead
# / stuck / UNKNOWN-past-budget and the session was cancelled. Kept in the
# "error:" family so callers without a dedicated branch fall back to the
# generic error handling; chat_runner routes it to a dedicated recovery
# (continue-nudge, NOT a verbatim re-run of the original message).
STOP_REASON_TOOL_STALL = "error: tool stall"
# Signalled by the ACP layer when automatic compaction reported `failed`
# and the backend then abandoned the turn (no prompt response, no
# end_turn) past the post-failure budget. Kept in the "error:" family so
# callers without a dedicated branch fall back to generic error handling;
# it deliberately triggers NO retry — the user-visible compaction notice
# already explains what happened, and this only releases the slot.
STOP_REASON_COMPACTION_FAILED = "error: compaction failed"

__all__ = [
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
]
