"""GATE -- the event-kind and stop-reason vocabulary is SDK-owned, and only once.

``kiro_crew.agent_sdk.events`` now defines every ``EVENT_*`` kind and the
provider-neutral ``STOP_REASON_*`` reasons; ``kiro_crew.acp.types`` re-exports
them so no consumer changed. Three properties make that a move rather than a
copy, and each is a separate failure mode:

1. **The shim is the same object.** Every name reachable as
   ``kiro_crew.acp.types.X`` IS ``kiro_crew.agent_sdk.events.X``. Value equality
   is checked too, because CPython interns short identifier-like literals and an
   ``is`` assertion alone would pass on a re-declared ``"cancelled"``.
2. **There is one declaration.** ``acp/types.py`` must not assign an ``EVENT_*``
   or ``STOP_REASON_*`` name itself -- the one exception is
   ``STOP_REASON_CONTENT_FILTERED_WIRE``, a harness's own spelling that is
   normalised before any consumer sees it. This is the assertion that actually
   catches drift; interning hides it from ``is``.
3. **The direction is ``acp -> agent_sdk``, never back.** The import gate exempts
   ``agent_sdk/`` wholly, so the one channel it cannot see is a verbatim
   re-export *inside* the SDK -- precisely the ``providers/base.py`` aliasing
   (``LLMEvent = AcpEvent``) that made two forbidden roots necessary. Checked
   structurally (the module's own imports) and dynamically (a fresh interpreter
   importing it loads no ACP module).

The corpus check closes the last gap: a vocabulary the SDK owns but the dispatch
layer does not emit would satisfy everything above and still be wrong, so every
``kind`` in the committed replay snapshots must be a kind this module defines.

See ``docs/request-for-change/rfc-crew-agent-sdk-boundary.md`` §PR 2.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from kiro_crew.acp import types as acp_types
from kiro_crew.agent_sdk import events as sdk_events
from kiro_crew.subprocess_utf8 import UTF8_TEXT

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
EVENTS_MODULE = SRC / "kiro_crew" / "agent_sdk" / "events.py"
ACP_TYPES_MODULE = SRC / "kiro_crew" / "acp" / "types.py"
FRAME_FIXTURES = ROOT / "test" / "fixtures" / "acp_frames"

#: The two package roots the SDK is not allowed to reach. ``kiro_crew.acp`` is
#: matched EXACTLY or as a dotted parent, never as a string prefix: the sibling
#: leaf ``kiro_crew.acp_backends`` imports no ACP at all, and a ``startswith``
#: check is the bug that made an earlier RFC draft overcount the baseline.
FORBIDDEN_ROOTS = ("kiro_crew.acp", "kiro_crew.providers")

#: The one stop reason that stays in ``acp/types.py``. It is a wire literal.
WIRE_ONLY_NAMES = frozenset({"STOP_REASON_CONTENT_FILTERED_WIRE"})


def _reaches_forbidden_root(module: str) -> bool:
    """Whether *module* names one of :data:`FORBIDDEN_ROOTS` or a child of one."""
    return any(module == root or module.startswith(root + ".") for root in FORBIDDEN_ROOTS)


def _vocabulary_names() -> list[str]:
    """Every ``EVENT_*`` / ``STOP_REASON_*`` name the SDK module exports."""
    return sorted(
        name
        for name in sdk_events.__all__
        if name.startswith("EVENT_") or name.startswith("STOP_REASON_")
    )


def _assigned_names(source: Path) -> set[str]:
    """Module-scope names *source* assigns a value to."""
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    assigned: set[str] = set()
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                assigned.add(target.id)
    return assigned


def _run_child(code: str) -> subprocess.CompletedProcess[str]:
    """Run *code* in an isolated interpreter pinned to this repository's ``src/``.

    ``-I`` isolates it from ``PYTHONPATH`` and user site so it measures this
    tree rather than an editable install's; ``-B`` is separate and not implied,
    and keeps a read-only assertion from writing ``__pycache__`` into ``src/``.
    """
    prelude = f"import sys; sys.path.insert(0, {str(SRC)!r})\n"
    return subprocess.run(
        [sys.executable, "-I", "-B", "-c", prelude + code],
        cwd=str(ROOT),
        capture_output=True,
        timeout=120,
        **UTF8_TEXT,
    )


# ── 1. the shim is the same object ──────────────────────────────────────────


def test_the_vocabulary_is_not_empty() -> None:
    """Guard every parametrised test below against an empty name list."""
    names = _vocabulary_names()
    kinds = [name for name in names if name.startswith("EVENT_")]
    reasons = [name for name in names if name.startswith("STOP_REASON_")]
    assert len(kinds) == 19, f"expected 19 event kinds, found {len(kinds)}: {kinds}"
    assert len(reasons) >= 6, f"expected the provider-neutral stop reasons, found {reasons}"


@pytest.mark.parametrize("name", _vocabulary_names())
def test_the_acp_shim_re_exports_the_sdk_object(name: str) -> None:
    """``from kiro_crew.acp.types import EVENT_*`` must still work, unchanged."""
    assert hasattr(acp_types, name), (
        f"kiro_crew.acp.types no longer exports {name}. Every existing importer "
        "reads it from there; add it back to the re-export list rather than "
        "editing the consumers."
    )
    sdk_value = getattr(sdk_events, name)
    acp_value = getattr(acp_types, name)
    assert acp_value == sdk_value, (
        f"{name} drifted: kiro_crew.acp.types has {acp_value!r} but "
        f"kiro_crew.agent_sdk.events has {sdk_value!r}. The ACP layer must read "
        "the SDK's literal, not carry its own."
    )
    assert acp_value is sdk_value, (
        f"{name} is a different object in kiro_crew.acp.types. It must be the "
        "re-exported SDK constant, not a second declaration of the same string."
    )


def test_all_event_kinds_covers_every_event_constant() -> None:
    """A kind added to the module but not the frozenset is invisible to callers."""
    declared = {
        getattr(sdk_events, name) for name in _vocabulary_names() if name.startswith("EVENT_")
    }
    assert sdk_events.ALL_EVENT_KINDS == declared, (
        "ALL_EVENT_KINDS and the EVENT_* constants disagree. Symmetric difference: "
        f"{sorted(sdk_events.ALL_EVENT_KINDS ^ declared)}"
    )
    assert isinstance(sdk_events.ALL_EVENT_KINDS, frozenset)


def test_every_event_kind_string_is_distinct() -> None:
    """Two kinds sharing a string would make a dispatcher branch unreachable."""
    kinds = [getattr(sdk_events, name) for name in _vocabulary_names()]
    events = [k for k in kinds if k in sdk_events.ALL_EVENT_KINDS]
    assert len(set(events)) == len(events), f"duplicate event-kind string among {events}"


# ── 2. there is one declaration ─────────────────────────────────────────────


def test_the_acp_layer_declares_no_vocabulary_of_its_own() -> None:
    """The real anti-drift assertion: interning hides a duplicate from ``is``.

    ``"cancelled" is "cancelled"`` is True across modules because CPython
    interns identifier-like constants, so a re-declared short literal in
    ``acp/types.py`` would satisfy the identity test above. This one reads the
    source instead.
    """
    redeclared = {
        name
        for name in _assigned_names(ACP_TYPES_MODULE)
        if (name.startswith("EVENT_") or name.startswith("STOP_REASON_"))
        and name not in WIRE_ONLY_NAMES
    }
    assert not redeclared, (
        f"src/kiro_crew/acp/types.py assigns {sorted(redeclared)} itself. The "
        "vocabulary lives in kiro_crew.agent_sdk.events and is re-exported here; "
        "a second assignment is a copy that can drift."
    )


def test_the_wire_only_reason_stays_in_the_acp_layer() -> None:
    """It is a harness spelling, not vocabulary a consumer compares against."""
    for name in sorted(WIRE_ONLY_NAMES):
        assert name in _assigned_names(ACP_TYPES_MODULE), (
            f"{name} left src/kiro_crew/acp/types.py. It is normalised to "
            "STOP_REASON_REFUSAL before any consumer sees it, so promoting it "
            "into the SDK would export a literal nothing above the boundary reads."
        )
        assert not hasattr(sdk_events, name), (
            f"{name} was added to kiro_crew.agent_sdk.events. See above -- it is a "
            "wire detail owned by the parser."
        )


# ── 3. the direction is acp -> agent_sdk, never back ────────────────────────


def test_the_sdk_vocabulary_module_imports_no_backend_package() -> None:
    """Structural half of the identity guard: read what the module names."""
    tree = ast.parse(EVENTS_MODULE.read_text(encoding="utf-8"), filename=str(EVENTS_MODULE))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders += [a.name for a in node.names if _reaches_forbidden_root(a.name)]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if _reaches_forbidden_root(node.module):
                offenders.append(node.module)
    assert not offenders, (
        f"src/kiro_crew/agent_sdk/events.py imports {offenders}. This module is the "
        "leaf the boundary points at: the ACP layer reads it, never the reverse. A "
        "re-export the other way round would let a consumer look migrated while "
        "holding the ACP object, and the import gate cannot see it because it "
        "exempts agent_sdk/ wholly."
    )


def test_importing_the_sdk_vocabulary_loads_no_acp_module() -> None:
    """Dynamic half: a lazily-added edge fails here even if the source looks clean."""
    proc = _run_child(
        "import kiro_crew.agent_sdk.events\n"
        "leaked = sorted(m for m in sys.modules if "
        f"any(m == r or m.startswith(r + '.') for r in {FORBIDDEN_ROOTS!r}))\n"
        "print('ANSWER:' + ' '.join(leaked))\n"
    )
    assert proc.returncode == 0, (
        "importing kiro_crew.agent_sdk.events as the first kiro_crew module failed. "
        "kiro_crew.acp.types now imports it, so an edge back would close a cycle "
        "and the ACP layer would only be importable after the SDK.\n"
        f"stderr:\n{proc.stderr}"
    )
    answers = [
        line[len("ANSWER:") :].strip()
        for line in proc.stdout.splitlines()
        if line.startswith("ANSWER:")
    ]
    assert len(answers) == 1, f"expected one sentinel line, got {answers!r}"
    assert not answers[0], (
        "importing kiro_crew.agent_sdk.events dragged in backend-layer modules: "
        f"{answers[0].split()}. The SDK vocabulary is a leaf."
    )


def test_no_sdk_export_is_a_backend_object() -> None:
    """No name the SDK package exports may be defined in the backend packages."""
    import kiro_crew.agent_sdk as sdk

    checked = 0
    for name in sdk.__all__:
        obj = getattr(sdk, name)
        origin = getattr(obj, "__module__", None)
        if not isinstance(origin, str):
            continue
        checked += 1
        assert not _reaches_forbidden_root(origin), (
            f"kiro_crew.agent_sdk exports {name}, which is defined in {origin}. A "
            "verbatim re-export of a backend object makes a consumer read as "
            "migrated while holding it, and shrinks the boundary baseline for free."
        )
    assert checked >= 3, (
        f"only {checked} exported name carried a __module__, so this assertion is "
        "close to vacuous. Point it at the classes and functions the SDK exports."
    )


# ── the replay corpus agrees with the vocabulary ─────────────────────────────


def _snapshot_kinds() -> set[str]:
    """Every ``kind`` value in the committed replay snapshots."""
    kinds: set[str] = set()
    for path in sorted(FRAME_FIXTURES.glob("*/*.expected.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        stack = [payload]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                kind = node.get("kind")
                if isinstance(kind, str):
                    kinds.add(kind)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    return kinds


def test_the_replay_corpus_emits_only_sdk_event_kinds() -> None:
    """The dispatch layer's real output must be spelled in the SDK's vocabulary."""
    kinds = _snapshot_kinds()
    assert len(kinds) >= 5, (
        f"only {len(kinds)} kind(s) found in {FRAME_FIXTURES}/*/*.expected.json, so "
        "this assertion proves nothing. Check the fixture layout before relaxing it."
    )
    unknown = kinds - sdk_events.ALL_EVENT_KINDS
    assert not unknown, (
        f"the replay snapshots emit {sorted(unknown)}, which kiro_crew.agent_sdk."
        "events does not define. Either the dispatch layer invented a kind or a "
        "constant was renamed without the corpus being regenerated."
    )
