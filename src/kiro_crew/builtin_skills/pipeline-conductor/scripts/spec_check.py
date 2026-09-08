#!/usr/bin/env python3
"""Pipeline spec check — the startup predicate for the spec's closed-value fields.

One invocation answers "is this spec runnable?" for every field whose value set
is CLOSED, before the run arms anything.

WHY ONLY THE CLOSED FIELDS. A closed field is the one shape where a typo is
SILENT. A misspelled repo, branch pattern or threshold fails at first use, loudly
and immediately. A misspelled enum matches no branch: the mode the operator asked
for never engages, the run proceeds under whatever the surrounding procedure does
by default, and the report reads as a normal run. ``verifier.repro_gate`` is the
field that made this concrete — ``pod_required`` is a hard admission gate whose
whole purpose is to make unit-only evidence inadmissible, and
``"pod-required"`` (hyphen) is neither value, so the gate is off while the spec
says it is on and the campaign's own metric still counts the run as pod-verified.
That is precisely the failure the gate exists to prevent, reintroduced one typo
lower.

So the check FAILS CLOSED: any value outside the declared set refuses the run
rather than picking a default. Choosing a default here would be the same silent
degradation with an extra step.

An ABSENT field is not an error — the spec documents a default for every field,
and omission is how a pipeline asks for it. An explicit ``null`` is not omission
and is refused: it is a value, and it is not one of the declared ones.

Usage:
    python3 spec_check.py --spec <pipeline-spec.json>

Exit codes:

    0   the spec's closed-value fields are usable
    2   malformed spec — stderr names the field, the offending value, and the
        accepted set. Do not start the run. Also returned when the spec path is
        REFUSED by the sensitive-path read gate, or when that gate cannot be
        enforced at all: an unenforceable precondition is a refusal here, never
        a plain read.

Reads one file; writes nothing; no subprocess.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

try:
    # The spec path comes from the operator's seed message, so it is
    # caller-influenced: a symlink could point it at a credential store the
    # sandbox leaves readable. ``safe_read_file`` canonicalizes the path,
    # re-checks the RESOLVED target against ``is_sensitive_path``, and opens it
    # ``O_NOFOLLOW``, so the gate holds through a link and through a TOCTOU swap.
    from kiro_crew.hooks import safe_read_file
except Exception:  # pragma: no cover - exercised when the package is not importable
    # A skill's scripts are synced OUT of the package tree and can run as bare
    # files, so ``kiro_crew`` is not guaranteed to be importable. There is no
    # safe degradation for a READ GATE: falling back to ``read_text`` would
    # reintroduce exactly the bypass the import exists to close, and it would do
    # so silently, in the case that is hardest to notice. So the fallback is a
    # refusal, which is also what this script does with every other precondition
    # it cannot establish.
    safe_read_file = None  # type: ignore[assignment]

#: Spec field (dotted path) -> the values it accepts.
#:
#: This table is the seam: a future closed field is registered here and inherits
#: the fail-closed behavior and the error shape, rather than growing a second
#: validator somewhere else. Fields with open value sets belong nowhere near it —
#: listing one would turn a legitimate value into a refused startup.
_ENUMS: dict[str, tuple[str, ...]] = {
    "verifier.repro_gate": ("best_effort", "pod_required"),
}


def _expected(values: tuple[str, ...]) -> str:
    """Render an accepted set the way the error message needs it."""
    quoted = [repr(value) for value in values]
    if len(quoted) == 1:
        return quoted[0]
    if len(quoted) == 2:
        return f"{quoted[0]} or {quoted[1]}"
    return f"{', '.join(quoted[:-1])}, or {quoted[-1]}"


def spec_error(spec: dict[str, Any]) -> str | None:
    """Return the first problem in ``spec``, or ``None`` when it is runnable.

    One message, not a list: a spec with two bad enums is refused on the first,
    and the operator re-runs the check after fixing it. A partial spec is never
    "runnable except for" — there is no degraded mode to report.
    """
    for path, allowed in _ENUMS.items():
        parent: Any = spec
        keys = path.split(".")
        for key in keys[:-1]:
            if not isinstance(parent, dict) or key not in parent:
                parent = None
                break
            parent = parent[key]
            if not isinstance(parent, dict):
                # A block spelled as a scalar or a list hides every field under
                # it, so the enum below would read as absent and default.
                return f"{key}: expected a JSON object"
        leaf = keys[-1]
        if not isinstance(parent, dict) or leaf not in parent:
            # Absent: the spec's documented default applies.
            continue
        value = parent[leaf]
        if not isinstance(value, str) or value not in allowed:
            return f"{path} {value!r}: expected {_expected(allowed)}"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a pipeline spec before a run.")
    parser.add_argument("--spec", required=True, help="path to the pipeline spec JSON")
    args = parser.parse_args(argv)

    if safe_read_file is None:
        print(
            "malformed spec: cannot enforce the sensitive-path read gate "
            "(kiro_crew.hooks is not importable); refusing to read the spec",
            file=sys.stderr,
        )
        return 2
    try:
        spec = json.loads(safe_read_file(args.spec))
        if not isinstance(spec, dict):
            raise ValueError("spec must be a JSON object")
    except PermissionError as exc:
        # The gate's own refusal, kept distinct from a malformed file: the spec
        # may be perfectly well-formed and still not be ours to read.
        print(f"refused spec: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"malformed spec: {exc}", file=sys.stderr)
        return 2
    problem = spec_error(spec)
    if problem is not None:
        print(f"malformed spec: {problem}", file=sys.stderr)
        return 2
    print(f"OK {args.spec}: {len(_ENUMS)} closed-value field(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
