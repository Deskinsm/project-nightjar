from __future__ import annotations

import json

from nightjar.models import Mission


class PlannerError(ValueError):
    """Raised when a planner response cannot be converted to a mission."""


def parse_planner_output(raw_output: str) -> Mission:
    """Parse JSON produced by an LLM or another planning component.

    This function deliberately performs no execution. Its output must still be
    evaluated by the deterministic policy engine.
    """

    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise PlannerError(f"Planner output is not valid JSON: {exc}") from exc

    try:
        return Mission.model_validate(payload)
    except Exception as exc:
        raise PlannerError(f"Planner output violates the mission schema: {exc}") from exc
