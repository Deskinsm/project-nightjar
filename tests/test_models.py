import pytest
from pydantic import ValidationError

from nightjar.models import Mission


def test_mission_requires_safe_termination() -> None:
    with pytest.raises(ValidationError):
        Mission.model_validate(
            {
                "description": "Unsafe unfinished mission",
                "actions": [
                    {"type": "takeoff", "altitude_m": 5},
                    {"type": "hold", "duration_seconds": 10},
                ],
            }
        )


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Mission.model_validate(
            {
                "description": "Contains an unapproved instruction",
                "actions": [
                    {
                        "type": "takeoff",
                        "altitude_m": 5,
                        "shell_command": "do-not-run",
                    },
                    {"type": "land"},
                ],
            }
        )
