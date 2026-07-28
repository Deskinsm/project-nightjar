from nightjar.models import Mission
from nightjar.policy import PolicyEngine


def test_safe_mission_is_approved() -> None:
    mission = Mission.model_validate(
        {
            "description": "Safe local test",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "hold", "duration_seconds": 10},
                {"type": "return_home"},
                {"type": "land"},
            ],
        }
    )

    decision = PolicyEngine().evaluate(mission)

    assert decision.approved is True
    assert decision.reasons == ()


def test_excessive_altitude_is_rejected() -> None:
    mission = Mission.model_validate(
        {
            "description": "Unsafe altitude test",
            "actions": [
                {"type": "takeoff", "altitude_m": 500},
                {"type": "land"},
            ],
        }
    )

    decision = PolicyEngine().evaluate(mission)

    assert decision.approved is False
    assert any("exceeds" in reason for reason in decision.reasons)


def test_action_after_landing_is_rejected() -> None:
    mission = Mission.model_validate(
        {
            "description": "Invalid state transition",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "land"},
                {"type": "return_home"},
            ],
        }
    )

    decision = PolicyEngine().evaluate(mission)

    assert decision.approved is False
    assert any("after landing" in reason for reason in decision.reasons)
