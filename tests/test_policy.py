from nightjar.models import Mission
from nightjar.policy import PolicyEngine, PolicyLimits


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


def test_aggregate_hold_budget_is_enforced() -> None:
    mission = Mission.model_validate(
        {
            "description": "Too much cumulative holding",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "hold", "duration_seconds": 60},
                {"type": "hold", "duration_seconds": 60},
                {"type": "hold", "duration_seconds": 1},
                {"type": "land"},
            ],
        }
    )

    decision = PolicyEngine().evaluate(mission)

    assert decision.approved is False
    assert any("total hold time" in reason for reason in decision.reasons)


def test_aggregate_distance_budget_is_enforced() -> None:
    mission = Mission.model_validate(
        {
            "description": "Long path inside local radius",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "goto", "north_m": 30, "east_m": 0, "altitude_m": 5},
                {"type": "goto", "north_m": -30, "east_m": 0, "altitude_m": 5},
                {"type": "goto", "north_m": 30, "east_m": 0, "altitude_m": 5},
                {"type": "land"},
            ],
        }
    )

    decision = PolicyEngine().evaluate(mission)

    assert decision.approved is False
    assert any("total horizontal distance" in reason for reason in decision.reasons)


def test_goto_action_budget_is_enforced() -> None:
    mission = Mission.model_validate(
        {
            "description": "Too many small waypoints",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "goto", "north_m": 1, "east_m": 0, "altitude_m": 5},
                {"type": "goto", "north_m": 2, "east_m": 0, "altitude_m": 5},
                {"type": "goto", "north_m": 3, "east_m": 0, "altitude_m": 5},
                {"type": "goto", "north_m": 4, "east_m": 0, "altitude_m": 5},
                {"type": "goto", "north_m": 5, "east_m": 0, "altitude_m": 5},
                {"type": "goto", "north_m": 6, "east_m": 0, "altitude_m": 5},
                {"type": "land"},
            ],
        }
    )

    decision = PolicyEngine().evaluate(mission)

    assert decision.approved is False
    assert any("goto actions" in reason for reason in decision.reasons)


def test_return_home_leg_counts_toward_distance_budget() -> None:
    mission = Mission.model_validate(
        {
            "description": "Return-home distance budget test",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "goto", "north_m": 30, "east_m": 0, "altitude_m": 5},
                {"type": "return_home"},
                {"type": "land"},
            ],
        }
    )

    limits = PolicyLimits(max_total_horizontal_distance_m=50)
    decision = PolicyEngine(limits).evaluate(mission)

    assert decision.approved is False
    assert any("total horizontal distance" in reason for reason in decision.reasons)
