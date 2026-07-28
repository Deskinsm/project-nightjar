from nightjar.models import Mission
from nightjar.policy import PolicyLimits
from nightjar.security import (
    canonical_json_bytes,
    mission_sha256,
    policy_sha256,
    sha256_hex,
)


def build_mission(altitude_m: float = 5) -> Mission:
    return Mission.model_validate(
        {
            "mission_id": "42b6a3fd-1b5c-4d2a-9c86-b82679b2f88c",
            "description": "Security hashing test mission.",
            "actions": [
                {
                    "type": "takeoff",
                    "altitude_m": altitude_m,
                },
                {
                    "type": "land",
                },
            ],
        }
    )


def test_canonical_json_ignores_dictionary_key_order() -> None:
    first = {"alpha": 1, "bravo": 2}
    second = {"bravo": 2, "alpha": 1}

    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert sha256_hex(first) == sha256_hex(second)


def test_mission_hash_is_deterministic() -> None:
    first = build_mission()
    second = build_mission()

    assert mission_sha256(first) == mission_sha256(second)


def test_mission_change_changes_hash() -> None:
    approved = build_mission(altitude_m=5)
    altered = build_mission(altitude_m=6)

    assert mission_sha256(approved) != mission_sha256(altered)


def test_policy_change_changes_hash() -> None:
    original = PolicyLimits(max_altitude_m=10)
    altered = PolicyLimits(max_altitude_m=20)

    assert policy_sha256(original) != policy_sha256(altered)
