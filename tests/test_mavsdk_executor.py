from __future__ import annotations

from typing import Any

import pytest

from nightjar.mavsdk_executor import (
    MavsdkExecutor,
    MavsdkPolicyRejectedError,
    UnsupportedMavsdkActionError,
)
from nightjar.models import Mission


class FakeConnectionState:
    is_connected = True


class FakeCore:
    async def connection_state(self):
        yield FakeConnectionState()


class FakeTelemetry:
    async def in_air(self):
        yield False


class FakeAction:
    def __init__(self, calls: list[tuple[str, Any]]) -> None:
        self.calls = calls

    async def set_takeoff_altitude(self, altitude_m: float) -> None:
        self.calls.append(("set_takeoff_altitude", altitude_m))

    async def arm(self) -> None:
        self.calls.append(("arm", None))

    async def takeoff(self) -> None:
        self.calls.append(("takeoff", None))

    async def land(self) -> None:
        self.calls.append(("land", None))


class FakeSystem:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.core = FakeCore()
        self.telemetry = FakeTelemetry()
        self.action = FakeAction(self.calls)

    async def connect(self, *, system_address: str) -> None:
        self.calls.append(("connect", system_address))


def test_supported_mission_executes_against_fake_system(tmp_path) -> None:
    mission = Mission.model_validate(
        {
            "description": "MAVSDK executor happy path",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "hold", "duration_seconds": 2},
                {"type": "land"},
            ],
        }
    )

    drone = FakeSystem()
    sleep_calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    executor = MavsdkExecutor(
        system_factory=lambda: drone,
        sleep_function=fake_sleep,
        log_directory=tmp_path,
    )

    result = executor.execute(mission)

    assert result.completed is True
    assert result.log_path.exists()
    assert drone.calls == [
        ("connect", "udpin://127.0.0.1:14540"),
        ("set_takeoff_altitude", 5.0),
        ("arm", None),
        ("takeoff", None),
        ("land", None),
    ]
    assert sleep_calls == [2]


def test_policy_rejection_happens_before_system_creation() -> None:
    mission = Mission.model_validate(
        {
            "description": "Unsafe altitude",
            "actions": [
                {"type": "takeoff", "altitude_m": 500},
                {"type": "land"},
            ],
        }
    )

    factory_called = False

    def system_factory():
        nonlocal factory_called
        factory_called = True
        raise AssertionError("MAVSDK system must not be created for rejected missions.")

    executor = MavsdkExecutor(system_factory=system_factory)

    with pytest.raises(MavsdkPolicyRejectedError, match="Mission rejected by policy"):
        executor.execute(mission)

    assert factory_called is False


def test_unsupported_action_happens_before_system_creation() -> None:
    mission = Mission.model_validate(
        {
            "description": "Goto not implemented yet",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "goto", "north_m": 5, "east_m": 0, "altitude_m": 5},
                {"type": "land"},
            ],
        }
    )

    factory_called = False

    def system_factory():
        nonlocal factory_called
        factory_called = True
        raise AssertionError("MAVSDK system must not be created for unsupported missions.")

    executor = MavsdkExecutor(system_factory=system_factory)

    with pytest.raises(
        UnsupportedMavsdkActionError,
        match="does not support these mission actions yet: goto",
    ):
        executor.execute(mission)

    assert factory_called is False


def test_vehicle_failure_is_audited(tmp_path) -> None:
    mission = Mission.model_validate(
        {
            "description": "Vehicle failure test",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "land"},
            ],
        }
    )

    class FailingAction(FakeAction):
        async def arm(self) -> None:
            self.calls.append(("arm", None))
            raise RuntimeError("simulated arm failure")

    drone = FakeSystem()
    drone.action = FailingAction(drone.calls)

    executor = MavsdkExecutor(
        system_factory=lambda: drone,
        log_directory=tmp_path,
    )

    with pytest.raises(RuntimeError, match="simulated arm failure"):
        executor.execute(mission)

    log_path = tmp_path / f"{mission.mission_id}.jsonl"
    records = log_path.read_text(encoding="utf-8")

    assert '"event": "mission_failed"' in records
    assert '"error": "simulated arm failure"' in records
    assert '"event": "mission_completed"' not in records
