from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nightjar.approval import (
    ApprovalError,
    SignedApproval,
    build_approval_payload,
    sign_approval,
)
from nightjar.authorization import verify_and_consume_approval
from nightjar.mavsdk_executor import (
    MAVSDK_EXECUTOR_NAME,
    MavsdkExecutor,
    MavsdkExecutorError,
    MavsdkPolicyRejectedError,
    UnsupportedMavsdkActionError,
)
from nightjar.models import Mission
from nightjar.policy import PolicyLimits
from nightjar.replay import ApprovalReplayError, SQLiteNonceStore


class FakeConnectionState:
    is_connected = True


class FakeCore:
    async def connection_state(self):
        yield FakeConnectionState()


class FakePosition:
    def __init__(self, relative_altitude_m: float) -> None:
        self.relative_altitude_m = relative_altitude_m


class FakeTelemetry:
    async def position(self):
        yield FakePosition(relative_altitude_m=5.0)

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


def build_approval(
    *,
    private_key: Ed25519PrivateKey,
    mission: Mission,
    limits: PolicyLimits | None = None,
    executor: str = "mavsdk",
    nonce: str | None = None,
) -> SignedApproval:
    payload = build_approval_payload(
        mission=mission,
        limits=limits or PolicyLimits(),
        executor=executor,
        ttl_seconds=300,
        now_unix=int(time.time()),
        nonce=nonce,
    )

    return sign_approval(private_key, payload)


def build_executor(
    *,
    private_key: Ed25519PrivateKey,
    tmp_path: Path,
    **kwargs: Any,
) -> MavsdkExecutor:
    return MavsdkExecutor(
        public_key=private_key.public_key(),
        nonce_store=SQLiteNonceStore(tmp_path / "approvals.sqlite3"),
        **kwargs,
    )


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

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(
        private_key=private_key,
        mission=mission,
    )

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        sleep_function=fake_sleep,
        log_directory=tmp_path,
    )

    result = executor.execute(
        mission,
        approval=approval,
    )

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


def test_policy_rejection_happens_before_system_creation(tmp_path) -> None:
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

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(
        private_key=private_key,
        mission=mission,
    )

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=system_factory,
    )

    with pytest.raises(MavsdkPolicyRejectedError, match="Mission rejected by policy"):
        executor.execute(
            mission,
            approval=approval,
        )

    assert factory_called is False


def test_unsupported_action_happens_before_system_creation(tmp_path) -> None:
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

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(
        private_key=private_key,
        mission=mission,
    )

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=system_factory,
    )

    with pytest.raises(
        UnsupportedMavsdkActionError,
        match="does not support these mission actions yet: goto",
    ):
        executor.execute(
            mission,
            approval=approval,
        )

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

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(
        private_key=private_key,
        mission=mission,
    )

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        log_directory=tmp_path,
    )

    with pytest.raises(RuntimeError, match="simulated arm failure"):
        executor.execute(
            mission,
            approval=approval,
        )

    log_path = tmp_path / f"{mission.mission_id}.jsonl"
    records = log_path.read_text(encoding="utf-8")

    assert '"event": "mission_failed"' in records
    assert '"error": "simulated arm failure"' in records
    assert '"event": "mission_completed"' not in records


def test_hold_waits_until_takeoff_altitude_is_reached(tmp_path) -> None:
    mission = Mission.model_validate(
        {
            "description": "Wait for takeoff altitude before hold",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "hold", "duration_seconds": 2},
                {"type": "land"},
            ],
        }
    )

    class ClimbingTelemetry:
        def __init__(self) -> None:
            self.altitudes_seen: list[float] = []

        async def position(self):
            for altitude_m in (1.0, 3.0, 4.6):
                self.altitudes_seen.append(altitude_m)
                yield FakePosition(relative_altitude_m=altitude_m)

        async def in_air(self):
            yield False

    drone = FakeSystem()
    telemetry = ClimbingTelemetry()
    drone.telemetry = telemetry

    hold_started_at_altitude: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        assert seconds == 2
        hold_started_at_altitude.append(telemetry.altitudes_seen[-1])

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(
        private_key=private_key,
        mission=mission,
    )

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        sleep_function=fake_sleep,
        log_directory=tmp_path,
    )

    result = executor.execute(
        mission,
        approval=approval,
    )

    assert result.completed is True
    assert telemetry.altitudes_seen == [1.0, 3.0, 4.6]
    assert hold_started_at_altitude == [4.6]


def test_takeoff_timeout_blocks_hold_and_is_audited(tmp_path) -> None:
    mission = Mission.model_validate(
        {
            "description": "Takeoff altitude timeout",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "hold", "duration_seconds": 2},
                {"type": "land"},
            ],
        }
    )

    class StalledTelemetry:
        async def position(self):
            yield FakePosition(relative_altitude_m=1.0)
            await asyncio.sleep(1)
            yield FakePosition(relative_altitude_m=1.0)

        async def in_air(self):
            yield False

    drone = FakeSystem()
    drone.telemetry = StalledTelemetry()

    hold_started = False

    async def fake_sleep(seconds: float) -> None:
        nonlocal hold_started
        hold_started = True

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(
        private_key=private_key,
        mission=mission,
    )

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        sleep_function=fake_sleep,
        log_directory=tmp_path,
        takeoff_timeout_seconds=0.01,
    )

    with pytest.raises(
        MavsdkExecutorError,
        match="Timed out waiting 0.01 seconds to reach takeoff altitude 5 m",
    ):
        executor.execute(
            mission,
            approval=approval,
        )

    assert hold_started is False

    log_path = tmp_path / f"{mission.mission_id}.jsonl"
    records = log_path.read_text(encoding="utf-8")

    assert '"event": "mission_failed"' in records
    assert '"event": "mission_completed"' not in records


def test_invalid_signature_blocks_system_creation(tmp_path) -> None:
    mission = Mission.model_validate(
        {
            "description": "Invalid signature must not reach MAVSDK",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "land"},
            ],
        }
    )

    trusted_key = Ed25519PrivateKey.generate()
    untrusted_key = Ed25519PrivateKey.generate()

    approval = build_approval(
        private_key=untrusted_key,
        mission=mission,
    )

    factory_called = False

    def system_factory():
        nonlocal factory_called
        factory_called = True
        raise AssertionError("MAVSDK system must not be created.")

    executor = build_executor(
        private_key=trusted_key,
        tmp_path=tmp_path,
        system_factory=system_factory,
    )

    with pytest.raises(ApprovalError, match="signature"):
        executor.execute(
            mission,
            approval=approval,
        )

    assert factory_called is False


def test_wrong_executor_blocks_system_creation(tmp_path) -> None:
    mission = Mission.model_validate(
        {
            "description": "Wrong executor binding",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "land"},
            ],
        }
    )

    private_key = Ed25519PrivateKey.generate()

    approval = build_approval(
        private_key=private_key,
        mission=mission,
        executor="dry-run",
    )

    factory_called = False

    def system_factory():
        nonlocal factory_called
        factory_called = True
        raise AssertionError("MAVSDK system must not be created.")

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=system_factory,
    )

    with pytest.raises(ApprovalError, match="executor"):
        executor.execute(
            mission,
            approval=approval,
        )

    assert factory_called is False


def test_policy_hash_mismatch_blocks_system_creation(tmp_path) -> None:
    mission = Mission.model_validate(
        {
            "description": "Approval was created under different policy",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "land"},
            ],
        }
    )

    private_key = Ed25519PrivateKey.generate()

    approved_limits = PolicyLimits(max_altitude_m=9.0)

    approval = build_approval(
        private_key=private_key,
        mission=mission,
        limits=approved_limits,
    )

    factory_called = False

    def system_factory():
        nonlocal factory_called
        factory_called = True
        raise AssertionError("MAVSDK system must not be created.")

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=system_factory,
    )

    with pytest.raises(ApprovalError, match="policy"):
        executor.execute(
            mission,
            approval=approval,
        )

    assert factory_called is False


def test_replayed_approval_blocks_second_system_creation(tmp_path) -> None:
    mission = Mission.model_validate(
        {
            "description": "Approval may authorize only one execution",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "land"},
            ],
        }
    )

    private_key = Ed25519PrivateKey.generate()

    approval = build_approval(
        private_key=private_key,
        mission=mission,
        nonce="r" * 32,
    )

    factory_calls = 0

    def system_factory():
        nonlocal factory_calls
        factory_calls += 1
        return FakeSystem()

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=system_factory,
        log_directory=tmp_path,
    )

    result = executor.execute(
        mission,
        approval=approval,
    )

    assert result.completed is True
    assert factory_calls == 1

    with pytest.raises(
        ApprovalReplayError,
        match="already been used",
    ):
        executor.execute(
            mission,
            approval=approval,
        )

    assert factory_calls == 1


def test_unsupported_action_does_not_consume_approval(tmp_path) -> None:
    mission = Mission.model_validate(
        {
            "description": "Unsupported mission must not consume approval",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {
                    "type": "goto",
                    "north_m": 5,
                    "east_m": 0,
                    "altitude_m": 5,
                },
                {"type": "land"},
            ],
        }
    )

    private_key = Ed25519PrivateKey.generate()

    approval = build_approval(
        private_key=private_key,
        mission=mission,
        nonce="u" * 32,
    )

    factory_called = False

    def system_factory():
        nonlocal factory_called
        factory_called = True
        raise AssertionError("MAVSDK system must not be created.")

    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=system_factory,
    )

    with pytest.raises(UnsupportedMavsdkActionError):
        executor.execute(
            mission,
            approval=approval,
        )

    assert factory_called is False

    verified = verify_and_consume_approval(
        envelope=approval,
        public_key=private_key.public_key(),
        mission=mission,
        limits=executor.limits,
        expected_executor=MAVSDK_EXECUTOR_NAME,
        nonce_store=executor.nonce_store,
    )

    assert verified == approval.payload
