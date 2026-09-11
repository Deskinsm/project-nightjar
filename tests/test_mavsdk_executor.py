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
from nightjar.audit import write_audit_record
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

    async def disarm(self) -> None:
        self.calls.append(("disarm", None))

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


# --- Audit failure boundary ----------------------------------------------------
#
# These tests rely on an import-binding detail: mavsdk_executor.py binds
# ``write_audit_record`` at import time, while ``write_audit_record_best_effort``
# resolves ``nightjar.audit.write_audit_record`` at call time. Patching the
# module global in ``nightjar.audit`` therefore fails ONLY the best-effort path,
# leaving the executor's strict pre-flight writes untouched. If the executor's
# import style ever changes, these tests will break loudly rather than silently.


def _mission_takeoff_hold_land() -> Mission:
    return Mission.model_validate(
        {
            "description": "Audit boundary test",
            "actions": [
                {"type": "takeoff", "altitude_m": 5},
                {"type": "hold", "duration_seconds": 1},
                {"type": "land"},
            ],
        }
    )


def test_audit_failure_after_takeoff_does_not_abort_flight(tmp_path, monkeypatch, capsys) -> None:
    mission = _mission_takeoff_hold_land()
    drone = FakeSystem()

    def broken_writer(**kwargs):
        raise OSError("simulated disk full")

    monkeypatch.setattr("nightjar.audit.write_audit_record", broken_writer)

    async def fake_sleep(seconds: float) -> None:
        return None

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        sleep_function=fake_sleep,
        log_directory=tmp_path,
    )

    result = executor.execute(mission, approval=approval)

    # Flight control ran to completion despite every post-commit audit write failing.
    assert result.completed is True
    assert ("takeoff", None) in drone.calls
    assert ("land", None) in drone.calls

    # Strict pre-flight records were written; nothing after the boundary was.
    records = (tmp_path / f"{mission.mission_id}.jsonl").read_text(encoding="utf-8")
    assert '"event": "mission_started"' in records
    assert '"event": "action_started"' in records
    assert '"action_type": "takeoff"' not in records  # takeoff's action_completed is post-boundary
    assert '"event": "mission_completed"' not in records

    # Every lost record was reported through the fallback.
    stderr = capsys.readouterr().err
    assert stderr.count("nightjar-audit-fallback") == 6  # takeoff done, hold x2, land x2, completed
    assert "error_type=OSError" in stderr


def test_audit_failure_before_takeoff_aborts_flight(tmp_path, monkeypatch) -> None:
    mission = _mission_takeoff_hold_land()
    drone = FakeSystem()
    calls = 0

    real_writer = write_audit_record

    def writer_failing_on_takeoff_record(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:  # 1 = mission_started, 2 = TAKEOFF action_started
            raise OSError("simulated audit failure before takeoff")
        return real_writer(**kwargs)

    # Patch the executor's own binding so the STRICT path fails.
    monkeypatch.setattr(
        "nightjar.mavsdk_executor.write_audit_record", writer_failing_on_takeoff_record
    )

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        log_directory=tmp_path,
    )

    with pytest.raises(OSError, match="before takeoff"):
        executor.execute(mission, approval=approval)

    # Connected, but never armed or launched: fail closed on audit integrity.
    assert ("connect", "udpin://127.0.0.1:14540") in drone.calls
    assert ("arm", None) not in drone.calls
    assert ("takeoff", None) not in drone.calls


def test_audit_failure_in_handler_does_not_mask_flight_exception(tmp_path, monkeypatch) -> None:
    mission = _mission_takeoff_hold_land()

    class FailingAction(FakeAction):
        async def arm(self) -> None:
            self.calls.append(("arm", None))
            raise RuntimeError("simulated arm failure")

    drone = FakeSystem()
    drone.action = FailingAction(drone.calls)
    calls = 0
    real_writer = write_audit_record

    def writer_failing_from_third_call(**kwargs):
        nonlocal calls
        calls += 1
        if calls >= 3:  # 1 = mission_started, 2 = TAKEOFF action_started, 3 = mission_failed
            raise OSError("simulated disk full")
        return real_writer(**kwargs)

    # Patch BOTH bindings so the handler's write fails whichever path it takes.
    # Against the pre-fix executor this masks the arm failure with the OSError.
    monkeypatch.setattr(
        "nightjar.mavsdk_executor.write_audit_record", writer_failing_from_third_call
    )
    monkeypatch.setattr("nightjar.audit.write_audit_record", writer_failing_from_third_call)

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        log_directory=tmp_path,
    )

    # The original flight exception must surface, not the audit failure that
    # occurred while trying to record it.
    with pytest.raises(RuntimeError, match="simulated arm failure"):
        executor.execute(mission, approval=approval)

    assert calls == 3


@pytest.mark.parametrize("failure_phase", ["takeoff", "hold"])
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt])
def test_flight_failure_attempts_land_and_preserves_original_error(
    tmp_path, failure_phase, error_type
) -> None:
    mission = _mission_takeoff_hold_land()
    original_error = error_type(f"simulated {failure_phase} failure")

    class RecoveryTestAction(FakeAction):
        async def takeoff(self) -> None:
            await super().takeoff()
            if failure_phase == "takeoff":
                raise original_error

    drone = FakeSystem()
    drone.action = RecoveryTestAction(drone.calls)
    hold_calls = []

    async def failing_hold(seconds: float) -> None:
        hold_calls.append(seconds)
        raise original_error

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        sleep_function=failing_hold,
        log_directory=tmp_path,
    )

    with pytest.raises(error_type) as caught:
        executor.execute(mission, approval=approval)

    assert caught.value is original_error
    assert hold_calls == ([] if failure_phase == "takeoff" else [1])
    assert drone.calls.count(("land", None)) == 1
    assert drone.calls[-1] == ("land", None)


def test_recovery_land_failure_preserves_original_error(tmp_path) -> None:
    import json

    mission = _mission_takeoff_hold_land()
    original_error = RuntimeError("simulated hold failure")

    class FailedRecoveryAction(FakeAction):
        async def land(self) -> None:
            await super().land()
            raise OSError("simulated recovery land failure")

    drone = FakeSystem()
    drone.action = FailedRecoveryAction(drone.calls)

    async def failing_hold(seconds: float) -> None:
        raise original_error

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        sleep_function=failing_hold,
        log_directory=tmp_path,
    )

    with pytest.raises(RuntimeError) as caught:
        executor.execute(mission, approval=approval)

    assert caught.value is original_error
    assert drone.calls.count(("land", None)) == 1

    records = [
        json.loads(line)
        for line in (tmp_path / f"{mission.mission_id}.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    failures = [record for record in records if record["event"] == "mission_failed"]
    assert len(failures) == 1
    assert failures[0]["details"]["error"] == str(original_error)
    assert failures[0]["details"]["recovery_status"] == "failed"
    assert failures[0]["details"]["recovery_error_type"] == "OSError"
    assert not any(record["event"] == "mission_completed" for record in records)


@pytest.mark.parametrize("stall_phase", ["command", "telemetry"])
def test_recovery_timeout_preserves_original_error(tmp_path, stall_phase) -> None:
    import json

    mission = _mission_takeoff_hold_land()
    original_error = RuntimeError("simulated hold failure")
    stalled_operations = []
    cancelled_operations = []

    async def stall() -> None:
        stalled_operations.append(stall_phase)
        try:
            await asyncio.Event().wait()
        finally:
            cancelled_operations.append(stall_phase)

    class StalledRecoveryAction(FakeAction):
        async def land(self) -> None:
            await super().land()
            if stall_phase == "command":
                await stall()

    class StalledRecoveryTelemetry(FakeTelemetry):
        async def in_air(self):
            yield True
            await stall()

    drone = FakeSystem()
    drone.action = StalledRecoveryAction(drone.calls)
    drone.telemetry = StalledRecoveryTelemetry()

    async def failing_hold(seconds: float) -> None:
        raise original_error

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        sleep_function=failing_hold,
        log_directory=tmp_path,
        landing_timeout_seconds=0.05,
    )

    with pytest.raises(RuntimeError) as caught:
        executor.execute(mission, approval=approval)

    assert caught.value is original_error
    assert drone.calls.count(("land", None)) == 1
    assert stalled_operations == [stall_phase]
    assert cancelled_operations == [stall_phase]

    records = [
        json.loads(line)
        for line in (tmp_path / f"{mission.mission_id}.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    failures = [record for record in records if record["event"] == "mission_failed"]
    assert len(failures) == 1
    assert failures[0]["details"]["recovery_status"] == "failed"
    assert failures[0]["details"]["recovery_error_type"] == "TimeoutError"
    assert not any(record["event"] == "mission_completed" for record in records)


def test_cancellation_during_hold_attempts_land_then_propagates(tmp_path) -> None:
    mission = _mission_takeoff_hold_land()
    drone = FakeSystem()
    cancellations = []

    async def cancelled_hold(seconds: float) -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel("simulated operator cancellation")
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError as exc:
            cancellations.append(exc)
            raise

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        sleep_function=cancelled_hold,
        log_directory=tmp_path,
    )

    with pytest.raises(asyncio.CancelledError) as caught:
        executor.execute(mission, approval=approval)

    assert len(cancellations) == 1
    assert caught.value is cancellations[0]
    assert drone.calls.count(("land", None)) == 1
    assert drone.calls[-1] == ("land", None)


def test_second_cancellation_does_not_abandon_recovery(tmp_path) -> None:
    mission = _mission_takeoff_hold_land()
    drone = FakeSystem()
    mission_tasks = []
    original_cancellations = []
    landing_completed = []

    async def cancelled_hold(seconds: float) -> None:
        task = asyncio.current_task()
        assert task is not None
        mission_tasks.append(task)
        task.cancel("first cancellation")
        try:
            await asyncio.sleep(0)
        except asyncio.CancelledError as exc:
            original_cancellations.append(exc)
            raise

    class InterruptedRecoveryAction(FakeAction):
        async def land(self) -> None:
            await super().land()
            mission_tasks[0].cancel("second cancellation")
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            landing_completed.append(True)

    drone.action = InterruptedRecoveryAction(drone.calls)

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        sleep_function=cancelled_hold,
        log_directory=tmp_path,
    )

    with pytest.raises(asyncio.CancelledError) as caught:
        executor.execute(mission, approval=approval)

    assert len(original_cancellations) == 1
    assert caught.value is original_cancellations[0]
    assert landing_completed == [True]
    assert drone.calls.count(("land", None)) == 1


@pytest.mark.parametrize("in_air", [False, True])
def test_arm_failure_recovers_according_to_telemetry(tmp_path, in_air) -> None:
    mission = _mission_takeoff_hold_land()
    original_error = RuntimeError("arm acknowledgment lost")
    telemetry_observations = []

    class ArmFailureAction(FakeAction):
        async def arm(self) -> None:
            await super().arm()
            raise original_error

        async def disarm(self) -> None:
            assert telemetry_observations == [False]
            self.calls.append(("disarm", None))

    class RecoveryTelemetry(FakeTelemetry):
        async def in_air(self):
            # After a landing request, report touchdown.
            observed = in_air and ("land", None) not in drone.calls
            telemetry_observations.append(observed)
            yield observed

    drone = FakeSystem()
    drone.action = ArmFailureAction(drone.calls)
    drone.telemetry = RecoveryTelemetry()

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        log_directory=tmp_path,
    )

    with pytest.raises(RuntimeError) as caught:
        executor.execute(mission, approval=approval)

    assert caught.value is original_error
    assert ("takeoff", None) not in drone.calls

    if in_air:
        assert drone.calls.count(("land", None)) == 1
        assert ("disarm", None) not in drone.calls
        assert telemetry_observations == [True, False]
    else:
        assert drone.calls.count(("disarm", None)) == 1
        assert ("land", None) not in drone.calls
        assert telemetry_observations == [False]


@pytest.mark.parametrize("telemetry_failure", ["empty", "invalid", "error", "stall"])
def test_arm_recovery_without_valid_telemetry_never_disarms(tmp_path, telemetry_failure) -> None:
    import json

    mission = _mission_takeoff_hold_land()
    original_error = RuntimeError("arm acknowledgment lost")

    class ArmFailureAction(FakeAction):
        async def arm(self) -> None:
            await super().arm()
            raise original_error

    class UnavailableTelemetry(FakeTelemetry):
        async def in_air(self):
            if telemetry_failure == "invalid":
                yield None
            elif telemetry_failure == "error":
                raise OSError("telemetry unavailable")
            elif telemetry_failure == "stall":
                await asyncio.Event().wait()

    drone = FakeSystem()
    drone.action = ArmFailureAction(drone.calls)
    drone.telemetry = UnavailableTelemetry()

    private_key = Ed25519PrivateKey.generate()
    approval = build_approval(private_key=private_key, mission=mission)
    executor = build_executor(
        private_key=private_key,
        tmp_path=tmp_path,
        system_factory=lambda: drone,
        log_directory=tmp_path,
        landing_timeout_seconds=0.05,
    )

    with pytest.raises(RuntimeError) as caught:
        executor.execute(mission, approval=approval)

    assert caught.value is original_error
    assert ("takeoff", None) not in drone.calls
    assert ("disarm", None) not in drone.calls
    assert ("land", None) not in drone.calls

    records = [
        json.loads(line)
        for line in (tmp_path / f"{mission.mission_id}.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    failures = [record for record in records if record["event"] == "mission_failed"]
    assert len(failures) == 1
    assert failures[0]["details"]["recovery_status"] == "failed"
    expected_error = {
        "empty": "MavsdkExecutorError",
        "invalid": "MavsdkExecutorError",
        "error": "OSError",
        "stall": "TimeoutError",
    }
    assert failures[0]["details"]["recovery_error_type"] == expected_error[telemetry_failure]
    assert not any(record["event"] == "mission_completed" for record in records)
