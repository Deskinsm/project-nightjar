from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nightjar.approval import SignedApproval
from nightjar.audit import write_audit_record
from nightjar.authorization import verify_and_consume_approval
from nightjar.executor import ExecutionResult
from nightjar.models import HoldAction, LandAction, Mission, TakeoffAction
from nightjar.policy import PolicyEngine, PolicyLimits
from nightjar.replay import NonceStore

MAVSDK_EXECUTOR_NAME = "mavsdk"


class MavsdkExecutorError(RuntimeError):
    """Base error for MAVSDK execution failures."""


class MavsdkPolicyRejectedError(MavsdkExecutorError):
    """Raised when a mission fails deterministic Nightjar policy."""


class UnsupportedMavsdkActionError(MavsdkExecutorError):
    """Raised when a mission contains actions this executor cannot safely translate."""


def _default_system_factory() -> Any:
    try:
        from mavsdk import System
    except ImportError as exc:
        raise MavsdkExecutorError(
            'MAVSDK flight support is not installed. Install Nightjar with the "flight" extra.'
        ) from exc

    return System()


@dataclass(frozen=True)
class MavsdkExecutor:
    """Authorize and execute restricted Nightjar missions against MAVSDK/PX4."""

    public_key: Ed25519PublicKey
    nonce_store: NonceStore
    system_address: str = "udpin://127.0.0.1:14540"
    connection_timeout_seconds: float = 20.0
    takeoff_timeout_seconds: float = 30.0
    takeoff_altitude_tolerance_m: float = 0.5
    landing_timeout_seconds: float = 30.0
    log_directory: Path | None = None
    limits: PolicyLimits = field(default_factory=PolicyLimits)
    system_factory: Callable[[], Any] = _default_system_factory
    sleep_function: Callable[[float], Awaitable[None]] = asyncio.sleep

    def validate_mission(self, mission: Mission) -> None:
        decision = PolicyEngine(self.limits).evaluate(mission)

        if not decision.approved:
            reasons = "; ".join(decision.reasons)
            raise MavsdkPolicyRejectedError(f"Mission rejected by policy: {reasons}")

        unsupported = [
            action.type.value
            for action in mission.actions
            if not isinstance(action, (TakeoffAction, HoldAction, LandAction))
        ]

        if unsupported:
            action_names = ", ".join(dict.fromkeys(unsupported))
            raise UnsupportedMavsdkActionError(
                f"MAVSDK executor does not support these mission actions yet: {action_names}."
            )

    def execute(
        self,
        mission: Mission,
        *,
        approval: SignedApproval,
    ) -> ExecutionResult:
        """Authorize and execute a restricted MAVSDK mission.

        Mission capability and deterministic policy checks occur before approval
        consumption. MAVSDK system creation occurs only after the signed approval
        has been verified and its nonce atomically consumed.
        """
        self.validate_mission(mission)

        verify_and_consume_approval(
            envelope=approval,
            public_key=self.public_key,
            mission=mission,
            limits=self.limits,
            expected_executor=MAVSDK_EXECUTOR_NAME,
            nonce_store=self.nonce_store,
        )

        return asyncio.run(self._execute(mission))

    async def _execute(self, mission: Mission) -> ExecutionResult:
        drone = self.system_factory()

        log_path = write_audit_record(
            mission_id=mission.mission_id,
            event="mission_started",
            details={
                "description": mission.description,
                "executor": MAVSDK_EXECUTOR_NAME,
                "system_address": self.system_address,
            },
            log_directory=self.log_directory,
        )

        try:
            await drone.connect(system_address=self.system_address)
            await self._wait_for_connection(drone)

            for sequence, action in enumerate(mission.actions, start=1):
                write_audit_record(
                    mission_id=mission.mission_id,
                    event="action_started",
                    details={
                        "sequence": sequence,
                        "action": action.model_dump(mode="json"),
                        "executor": MAVSDK_EXECUTOR_NAME,
                    },
                    log_directory=self.log_directory,
                )

                if isinstance(action, TakeoffAction):
                    await drone.action.set_takeoff_altitude(action.altitude_m)
                    await drone.action.arm()
                    await drone.action.takeoff()
                    await self._wait_until_takeoff_altitude(
                        drone,
                        target_altitude_m=action.altitude_m,
                    )

                elif isinstance(action, HoldAction):
                    await self.sleep_function(action.duration_seconds)

                elif isinstance(action, LandAction):
                    await drone.action.land()
                    await self._wait_until_landed(drone)

                write_audit_record(
                    mission_id=mission.mission_id,
                    event="action_completed",
                    details={
                        "sequence": sequence,
                        "action_type": action.type.value,
                        "executor": MAVSDK_EXECUTOR_NAME,
                    },
                    log_directory=self.log_directory,
                )

        except Exception as exc:
            write_audit_record(
                mission_id=mission.mission_id,
                event="mission_failed",
                details={
                    "executor": MAVSDK_EXECUTOR_NAME,
                    "error": str(exc),
                },
                log_directory=self.log_directory,
            )
            raise

        write_audit_record(
            mission_id=mission.mission_id,
            event="mission_completed",
            details={"executor": MAVSDK_EXECUTOR_NAME},
            log_directory=self.log_directory,
        )

        return ExecutionResult(completed=True, log_path=log_path)

    async def _wait_for_connection(self, drone: Any) -> None:
        async def wait() -> None:
            async for state in drone.core.connection_state():
                if state.is_connected:
                    return

            raise MavsdkExecutorError("MAVSDK connection-state stream ended before PX4 connected.")

        try:
            await asyncio.wait_for(
                wait(),
                timeout=self.connection_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise MavsdkExecutorError(
                f"Timed out waiting {self.connection_timeout_seconds:g} seconds for PX4."
            ) from exc

    async def _wait_until_takeoff_altitude(
        self,
        drone: Any,
        target_altitude_m: float,
    ) -> None:
        minimum_altitude_m = max(
            target_altitude_m * 0.9,
            target_altitude_m - self.takeoff_altitude_tolerance_m,
        )

        async def wait() -> None:
            async for position in drone.telemetry.position():
                if position.relative_altitude_m >= minimum_altitude_m:
                    return

            raise MavsdkExecutorError(
                "MAVSDK position telemetry ended before takeoff altitude was reached."
            )

        try:
            await asyncio.wait_for(
                wait(),
                timeout=self.takeoff_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise MavsdkExecutorError(
                f"Timed out waiting {self.takeoff_timeout_seconds:g} seconds "
                f"to reach takeoff altitude {target_altitude_m:g} m."
            ) from exc

    async def _wait_until_landed(self, drone: Any) -> None:
        async def wait() -> None:
            async for is_in_air in drone.telemetry.in_air():
                if not is_in_air:
                    return

            raise MavsdkExecutorError("MAVSDK in-air telemetry ended before landing was confirmed.")

        try:
            await asyncio.wait_for(
                wait(),
                timeout=self.landing_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise MavsdkExecutorError(
                f"Timed out waiting {self.landing_timeout_seconds:g} seconds for landing."
            ) from exc
