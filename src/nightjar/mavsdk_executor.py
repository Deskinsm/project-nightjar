from __future__ import annotations

import asyncio
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from nightjar.approval import SignedApproval
from nightjar.audit import write_audit_record, write_audit_record_best_effort
from nightjar.authorization import verify_and_consume_approval
from nightjar.executor import ExecutionResult
from nightjar.home import (
    FRAME_ID,
    HomeSnapshot,
    home_sha256,
    snapshot_from_telemetry,
    within_tolerance,
)
from nightjar.models import HoldAction, LandAction, Mission, TakeoffAction
from nightjar.policy import PolicyEngine, PolicyLimits
from nightjar.replay import NonceStore

MAVSDK_EXECUTOR_NAME = "mavsdk"


class MavsdkExecutorError(RuntimeError):
    """Base error for MAVSDK execution failures."""


class MavsdkPolicyRejectedError(MavsdkExecutorError):
    """Raised when a mission fails deterministic Nightjar policy."""


class HomeUnavailableError(MavsdkExecutorError):
    """Raised when a trusted home cannot be obtained from telemetry."""


class HomeMismatchError(MavsdkExecutorError):
    """Raised when the live home differs from the bound home beyond tolerance."""


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

        drone_holder: list[Any] = []

        async def _run() -> ExecutionResult:
            return await self._execute(mission, approval, drone_holder)

        try:
            return asyncio.run(_run())
        finally:
            # Explicitly stop mavsdk_server if the installed SDK exposes it.
            # Do not assume a System.close() method exists. This is best-effort
            # so a cleanup failure cannot replace the mission result.
            for drone in drone_holder:
                stop = getattr(drone, "_stop_mavsdk_server", None)
                if callable(stop):
                    try:
                        stop()
                    except Exception as exc:  # noqa: BLE001
                        # Best-effort: a cleanup failure must not replace the
                        # mission result. Log the type only.
                        print(
                            f"MAVSDK server stop failed: {type(exc).__name__}",
                            file=sys.stderr,
                        )

    async def _execute(
        self,
        mission: Mission,
        approval: SignedApproval,
        drone_holder: list[Any] | None = None,
    ) -> ExecutionResult:
        drone = self.system_factory()
        if drone_holder is not None:
            drone_holder.append(drone)

        # Strict: if Nightjar cannot record that a flight is starting, it must not start.
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

        # Flips to True once takeoff() has been accepted by the vehicle. Before that
        # point an audit failure aborts the mission (fail closed on audit integrity).
        # After it, the vehicle may be airborne and an audit failure must never
        # interrupt flight control. This flag selects strict vs best-effort auditing
        # only; it carries no recovery behavior.
        flight_committed = False
        recovery_required = False
        takeoff_attempted = False

        try:
            await drone.connect(system_address=self.system_address)
            await self._wait_for_connection(drone)

            # Re-verify the bound home before any vehicle command.
            # Nonce is already consumed; a mismatch here burns the approval.
            bound_home = self._bound_home(approval)
            live_home = await self._read_home(drone)
            self._verify_home(bound_home, live_home, phase="pre_arm", mission_id=mission.mission_id)

            for sequence, action in enumerate(mission.actions, start=1):
                self._audit_writer(flight_committed)(
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

                    # Arm may reach the vehicle even if its acknowledgment fails.
                    # recovery_required is set before the arm call so a lost
                    # acknowledgment still enters cleanup.
                    takeoff_attempted = False
                    recovery_required = True
                    await drone.action.arm()

                    # An arm call that does not raise does not prove the vehicle
                    # is armed. Wait for armed telemetry before takeoff.
                    # Missing confirmation enters the existing cleanup path
                    # (takeoff_attempted stays False).
                    await self._wait_until_armed(drone)

                    # PX4 can reset home on arming. Re-read and compare.
                    # If it moved beyond tolerance, do not take off: disarm
                    # through the existing armed-on-ground recovery path.
                    post_arm_home = await self._read_home(drone)
                    self._verify_home(
                        bound_home,
                        post_arm_home,
                        phase="post_arm",
                        mission_id=mission.mission_id,
                    )

                    # Once armed confirmation is observed, takeoff requires
                    # landing recovery.
                    takeoff_attempted = True
                    await drone.action.takeoff()
                    flight_committed = True

                    await self._wait_until_takeoff_altitude(
                        drone,
                        target_altitude_m=action.altitude_m,
                    )

                elif isinstance(action, HoldAction):
                    await self.sleep_function(action.duration_seconds)

                elif isinstance(action, LandAction):
                    await drone.action.land()
                    await self._wait_until_landed(drone)
                    recovery_required = False

                self._audit_writer(flight_committed)(
                    mission_id=mission.mission_id,
                    event="action_completed",
                    details={
                        "sequence": sequence,
                        "action_type": action.type.value,
                        "executor": MAVSDK_EXECUTOR_NAME,
                    },
                    log_directory=self.log_directory,
                )

        except (Exception, asyncio.CancelledError, KeyboardInterrupt) as exc:
            recovery_status = "not_required"
            recovery_error_type = None

            if recovery_required:
                try:
                    recovery_status = await self._recover_protected(
                        drone, takeoff_attempted=takeoff_attempted
                    )
                # Preserve the original mission failure if recovery also fails.
                except (Exception, asyncio.CancelledError) as recovery_exc:  # noqa: BLE001
                    recovery_status = "failed"
                    recovery_error_type = type(recovery_exc).__name__

            # Recovery runs before logging, and its failure does not replace
            # the original mission exception.
            write_audit_record_best_effort(
                mission_id=mission.mission_id,
                event="mission_failed",
                details={
                    "executor": MAVSDK_EXECUTOR_NAME,
                    "error": str(exc),
                    "recovery_status": recovery_status,
                    "recovery_error_type": recovery_error_type,
                },
                log_directory=self.log_directory,
            )
            raise

        # Best-effort: a logging failure after a completed flight must not
        # reinterpret that flight as an execution failure.
        write_audit_record_best_effort(
            mission_id=mission.mission_id,
            event="mission_completed",
            details={"executor": MAVSDK_EXECUTOR_NAME},
            log_directory=self.log_directory,
        )

        return ExecutionResult(completed=True, log_path=log_path)

    @staticmethod
    def _audit_writer(flight_committed: bool) -> Callable[..., Path | None]:
        """Select the audit writer for the current flight phase."""
        return write_audit_record_best_effort if flight_committed else write_audit_record

    async def _recover_protected(self, drone: Any, *, takeoff_attempted: bool) -> str:
        """Finish bounded recovery despite cancellation of the mission task."""
        recovery_task = asyncio.create_task(
            asyncio.wait_for(
                self._recover(drone, takeoff_attempted=takeoff_attempted),
                timeout=self.landing_timeout_seconds,
            )
        )

        while not recovery_task.done():
            try:
                await asyncio.shield(recovery_task)
            except asyncio.CancelledError:
                # Keep the same task and timeout through repeated cancellation.
                continue

        return recovery_task.result()

    async def _recover(self, drone: Any, *, takeoff_attempted: bool) -> str:
        """Choose cleanup from the attempted commands and vehicle telemetry."""
        if not takeoff_attempted:
            async for in_air in drone.telemetry.in_air():
                if in_air is False:
                    await drone.action.disarm()
                    return "disarm_accepted"
                if in_air is True:
                    break
                raise MavsdkExecutorError("Invalid in-air telemetry during arm recovery.")
            else:
                raise MavsdkExecutorError(
                    "In-air telemetry ended before arm recovery could choose cleanup."
                )

        await drone.action.land()
        await self._wait_until_landed(drone)
        return "landing_confirmed"

    def _bound_home(self, approval: SignedApproval) -> HomeSnapshot:
        """Reconstruct the bound home from the signed approval integers."""
        payload = approval.payload
        if payload.frame_id != FRAME_ID:
            raise HomeMismatchError(f"Approval frame {payload.frame_id!r} is not {FRAME_ID!r}.")
        snapshot = snapshot_from_telemetry(
            latitude_deg=payload.home_latitude_e7 / 10_000_000,
            longitude_deg=payload.home_longitude_e7 / 10_000_000,
            absolute_altitude_m=payload.home_altitude_mm / 1_000,
            captured_at="bound",
        )
        if home_sha256(snapshot) != payload.home_sha256:
            raise HomeMismatchError("Approval home_sha256 does not match the signed home integers.")
        return snapshot

    async def _read_home(self, drone: Any) -> HomeSnapshot:
        """Read home from telemetry, gated on health flags. Bounded timeout."""

        async def wait() -> HomeSnapshot:
            health_stream = getattr(drone.telemetry, "health", None)
            home_stream = getattr(drone.telemetry, "home", None)
            if health_stream is None or home_stream is None:
                raise HomeUnavailableError("MAVSDK telemetry does not expose health or home.")
            async for health in health_stream():
                if getattr(health, "is_home_position_ok", False) and getattr(
                    health, "is_global_position_ok", False
                ):
                    break
            else:
                raise HomeUnavailableError("Health stream ended before home was OK.")
            async for home in home_stream():
                return snapshot_from_telemetry(
                    latitude_deg=home.latitude_deg,
                    longitude_deg=home.longitude_deg,
                    absolute_altitude_m=home.absolute_altitude_m,
                )
            raise HomeUnavailableError("Home stream ended before a position arrived.")

        try:
            return await asyncio.wait_for(wait(), timeout=self.connection_timeout_seconds)
        except asyncio.TimeoutError as exc:
            raise HomeUnavailableError(
                f"Timed out waiting {self.connection_timeout_seconds:g} seconds for home."
            ) from exc

    def _verify_home(
        self,
        bound: HomeSnapshot,
        live: HomeSnapshot,
        *,
        phase: str,
        mission_id: Any,
    ) -> None:
        ok = within_tolerance(
            bound,
            live,
            horizontal_m=self.limits.home_horizontal_tolerance_m,
            vertical_m=self.limits.home_vertical_tolerance_m,
        )
        write_audit_record(
            mission_id=mission_id,
            event="home_check",
            details={
                "phase": phase,
                "frame_id": FRAME_ID,
                "home_sha256": home_sha256(bound),
                "within_tolerance": ok,
                "bound": bound.canonical(),
                "live": live.canonical(),
            },
            log_directory=self.log_directory,
        )
        if not ok:
            raise HomeMismatchError(
                f"Home mismatch at {phase}: live home exceeds policy tolerance."
            )

    async def _wait_until_armed(self, drone: Any) -> None:
        """Wait for armed telemetry. An arm call that does not raise is not proof."""

        async def wait() -> None:
            armed_stream = getattr(drone.telemetry, "armed", None)
            if armed_stream is None:
                raise MavsdkExecutorError(
                    "MAVSDK telemetry does not expose armed state; cannot confirm arming."
                )
            async for is_armed in armed_stream():
                if is_armed is True:
                    return
            raise MavsdkExecutorError(
                "MAVSDK armed telemetry ended before the vehicle reported armed."
            )

        try:
            await asyncio.wait_for(wait(), timeout=self.takeoff_timeout_seconds)
        except asyncio.TimeoutError as exc:
            raise MavsdkExecutorError(
                f"Timed out waiting {self.takeoff_timeout_seconds:g} seconds "
                "for armed telemetry after arm()."
            ) from exc

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
