from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from math import hypot

from nightjar.models import (
    ActionType,
    GotoAction,
    HoldAction,
    Mission,
    TakeoffAction,
)


class FlightState(str, Enum):
    DISARMED = "disarmed"
    AIRBORNE = "airborne"
    RETURNING = "returning"
    LANDED = "landed"


@dataclass(frozen=True)
class PolicyLimits:
    max_altitude_m: float = 10.0
    max_distance_from_home_m: float = 30.0
    max_hold_seconds: int = 60
    max_mission_actions: int = 10


@dataclass(frozen=True)
class PolicyDecision:
    approved: bool
    reasons: tuple[str, ...]


class PolicyEngine:
    def __init__(self, limits: PolicyLimits | None = None) -> None:
        self.limits = limits or PolicyLimits()

    def evaluate(self, mission: Mission) -> PolicyDecision:
        reasons: list[str] = []
        state = FlightState.DISARMED

        if len(mission.actions) > self.limits.max_mission_actions:
            reasons.append(
                f"Mission has {len(mission.actions)} actions; "
                f"maximum is {self.limits.max_mission_actions}."
            )

        for index, action in enumerate(mission.actions, start=1):
            prefix = f"Action {index} ({action.type})"

            if isinstance(action, TakeoffAction):
                if state is not FlightState.DISARMED:
                    reasons.append(f"{prefix}: takeoff is only allowed from disarmed state.")
                if action.altitude_m > self.limits.max_altitude_m:
                    reasons.append(
                        f"{prefix}: altitude {action.altitude_m} m exceeds "
                        f"{self.limits.max_altitude_m} m."
                    )
                state = FlightState.AIRBORNE

            elif isinstance(action, HoldAction):
                if state is not FlightState.AIRBORNE:
                    reasons.append(f"{prefix}: hold requires airborne state.")
                if action.duration_seconds > self.limits.max_hold_seconds:
                    reasons.append(
                        f"{prefix}: duration {action.duration_seconds} s exceeds "
                        f"{self.limits.max_hold_seconds} s."
                    )

            elif isinstance(action, GotoAction):
                if state is not FlightState.AIRBORNE:
                    reasons.append(f"{prefix}: goto requires airborne state.")
                if action.altitude_m > self.limits.max_altitude_m:
                    reasons.append(
                        f"{prefix}: altitude {action.altitude_m} m exceeds "
                        f"{self.limits.max_altitude_m} m."
                    )
                distance = hypot(action.north_m, action.east_m)
                if distance > self.limits.max_distance_from_home_m:
                    reasons.append(
                        f"{prefix}: distance {distance:.1f} m exceeds "
                        f"{self.limits.max_distance_from_home_m} m."
                    )

            elif action.type is ActionType.RETURN_HOME:
                if state is not FlightState.AIRBORNE:
                    reasons.append(f"{prefix}: return_home requires airborne state.")
                state = FlightState.RETURNING

            elif action.type is ActionType.LAND:
                if state not in {FlightState.AIRBORNE, FlightState.RETURNING}:
                    reasons.append(f"{prefix}: land requires airborne or returning state.")
                state = FlightState.LANDED

            if state in {FlightState.RETURNING, FlightState.LANDED}:
                remaining = mission.actions[index:]
                if remaining:
                    next_types = ", ".join(str(item.type) for item in remaining)
                    if state is FlightState.LANDED:
                        reasons.append(
                            f"{prefix}: no actions are allowed after landing; found {next_types}."
                        )
                    elif any(
                        item.type not in {ActionType.LAND}
                        for item in remaining
                    ):
                        reasons.append(
                            f"{prefix}: only land may follow return_home; found {next_types}."
                        )

        if mission.actions[0].type is not ActionType.TAKEOFF:
            reasons.append("The first action must be takeoff.")

        return PolicyDecision(approved=not reasons, reasons=tuple(dict.fromkeys(reasons)))
