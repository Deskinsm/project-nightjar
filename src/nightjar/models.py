from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Reject fields that are not part of the approved mission schema."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class ActionType(str, Enum):
    TAKEOFF = "takeoff"
    HOLD = "hold"
    GOTO = "goto"
    RETURN_HOME = "return_home"
    LAND = "land"


class TakeoffAction(StrictModel):
    type: Literal[ActionType.TAKEOFF]
    altitude_m: float = Field(gt=0)


class HoldAction(StrictModel):
    type: Literal[ActionType.HOLD]
    duration_seconds: int = Field(gt=0)


class GotoAction(StrictModel):
    type: Literal[ActionType.GOTO]
    north_m: float
    east_m: float
    altitude_m: float = Field(gt=0)


class ReturnHomeAction(StrictModel):
    type: Literal[ActionType.RETURN_HOME]


class LandAction(StrictModel):
    type: Literal[ActionType.LAND]


MissionAction = Annotated[
    Union[
        TakeoffAction,
        HoldAction,
        GotoAction,
        ReturnHomeAction,
        LandAction,
    ],
    Field(discriminator="type"),
]


class Mission(StrictModel):
    mission_id: UUID = Field(default_factory=uuid4)
    description: str = Field(min_length=1, max_length=300)
    actions: tuple[MissionAction, ...] = Field(min_length=1, max_length=10)

    @model_validator(mode="after")
    def requires_safe_termination(self) -> "Mission":
        final_type = self.actions[-1].type
        if final_type not in {ActionType.RETURN_HOME, ActionType.LAND}:
            raise ValueError("Mission must end with return_home or land.")
        return self
