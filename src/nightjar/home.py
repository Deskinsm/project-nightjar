"""Trusted home snapshot and frame binding.

Home is obtained from vehicle telemetry, never from a client. The
canonical form uses integers so the hash is stable across float jitter
and serialization order.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from pydantic import Field

from nightjar.models import StrictModel
from nightjar.security import sha256_hex

FRAME_ID = "home_ned_v1"
SOURCE_TELEMETRY = "telemetry"

# Integer scales matching MAVLink conventions.
LAT_LON_SCALE = 10_000_000  # degrees * 1e7
ALTITUDE_SCALE = 1_000  # meters -> mm


class HomeSnapshot(StrictModel):
    """A home position captured from vehicle telemetry."""

    latitude_deg: float
    longitude_deg: float
    absolute_altitude_m: float
    captured_at: str = Field(min_length=1)
    source: str = Field(default=SOURCE_TELEMETRY)

    @property
    def latitude_e7(self) -> int:
        return round(self.latitude_deg * LAT_LON_SCALE)

    @property
    def longitude_e7(self) -> int:
        return round(self.longitude_deg * LAT_LON_SCALE)

    @property
    def altitude_mm(self) -> int:
        return round(self.absolute_altitude_m * ALTITUDE_SCALE)

    def canonical(self) -> dict[str, int | str]:
        """Integer form used for hashing. Order is fixed by sort_keys."""
        return {
            "altitude_mm": self.altitude_mm,
            "latitude_e7": self.latitude_e7,
            "longitude_e7": self.longitude_e7,
            "source": self.source,
        }


def home_sha256(snapshot: HomeSnapshot) -> str:
    """SHA-256 of the canonical integer form. captured_at is not hashed."""
    return sha256_hex(snapshot.canonical())


def horizontal_distance_m(a: HomeSnapshot, b: HomeSnapshot) -> float:
    """Haversine distance in meters. Accurate enough at the 2 m scale."""
    radius_m = 6_371_000.0
    lat1 = math.radians(a.latitude_deg)
    lat2 = math.radians(b.latitude_deg)
    dlat = lat2 - lat1
    dlon = math.radians(b.longitude_deg - a.longitude_deg)
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * radius_m * math.asin(math.sqrt(h))


def vertical_difference_m(a: HomeSnapshot, b: HomeSnapshot) -> float:
    return abs(a.absolute_altitude_m - b.absolute_altitude_m)


def within_tolerance(
    bound: HomeSnapshot,
    live: HomeSnapshot,
    *,
    horizontal_m: float,
    vertical_m: float,
) -> bool:
    return (
        horizontal_distance_m(bound, live) <= horizontal_m
        and vertical_difference_m(bound, live) <= vertical_m
    )


def snapshot_from_telemetry(
    *,
    latitude_deg: float,
    longitude_deg: float,
    absolute_altitude_m: float,
    captured_at: str | None = None,
) -> HomeSnapshot:
    return HomeSnapshot(
        latitude_deg=latitude_deg,
        longitude_deg=longitude_deg,
        absolute_altitude_m=absolute_altitude_m,
        captured_at=captured_at or datetime.now(timezone.utc).isoformat(),
        source=SOURCE_TELEMETRY,
    )
