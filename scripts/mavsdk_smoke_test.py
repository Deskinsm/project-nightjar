import asyncio

from mavsdk import System
from mavsdk.action import ActionError


async def wait_for_connection(drone: System) -> None:
    print("Waiting for PX4...")

    async for state in drone.core.connection_state():
        if state.is_connected:
            print("Connected to PX4.")
            return


async def wait_until_landed(drone: System) -> None:
    async for is_in_air in drone.telemetry.in_air():
        if not is_in_air:
            print("Landing confirmed.")
            return


async def main() -> None:
    drone = System()

    await drone.connect(
        system_address="udpin://0.0.0.0:14540"
    )

    try:
        await asyncio.wait_for(
            wait_for_connection(drone),
            timeout=20,
        )

        print("Arming...")
        await drone.action.arm()

        print("Taking off...")
        await drone.action.takeoff()

        print("Holding for 10 seconds...")
        await asyncio.sleep(10)

        print("Landing...")
        await drone.action.land()

        await asyncio.wait_for(
            wait_until_landed(drone),
            timeout=30,
        )

        print("MAVSDK flight completed successfully.")

    except asyncio.TimeoutError:
        print("Timed out waiting for PX4 or landing confirmation.")
        raise SystemExit(1)

    except ActionError as exc:
        print(f"PX4 rejected an action: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
