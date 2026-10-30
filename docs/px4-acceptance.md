# PX4 acceptance procedure

The Phase 1 acceptance evidence was produced on commit `52d6a14` by `scripts/px4_acceptance_harness.py` against PX4 SIH (`sihsim_quadx`).

## What the harness proves

| Scenario | Required evidence |
|---|---|
| Signed mission | Exit 0, success message, `mission_completed` audit |
| Replay rejection | Exit 4, already-used rejection, no audit (supporting evidence; system-creation proof is in the regression tests) |
| Controlled failure | Exit 5, injected hold error visible, `recovery_status == "landing_confirmed"`, no recovery error |

The controlled-failure scenario uses `scripts/acceptance_failure_adapter.py`, not `nightjar run`. It constructs a normal `MavsdkExecutor` with a sleep function that raises during hold.

## Simulator reset requirement

Acceptance uses a fresh PX4 boot before the recovery scenario. Back-to-back flights on the same SIH instance are not claimed for this release. An explicit, reproducible reset between the success flight and the recovery scenario is the supported isolation measure.

Set `NIGHTJAR_PX4_RESTART_CMD` to a command that stops the current PX4 and starts a new, armable instance on `udpin://127.0.0.1:14540` before the harness continues. The harness records the command and its output in `px4_restart.txt` inside the evidence bundle.

### Timing note from the 52d6a14 run

The restart stopped the first simulator after it had logged landing detection and after Nightjar had written `mission_completed`, but before that simulator logged “Disarmed by landing.” This does not affect the stated landing-confirmed result for either scenario. Do not claim that both flights demonstrated disarming. The recovery scenario’s PX4 log did show “Disarmed by landing.”

## Restart procedure used for the 52d6a14 evidence

The following scripts were used on the acceptance machine. They are preserved here so the procedure can be reproduced. Paths are environment-specific.

`px4_restart.sh`:

```bash
#!/usr/bin/env bash
# Restart PX4 SIH (sihsim_quadx, headless) and wait until it is armable on udpin://127.0.0.1:14540.
set -u
B=/workspace/PX4-Autopilot/build/px4_sitl_sih
PX4_BIN="$B/bin/px4"
LOG=/workspace/px4_sih_restart.log
PY=/workspace/project-nightjar/.venv/bin/python
READY_LOG=/workspace/px4_restart_ready.log

echo "[restart] $(date '+%F %T %Z') old px4 pids: $(pgrep -x px4 | tr '\n' ' ')"
pkill -x px4 || true
for i in $(seq 1 20); do pgrep -x px4 >/dev/null || break; sleep 0.5; done
if pgrep -x px4 >/dev/null; then echo "[restart] SIGKILL lingering px4"; pkill -9 -x px4 || true; sleep 1; fi
pgrep -x px4 >/dev/null && { echo "[restart] px4 still running, abort"; exit 2; }

cd "$B/rootfs" || exit 3
# Fully detach: own session, no inherited stdio (the harness captures our pipes).
PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim setsid nohup "$PX4_BIN" -d "$B/etc" \
  > "$LOG" 2>&1 < /dev/null &
NEWPID=$!
echo "[restart] started px4 pid $NEWPID, log $LOG"

# Active readiness wait (mavsdk_server stopped by the checker; its output goes to a file).
"$PY" /workspace/px4_ready_check.py 90 50081 > "$READY_LOG" 2>&1 < /dev/null
RC=$?
tail -n 3 "$READY_LOG"
pkill -f "mavsdk_server -p 50081" 2>/dev/null || true
if [ $RC -ne 0 ]; then echo "[restart] PX4 not ready (rc=$RC)"; exit 1; fi
echo "[restart] $(date '+%F %T %Z') PX4 ready, pid $(pgrep -x px4 | tr '\n' ' ')"
exit 0
```

`px4_ready_check.py`:

```python
"""Wait until PX4 on udpin://127.0.0.1:14540 is armable, global pos OK, not in LAND."""

import asyncio, sys, time
from mavsdk import System
from mavsdk.telemetry import FlightMode

TIMEOUT = float(sys.argv[1]) if len(sys.argv) > 1 else 90.0
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 50081


async def check(d):
    await d.connect(system_address="udpin://127.0.0.1:14540")
    async for s in d.core.connection_state():
        if s.is_connected:
            print("connected", flush=True)
            break
    while True:
        async for h in d.telemetry.health():
            break
        async for m in d.telemetry.flight_mode():
            break
        async for a in d.telemetry.armed():
            break
        print(
            f"armable={h.is_armable} global_ok={h.is_global_position_ok} mode={m} armed={a}",
            flush=True,
        )
        if h.is_armable and h.is_global_position_ok and m != FlightMode.LAND and not a:
            return
        await asyncio.sleep(2)


async def main():
    d = System(port=PORT)
    try:
        await asyncio.wait_for(check(d), timeout=TIMEOUT)
        print("READY", flush=True)
        return 0
    except asyncio.TimeoutError:
        print(f"NOT READY after {TIMEOUT:g}s", flush=True)
        return 1
    finally:
        try:
            d._stop_mavsdk_server()
        except Exception as e:
            print("stop failed", type(e).__name__)


sys.exit(asyncio.run(main()))
```

The readiness check calls the private `_stop_mavsdk_server()` method and the shell script also runs a `pkill` as a backup. A MAVSDK upgrade could change that private method.

## Evidence from the 52d6a14 run

- Overall: PASS
- Signed mission: PASS — signed mission completed with audit confirmation
- Replay rejection: PASS — replay rejected with already-used; no audit written
- Controlled failure: PASS — injected failure recovered with landing_confirmed
- Git SHA: `52d6a14e29045b45bff6db80e6d8b32eb07ae104`
- Bundle path on the acceptance machine: `/workspace/project-nightjar/evidence/px4-acceptance-20261030T194406Z`
- CI for that commit: success
