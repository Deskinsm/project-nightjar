# Project Nightjar

[![CI](https://github.com/Deskinsm/project-nightjar/actions/workflows/ci.yml/badge.svg)](https://github.com/Deskinsm/project-nightjar/actions/workflows/ci.yml)

A safety-first architecture for AI-assisted drone mission planning and execution.

> **Constitution:** An intelligent planner may propose actions. Only deterministic policy and cryptographic human authorization may permit execution.

Nightjar is intentionally divided into four trust layers:

1. **Planner**: proposes a structured mission and is treated as untrusted.
2. **Schema and policy**: validate the mission and enforce deterministic safety limits.
3. **Authorization**: verifies a mission-bound Ed25519 approval and atomically consumes its nonce.
4. **Executor**: receives only validated and policy-approved missions through narrowly defined execution boundaries. Signed execution paths additionally require explicit cryptographic authorization.

The current repository contains two execution paths that share the same authorization boundary:

- **Signed dry-run path:** deterministic policy, mission-bound Ed25519 authorization, replay protection, and dry-run execution.
- **Restricted PX4 simulation path:** the same signed authorization and policy checks, followed by a constrained MAVSDK executor supporting takeoff, hold, and land. Approval consumption occurs inside the executor so unsupported actions are rejected before the nonce is spent.

Nightjar remains a research and simulation project. It has **not** controlled a physical aircraft.

## Safety boundary

The planner must never directly:

- call MAVSDK or MAVLink
- arm a vehicle
- modify autopilot parameters
- alter geofences or failsafes
- execute shell commands
- approve its own output

Human approval remains mandatory before execution.

## Repository map


Key security and execution components:

- `src/nightjar/models.py`: strict typed mission schema
- `src/nightjar/policy.py`: deterministic per-action and aggregate mission limits
- `src/nightjar/security.py`: canonical mission and policy hashing
- `src/nightjar/approval.py`: Ed25519 approval envelopes
- `src/nightjar/authorization.py`: verification and one-time consumption
- `src/nightjar/replay.py`: atomic SQLite replay protection
- `src/nightjar/cli.py`: fail-closed signed dry-run execution
- `src/nightjar/mavsdk_executor.py`: restricted PX4/MAVSDK simulation executor

## Requirements

- Python 3.10+
- Git
- PowerShell, Bash, or another terminal

## Start on Windows PowerShell

```powershell
git clone https://github.com/Deskinsm/project-nightjar.git
cd project-nightjar
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
pytest
nightjar validate .\missions\example_mission.json
```

## Start on macOS or Linux

```bash
git clone https://github.com/Deskinsm/project-nightjar.git
cd project-nightjar
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
pytest
nightjar validate missions/example_mission.json
```
### Optional PX4/MAVSDK simulation support

MAVSDK is intentionally kept outside the core dependency set.

Install the optional flight dependencies with:

```bash
pip install -e ".[dev,flight]"
```

The restricted MAVSDK executor currently supports only `takeoff`, `hold`, and `land`. `goto` and `return_home` are rejected until their coordinate and behavioral semantics are implemented explicitly.


## Current behavior

`nightjar validate` checks mission structure, supported actions, per-action limits, aggregate mission budgets, state transitions, mission termination, and unknown fields.

Aggregate policy controls include total hold time, total horizontal travel, total `goto` actions, and total mission action count.

`nightjar run` requires a signed, mission-bound approval envelope. The approval binds the mission hash, policy hash, executor, validity window, and nonce. A successfully verified approval is consumed exactly once.

Supported executors:

- `dry-run`: verifies and consumes the approval, then simulates the mission without contacting a vehicle.
- `mavsdk`: passes the approval, trusted public key, nonce store, and policy limits into the restricted `MavsdkExecutor`. Capability and policy checks occur before the nonce is consumed. The default endpoint is the loopback PX4 simulation address (`udpin://127.0.0.1:14540`).

A restricted simulation mission containing only takeoff, hold, and land is provided at `missions/mavsdk_simulation_mission.json`. The existing `example_mission.json` includes `return_home`, which the MAVSDK executor rejects.

The restricted `MavsdkExecutor`:

- runs deterministic policy validation before MAVSDK system creation
- rejects unsupported actions (including `goto` and `return_home`) before connecting to PX4 and before consuming the approval
- supports takeoff, hold, and land
- waits for relative-altitude telemetry before completing takeoff
- waits for landing telemetry before completing land
- records mission and action lifecycle events in the audit log
- performs telemetry-based recovery on failure after arming

Approval consumption for the MAVSDK path happens inside the executor before any connection or flight attempt. If the connection or flight later fails, the approval has already been consumed even though the CLI only prints “Signed approval verified and consumed.” after a successful completion. A failed run (exit code 5) still spends the nonce; retries require a fresh signed approval.

The signed CLI path and the restricted MAVSDK executor are now connected for this limited simulation surface.

The repository does not include a private signing key or reusable approval envelope. Tests generate ephemeral Ed25519 keys in temporary directories.

See `docs/project-record.md` for the full architecture, verified milestones, and known limitations.

## Next milestone

Validate the signed CLI path against a live PX4 software simulation, record successful completion and replay rejection, and exercise at least one recoverable failure scenario. That evidence is required before treating the authorized simulation path as a shippable v1.

The intended demonstrated path is:

```text
mission
→ deterministic policy
→ mission-bound signed approval
→ signature / expiration / executor verification
→ atomic replay protection
→ restricted MAVSDK executor
→ PX4 software simulation
```

Executable `goto`, `return_home`, ATAK execution, distributed replay protection, and physical-flight readiness remain outside the current simulation v1 boundary.

## Personal records

Do not commit TRUST certificates, registration documents, identification, authentication tokens, API keys, or real flight logs containing sensitive location data. The repository ignores common certificate and private-record paths by default.


## Ubuntu 22.04 prerequisites

```bash
sudo apt update
sudo apt install -y unzip python3-venv python3-pip git build-essential
```

This repository version is compatible with Ubuntu 22.04's default Python 3.10.
