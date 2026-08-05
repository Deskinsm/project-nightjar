# Project Nightjar

[![CI](https://github.com/Deskinsm/project-nightjar/actions/workflows/ci.yml/badge.svg)](https://github.com/Deskinsm/project-nightjar/actions/workflows/ci.yml)

A safety-first architecture for AI-assisted drone mission planning and execution.

> **Constitution:** An intelligent planner may propose actions. Only deterministic policy and cryptographic human authorization may permit execution.

Nightjar is intentionally divided into four trust layers:

1. **Planner**: proposes a structured mission and is treated as untrusted.
2. **Schema and policy**: validate the mission and enforce deterministic safety limits.
3. **Authorization**: verifies a mission-bound Ed25519 approval and atomically consumes its nonce.
4. **Executor**: receives only validated, policy-approved, explicitly authorized missions.

The current repository supports signed dry-run execution and a separate PX4/MAVSDK simulation smoke test. It does **not** control a physical aircraft.

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

See `REPOSITORY_TREE.txt` for the complete file listing.

Key security components:

- `src/nightjar/security.py`: canonical mission and policy hashing
- `src/nightjar/approval.py`: Ed25519 approval envelopes
- `src/nightjar/authorization.py`: verification and one-time consumption
- `src/nightjar/replay.py`: atomic SQLite replay protection
- `src/nightjar/cli.py`: fail-closed signed dry-run execution

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

## Current behavior

`nightjar validate` checks mission structure, supported actions, policy limits, state transitions, mission termination, and unknown fields.

`nightjar run` requires a signed, mission-bound approval envelope. The approval binds the mission hash, policy hash, executor, validity window, and nonce. A successfully verified approval is consumed exactly once before dry-run execution.

The repository does not include a private signing key or reusable approval envelope. Tests generate ephemeral Ed25519 keys in temporary directories.

See `docs/project-record.md` for the full architecture, verified milestones, and known limitations.

## Next milestone

Add aggregate mission budgets so individually permitted actions cannot combine into an excessive total mission.

## Personal records

Do not commit TRUST certificates, registration documents, identification, authentication tokens, API keys, or real flight logs containing sensitive location data. The repository ignores common certificate and private-record paths by default.


## Ubuntu 22.04 prerequisites

```bash
sudo apt update
sudo apt install -y unzip python3-venv python3-pip git build-essential
```

This repository version is compatible with Ubuntu 22.04's default Python 3.10.
