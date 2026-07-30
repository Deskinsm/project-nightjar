# Project Nightjar

A safety-first natural-language mission controller for simulated and physical drones.

> **Constitution:** The LLM may propose actions. Only deterministic code may authorize and execute them.

Nightjar is intentionally split into three layers:

1. **Planner**: converts a user request into a structured mission.
2. **Policy engine**: deterministically approves or rejects every action.
3. **Executor**: sends only approved actions to a simulator or flight-control interface.

The current starter repository implements the mission model, policy engine, audit logging, CLI, and tests. It does **not** arm or control a real vehicle.

## Safety boundary

The LLM must never:

- call MAVSDK or MAVLink directly
- arm a vehicle
- modify autopilot parameters
- alter geofences or failsafes
- execute shell commands
- approve its own output

Human approval remains mandatory before execution.

## Repository map

```text
nightjar/
├── docs/
│   ├── architecture.md
│   ├── compliance-checklist.md
│   ├── safety-policy.md
│   └── threat-model.md
├── missions/
│   ├── example_mission.json
│   └── rejected_mission.json
├── src/nightjar/
│   ├── __init__.py
│   ├── audit.py
│   ├── cli.py
│   ├── executor.py
│   ├── models.py
│   ├── planner.py
│   └── policy.py
├── tests/
│   ├── test_models.py
│   └── test_policy.py
├── logs/
├── .env.example
├── .gitignore
└── pyproject.toml
```

## Requirements

- Python 3.10+
- Git
- PowerShell, Bash, or another terminal

## Start on Windows PowerShell

```powershell
cd nightjar
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
pytest
nightjar validate .\missions\example_mission.json
nightjar run .\missions\example_mission.json --executor dry-run --approval-file .\approval.json --public-key-file .\approver-public.pem
```

## Start on macOS or Linux

```bash
cd nightjar
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
pytest
nightjar validate missions/example_mission.json
nightjar run missions/example_mission.json --executor dry-run --approval-file approval.json --public-key-file approver-public.pem
```

## Current behavior

`nightjar validate` checks:

- mission structure
- approved action types
- altitude, distance, and duration limits
- state transitions
- mission termination
- unsafe or unknown fields

`nightjar run` requires a signed, mission-bound approval envelope. A successfully verified approval is consumed exactly once before execution.

## Next milestone

Replace `DryRunExecutor` with a `MavsdkExecutor` that connects to PX4 Software-in-the-Loop. Keep the policy boundary unchanged.

## Personal records

Do not commit TRUST certificates, registration documents, identification, authentication tokens, API keys, or real flight logs containing sensitive location data. The repository ignores common certificate and private-record paths by default.


## Ubuntu 22.04 prerequisites

```bash
sudo apt update
sudo apt install -y unzip python3-venv python3-pip git build-essential
```

This repository version is compatible with Ubuntu 22.04's default Python 3.10.
