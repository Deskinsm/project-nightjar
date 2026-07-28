# Safety Policy v0.1

## Default limits

| Control | Limit |
|---|---:|
| Maximum altitude | 10 m |
| Maximum horizontal distance from home | 30 m |
| Maximum hold duration | 60 s |
| Maximum actions per mission | 10 |

These are conservative development limits, not statements of legal operating limits.

## Required controls

- Explicit human approval before execution
- Deterministic validation of every mission
- Strict rejection of unknown fields
- Valid state transitions
- Safe mission termination
- Independent autopilot failsafes
- Manual RC override before physical testing
- Audit logging of planning, policy, approval, commands, and outcomes

## Prohibited capabilities

- LLM access to MAVSDK or MAVLink
- LLM access to a shell
- In-flight modification of safety limits
- Modification of flight-controller parameters
- Automatic arming
- Autonomous disabling of return-to-home, geofence, or battery failsafes
