# Threat Model

## Assets

- Vehicle control
- Flight safety
- Operator identity and credentials
- API credentials
- Telemetry and location data
- Mission integrity
- Audit-log integrity

## Initial threats

1. Prompt injection changes mission intent.
2. Malformed planner output bypasses validation.
3. Unknown action fields smuggle executable instructions.
4. A compromised companion computer sends unauthorized MAVLink commands.
5. Telemetry loss causes stale decisions.
6. GPS spoofing or degradation corrupts navigation.
7. Replay of a previously approved mission causes unauthorized movement.
8. Camera-visible text manipulates a vision-language model.
9. Secrets or precise locations leak into logs.
10. A model attempts to modify the policy governing its own output.

## Initial mitigations

- Treat all model output as untrusted data.
- Use discriminated, strict schemas.
- Keep limits outside prompts and model-controlled storage.
- Require approval for each mission.
- Bind approvals to mission hashes in a future version.
- Use authenticated communication where supported.
- Prefer fail-closed behavior.
- Redact credentials and sensitive location data.
- Keep physical RC override and autopilot failsafes independent.
