# Project Nightjar Record

## Project Mission

Project Nightjar explores a safety-first architecture for AI-assisted drone mission planning and execution.

The central design principle is:

> An intelligent planner may propose actions, but deterministic policy and cryptographic human authorization decide what may reach an executor.

Nightjar is currently a research and simulation project. It is not production flight software and has not been tested on a physical aircraft.

## Safety Architecture

Nightjar’s execution path is:

1. Human instruction
2. LLM or other untrusted planner
3. Strict mission schema
4. Deterministic policy engine
5. Mission and policy hashing
6. Signed human approval
7. Signature, expiration, executor, and replay verification
8. Executor
9. PX4 through MAVSDK or MAVLink

The planner is treated as untrusted input.

The planner does not receive direct access to:

- Motors or flight-control commands
- MAVSDK or MAVLink
- The operating-system shell
- Policy configuration
- Approval-signing keys

## Threat Model

Nightjar is designed to reduce risks arising from:

- Invalid or malformed mission plans
- Planner hallucinations
- Missions exceeding configured safety limits
- Unauthorized executor selection
- Approval reuse or replay
- Mission modification after approval
- Policy modification after approval
- Expired approvals
- Untrusted signing keys
- Unnecessary network exposure

The current architecture does not claim to defend against a fully compromised executor host, compromised signing authority, malicious PX4 firmware, or physical attacks against flight hardware.

## Implemented Guarantees

### Strict Mission Schema

Mission files are validated with strict Pydantic models before policy evaluation or execution.

Supported actions currently include:

- Takeoff
- Hold
- Navigate to a location
- Return home
- Land

### Deterministic Policy Enforcement

Mission plans are evaluated by deterministic policy code rather than by the language model.

Current policy controls include:

- Maximum altitude
- Maximum distance from home
- Maximum hold duration
- Maximum action count
- Valid action ordering

A rejected policy decision prevents execution.

### Canonical Hashing

Mission and policy objects are serialized canonically and hashed with SHA-256.

An approval therefore binds to one exact mission and one exact policy configuration. Changing either invalidates the approval.

### Ed25519 Approval Signatures

Signed approval payloads contain:

- Mission SHA-256
- Policy SHA-256
- Authorized executor
- Issuance time
- Expiration time
- One-time nonce

The executor requires only the public verification key. The private signing key can remain outside the executor trust domain.

### Executor Binding

An approval authorizes one named executor.

An approval created for the dry-run executor cannot authorize a different executor.

### Approval Expiration

Expired approvals, approvals issued too far in the future, and approvals with excessive lifetimes are rejected.

### One-Time Approval Consumption

Approval nonces are stored in SQLite using a unique primary-key constraint.

The database insertion acts as an atomic replay check. An approval can succeed once and is rejected on subsequent attempts by processes sharing the same nonce database.

### Loopback-Only MAVSDK Connection

The MAVSDK smoke test connects through 127.0.0.1 rather than listening on every network interface.

## Verified Milestones

### Mission Validation

- Valid missions pass schema and policy checks.
- Unsafe missions are rejected before execution.
- A test mission requesting excessive distance was successfully blocked.

### PX4 Simulation

Manual simulator commands successfully:

- Armed the vehicle
- Took off
- Held altitude
- Landed
- Disarmed

### Python MAVSDK Flight

A Python MAVSDK smoke test successfully:

- Connected to PX4
- Armed
- Took off
- Held for ten seconds
- Landed
- Confirmed landing

### Cryptographic Authorization

Automated tests verify rejection of:

- Modified missions
- Modified policies
- Incorrect executors
- Expired approvals
- Invalid signatures
- Malformed signatures

### Replay Protection

A live CLI test demonstrated:

1. A signed approval was verified and consumed.
2. The authorized dry-run executed.
3. Reusing the identical approval was rejected.
4. The replay attempt returned exit code 4.

## Current Development Snapshot

Current branch:

`feature/security-foundation`

Latest milestone commit:

`ff8cbc4 Enforce signed approvals in CLI`

Current automated test count:

`24 passing tests`

Primary milestone commits:

- `ff8cbc4 Enforce signed approvals in CLI`
- `391e5d7 Add one-time signed approval enforcement`
- `29637e8 Add signed approval envelope verification`
- `1dfa2a7 Bind MAVSDK smoke test to loopback`
- `7feebb2 Add canonical mission and policy hashing`
- `2df21c0 Complete PX4 MAVSDK smoke flight`

## Security Decisions

### Why the Planner Cannot Invoke MAVSDK Directly

A language model is probabilistic and may produce malformed, unsafe, ambiguous, or adversarial output.

Nightjar treats planner output as a proposal rather than a command. Only validated missions that pass deterministic policy and cryptographic authorization may reach an executor.

### Why Ed25519 Is Used Instead of HMAC

HMAC requires the approval issuer and executor to share the same secret.

Ed25519 separates those roles:

- The approval authority holds the private signing key.
- The executor holds only the public verification key.

Compromise of the executor does not automatically grant the ability to mint approvals.

### Why SQLite Is Used for Replay Protection

A read-then-write text ledger can contain a time-of-check-to-time-of-use race.

SQLite provides an atomic uniqueness constraint on the nonce, making the insertion itself the replay decision.

### Why Authorization Occurs Inside Nightjar Run

Verification and nonce consumption are part of the execution boundary.

Execution may begin only after the signed approval has been verified and atomically consumed.

## Known Limitations

- Replay protection currently applies only to processes sharing the same SQLite database.
- The nonce database is not replicated across executor hosts.
- Audit records are append-only JSONL but are not cryptographically chained or externally anchored.
- Audit-log availability is not yet separated from recovery behavior.
- Aggregate mission budgets have not yet been implemented.
- Individually safe actions could combine into an excessive total mission.
- The primary CLI currently authorizes only the dry-run executor.
- The MAVSDK smoke test is separate from the signed CLI execution path.
- No production key-management or key-rotation process exists.
- Testing has used PX4 software simulation.
- No hardware-in-the-loop testing has occurred.
- No physical aircraft has been controlled by Nightjar.
- The architecture does not protect against a fully compromised executor operating system.

## Development Roadmap

Near-term work:

1. Add aggregate mission budgets.
2. Separate structural schema limits from operational policy limits.
3. Define recovery behavior independent of audit writes.
4. Introduce an audit-sink abstraction.
5. Add chained audit records and external anchoring.
6. Implement a policy-controlled MAVSDK executor.
7. Connect signed approvals to simulated MAVSDK execution.
8. Define signing-key custody and rotation.
9. Add hardware-in-the-loop testing.

Potential later work:

- Multiple trusted approvers
- Public-key identifiers and rotation
- Executor configuration hashing
- Distributed replay protection
- Geofencing
- Vehicle identity binding
- Mission approval interfaces
- LLM planner integration
- Security telemetry and incident-response hooks

## Publication Review

Completed:

- [x] Git author metadata reviewed across all commits
- [x] Personal email excluded through GitHub noreply addressing
- [x] Sensitive filenames reviewed across repository history
- [x] Common secret patterns reviewed across repository history
- [x] No committed private or serialized signing keys found
- [x] No committed nonce databases or generated audit logs found
- [x] Infrastructure identifiers reviewed
- [x] No Git remote currently configured
- [x] Test suite passing
- [x] Ruff linting passing
- [x] Formatting checks passing

Remaining:

- [ ] Review and strengthen `.gitignore`
- [ ] Add a license
- [ ] Add `SECURITY.md`
- [ ] Add continuous-integration checks
- [ ] Perform a clean-clone installation test
- [ ] Review README claims against implemented behavior
- [ ] Merge the security-foundation branch
- [ ] Tag the first public release

## Proposed First Release

`v0.1.0: Secure Simulation Foundation`

This release would document a simulator-first architecture with deterministic policy enforcement, signed approvals, executor binding, expiration checks, and atomic replay protection.

It would not claim production readiness, physical-flight validation, or complete protection against host compromise.
