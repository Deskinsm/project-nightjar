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
- Maximum per-action hold duration
- Maximum mission action count
- Maximum aggregate hold time
- Maximum aggregate horizontal travel
- Maximum total `goto` actions
- Valid action ordering and termination

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

### Restricted MAVSDK Executor

Nightjar includes a restricted MAVSDK/PX4 simulation executor.

The executor:

- connects only through the configured MAVSDK endpoint
- runs deterministic Nightjar policy before MAVSDK system creation
- currently supports only takeoff, hold, and land
- rejects `goto` and `return_home` before connecting to PX4
- waits for relative-altitude telemetry before completing takeoff
- waits for landing telemetry before completing land
- records action and mission lifecycle events in the audit log

The default simulation endpoint uses `127.0.0.1`.

The MAVSDK executor is intentionally not yet connected to the signed CLI authorization path.

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

### Restricted MAVSDK PX4 Simulation

The Nightjar MAVSDK executor successfully:

- Connected to PX4
- Armed the simulated vehicle
- Requested a 5 m takeoff
- Waited for relative-altitude telemetry before completing takeoff
- Began a ten-second hold only after the takeoff threshold was reached
- Issued landing
- Waited for landing confirmation
- Completed the audited mission lifecycle

A regression test also verifies that a takeoff which never reaches the required altitude times out, blocks subsequent actions, and records mission failure.

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

`main`

Latest verified implementation checkpoint:

`0a5b161 Confirm takeoff altitude before continuing`

Current automated test count:

`41 passing tests`

Latest validation:

- Windows / Python 3.11: 41 passing tests
- Linux / Python 3.10: 41 passing tests
- Ruff checks passing
- PX4 SIH simulation completed successfully with telemetry-confirmed takeoff and landing

Primary milestone commits:

- `0a5b161 Confirm takeoff altitude before continuing`
- `1b6f8c1 Add restricted MAVSDK executor`
- `71aad27 Add optional MAVSDK flight dependency`
- `229a7e2 Evaluate aggregate budgets after mission actions`
- `568e423 Enforce aggregate mission budgets`
- `391e5d7 Add one-time signed approval enforcement`
- `29637e8 Add signed approval envelope verification`
- `7feebb2 Add canonical mission and policy hashing`

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
- The primary CLI currently authorizes only the dry-run executor.
- No production key-management or key-rotation process exists.
- Testing has used PX4 software simulation.
- No hardware-in-the-loop testing has occurred.
- No physical aircraft has been controlled by Nightjar.
- The architecture does not protect against a fully compromised executor operating system.
- The restricted MAVSDK executor is not yet connected to the signed CLI authorization path.
- `goto` and `return_home` are intentionally unsupported by the MAVSDK executor until their coordinate and behavioral semantics are defined.
- Takeoff and landing state confirmation have been tested only in PX4 software simulation.

## Development Roadmap

Near-term work:

1. Connect signed approvals to the restricted MAVSDK executor in PX4 simulation.
2. Ensure the exact authorized `PolicyLimits` instance governs MAVSDK execution.
3. Define executor abort and recovery behavior for failures after arming.
4. Separate structural schema limits from operational policy limits.
5. Define recovery behavior independent of audit writes.
6. Introduce an audit-sink abstraction.
7. Add chained audit records and external anchoring.
8. Define signing-key custody and rotation.
9. Add hardware-in-the-loop testing.

Completed roadmap milestones:

- Aggregate mission budgets
- Non-finite mission-value rejection
- Policy-controlled restricted MAVSDK executor
- Telemetry-confirmed takeoff and landing in PX4 simulation

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
- [x] Git remote absence verified before publication
- [x] Test suite passing
- [x] Ruff linting passing
- [x] Formatting checks passing

Remaining:

- [x] Review and strengthen `.gitignore`
- [x] Add a license
- [x] Add `SECURITY.md`
- [x] Add continuous-integration configuration
- [x] Perform a clean-clone installation test
- [x] Review README claims against implemented behavior
- [x] Merge the security-foundation branch
- [x] Tag and publish the first public release (`v0.1.1`)

## Current Public Release

`v0.1.1: Secure Simulation Foundation`

The first public release established the simulator-first security foundation with deterministic policy enforcement, signed approvals, executor binding, expiration checks, and atomic replay protection.

Development on `main` has advanced beyond that release and now also includes aggregate mission budgets and the restricted MAVSDK/PX4 executor.

The project still does not claim production readiness, hardware-in-the-loop validation, physical-flight validation, or protection against a fully compromised executor host.
