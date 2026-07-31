# Security Policy

## Supported Versions

Project Nightjar is currently pre-release software.

Only the latest commit on the `main` branch is supported. Older commits,
development branches, and untagged snapshots may not receive security fixes.

## Reporting a Vulnerability

After this repository becomes public, please use GitHub private vulnerability
reporting through the repository's Security page.

Do not disclose a suspected vulnerability in a public issue.

A useful report should include:

- A description of the vulnerability
- The affected component
- Reproduction steps or a proof of concept
- The expected security impact
- Any suggested mitigation

## Security-Relevant Areas

Reports are especially welcome for:

- Policy-engine bypasses
- Mission or policy hash inconsistencies
- Signature-verification failures
- Approval replay or nonce-consumption races
- Executor-binding bypasses
- Unsafe transitions into MAVSDK or MAVLink
- Exposure of signing keys or authorization state

## Safety Notice

Nightjar is research and simulation software. It is not production flight
software and has not been validated on a physical aircraft.

Do not test suspected vulnerabilities using a live aircraft, populated airspace,
or systems that could endanger people or property.
