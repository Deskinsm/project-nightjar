# Next Session

## Objective

Implement signed, mission-bound approval envelopes.

## Approval must bind

- Mission SHA-256
- Policy SHA-256
- Executor name
- Issued time
- Expiration time
- Nonce

## Required rejection tests

- Modified mission
- Modified policy
- Wrong executor
- Expired approval
- Invalid signature
- Malformed envelope

## Explicitly out of scope

- MAVSDK executor integration
- Persistent nonce replay ledger
- Audit hash chaining
