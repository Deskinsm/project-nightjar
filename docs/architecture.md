# Architecture

## Trust boundaries

```text
User instruction
      |
      v
LLM planner [UNTRUSTED]
      |
      v
Mission schema validation [DETERMINISTIC]
      |
      v
Policy engine [DETERMINISTIC]
      |
      v
Human approval [REQUIRED]
      |
      v
Executor adapter
      |
      v
PX4 / ArduPilot
```

The planner can suggest only actions represented in the approved mission schema.
Unknown fields are rejected.

## Components

### Planner

Transforms natural language into a mission object. The initial repository includes
only a parser boundary. An LLM provider can be added later.

### Mission model

Defines the complete command vocabulary. The initial vocabulary is:

- `takeoff`
- `hold`
- `goto`
- `return_home`
- `land`

### Policy engine

Evaluates mission actions against fixed limits and legal state transitions.

### Executor

`DryRunExecutor` emits audit records and does not connect to any aircraft.
A future `MavsdkExecutor` will implement the same interface.

## Design rule

No component may bypass policy evaluation. The executor accepts a validated
`Mission`, but the application must also require a successful `PolicyDecision`
and explicit human approval.
