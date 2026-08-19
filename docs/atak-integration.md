# ATAK Integration — Experiment Track

**Branch:** `experiment/atak-poc`
**Status:** Phase 0 — read-only validation service and map client. Nothing executes.
**Relationship to main track:** parallel and non-blocking. This branch does not modify
`Mission`, `PolicyLimits`, `security.py`, `approval.py`, `authorization.py`, `replay.py`,
or any executor.

---

## 1. Purpose

Determine whether ATAK / TAK can serve as an operator-facing geospatial interface for
Nightjar **without changing Nightjar's trust model**.

ATAK is a client of Nightjar. It is not part of Nightjar's trusted core.

## 2. Trust boundary

```
  ┌─ UNTRUSTED ──────────────────────────────┐   ┌─ NIGHTJAR ─────────────────┐
  │                                          │   │                            │
  │  operator picks WGS84 point              │   │  Mission schema            │
  │            ↓                             │   │  PolicyEngine              │
  │  EXPERIMENTAL client-side geodesy        │──▶│  canonical hashing         │
  │  WGS84 → local NED                       │   │                            │
  │            ↓                             │   │  ✗ no signing key          │
  │  Nightjar mission proposal (JSON)        │◀──│  ✗ no approval issuance    │
  │            ↑                             │   │  ✗ no executor reachable   │
  │  re-render normalized mission on map     │   │                            │
  └──────────────────────────────────────────┘   └────────────────────────────┘
```

The client-side geodesy step is **experimental scaffolding for Phase 0 only**. It is a
demo mechanism, not a safety mechanism. See §5.

## 3. Constraints (binding for this branch)

The client must not, and structurally cannot via this service:

- call MAVSDK or MAVLink
- bypass or reconfigure the policy engine
- modify `PolicyLimits`
- mark its own mission approved
- hold Nightjar signing authority
- cause anything to execute

Any mission modification produces a **new proposal**, revalidated from scratch. There is no
mutate-in-place path.

## 4. Interface contract

One endpoint. Read-only. No side effects. No persistence.

```
POST /v1/missions/validate
Content-Type: application/json

  → { "mission": <Mission JSON> }

  ← 200 {
      "service_version":   "0.1.0-phase0",
      "approved":          bool,
      "reasons":           [str],
      "mission_sha256":    str,
      "policy_sha256":     str,
      "policy_limits":     { ... },
      "normalized_mission":{ ... },
      "authorization":     "REQUIRED_NOT_GRANTED",
      "execution":         "NOT_AVAILABLE_IN_THIS_SERVICE"
    }

  ← 422 { "error": "schema", "reasons": [str], ... }
```

`authorization` and `execution` are **constants**. The service has no code path that can
emit any other value for them.

### Why each field exists

| Field | Reason |
|---|---|
| `policy_limits` | client renders the fence *before* the operator picks a point |
| `mission_sha256` / `policy_sha256` | client can later prove what was evaluated |
| `normalized_mission` | client re-renders exactly what Nightjar parsed, not what it sent |

### Gotcha: supply `mission_id`

`Mission.mission_id` has `default_factory=uuid4`. A proposal submitted without one gets a
fresh UUID per request, so `mission_sha256` changes on every call for identical input.
**Clients must supply a stable `mission_id` for retries of the same proposal** or hash
comparison is meaningless. A changed destination, altitude, home selection, or other mission
content is a new proposal and must receive a new ID.

### Transport

Phase 0 binds `127.0.0.1` and expects `adb reverse tcp:8787 tcp:8787`. The service does
not accept a host argument; changing network exposure requires a code change and review.
Validation responses carry `Cache-Control: no-store`. No TLS, no network exposure, no
certificate work. TLS is a Phase 2 problem.

## 5. BLOCKING DESIGN ITEM — reference frame origin

**This must be resolved before Nightjar ever enables executable `goto`. It is not to be
implemented in this branch.**

### The issue

`GotoAction` carries `north_m` / `east_m`. `PolicyEngine` measures
`max_distance_from_home_m` from an implicit origin of `(0, 0)`. No mission field anchors
that origin to anywhere on earth. The approval binds the mission hash and the policy
hash — it does not bind a reference frame.

Consequence: a client performing the WGS84 → NED conversion is choosing the datum against
which the safety limit is measured. "30 m from home" validates identically regardless of
where the aircraft actually is.

### Current severity: latent, not live

`MavsdkExecutor.validate_mission()` rejects `goto` as an unsupported action
(`UnsupportedMavsdkActionError`). Verified on this branch. The executable surface today is
takeoff / hold / land, none of which carry horizontal coordinates. So this is a
**must-fix-before-goto**, not an active bypass.

### Rejected solution

Adding `home: {lat, lon}` to `Mission` and letting the client populate it. Signing the value
binds it, but an untrusted client still gets to declare where the aircraft is. Binding a lie
makes it tamper-evident, not true.

### Intended eventual design

```
client proposes DESTINATION
        ↓
Nightjar obtains TRUSTED VEHICLE HOME  (from telemetry, not from the client)
        ↓
WGS84 → local NED conversion, Nightjar-side
        ↓
approval binds: mission + policy + reference frame
        ↓
executor verifies live vehicle home matches the bound frame
        ↓
flight
```

The client chooses **where it wants to go**. The client does not get to declare **where the
aircraft currently is**.

Open sub-questions for the main track: altitude datum reconciliation (ATAK reports
HAE/MSL; `altitude_m` is relative-to-takeoff), frame-drift tolerance at executor
verification time, and behaviour when telemetry home moves mid-mission.

### Not a substitute

"The operator visually confirms the re-rendered mission on the map" is acceptable as a
Phase 0 demo check. It must **not** migrate into the safety boundary for executable
missions. Human visual confirmation is not a deterministic control.

## 6. Threat-model addendum (for `docs/threat-model.md`, main track)

ATAK's UAS Tool plugin provides full C2 over MAVLink for PX4 and ArduPilot and is freely
available. An operator running a Nightjar plugin on a tablet that also has UAS Tool
installed can ignore Nightjar and command the vehicle directly.

This is a **deployment limitation, not a Nightjar architecture defect** — structurally
identical to the existing observation that hostile code already inside the privileged
executor environment could invoke MAVSDK directly rather than going through the Nightjar
API. The security claim should be stated as:

> Nightjar constrains actions performed **through the Nightjar execution path**.
> System-level exclusivity over the vehicle is a **deployment requirement** for stronger
> enforcement.

## 7. Phase plan

**Phase 0 — this branch.** Validation service + browser map client. Proves the contract
with no Android toolchain. Exit: one map point travels client → service → decision → re-render,
and the rejected case renders its reasons correctly.

**Phase 1 — ATAK plugin.** Port the Phase 0 client into an ATAK-CIV plugin. Kotlin,
official TPC plugin template, `MapComponent` + `DropDownReceiver`, OkHttp. Same contract,
unchanged. Pin an ATAK API compatibility range in the README.

**Phase 2 — situational awareness.** Outbound CoT for vehicle status and mission
visualization.

**CoT rule:** outbound only. CoT is XML on a shared bus; TAK Server TLS provides transport
authentication, not message-level integrity. **Never accept a mission or an approval over
CoT.**

**Phase 3 — operator approval UX.** Requires the §5 resolution first, plus Android
keystore / StrongBox custody and a display-what-you-sign guarantee. Out of scope until the
main track decides.

## 8. Regulatory note

The FAA TRUST certificate covering this project is recreational. An operator-facing
tactical C2 interface plausibly reads as a Part 107 use case. Resolve before any of this
touches an aircraft.
