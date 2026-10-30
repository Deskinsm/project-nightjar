#!/usr/bin/env python3
"""Repeatable PX4 software-simulation acceptance harness for Nightjar.

Produces a reviewable evidence bundle for three scenarios:

1. Signed mission completes (exit 0) with telemetry-confirmed landing.
2. Replaying the same approval is rejected before MAVSDK connection.
3. An acceptance-only failure during hold triggers landing recovery;
   the original error remains visible and recovery_status is landing_confirmed.

Private keys are generated in a temporary directory and are never
copied into the evidence bundle. The mission, approvals, and public key
are preserved in the bundle.

Prerequisites
-------------
- Nightjar installed with the flight extra: ``pip install -e ".[dev,flight]"``
- PX4 software simulation already running and reachable at
  ``udpin://127.0.0.1:14540`` (the default MAVSDK loopback endpoint).

Usage
-----
    python scripts/px4_acceptance_harness.py

The evidence bundle is written to ``evidence/px4-acceptance-<timestamp>/``.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# Allow running from a checkout without an editable install.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from nightjar.acceptance_checks import (
    INJECTED_ERROR,
    controlled_failure_recovered,
    replay_rejected,
    signed_mission_passed,
)
from nightjar.approval import build_approval_payload, sign_approval
from nightjar.cli import load_mission
from nightjar.policy import PolicyLimits

MISSION_PATH = ROOT / "missions" / "mavsdk_simulation_mission.json"
ADAPTER_PATH = ROOT / "scripts" / "acceptance_failure_adapter.py"
SYSTEM_ADDRESS = "udpin://127.0.0.1:14540"


def git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def package_versions() -> dict[str, str]:
    versions = {"python": platform.python_version()}
    for name in ("mavsdk", "cryptography", "pydantic"):
        try:
            out = subprocess.check_output(
                [sys.executable, "-m", "pip", "show", name],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                if line.startswith("Version:"):
                    versions[name] = line.split(":", 1)[1].strip()
                    break
            else:
                versions[name] = "not installed"
        except (subprocess.CalledProcessError, FileNotFoundError):
            versions[name] = "unknown"
    return versions


def write_key_pair(directory: Path) -> tuple[Path, Path, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    private_path = directory / "approver-private.pem"
    public_path = directory / "approver-public.pem"

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path, private_key


def issue_approval(
    mission_path: Path,
    private_key: Ed25519PrivateKey,
    approval_path: Path,
    nonce: str,
) -> None:
    mission = load_mission(mission_path)
    payload = build_approval_payload(
        mission=mission,
        limits=PolicyLimits(),
        executor="mavsdk",
        ttl_seconds=300,
        now_unix=int(time.time()),
        nonce=nonce,
    )
    approval_path.write_text(
        sign_approval(private_key, payload).model_dump_json(indent=2),
        encoding="utf-8",
    )


def isolated_env(state_home: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return an environment that isolates audit state and clears injection settings.

    Sets both XDG_STATE_HOME and LOCALAPPDATA so the platform-appropriate
    audit directory used by Nightjar lands inside the isolated tree on
    Linux/macOS and Windows alike. Inherited fault-injection variables
    are removed.
    """
    env = os.environ.copy()
    env.pop("NIGHTJAR_SIM_FAIL_DURING_HOLD", None)
    env["XDG_STATE_HOME"] = str(state_home)
    env["LOCALAPPDATA"] = str(state_home)
    if extra:
        env.update(extra)
    return env


def expected_audit_dir(state_home: Path) -> Path:
    """Return the audit directory Nightjar will use given the isolated env."""
    # Matches nightjar.audit.default_audit_directory for both platforms.
    return (state_home / "nightjar" / "audit").resolve()


# Enough for connection (20s) + arm/takeoff (30s) + hold + land (30s)
# + recovery window (30s), with margin. Forced cleanup only after this.
SCENARIO_TIMEOUT_SECONDS = 180


def run_command(
    cmd: list[str],
    *,
    state_home: Path,
    extra_env: dict[str, str] | None = None,
    timeout_seconds: float = SCENARIO_TIMEOUT_SECONDS,
) -> tuple[int, str, str, bool]:
    """Run a command with a bounded timeout.

    Returns (exit_code, stdout, stderr, timed_out). On timeout, partial
    output is preserved, the process group is terminated, and the caller
    still receives a result so the evidence bundle can be written.
    """
    env = isolated_env(state_home, extra_env)
    # start_new_session so we can kill the whole process group, including
    # any mavsdk_server child that would otherwise keep pipes open.
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=ROOT,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
        return proc.returncode if proc.returncode is not None else 1, stdout, stderr, False
    except subprocess.TimeoutExpired:
        timed_out = True
        # Terminate the process group. The adapter itself may still be
        # alive, or only a child may be holding the pipes; killing the
        # group covers both.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
        note = (
            f"\n[harness] scenario timed out after {timeout_seconds:g}s; "
            "process group terminated.\n"
        )
        return 124, (stdout or "") + note, stderr or "", timed_out


def collect_audit(state_home: Path, mission_id: str) -> Path | None:
    candidate = expected_audit_dir(state_home) / f"{mission_id}.jsonl"
    return candidate if candidate.exists() else None


def write_scenario(
    bundle: Path,
    name: str,
    *,
    command: list[str],
    exit_code: int,
    stdout: str,
    stderr: str,
    audit_src: Path | None,
    notes: str,
    passed: bool,
    detail: str,
) -> dict:
    scenario_dir = bundle / name
    scenario_dir.mkdir(parents=True, exist_ok=True)

    (scenario_dir / "command.txt").write_text(" ".join(command) + "\n", encoding="utf-8")
    (scenario_dir / "exit_code.txt").write_text(str(exit_code) + "\n", encoding="utf-8")
    (scenario_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
    (scenario_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
    (scenario_dir / "notes.txt").write_text(notes + "\n", encoding="utf-8")
    (scenario_dir / "result.txt").write_text(
        f"{'PASS' if passed else 'FAIL'}: {detail}\n",
        encoding="utf-8",
    )

    if audit_src is not None:
        shutil.copy2(audit_src, scenario_dir / "audit.jsonl")

    return {
        "name": name,
        "exit_code": exit_code,
        "command": command,
        "audit_present": audit_src is not None,
        "passed": passed,
        "detail": detail,
        "notes": notes,
    }


def main() -> int:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bundle = ROOT / "evidence" / f"px4-acceptance-{timestamp}"
    bundle.mkdir(parents=True, exist_ok=True)

    print(f"Evidence bundle: {bundle}")
    print(f"Expecting PX4 at {SYSTEM_ADDRESS}")
    print()

    mission = load_mission(MISSION_PATH)
    mission_id = str(mission.mission_id)

    # Preserve the mission in the bundle.
    shutil.copy2(MISSION_PATH, bundle / "mission.json")

    # Private keys live only in this temporary directory.
    with tempfile.TemporaryDirectory(prefix="nightjar-keys-") as key_dir_name:
        key_dir = Path(key_dir_name)
        _private_path, public_path, private_key = write_key_pair(key_dir)

        # Preserve the public key (never the private key).
        shutil.copy2(public_path, bundle / "approver-public.pem")

        # --- Scenario 1: successful signed mission ---
        print("=== Signed mission ===")
        approval = key_dir / "approval-success.json"
        nonce_db = key_dir / "success.sqlite3"
        state_home = key_dir / "state-success"
        issue_approval(MISSION_PATH, private_key, approval, nonce="s" * 32)
        shutil.copy2(approval, bundle / "approval-success.json")

        cmd = [
            sys.executable,
            "-m",
            "nightjar.cli",
            "run",
            str(MISSION_PATH),
            "--executor",
            "mavsdk",
            "--approval-file",
            str(approval),
            "--public-key-file",
            str(public_path),
            "--nonce-db",
            str(nonce_db),
        ]
        code, out, err, timed_out = run_command(cmd, state_home=state_home)
        if timed_out:
            detail_prefix = "TIMED OUT — "
        else:
            detail_prefix = ""
        audit = collect_audit(state_home, mission_id)
        ok, detail = signed_mission_passed(exit_code=code, stdout=out, audit_path=audit)
        success = write_scenario(
            bundle,
            "signed_mission",
            command=cmd,
            exit_code=code,
            stdout=out,
            stderr=err,
            audit_src=audit,
            notes="Expected: exit 0, success message, mission_completed audit.",
            passed=ok and not timed_out,
            detail=detail_prefix + detail,
        )
        print(f"  {'PASS' if ok else 'FAIL'}: {detail}")
        print(out.strip() or "(no stdout)")

        # --- Scenario 2: replay rejection ---
        print("\n=== Replay rejection ===")
        cmd2 = cmd  # same approval and nonce database
        code2, out2, err2, timed_out2 = run_command(cmd2, state_home=key_dir / "state-replay")
        if timed_out2:
            detail_prefix2 = "TIMED OUT — "
        else:
            detail_prefix2 = ""
        audit2 = collect_audit(key_dir / "state-replay", mission_id)
        ok2, detail2 = replay_rejected(exit_code=code2, stdout=out2, audit_path=audit2)
        replay = write_scenario(
            bundle,
            "replay_rejection",
            command=cmd2,
            exit_code=code2,
            stdout=out2,
            stderr=err2,
            audit_src=audit2,
            notes="Expected: exit 4, already-used rejection, no audit (supporting evidence).",
            passed=ok2 and not timed_out2,
            detail=detail_prefix2 + detail2,
        )
        print(f"  {'PASS' if ok2 else 'FAIL'}: {detail2}")
        print(out2.strip() or "(no stdout)")

        # --- Scenario 3: controlled failure during hold ---
        # Isolate recovery testing from the first flight's leftover state
        # by restarting PX4 when a restart command is provided. A fresh
        # boot is a practical isolation measure; one failed second flight
        # does not establish that SIH always requires a restart.
        print("\n=== Controlled failure during hold ===")
        restart_log = bundle / "px4_restart.txt"
        restart_cmd = os.environ.get("NIGHTJAR_PX4_RESTART_CMD")
        if restart_cmd:
            print(f"  Restarting PX4: {restart_cmd}")
            restart = subprocess.run(
                restart_cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=False,
            )
            restart_log.write_text(
                f"command: {restart_cmd}\n"
                f"exit: {restart.returncode}\n"
                f"--- stdout ---\n{restart.stdout}\n"
                f"--- stderr ---\n{restart.stderr}\n",
                encoding="utf-8",
            )
            # Brief pause so the new instance can bind the port.
            time.sleep(5)
        else:
            restart_log.write_text(
                "No NIGHTJAR_PX4_RESTART_CMD set. Recovery scenario used "
                "the existing PX4 instance. For isolation, set "
                "NIGHTJAR_PX4_RESTART_CMD to a command that stops and "
                "restarts PX4 SIH before this scenario.\n",
                encoding="utf-8",
            )

        approval_fail = key_dir / "approval-failure.json"
        nonce_db_fail = key_dir / "failure.sqlite3"
        state_home_fail = key_dir / "state-failure"
        issue_approval(MISSION_PATH, private_key, approval_fail, nonce="f" * 32)
        shutil.copy2(approval_fail, bundle / "approval-failure.json")

        cmd3 = [
            sys.executable,
            str(ADAPTER_PATH),
            str(MISSION_PATH),
            "--approval-file",
            str(approval_fail),
            "--public-key-file",
            str(public_path),
            "--nonce-db",
            str(nonce_db_fail),
        ]
        code3, out3, err3, timed_out3 = run_command(cmd3, state_home=state_home_fail)
        if timed_out3:
            detail_prefix3 = "TIMED OUT — "
        else:
            detail_prefix3 = ""
        audit3 = collect_audit(state_home_fail, mission_id)
        ok3, detail3 = controlled_failure_recovered(exit_code=code3, stdout=out3, audit_path=audit3)
        failure = write_scenario(
            bundle,
            "controlled_failure",
            command=cmd3,
            exit_code=code3,
            stdout=out3,
            stderr=err3,
            audit_src=audit3,
            notes=(
                f"Expected: exit 5, {INJECTED_ERROR!r} visible, "
                "recovery_status=landing_confirmed, no recovery error. "
                "Uses the acceptance-only adapter, not nightjar run."
            ),
            passed=ok3 and not timed_out3,
            detail=detail_prefix3 + detail3,
        )
        print(f"  {'PASS' if ok3 else 'FAIL'}: {detail3}")
        print(out3.strip() or "(no stdout)")

    # Manifest (no private key material)
    overall = success["passed"] and replay["passed"] and failure["passed"]
    overall_label = "PASS" if overall else "FAIL"
    manifest = {
        "timestamp_utc": timestamp,
        "git_sha": git_sha(),
        "system_address": SYSTEM_ADDRESS,
        "mission": str(MISSION_PATH.relative_to(ROOT)),
        "mission_id": mission_id,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "package_versions": package_versions(),
        "overall": overall_label,
        "scenarios": [success, replay, failure],
        "notes": (
            "Private signing keys were generated in a temporary directory "
            "and were not included in this bundle. The mission, approvals, "
            "and public key are included."
        ),
    }
    (bundle / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    # Human-readable summary
    summary_lines = [
        "# PX4 Acceptance Evidence",
        "",
        f"**Overall: {overall_label}**",
        "",
        f"- Timestamp (UTC): {timestamp}",
        f"- Git SHA: {manifest['git_sha']}",
        f"- System address: {SYSTEM_ADDRESS}",
        f"- Mission: {manifest['mission']}",
        "",
        "## Results",
        "",
        "CLI validation (via `nightjar run --executor mavsdk`):",
        f"- Signed mission: {'PASS' if success['passed'] else 'FAIL'} — {success['detail']}",
        f"- Replay rejection: {'PASS' if replay['passed'] else 'FAIL'} — {replay['detail']}",
        "",
        "Executor recovery validation (via acceptance-only adapter, not `nightjar run`):",
        f"- Controlled failure: {'PASS' if failure['passed'] else 'FAIL'} — {failure['detail']}",
        "",
        (
            "Absence of an audit on replay is supporting evidence that the "
            "executor did not reach mission_started. Direct proof that MAVSDK "
            "system creation never occurs on a rejected replay is provided by "
            "the existing regression tests, because the executor creates the "
            "system before writing the first audit record."
        ),
        "",
        (
            "See each scenario directory for the exact command, exit code, "
            "stdout, stderr, and audit log (when produced)."
        ),
        "",
        "Private keys were not included in this bundle.",
    ]
    (bundle / "SUMMARY.md").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    print(f"\nOverall: {overall_label}")
    print(f"Evidence written to {bundle}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
