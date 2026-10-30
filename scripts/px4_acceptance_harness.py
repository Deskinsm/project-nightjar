#!/usr/bin/env python3
"""Repeatable PX4 software-simulation acceptance harness for Nightjar.

Produces a reviewable evidence bundle for three scenarios:

1. Signed mission completes (exit 0) with telemetry-confirmed landing.
2. Replaying the same approval is rejected before MAVSDK connection.
3. A simulation-only failure during hold triggers landing recovery;
   the original error remains visible.

Private keys are generated in a temporary directory and are never
copied into the evidence bundle.

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

from nightjar.approval import build_approval_payload, sign_approval
from nightjar.cli import load_mission
from nightjar.policy import PolicyLimits

MISSION_PATH = ROOT / "missions" / "mavsdk_simulation_mission.json"
SYSTEM_ADDRESS = "udpin://127.0.0.1:14540"


def git_sha() -> str:
    try:
        return (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=ROOT,
                text=True,
            )
            .strip()
        )
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


def run_cli(
    *,
    mission_path: Path,
    approval_path: Path,
    public_key_path: Path,
    nonce_db: Path,
    state_home: Path,
    extra_env: dict[str, str] | None = None,
) -> tuple[int, str, str, list[str]]:
    cmd = [
        sys.executable,
        "-m",
        "nightjar.cli",
        "run",
        str(mission_path),
        "--executor",
        "mavsdk",
        "--approval-file",
        str(approval_path),
        "--public-key-file",
        str(public_key_path),
        "--nonce-db",
        str(nonce_db),
    ]
    env = os.environ.copy()
    env["XDG_STATE_HOME"] = str(state_home)
    if extra_env:
        env.update(extra_env)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        check=False,
    )
    return result.returncode, result.stdout, result.stderr, cmd


def collect_audit(state_home: Path, mission_id: str) -> Path | None:
    audit_dir = state_home / "nightjar" / "audit"
    if not audit_dir.exists():
        return None
    candidate = audit_dir / f"{mission_id}.jsonl"
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
) -> dict:
    scenario_dir = bundle / name
    scenario_dir.mkdir(parents=True, exist_ok=True)

    (scenario_dir / "command.txt").write_text(" ".join(command) + "\n", encoding="utf-8")
    (scenario_dir / "exit_code.txt").write_text(str(exit_code) + "\n", encoding="utf-8")
    (scenario_dir / "stdout.txt").write_text(stdout, encoding="utf-8")
    (scenario_dir / "stderr.txt").write_text(stderr, encoding="utf-8")
    (scenario_dir / "notes.txt").write_text(notes + "\n", encoding="utf-8")

    if audit_src is not None:
        shutil.copy2(audit_src, scenario_dir / "audit.jsonl")

    return {
        "name": name,
        "exit_code": exit_code,
        "command": command,
        "audit_present": audit_src is not None,
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

    # Private keys live only in this temporary directory.
    with tempfile.TemporaryDirectory(prefix="nightjar-keys-") as key_dir_name:
        key_dir = Path(key_dir_name)
        _private_path, public_path, private_key = write_key_pair(key_dir)

        # --- Scenario 1: successful signed mission ---
        print("=== Signed mission ===")
        approval = key_dir / "approval-success.json"
        nonce_db = key_dir / "success.sqlite3"
        state_home = key_dir / "state-success"
        issue_approval(MISSION_PATH, private_key, approval, nonce="s" * 32)

        code, out, err, cmd = run_cli(
            mission_path=MISSION_PATH,
            approval_path=approval,
            public_key_path=public_path,
            nonce_db=nonce_db,
            state_home=state_home,
        )
        audit = collect_audit(state_home, mission_id)
        success = write_scenario(
            bundle,
            "signed_mission",
            command=cmd,
            exit_code=code,
            stdout=out,
            stderr=err,
            audit_src=audit,
            notes="Expected: exit 0, telemetry-confirmed landing.",
        )
        print(f"  exit {code}")
        print(out.strip() or "(no stdout)")

        # --- Scenario 2: replay rejection ---
        print("\n=== Replay rejection ===")
        code2, out2, err2, cmd2 = run_cli(
            mission_path=MISSION_PATH,
            approval_path=approval,
            public_key_path=public_path,
            nonce_db=nonce_db,
            state_home=key_dir / "state-replay",
        )
        replay = write_scenario(
            bundle,
            "replay_rejection",
            command=cmd2,
            exit_code=code2,
            stdout=out2,
            stderr=err2,
            audit_src=None,
            notes="Expected: exit 4, nonce already used, no MAVSDK connection.",
        )
        print(f"  exit {code2}")
        print(out2.strip() or "(no stdout)")

        # --- Scenario 3: controlled failure during hold ---
        print("\n=== Controlled failure during hold ===")
        approval_fail = key_dir / "approval-failure.json"
        nonce_db_fail = key_dir / "failure.sqlite3"
        state_home_fail = key_dir / "state-failure"
        issue_approval(MISSION_PATH, private_key, approval_fail, nonce="f" * 32)

        code3, out3, err3, cmd3 = run_cli(
            mission_path=MISSION_PATH,
            approval_path=approval_fail,
            public_key_path=public_path,
            nonce_db=nonce_db_fail,
            state_home=state_home_fail,
            extra_env={"NIGHTJAR_SIM_FAIL_DURING_HOLD": "1"},
        )
        audit_fail = collect_audit(state_home_fail, mission_id)
        failure = write_scenario(
            bundle,
            "controlled_failure",
            command=cmd3,
            exit_code=code3,
            stdout=out3,
            stderr=err3,
            audit_src=audit_fail,
            notes=(
                "Expected: exit 5, original injected-failure error visible, "
                "recovery lands the vehicle."
            ),
        )
        print(f"  exit {code3}")
        print(out3.strip() or "(no stdout)")

    # Manifest (no private key material)
    manifest = {
        "timestamp_utc": timestamp,
        "git_sha": git_sha(),
        "system_address": SYSTEM_ADDRESS,
        "mission": str(MISSION_PATH.relative_to(ROOT)),
        "mission_id": mission_id,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "package_versions": package_versions(),
        "scenarios": [success, replay, failure],
        "notes": (
            "Private signing keys were generated in a temporary directory "
            "and were not included in this bundle."
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
        f"- Timestamp (UTC): {timestamp}",
        f"- Git SHA: {manifest['git_sha']}",
        f"- System address: {SYSTEM_ADDRESS}",
        f"- Mission: {manifest['mission']}",
        "",
        "## Results",
        "",
        (
            f"- Signed mission: exit {success['exit_code']} "
            f"({'PASS' if success['exit_code'] == 0 else 'FAIL'})"
        ),
        (
            f"- Replay rejection: exit {replay['exit_code']} "
            f"({'PASS' if replay['exit_code'] == 4 else 'FAIL'})"
        ),
        (
            f"- Controlled failure: exit {failure['exit_code']} "
            f"({'PASS' if failure['exit_code'] == 5 else 'FAIL'})"
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

    print(f"\nEvidence written to {bundle}")
    overall = (
        success["exit_code"] == 0
        and replay["exit_code"] == 4
        and failure["exit_code"] == 5
    )
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
