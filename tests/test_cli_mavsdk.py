from __future__ import annotations

import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from nightjar.approval import build_approval_payload, sign_approval
from nightjar.cli import load_mission, main
from nightjar.executor import ExecutionResult
from nightjar.home import snapshot_from_telemetry
from nightjar.policy import PolicyLimits

DEFAULT_HOME = snapshot_from_telemetry(
    latitude_deg=47.3977419,
    longitude_deg=8.5455938,
    absolute_altitude_m=488.0,
    captured_at="2026-01-01T00:00:00+00:00",
)


def write_public_key(
    path: Path,
    private_key: Ed25519PrivateKey,
) -> None:
    pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def create_mavsdk_authorization(
    tmp_path: Path,
    mission_path: Path,
    executor: str = "mavsdk",
    nonce: str | None = None,
) -> tuple[Path, Path, Ed25519PrivateKey]:
    mission = load_mission(mission_path)
    private_key = Ed25519PrivateKey.generate()

    payload = build_approval_payload(
        mission=mission,
        limits=PolicyLimits(),
        executor=executor,
        home=DEFAULT_HOME,
        ttl_seconds=300,
        now_unix=int(time.time()),
        nonce=nonce or ("m" * 32),
    )

    approval_path = tmp_path / "approval.json"
    approval_path.write_text(
        sign_approval(private_key, payload).model_dump_json(indent=2),
        encoding="utf-8",
    )

    public_key_path = tmp_path / "approver-public.pem"
    write_public_key(public_key_path, private_key)

    return approval_path, public_key_path, private_key


def run_mavsdk_cli(
    monkeypatch,
    *,
    mission_path: Path,
    approval_path: Path,
    public_key_path: Path,
    nonce_db: Path,
) -> int:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "nightjar",
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
        ],
    )
    return main()


def test_mavsdk_successful_dispatch_and_replay_rejection(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    mission_path = Path("missions/mavsdk_simulation_mission.json").resolve()
    approval, public_key, _ = create_mavsdk_authorization(tmp_path, mission_path)
    nonce_db = tmp_path / "approvals.sqlite3"

    # Skip the real MAVSDK connection; only exercise authorization + dispatch.
    async def fake_execute(self, mission, approval, drone_holder=None):
        return ExecutionResult(completed=True, log_path=tmp_path / "audit.jsonl")

    import nightjar.mavsdk_executor as mev

    monkeypatch.setattr(mev.MavsdkExecutor, "_execute", fake_execute)
    monkeypatch.chdir(tmp_path)

    first = run_mavsdk_cli(
        monkeypatch,
        mission_path=mission_path,
        approval_path=approval,
        public_key_path=public_key,
        nonce_db=nonce_db,
    )
    assert first == 0
    out = capsys.readouterr().out
    assert "Signed approval verified and consumed." in out
    assert "MAVSDK simulation complete." in out

    # Replay must be rejected and the nonce remains consumed.
    second = run_mavsdk_cli(
        monkeypatch,
        mission_path=mission_path,
        approval_path=approval,
        public_key_path=public_key,
        nonce_db=nonce_db,
    )
    out = capsys.readouterr().out
    assert second == 4
    assert "already been used" in out


def test_mavsdk_invalid_approval_does_not_consume(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    mission_path = Path("missions/mavsdk_simulation_mission.json").resolve()
    approval, public_key, trusted = create_mavsdk_authorization(tmp_path, mission_path)
    nonce_db = tmp_path / "approvals.sqlite3"

    # Swap in an untrusted key so the signature fails.
    untrusted = Ed25519PrivateKey.generate()
    write_public_key(public_key, untrusted)

    first = run_mavsdk_cli(
        monkeypatch,
        mission_path=mission_path,
        approval_path=approval,
        public_key_path=public_key,
        nonce_db=nonce_db,
    )
    assert first == 4
    assert "signature is invalid" in capsys.readouterr().out

    # Nonce must still be available for the legitimate key.
    # A subsequent attempt with the correct key should succeed (nonce not spent).
    write_public_key(public_key, trusted)

    async def fake_execute(self, mission, approval, drone_holder=None):
        return ExecutionResult(completed=True, log_path=tmp_path / "audit.jsonl")

    import nightjar.mavsdk_executor as mev

    monkeypatch.setattr(mev.MavsdkExecutor, "_execute", fake_execute)

    second = run_mavsdk_cli(
        monkeypatch,
        mission_path=mission_path,
        approval_path=approval,
        public_key_path=public_key,
        nonce_db=nonce_db,
    )
    assert second == 0
    assert "Signed approval verified and consumed." in capsys.readouterr().out


def test_mavsdk_unsupported_action_does_not_consume_nonce(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    # example_mission.json contains return_home, which MAVSDK rejects.
    mission_path = Path("missions/example_mission.json").resolve()
    approval, public_key, _ = create_mavsdk_authorization(
        tmp_path,
        mission_path,
        nonce="u" * 32,
    )
    nonce_db = tmp_path / "approvals.sqlite3"

    result = run_mavsdk_cli(
        monkeypatch,
        mission_path=mission_path,
        approval_path=approval,
        public_key_path=public_key,
        nonce_db=nonce_db,
    )
    out = capsys.readouterr().out
    assert result == 4
    assert "does not support" in out.lower() or "return_home" in out

    # Nonce must remain unconsumed so a corrected mission can still use it
    # (or a different approval). Here we just confirm the store does not
    # contain the nonce.
    import sqlite3

    with sqlite3.connect(nonce_db) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM consumed_approvals WHERE nonce = ?",
            ("u" * 32,),
        ).fetchone()[0]
    assert count == 0
