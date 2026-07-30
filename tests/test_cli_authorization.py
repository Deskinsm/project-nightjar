from __future__ import annotations

import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from nightjar.approval import build_approval_payload, sign_approval
from nightjar.cli import load_mission, main
from nightjar.policy import PolicyLimits


def write_public_key(
    path: Path,
    private_key: Ed25519PrivateKey,
) -> None:
    pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def create_authorization_files(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Ed25519PrivateKey]:
    mission_path = Path("missions/example_mission.json").resolve()
    mission = load_mission(mission_path)
    private_key = Ed25519PrivateKey.generate()

    payload = build_approval_payload(
        mission=mission,
        limits=PolicyLimits(),
        executor="dry-run",
        ttl_seconds=300,
        now_unix=int(time.time()),
        nonce="n" * 32,
    )

    approval_path = tmp_path / "approval.json"
    approval_path.write_text(
        sign_approval(private_key, payload).model_dump_json(indent=2),
        encoding="utf-8",
    )

    public_key_path = tmp_path / "approver-public.pem"
    write_public_key(public_key_path, private_key)

    return (
        mission_path,
        approval_path,
        public_key_path,
        private_key,
    )


def run_authorized_cli(
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
            "dry-run",
            "--approval-file",
            str(approval_path),
            "--public-key-file",
            str(public_key_path),
            "--nonce-db",
            str(nonce_db),
        ],
    )

    return main()


def test_signed_approval_executes_once(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    mission, approval, public_key, _ = create_authorization_files(tmp_path)
    nonce_db = tmp_path / "approvals.sqlite3"

    monkeypatch.chdir(tmp_path)

    first_result = run_authorized_cli(
        monkeypatch,
        mission_path=mission,
        approval_path=approval,
        public_key_path=public_key,
        nonce_db=nonce_db,
    )

    assert first_result == 0
    assert "Signed approval verified and consumed." in capsys.readouterr().out

    second_result = run_authorized_cli(
        monkeypatch,
        mission_path=mission,
        approval_path=approval,
        public_key_path=public_key,
        nonce_db=nonce_db,
    )

    output = capsys.readouterr().out

    assert second_result == 4
    assert "already been used" in output


def test_invalid_signature_does_not_consume_approval(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    mission, approval, public_key, trusted_private_key = create_authorization_files(tmp_path)
    nonce_db = tmp_path / "approvals.sqlite3"

    untrusted_private_key = Ed25519PrivateKey.generate()
    write_public_key(public_key, untrusted_private_key)

    first_result = run_authorized_cli(
        monkeypatch,
        mission_path=mission,
        approval_path=approval,
        public_key_path=public_key,
        nonce_db=nonce_db,
    )

    assert first_result == 4
    assert "signature is invalid" in capsys.readouterr().out

    write_public_key(public_key, trusted_private_key)

    second_result = run_authorized_cli(
        monkeypatch,
        mission_path=mission,
        approval_path=approval,
        public_key_path=public_key,
        nonce_db=nonce_db,
    )

    assert second_result == 0
    assert "Signed approval verified and consumed." in capsys.readouterr().out
