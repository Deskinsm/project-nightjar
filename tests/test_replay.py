from pathlib import Path

import pytest

from nightjar.replay import (
    ApprovalReplayError,
    SQLiteNonceStore,
    default_replay_db_path,
)


def consume_test_nonce(
    store: SQLiteNonceStore,
    nonce: str = "n" * 32,
) -> None:
    store.consume(
        nonce=nonce,
        mission_sha256="a" * 64,
        policy_sha256="b" * 64,
        executor="mavsdk",
        expires_at_unix=1_800_000_300,
        now_unix=1_800_000_001,
    )


def test_nonce_can_be_consumed_once(tmp_path: Path) -> None:
    store = SQLiteNonceStore(tmp_path / "approvals.sqlite3")

    consume_test_nonce(store)

    with pytest.raises(
        ApprovalReplayError,
        match="already been used",
    ):
        consume_test_nonce(store)


def test_consumed_nonce_persists_across_store_instances(
    tmp_path: Path,
) -> None:
    database = tmp_path / "approvals.sqlite3"

    first_store = SQLiteNonceStore(database)
    consume_test_nonce(first_store)

    second_store = SQLiteNonceStore(database)

    with pytest.raises(ApprovalReplayError):
        consume_test_nonce(second_store)


def test_different_nonces_are_accepted(tmp_path: Path) -> None:
    store = SQLiteNonceStore(tmp_path / "approvals.sqlite3")

    consume_test_nonce(store, nonce="a" * 32)
    consume_test_nonce(store, nonce="b" * 32)


def test_default_path_respects_xdg_state_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))

    expected = tmp_path.resolve() / "nightjar" / "approvals.sqlite3"

    assert default_replay_db_path() == expected
