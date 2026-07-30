from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Protocol


class ApprovalReplayError(ValueError):
    """Raised when an approval nonce has already been consumed."""


def default_replay_db_path() -> Path:
    """Return an absolute state path for the approval replay database."""

    state_root = Path(
        os.environ.get(
            "XDG_STATE_HOME",
            Path.home() / ".local" / "state",
        )
    )

    return state_root.expanduser().resolve() / "nightjar" / "approvals.sqlite3"


class NonceStore(Protocol):
    """Storage interface for one-time approval nonces."""

    def consume(
        self,
        *,
        nonce: str,
        mission_sha256: str,
        policy_sha256: str,
        executor: str,
        expires_at_unix: int,
        now_unix: int | None = None,
    ) -> None:
        """Consume an approval nonce exactly once."""
        ...


class SQLiteNonceStore:
    """Atomically records approval nonces so each approval can be used once."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path.expanduser().resolve() if path is not None else default_replay_db_path()

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )

        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(
            self.path,
            timeout=5,
        )

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_approvals (
                    nonce TEXT PRIMARY KEY,
                    mission_sha256 TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    executor TEXT NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    consumed_at_unix INTEGER NOT NULL
                )
                """
            )

        try:
            self.path.chmod(0o600)
        except OSError:
            # Some platforms do not support POSIX permission semantics.
            pass

    def consume(
        self,
        *,
        nonce: str,
        mission_sha256: str,
        policy_sha256: str,
        executor: str,
        expires_at_unix: int,
        now_unix: int | None = None,
    ) -> None:
        """Consume an approval nonce exactly once."""

        consumed_at = int(time.time()) if now_unix is None else now_unix

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO consumed_approvals (
                        nonce,
                        mission_sha256,
                        policy_sha256,
                        executor,
                        expires_at_unix,
                        consumed_at_unix
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        nonce,
                        mission_sha256,
                        policy_sha256,
                        executor,
                        expires_at_unix,
                        consumed_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise ApprovalReplayError("Approval nonce has already been used.") from exc
