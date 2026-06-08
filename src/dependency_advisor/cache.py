"""SQLite-backed cache for normalized package metadata."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from dependency_advisor.models import CachedPackageMetadata, Ecosystem, PackageMetadata


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(UTC)


class SQLitePackageCache:
    """Persist registry metadata for warm-cache recommendations."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS package_cache (
                    ecosystem TEXT NOT NULL,
                    package TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY (ecosystem, package)
                )
                """
            )
            connection.commit()

    def load(self, ecosystem: Ecosystem, package: str) -> CachedPackageMetadata | None:
        """Return cached metadata for a package if present."""

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT payload_json, fetched_at, expires_at
                FROM package_cache
                WHERE ecosystem = ? AND package = ?
                """,
                (ecosystem.value, package),
            ).fetchone()
        if row is None:
            return None
        return CachedPackageMetadata(
            package_metadata=PackageMetadata.model_validate_json(row["payload_json"]),
            fetched_at=_parse_timestamp(row["fetched_at"]),
            expires_at=_parse_timestamp(row["expires_at"]),
        )

    def save(self, record: CachedPackageMetadata) -> None:
        """Insert or replace cached package metadata."""

        package_metadata = record.package_metadata
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO package_cache (
                    ecosystem,
                    package,
                    payload_json,
                    fetched_at,
                    expires_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ecosystem, package) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    fetched_at = excluded.fetched_at,
                    expires_at = excluded.expires_at
                """,
                (
                    package_metadata.ecosystem.value,
                    package_metadata.package,
                    package_metadata.model_dump_json(),
                    record.fetched_at.isoformat(),
                    record.expires_at.isoformat(),
                ),
            )
            connection.commit()
