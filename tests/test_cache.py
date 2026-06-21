from datetime import UTC, datetime, timedelta

from dependency_advisor.cache import SQLitePackageCache
from dependency_advisor.models import (
    CachedPackageMetadata,
    Ecosystem,
    PackageMetadata,
    PackageVersion,
)


def test_cache_round_trip_persists_metadata(tmp_path) -> None:
    cache = SQLitePackageCache(tmp_path / "registry.sqlite3")
    record = CachedPackageMetadata(
        package_metadata=PackageMetadata(
            package="requests",
            ecosystem=Ecosystem.PYTHON,
            versions=(PackageVersion(version="2.32.4", released_on=datetime(2025, 6, 9).date()),),
            source="pypi",
            metadata_url="https://pypi.org/pypi/requests/json",
        ),
        fetched_at=datetime(2026, 6, 6, tzinfo=UTC),
        expires_at=datetime(2026, 6, 7, tzinfo=UTC),
    )

    cache.save(record)
    loaded = cache.load(Ecosystem.PYTHON, "requests")

    assert loaded == record


def test_cache_overwrites_existing_rows(tmp_path) -> None:
    cache = SQLitePackageCache(tmp_path / "registry.sqlite3")
    original = CachedPackageMetadata(
        package_metadata=PackageMetadata(
            package="requests",
            ecosystem=Ecosystem.PYTHON,
            versions=(PackageVersion(version="2.32.3", released_on=datetime(2024, 5, 29).date()),),
            source="pypi",
            metadata_url="https://pypi.org/pypi/requests/json",
        ),
        fetched_at=datetime(2026, 6, 6, tzinfo=UTC),
        expires_at=datetime(2026, 6, 6, 12, tzinfo=UTC),
    )
    replacement = original.model_copy(
        update={
            "package_metadata": original.package_metadata.model_copy(
                update={
                    "versions": (
                        PackageVersion(
                            version="2.32.4",
                            released_on=datetime(2025, 6, 9).date(),
                        ),
                    )
                }
            ),
            "expires_at": original.expires_at + timedelta(hours=24),
        }
    )

    cache.save(original)
    cache.save(replacement)

    loaded = cache.load(Ecosystem.PYTHON, "requests")
    assert loaded == replacement
