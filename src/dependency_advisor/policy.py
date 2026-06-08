"""Recommendation policy engine backed by registry metadata and caching."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime, time
from typing import Protocol

import httpx
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from dependency_advisor.cache import SQLitePackageCache
from dependency_advisor.config import AdvisorConfig
from dependency_advisor.models import (
    CachedPackageMetadata,
    CacheStatus,
    Ecosystem,
    PackageLookupResult,
    PackageMetadata,
    PackageVersion,
    PolicyMode,
    RecommendationProvenance,
    RecommendationRequest,
    RecommendationResult,
    RecommendationStatus,
    VulnerabilitySource,
)
from dependency_advisor.registry import (
    AdapterFactory,
    RegistryAdapter,
    default_registry_adapter_factories,
    normalize_package_name,
)
from dependency_advisor.vulnerabilities import (
    BootstrapVulnerabilityProvider,
    VulnerabilityProvider,
)

BUILTIN_CATALOG: dict[tuple[Ecosystem, str], PackageMetadata | tuple[PackageVersion, ...]] = {
    (
        Ecosystem.PYTHON,
        "requests",
    ): PackageMetadata(
        package="requests",
        ecosystem=Ecosystem.PYTHON,
        versions=(
            PackageVersion(version="2.32.4", released_on=date(2025, 6, 9)),
            PackageVersion(version="2.32.3", released_on=date(2024, 5, 29)),
            PackageVersion(version="2.31.0", released_on=date(2023, 5, 22)),
            PackageVersion(version="2.30.0", released_on=date(2023, 5, 3), blocked=True),
        ),
        source="builtin-catalog",
        metadata_url="builtin://catalog/requests",
    ),
    (
        Ecosystem.RUST,
        "serde",
    ): (
        PackageVersion(version="1.0.220", released_on=date(2025, 4, 18)),
        PackageVersion(version="1.0.219", released_on=date(2025, 3, 11)),
        PackageVersion(version="1.0.218", released_on=date(2025, 2, 6)),
    ),
    (
        Ecosystem.JAVASCRIPT,
        "minimist",
    ): (
        PackageVersion(version="1.2.9", released_on=date(2025, 4, 8)),
        PackageVersion(version="1.2.8", released_on=date(2025, 3, 6)),
    ),
}


def _reference_now(today: date | None) -> datetime:
    if today is None:
        return datetime.now(tz=UTC)
    return datetime.combine(today, time.min, tzinfo=UTC)


class RegistrySourceError(RuntimeError):
    """Raised when a registry fetch fails without a usable fallback."""


class PackageMetadataSource(Protocol):
    """Lookup contract for normalized package metadata."""

    async def lookup(
        self,
        ecosystem: Ecosystem,
        package: str,
        *,
        now: datetime,
    ) -> PackageLookupResult | None:
        """Return package metadata for an ecosystem package pair."""


class BuiltinCatalogSource:
    """Small offline fallback source preserved from Phase 1."""

    async def lookup(
        self,
        ecosystem: Ecosystem,
        package: str,
        *,
        now: datetime,
    ) -> PackageLookupResult | None:
        _unused = now
        metadata = BUILTIN_CATALOG.get((ecosystem, package))
        if metadata is None:
            return None
        if isinstance(metadata, PackageMetadata):
            package_metadata = metadata
        else:
            package_metadata = PackageMetadata(
                package=package,
                ecosystem=ecosystem,
                versions=metadata,
                source="builtin-catalog",
                metadata_url=f"builtin://catalog/{package}",
            )
        return PackageLookupResult(package_metadata=package_metadata)


class CompositePackageMetadataSource:
    """Lookup package metadata from sources in priority order."""

    def __init__(self, sources: Sequence[PackageMetadataSource]) -> None:
        self._sources = tuple(sources)

    async def lookup(
        self,
        ecosystem: Ecosystem,
        package: str,
        *,
        now: datetime,
    ) -> PackageLookupResult | None:
        for source in self._sources:
            try:
                result = await source.lookup(ecosystem, package, now=now)
            except RegistrySourceError:
                continue
            if result is not None:
                return result
        return None


class CachedRegistrySource:
    """Load package metadata from cache first, then refresh from a registry."""

    def __init__(
        self,
        config: AdvisorConfig,
        *,
        cache: SQLitePackageCache | None = None,
        adapter_factories: Mapping[Ecosystem, AdapterFactory] | None = None,
    ) -> None:
        self._config = config
        self._cache = cache
        if self._cache is None:
            try:
                self._cache = SQLitePackageCache(config.registry.cache_path)
            except (OSError, sqlite3.Error, ValueError):
                self._cache = None
        self._adapter_factories = dict(
            adapter_factories or default_registry_adapter_factories(config.registry)
        )

    async def lookup(
        self,
        ecosystem: Ecosystem,
        package: str,
        *,
        now: datetime,
    ) -> PackageLookupResult | None:
        normalized_package = normalize_package_name(ecosystem, package)
        cached_record = self._load_cached_record(ecosystem, normalized_package)
        if cached_record is not None and cached_record.expires_at >= now:
            return self._lookup_from_cache(cached_record, CacheStatus.HIT)

        adapter_factory = self._adapter_factories.get(ecosystem)
        if adapter_factory is None:
            return self._lookup_stale_if_available(cached_record)

        try:
            fresh_metadata = await self._fetch_from_registry(
                adapter_factory,
                normalized_package,
            )
        except Exception as error:
            if cached_record is not None and self._config.registry.allow_stale_on_error:
                return self._lookup_from_cache(cached_record, CacheStatus.STALE)
            raise RegistrySourceError(str(error)) from error

        if fresh_metadata is None:
            return None

        cached_fresh_metadata = CachedPackageMetadata(
            package_metadata=fresh_metadata,
            fetched_at=now,
            expires_at=now + self._config.registry.cache_ttl,
        )
        self._save_cached_record(cached_fresh_metadata)
        cache_status = CacheStatus.MISS if cached_record is None else CacheStatus.REFRESH
        return self._lookup_from_cache(cached_fresh_metadata, cache_status)

    async def _fetch_from_registry(
        self,
        adapter_factory: AdapterFactory,
        package: str,
    ) -> PackageMetadata | None:
        async with httpx.AsyncClient(
            timeout=self._config.registry.timeout_seconds,
            headers={"User-Agent": self._config.registry.user_agent},
        ) as client:
            adapter: RegistryAdapter = adapter_factory(client)
            return await adapter.fetch(package)

    def _lookup_from_cache(
        self,
        record: CachedPackageMetadata,
        cache_status: CacheStatus,
    ) -> PackageLookupResult:
        metadata = record.package_metadata
        provenance = RecommendationProvenance(
            source=metadata.source,
            metadata_url=metadata.metadata_url,
            fetched_at=record.fetched_at,
            expires_at=record.expires_at,
            cache_status=cache_status,
        )
        return PackageLookupResult(package_metadata=metadata, provenance=provenance)

    def _lookup_stale_if_available(
        self,
        cached_record: CachedPackageMetadata | None,
    ) -> PackageLookupResult | None:
        if cached_record is None:
            return None
        return self._lookup_from_cache(cached_record, CacheStatus.STALE)

    def _load_cached_record(
        self,
        ecosystem: Ecosystem,
        package: str,
    ) -> CachedPackageMetadata | None:
        if self._cache is None:
            return None
        try:
            return self._cache.load(ecosystem, package)
        except (OSError, sqlite3.Error, ValueError):
            return None

    def _save_cached_record(self, record: CachedPackageMetadata) -> None:
        if self._cache is None:
            return
        try:
            self._cache.save(record)
        except (OSError, sqlite3.Error, ValueError):
            return


class DependencyAdvisor:
    """Evaluate dependency candidates against policy settings."""

    def __init__(
        self,
        config: AdvisorConfig | None = None,
        *,
        metadata_source: PackageMetadataSource | None = None,
        vulnerability_provider: VulnerabilityProvider | None = None,
    ) -> None:
        self._config = config or AdvisorConfig()
        self._metadata_source = metadata_source or CompositePackageMetadataSource(
            (
                CachedRegistrySource(self._config),
                BuiltinCatalogSource(),
            )
        )
        self._vulnerability_provider = vulnerability_provider or BootstrapVulnerabilityProvider()

    async def arecommend(
        self,
        package: str,
        *,
        ecosystem: Ecosystem = Ecosystem.PYTHON,
        policy: PolicyMode | None = None,
        version_range: str | None = None,
        today: date | None = None,
    ) -> RecommendationResult:
        """Return a structured recommendation for a dependency."""

        request = RecommendationRequest(
            package=package.strip(),
            ecosystem=ecosystem,
            policy=policy or self._config.default_policy,
            version_range=version_range,
        )
        normalized_package = normalize_package_name(request.ecosystem, request.package)
        reference_now = _reference_now(today)
        lookup = await self._metadata_source.lookup(
            request.ecosystem,
            normalized_package,
            now=reference_now,
        )
        minimum_age_hours = self._config.minimum_release_age_hours(request.policy)

        if lookup is None:
            return RecommendationResult(
                package=normalized_package,
                ecosystem=request.ecosystem,
                policy=request.policy,
                status=RecommendationStatus.UNKNOWN_PACKAGE,
                reason="Package is not available from configured metadata sources.",
                candidates_considered=0,
                minimum_release_age_hours=minimum_age_hours,
                source="unknown",
                advisory_sources=(),
            )

        candidates = lookup.package_metadata.versions
        try:
            assessed_candidates = self._vulnerability_provider.enrich_candidates(
                request.ecosystem,
                normalized_package,
                candidates,
            )
        except Exception:
            assessed_candidates = candidates
        advisory_sources = self._decision_advisory_sources(assessed_candidates)
        eligible = [
            candidate
            for candidate in assessed_candidates
            if self._is_allowed(
                candidate,
                policy=request.policy,
                reference_date=reference_now.date(),
                version_range=request.version_range,
            )
        ]

        if not eligible:
            reason = (
                "No candidate satisfied version-range and safety policy checks."
                if request.version_range is not None
                else "No candidate satisfied safety and release-age policy checks."
            )
            return RecommendationResult(
                package=normalized_package,
                ecosystem=request.ecosystem,
                policy=request.policy,
                status=RecommendationStatus.BLOCKED,
                reason=reason,
                candidates_considered=len(assessed_candidates),
                minimum_release_age_hours=minimum_age_hours,
                source=lookup.package_metadata.source,
                provenance=lookup.provenance,
                advisory_sources=advisory_sources,
            )

        selected = max(eligible, key=lambda candidate: candidate.released_on)
        return RecommendationResult(
            package=normalized_package,
            ecosystem=request.ecosystem,
            policy=request.policy,
            status=RecommendationStatus.RECOMMENDED,
            recommended_version=selected.version,
            reason="Selected newest candidate that satisfies policy checks.",
            candidates_considered=len(assessed_candidates),
            minimum_release_age_hours=minimum_age_hours,
            source=lookup.package_metadata.source,
            provenance=lookup.provenance,
            advisory_sources=advisory_sources,
        )

    def recommend(
        self,
        package: str,
        *,
        ecosystem: Ecosystem = Ecosystem.PYTHON,
        policy: PolicyMode | None = None,
        version_range: str | None = None,
        today: date | None = None,
    ) -> RecommendationResult:
        """Return a structured recommendation for a dependency."""

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self.arecommend(
                    package,
                    ecosystem=ecosystem,
                    policy=policy,
                    version_range=version_range,
                    today=today,
                )
            )
        raise RuntimeError(
            "DependencyAdvisor.recommend() cannot run inside an active event loop; "
            "use arecommend() instead."
        )

    def _is_allowed(
        self,
        candidate: PackageVersion,
        *,
        policy: PolicyMode,
        reference_date: date,
        version_range: str | None,
    ) -> bool:
        release_age = reference_date - candidate.released_on
        minimum_age = self._config.policy_release_ages[policy]
        return (
            self._matches_version_range(candidate, version_range)
            and not candidate.vulnerable
            and not candidate.yanked
            and not candidate.deprecated
            and not candidate.blocked
            and release_age >= minimum_age
        )

    def _matches_version_range(self, candidate: PackageVersion, version_range: str | None) -> bool:
        if version_range is None:
            return True
        try:
            return SpecifierSet(version_range).contains(
                Version(candidate.version),
            )
        except InvalidVersion:
            return False

    def _decision_advisory_sources(
        self,
        candidates: tuple[PackageVersion, ...],
    ) -> tuple[VulnerabilitySource, ...]:
        seen: set[VulnerabilitySource] = set()
        ordered_sources: list[VulnerabilitySource] = []
        for candidate in candidates:
            for source in candidate.advisory_sources:
                if source not in seen:
                    seen.add(source)
                    ordered_sources.append(source)
        return tuple(ordered_sources)


def recommend(
    package: str,
    *,
    ecosystem: Ecosystem = Ecosystem.PYTHON,
    policy: PolicyMode = PolicyMode.STANDARD,
    version_range: str | None = None,
) -> RecommendationResult:
    """Return a dependency recommendation using default configuration."""

    return DependencyAdvisor().recommend(
        package,
        ecosystem=ecosystem,
        policy=policy,
        version_range=version_range,
    )
