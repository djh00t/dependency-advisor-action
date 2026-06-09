from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import date, datetime, timedelta
from time import perf_counter
from typing import cast

import httpx
import pytest
from pydantic import ValidationError

import dependency_advisor.policy as policy_module
from dependency_advisor.config import AdvisorConfig, RegistryConfig
from dependency_advisor.models import (
    CacheStatus,
    Ecosystem,
    PackageLookupResult,
    PackageMetadata,
    PackageVersion,
    PolicyMode,
    RecommendationResult,
    RecommendationStatus,
    VulnerabilitySource,
)
from dependency_advisor.policy import (
    BuiltinCatalogSource,
    CachedRegistrySource,
    CompositePackageMetadataSource,
    DependencyAdvisor,
    recommend,
)


class FakeRegistryAdapter:
    ecosystem = Ecosystem.PYTHON

    def __init__(self, responses: list[PackageMetadata | None | Exception]) -> None:
        self._responses = responses
        self.calls = 0

    async def fetch(self, package: str) -> PackageMetadata | None:
        self.calls += 1
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class BrokenCache:
    def __init__(
        self,
        *,
        load_error: Exception | None = None,
        save_error: Exception | None = None,
    ) -> None:
        self._load_error = load_error
        self._save_error = save_error

    def load(self, ecosystem: Ecosystem, package: str):
        _unused = (ecosystem, package)
        if self._load_error is not None:
            raise self._load_error
        return None

    def save(self, record) -> None:
        _unused = record
        if self._save_error is not None:
            raise self._save_error


def _package_metadata(*versions: PackageVersion) -> PackageMetadata:
    return PackageMetadata(
        package="requests",
        ecosystem=Ecosystem.PYTHON,
        versions=versions,
        source="pypi",
        metadata_url="https://pypi.org/pypi/requests/json",
    )


def _config(tmp_path, **registry_updates: object) -> AdvisorConfig:
    registry = RegistryConfig(
        cache_path=tmp_path / "registry.sqlite3",
        **registry_updates,
    )
    return AdvisorConfig(registry=registry)


def _advisor_for_adapter(
    tmp_path,
    adapter: FakeRegistryAdapter,
    *,
    vulnerability_provider=None,
    **registry_updates: object,
) -> DependencyAdvisor:
    config = _config(tmp_path, **registry_updates)
    source = CompositePackageMetadataSource(
        (
            CachedRegistrySource(
                config,
                adapter_factories={Ecosystem.PYTHON: lambda client: adapter},
            ),
        )
    )
    return DependencyAdvisor(
        config=config,
        metadata_source=source,
        vulnerability_provider=vulnerability_provider,
    )


class StaticMetadataSource:
    def __init__(self, package_metadata: PackageMetadata) -> None:
        self._package_metadata = package_metadata

    async def lookup(
        self,
        ecosystem: Ecosystem,
        package: str,
        *,
        now: datetime,
    ) -> PackageLookupResult | None:
        _unused = (ecosystem, package, now)
        return PackageLookupResult(package_metadata=self._package_metadata)


class NoopVulnerabilityProvider:
    def advisory_sources_for(
        self, ecosystem: Ecosystem, package: str, version: str
    ) -> tuple[VulnerabilitySource, ...]:
        _unused = (ecosystem, package, version)
        return ()

    def enrich_candidates(
        self,
        ecosystem: Ecosystem,
        package: str,
        candidates: Iterable[PackageVersion],
    ) -> tuple[PackageVersion, ...]:
        _unused = (ecosystem, package)
        return tuple(candidates)


def test_recommends_requests_for_standard_policy() -> None:
    result = DependencyAdvisor().recommend("requests", today=date(2026, 6, 6))

    assert result.status is RecommendationStatus.RECOMMENDED
    assert result.recommended_version == "2.34.2"
    assert result.minimum_release_age_hours == 336
    assert result.candidates_considered == 160
    assert result.advisory_sources == (
        VulnerabilitySource.OSV,
        VulnerabilitySource.PIP_AUDIT,
    )


def test_normalizes_package_names() -> None:
    result = DependencyAdvisor().recommend(" Requests ", today=date(2026, 6, 6))

    assert result.package == "requests"
    assert result.recommended_version == "2.34.2"


def test_unknown_package_returns_structured_result() -> None:
    result = DependencyAdvisor().recommend(" Not-A-Real-Bootstrap-Package ")

    assert result.status is RecommendationStatus.UNKNOWN_PACKAGE
    assert result.package == "not-a-real-bootstrap-package"
    assert result.recommended_version is None
    assert result.candidates_considered == 0


def test_whitespace_only_package_is_invalid() -> None:
    with pytest.raises(ValidationError):
        DependencyAdvisor().recommend("   ")


def test_policy_release_age_can_exclude_new_candidates() -> None:
    result = DependencyAdvisor().recommend(
        "requests",
        policy=PolicyMode.CONSERVATIVE,
        today=date(2025, 6, 20),
    )

    assert result.status is RecommendationStatus.RECOMMENDED
    assert result.recommended_version == "2.32.3"


def test_no_match_when_every_candidate_is_too_new() -> None:
    result = DependencyAdvisor().recommend(
        "requests",
        policy=PolicyMode.CONSERVATIVE,
        today=date(2000, 1, 1),
    )

    assert result.status is RecommendationStatus.BLOCKED
    assert result.recommended_version is None
    assert "release-age" in result.reason


def test_version_range_can_select_an_older_candidate() -> None:
    result = DependencyAdvisor().recommend(
        "requests",
        version_range="<2.32",
        today=date(2026, 6, 6),
    )

    assert result.status is RecommendationStatus.RECOMMENDED
    assert result.recommended_version == "2.31.0"


def test_version_range_does_not_force_prereleases(monkeypatch: pytest.MonkeyPatch) -> None:
    from dependency_advisor import policy as policy_module_local

    monkeypatch.setattr(
        policy_module_local,
        "BUILTIN_CATALOG",
        {
            (
                Ecosystem.PYTHON,
                "requests",
            ): (
                PackageVersion(version="2.33.0rc1", released_on=date(2026, 5, 1)),
                PackageVersion(version="2.32.4", released_on=date(2025, 6, 9)),
            )
        },
    )

    result = DependencyAdvisor(
        metadata_source=BuiltinCatalogSource(),
        vulnerability_provider=NoopVulnerabilityProvider(),
    ).recommend(
        "requests",
        version_range="<2.34",
        today=date(2026, 6, 6),
    )

    assert result.status is RecommendationStatus.RECOMMENDED
    assert result.recommended_version == "2.32.4"


def test_vulnerability_provider_failure_blocks_recommendation() -> None:
    class ExplodingProvider:
        def advisory_sources_for(
            self, ecosystem: Ecosystem, package: str, version: str
        ) -> tuple[VulnerabilitySource, ...]:
            _unused = (ecosystem, package, version)
            raise RuntimeError("provider boom")

        def enrich_candidates(
            self,
            ecosystem: Ecosystem,
            package: str,
            candidates: Iterable[PackageVersion],
        ) -> tuple[PackageVersion, ...]:
            _unused = (ecosystem, package, candidates)
            raise RuntimeError("provider boom")

    result = DependencyAdvisor(
        metadata_source=BuiltinCatalogSource(),
        vulnerability_provider=ExplodingProvider(),
    ).recommend("requests", today=date(2026, 6, 6))

    assert result.status is RecommendationStatus.RECOMMENDED
    assert result.recommended_version == "2.32.4"
    assert result.advisory_sources == ()


def test_version_range_can_block_when_no_candidate_matches() -> None:
    result = DependencyAdvisor().recommend(
        "requests",
        version_range=">3",
        today=date(2026, 6, 6),
    )

    assert result.status is RecommendationStatus.BLOCKED
    assert result.recommended_version is None
    assert "version-range" in result.reason


def test_version_range_can_select_a_javascript_caret_range() -> None:
    metadata = PackageMetadata(
        package="react",
        ecosystem=Ecosystem.JAVASCRIPT,
        versions=(
            PackageVersion(version="19.0.0", released_on=date(2025, 6, 1)),
            PackageVersion(version="18.1.0", released_on=date(2025, 5, 1)),
            PackageVersion(version="17.0.2", released_on=date(2024, 12, 1)),
        ),
        source="npm",
        metadata_url="https://registry.npmjs.org/react",
    )
    advisor = DependencyAdvisor(
        metadata_source=StaticMetadataSource(metadata),
        vulnerability_provider=NoopVulnerabilityProvider(),
    )

    result = advisor.recommend(
        "react",
        ecosystem=Ecosystem.JAVASCRIPT,
        version_range="^18.0.0",
        today=date(2026, 6, 6),
    )

    assert result.status is RecommendationStatus.RECOMMENDED
    assert result.recommended_version == "18.1.0"
    assert result.source == "npm"


def test_invalid_version_range_is_rejected() -> None:
    with pytest.raises(ValidationError):
        DependencyAdvisor().recommend("requests", version_range="not-a-specifier")


def test_function_uses_default_advisor(monkeypatch) -> None:
    expected = RecommendationResult(
        package="requests",
        ecosystem=Ecosystem.PYTHON,
        policy=PolicyMode.STANDARD,
        status=RecommendationStatus.RECOMMENDED,
        recommended_version="2.32.4",
        reason="Selected newest candidate that satisfies policy checks.",
        candidates_considered=4,
        minimum_release_age_hours=336,
        source="builtin-catalog",
        advisory_sources=(VulnerabilitySource.OSV, VulnerabilitySource.PIP_AUDIT),
    )

    class StubAdvisor:
        def recommend(self, *args, **kwargs) -> RecommendationResult:
            _unused = (args, kwargs)
            return expected

    monkeypatch.setattr(policy_module, "DependencyAdvisor", lambda: cast(object, StubAdvisor()))

    result = recommend("requests", ecosystem=Ecosystem.PYTHON, policy=PolicyMode.STANDARD)
    assert result == expected


def test_recommends_safe_rust_version_after_cargo_deny_rejects_latest() -> None:
    result = DependencyAdvisor().recommend(
        "serde",
        ecosystem=Ecosystem.RUST,
        today=date(2026, 6, 6),
    )

    assert result.status is RecommendationStatus.RECOMMENDED
    assert result.recommended_version == "1.0.228"
    assert result.advisory_sources == (
        VulnerabilitySource.OSV,
        VulnerabilitySource.CARGO_DENY,
    )


def test_reports_javascript_advisory_sources() -> None:
    result = DependencyAdvisor().recommend(
        "minimist",
        ecosystem=Ecosystem.JAVASCRIPT,
        today=date(2026, 6, 6),
    )

    assert result.status is RecommendationStatus.RECOMMENDED
    assert result.recommended_version == "0.2.4"
    assert result.advisory_sources == (
        VulnerabilitySource.OSV,
        VulnerabilitySource.NPM_AUDIT,
    )


def test_config_reports_release_age_hours() -> None:
    assert AdvisorConfig().minimum_release_age_hours(PolicyMode.AGGRESSIVE) == 48


def test_config_policy_release_ages_are_immutable() -> None:
    config = AdvisorConfig()

    with pytest.raises(TypeError):
        config.policy_release_ages[PolicyMode.STANDARD] = timedelta(hours=1)


def test_registry_cache_miss_populates_provenance(tmp_path) -> None:
    adapter = FakeRegistryAdapter(
        [
            _package_metadata(
                PackageVersion(version="2.32.4", released_on=date(2025, 6, 9)),
                PackageVersion(version="2.30.0", released_on=date(2023, 5, 3), blocked=True),
            )
        ]
    )
    advisor = _advisor_for_adapter(
        tmp_path,
        adapter,
        vulnerability_provider=NoopVulnerabilityProvider(),
    )

    result = advisor.recommend("requests", today=date(2026, 6, 6))

    assert result.status is RecommendationStatus.RECOMMENDED
    assert result.source == "pypi"
    assert result.provenance is not None
    assert result.provenance.cache_status is CacheStatus.MISS
    assert adapter.calls == 1


def test_registry_cache_hit_avoids_refresh(tmp_path) -> None:
    adapter = FakeRegistryAdapter(
        [
            _package_metadata(
                PackageVersion(version="2.32.4", released_on=date(2025, 6, 9)),
            )
        ]
    )
    advisor = _advisor_for_adapter(
        tmp_path,
        adapter,
        vulnerability_provider=NoopVulnerabilityProvider(),
    )

    advisor.recommend("requests", today=date(2026, 6, 6))
    result = advisor.recommend("requests", today=date(2026, 6, 6))

    assert result.provenance is not None
    assert result.provenance.cache_status is CacheStatus.HIT
    assert adapter.calls == 1


def test_stale_cache_refreshes_metadata(tmp_path) -> None:
    adapter = FakeRegistryAdapter(
        [
            _package_metadata(
                PackageVersion(version="2.32.3", released_on=date(2024, 5, 29)),
            ),
            _package_metadata(
                PackageVersion(version="2.32.4", released_on=date(2025, 6, 9)),
            ),
        ]
    )
    advisor = _advisor_for_adapter(
        tmp_path,
        adapter,
        vulnerability_provider=NoopVulnerabilityProvider(),
        cache_ttl=timedelta(days=-1),
    )

    advisor.recommend("requests", today=date(2026, 6, 6))
    result = advisor.recommend("requests", today=date(2026, 6, 7))

    assert result.provenance is not None
    assert result.provenance.cache_status is CacheStatus.REFRESH
    assert result.recommended_version == "2.32.4"
    assert adapter.calls == 2


def test_stale_cache_falls_back_on_fetch_error(tmp_path) -> None:
    adapter = FakeRegistryAdapter(
        [
            _package_metadata(
                PackageVersion(version="2.32.3", released_on=date(2024, 5, 29)),
            ),
            httpx.ConnectError("boom"),
        ]
    )
    advisor = _advisor_for_adapter(
        tmp_path,
        adapter,
        vulnerability_provider=NoopVulnerabilityProvider(),
        cache_ttl=timedelta(days=-1),
    )

    advisor.recommend("requests", today=date(2026, 6, 6))
    result = advisor.recommend("requests", today=date(2026, 6, 7))

    assert result.recommended_version == "2.32.3"
    assert result.provenance is not None
    assert result.provenance.cache_status is CacheStatus.STALE
    assert adapter.calls == 2


def test_stale_cache_falls_back_on_adapter_parse_error(tmp_path) -> None:
    adapter = FakeRegistryAdapter(
        [
            _package_metadata(
                PackageVersion(version="2.32.3", released_on=date(2024, 5, 29)),
            ),
            ValueError("bad payload"),
        ]
    )
    advisor = _advisor_for_adapter(
        tmp_path,
        adapter,
        vulnerability_provider=NoopVulnerabilityProvider(),
        cache_ttl=timedelta(days=-1),
    )

    advisor.recommend("requests", today=date(2026, 6, 6))
    result = advisor.recommend("requests", today=date(2026, 6, 7))

    assert result.recommended_version == "2.32.3"
    assert result.provenance is not None
    assert result.provenance.cache_status is CacheStatus.STALE
    assert adapter.calls == 2


def test_cache_load_failure_degrades_to_registry_fetch(tmp_path) -> None:
    adapter = FakeRegistryAdapter(
        [
            _package_metadata(
                PackageVersion(version="2.32.4", released_on=date(2025, 6, 9)),
            )
        ]
    )
    config = _config(tmp_path)
    source = CompositePackageMetadataSource(
        (
            CachedRegistrySource(
                config,
                cache=BrokenCache(load_error=OSError("cache unavailable")),
                adapter_factories={Ecosystem.PYTHON: lambda client: adapter},
            ),
            BuiltinCatalogSource(),
        )
    )

    result = DependencyAdvisor(
        config=config,
        metadata_source=source,
        vulnerability_provider=NoopVulnerabilityProvider(),
    ).recommend(
        "requests",
        today=date(2026, 6, 6),
    )

    assert result.source == "pypi"
    assert adapter.calls == 1


def test_cache_save_failure_returns_fresh_metadata(tmp_path) -> None:
    adapter = FakeRegistryAdapter(
        [
            _package_metadata(
                PackageVersion(version="2.32.4", released_on=date(2025, 6, 9)),
            )
        ]
    )
    config = _config(tmp_path)
    source = CompositePackageMetadataSource(
        (
            CachedRegistrySource(
                config,
                cache=BrokenCache(save_error=OSError("disk full")),
                adapter_factories={Ecosystem.PYTHON: lambda client: adapter},
            ),
            BuiltinCatalogSource(),
        )
    )

    result = DependencyAdvisor(
        config=config,
        metadata_source=source,
        vulnerability_provider=NoopVulnerabilityProvider(),
    ).recommend(
        "requests",
        today=date(2026, 6, 6),
    )

    assert result.source == "pypi"
    assert result.provenance is not None
    assert result.provenance.cache_status is CacheStatus.MISS
    assert adapter.calls == 1


def test_default_advisor_falls_back_when_cache_init_fails(monkeypatch) -> None:
    def broken_cache(path) -> None:
        _unused = path
        raise OSError("cannot initialize cache")

    monkeypatch.setattr(policy_module, "SQLitePackageCache", broken_cache)
    monkeypatch.setattr(policy_module, "default_registry_adapter_factories", lambda config: {})

    result = DependencyAdvisor(vulnerability_provider=NoopVulnerabilityProvider()).recommend(
        "requests", today=date(2026, 6, 6)
    )

    assert result.source == "builtin-catalog"
    assert result.recommended_version == "2.32.4"


def test_recommend_raises_clear_error_in_active_event_loop() -> None:
    advisor = DependencyAdvisor(vulnerability_provider=NoopVulnerabilityProvider())

    async def run() -> None:
        with pytest.raises(RuntimeError, match="use arecommend\\(\\) instead"):
            advisor.recommend("requests", today=date(2026, 6, 6))

    asyncio.run(run())


def test_warm_cache_mean_latency_stays_below_target(tmp_path) -> None:
    adapter = FakeRegistryAdapter(
        [
            _package_metadata(
                PackageVersion(version="2.32.4", released_on=date(2025, 6, 9)),
            )
        ]
    )
    advisor = _advisor_for_adapter(
        tmp_path,
        adapter,
        vulnerability_provider=NoopVulnerabilityProvider(),
    )
    advisor.recommend("requests", today=date(2026, 6, 6))

    iterations = 200
    started = perf_counter()

    async def run_iterations() -> None:
        for _ in range(iterations):
            result = await advisor.arecommend("requests", today=date(2026, 6, 6))
            assert result.provenance is not None
            assert result.provenance.cache_status is CacheStatus.HIT

    asyncio.run(run_iterations())
    elapsed_ms = (perf_counter() - started) * 1000
    mean_ms = elapsed_ms / iterations

    assert adapter.calls == 1
    assert mean_ms < 25, f"expected mean <25ms, got {mean_ms:.3f}ms"
