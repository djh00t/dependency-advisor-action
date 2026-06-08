"""Bootstrap vulnerability and audit-source normalization."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from dependency_advisor.models import Ecosystem, PackageVersion, VulnerabilitySource


class VulnerabilityProvider(Protocol):
    """Lookup vulnerability sources for package versions."""

    def advisory_sources_for(
        self, ecosystem: Ecosystem, package: str, version: str
    ) -> tuple[VulnerabilitySource, ...]: ...

    def enrich_candidates(
        self,
        ecosystem: Ecosystem,
        package: str,
        candidates: Iterable[PackageVersion],
    ) -> tuple[PackageVersion, ...]: ...


BOOTSTRAP_ADVISORY_CATALOG: dict[tuple[Ecosystem, str, str], tuple[VulnerabilitySource, ...]] = {
    (
        Ecosystem.PYTHON,
        "requests",
        "2.32.4",
    ): (
        VulnerabilitySource.OSV,
        VulnerabilitySource.PIP_AUDIT,
    ),
    (
        Ecosystem.RUST,
        "serde",
        "1.0.220",
    ): (
        VulnerabilitySource.OSV,
        VulnerabilitySource.CARGO_DENY,
    ),
    (
        Ecosystem.JAVASCRIPT,
        "minimist",
        "1.2.9",
    ): (
        VulnerabilitySource.OSV,
        VulnerabilitySource.NPM_AUDIT,
    ),
    (
        Ecosystem.JAVASCRIPT,
        "minimist",
        "1.2.8",
    ): (
        VulnerabilitySource.OSV,
        VulnerabilitySource.NPM_AUDIT,
    ),
}


class BootstrapVulnerabilityProvider:
    """Return fixture-backed advisory data for the bootstrap Phase 3 slice."""

    def advisory_sources_for(
        self, ecosystem: Ecosystem, package: str, version: str
    ) -> tuple[VulnerabilitySource, ...]:
        """Return normalized upstream sources for a candidate version."""

        return BOOTSTRAP_ADVISORY_CATALOG.get((ecosystem, package, version), ())

    def enrich_candidates(
        self,
        ecosystem: Ecosystem,
        package: str,
        candidates: Iterable[PackageVersion],
    ) -> tuple[PackageVersion, ...]:
        """Return candidates with derived vulnerability metadata attached."""

        normalized_package = package.strip().lower()
        return tuple(
            candidate.model_copy(
                update={
                    "vulnerable": bool(
                        advisory_sources := self.advisory_sources_for(
                            ecosystem,
                            normalized_package,
                            candidate.version,
                        )
                    ),
                    "advisory_sources": advisory_sources,
                }
            )
            for candidate in candidates
        )
