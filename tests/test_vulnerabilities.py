from datetime import date

from dependency_advisor.models import Ecosystem, PackageVersion, VulnerabilitySource
from dependency_advisor.vulnerabilities import BootstrapVulnerabilityProvider


def test_bootstrap_provider_normalizes_python_advisory_sources() -> None:
    provider = BootstrapVulnerabilityProvider()

    assert provider.advisory_sources_for(Ecosystem.PYTHON, "requests", "2.32.4") == (
        VulnerabilitySource.OSV,
        VulnerabilitySource.PIP_AUDIT,
    )


def test_bootstrap_provider_marks_vulnerable_candidates() -> None:
    provider = BootstrapVulnerabilityProvider()
    candidates = (
        PackageVersion(version="1.2.9", released_on=date(2025, 4, 8)),
        PackageVersion(version="1.2.7", released_on=date(2025, 1, 8)),
    )

    enriched = provider.enrich_candidates(Ecosystem.JAVASCRIPT, "minimist", candidates)

    assert enriched[0].vulnerable is True
    assert enriched[0].advisory_sources == (
        VulnerabilitySource.OSV,
        VulnerabilitySource.NPM_AUDIT,
    )
    assert enriched[1].vulnerable is False
    assert enriched[1].advisory_sources == ()
