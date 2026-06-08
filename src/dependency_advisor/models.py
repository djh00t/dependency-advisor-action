"""Typed models for dependency recommendations, repository scans and fast validation."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Ecosystem(StrEnum):
    """Supported package ecosystems."""

    PYTHON = "python"
    RUST = "rust"
    JAVASCRIPT = "javascript"
    SHELL = "shell"
    SWIFT = "swift"


class PolicyMode(StrEnum):
    """Release-age policy modes."""

    LOCO = "loco"
    AGGRESSIVE = "aggressive"
    STANDARD = "standard"
    CONSERVATIVE = "conservative"


def normalize_version_range(ecosystem: Ecosystem, value: str) -> str:
    """Normalize and validate a version range for an ecosystem."""

    if ecosystem is Ecosystem.PYTHON:
        try:
            SpecifierSet(value)
        except InvalidSpecifier as error:
            raise ValueError(f"Invalid version range: {value}") from error
        return value

    clauses = [clause.strip() for clause in value.split(",")]
    if any(not clause for clause in clauses):
        raise ValueError(f"Invalid version range: {value}")

    normalized_clauses: list[str] = []
    for clause in clauses:
        normalized_clauses.extend(_normalize_non_python_clause(clause))

    normalized_value = ",".join(normalized_clauses)
    try:
        SpecifierSet(normalized_value)
    except InvalidSpecifier as error:
        raise ValueError(f"Invalid version range: {value}") from error
    return normalized_value


def _normalize_non_python_clause(clause: str) -> list[str]:
    if clause.startswith("^"):
        base_version = _parse_version(clause[1:].strip())
        return [f">={base_version}", f"<{_caret_upper_bound(base_version)}"]

    for operator in (">=", "<=", "==", ">", "<", "="):
        if clause.startswith(operator):
            version_text = clause[len(operator) :].strip()
            if not version_text:
                raise ValueError(f"Invalid version range: {clause}")
            version = _parse_version(version_text)
            normalized_operator = "==" if operator == "=" else operator
            return [f"{normalized_operator}{version}"]

    version = _parse_version(clause)
    return [f"=={version}"]


def _parse_version(value: str) -> Version:
    try:
        return Version(value)
    except InvalidVersion as error:
        raise ValueError(f"Invalid version range: {value}") from error


def _caret_upper_bound(version: Version) -> Version:
    release = version.release
    major = release[0] if release else 0
    minor = release[1] if len(release) > 1 else 0
    patch = release[2] if len(release) > 2 else 0
    if major > 0:
        return Version(f"{major + 1}.0.0")
    if minor > 0:
        return Version(f"0.{minor + 1}.0")
    return Version(f"0.0.{patch + 1}")


class RecommendationStatus(StrEnum):
    """Recommendation outcome status."""

    RECOMMENDED = "recommended"
    BLOCKED = "blocked"
    UNKNOWN_PACKAGE = "unknown_package"


class VulnerabilitySource(StrEnum):
    """Supported upstream advisory and audit sources."""

    OSV = "osv"
    CARGO_DENY = "cargo-deny"
    PIP_AUDIT = "pip-audit"
    NPM_AUDIT = "npm-audit"


class CacheStatus(StrEnum):
    """How registry metadata was sourced for a recommendation."""

    HIT = "hit"
    MISS = "miss"
    REFRESH = "refresh"
    STALE = "stale"


class PackageVersion(BaseModel):
    """A candidate package version from a package source."""

    model_config = ConfigDict(frozen=True)

    version: str
    released_on: date
    vulnerable: bool = False
    advisory_sources: tuple[VulnerabilitySource, ...] = ()
    yanked: bool = False
    deprecated: bool = False
    blocked: bool = False


class RecommendationRequest(BaseModel):
    """Input for a dependency recommendation."""

    package: str = Field(min_length=1)
    ecosystem: Ecosystem = Ecosystem.PYTHON
    policy: PolicyMode = PolicyMode.STANDARD
    version_range: str | None = None

    @field_validator("package", mode="before")
    @classmethod
    def _normalize_package(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("version_range", mode="before")
    @classmethod
    def _normalize_version_range(cls, value: object) -> object:
        if value is None:
            return None
        if isinstance(value, str):
            normalized = value.strip()
            return normalized or None
        return value

    @field_validator("version_range")
    @classmethod
    def _validate_version_range(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value

    @model_validator(mode="after")
    def _validate_version_range_for_ecosystem(self) -> RecommendationRequest:
        if self.version_range is None:
            return self
        self.version_range = normalize_version_range(self.ecosystem, self.version_range)
        return self


class PackageMetadata(BaseModel):
    """Normalized registry metadata for a package."""

    model_config = ConfigDict(frozen=True)

    package: str
    ecosystem: Ecosystem
    versions: tuple[PackageVersion, ...]
    source: str
    metadata_url: str


class CachedPackageMetadata(BaseModel):
    """Persisted package metadata with cache freshness timestamps."""

    model_config = ConfigDict(frozen=True)

    package_metadata: PackageMetadata
    fetched_at: datetime
    expires_at: datetime


class RecommendationProvenance(BaseModel):
    """Source and cache metadata for a recommendation."""

    model_config = ConfigDict(frozen=True)

    source: str
    metadata_url: str | None = None
    fetched_at: datetime | None = None
    expires_at: datetime | None = None
    cache_status: CacheStatus | None = None


class PackageLookupResult(BaseModel):
    """Registry lookup result used by the recommendation engine."""

    model_config = ConfigDict(frozen=True)

    package_metadata: PackageMetadata
    provenance: RecommendationProvenance | None = None


class RecommendationResult(BaseModel):
    """Structured recommendation returned by the advisor."""

    package: str
    ecosystem: Ecosystem
    policy: PolicyMode
    status: RecommendationStatus
    recommended_version: str | None = None
    reason: str
    candidates_considered: int
    minimum_release_age_hours: int
    source: str
    provenance: RecommendationProvenance | None = None
    advisory_sources: tuple[VulnerabilitySource, ...] = ()


class ManifestDependency(BaseModel):
    """A direct dependency discovered in a repository manifest."""

    model_config = ConfigDict(frozen=True)

    package: str
    ecosystem: Ecosystem = Ecosystem.PYTHON
    manifest_path: str
    requirement: str
    line: int | None = None


class RepositoryDependencyResult(BaseModel):
    """Recommendation outcome for a dependency discovered during a repository scan."""

    model_config = ConfigDict(frozen=True)

    package: str
    ecosystem: Ecosystem
    manifest_path: str
    requirement: str
    line: int | None = None
    status: RecommendationStatus
    recommended_version: str | None = None
    reason: str
    candidates_considered: int
    minimum_release_age_hours: int
    source: str


class RepositoryScanSummary(BaseModel):
    """Summary counts for a repository scan."""

    model_config = ConfigDict(frozen=True)

    manifests_scanned: int
    dependencies_scanned: int
    findings: int
    status_counts: dict[RecommendationStatus, int]


class RepositoryScanReport(BaseModel):
    """Structured repository dependency scan report."""

    model_config = ConfigDict(frozen=True)

    root_path: str
    scanned_at: datetime
    policy: PolicyMode
    manifests_scanned: list[str]
    results: list[RepositoryDependencyResult]
    summary: RepositoryScanSummary


class FastValidationStatus(StrEnum):
    """Overall outcome status for fast manifest validation."""

    OK = "ok"
    BLOCKED = "blocked"
    NO_MANIFEST_CHANGES = "no_manifest_changes"


class FastValidationFinding(BaseModel):
    """Recommendation outcome for one dependency in a manifest validation run."""

    manifest_path: str
    line: int | None = None
    package: str
    status: RecommendationStatus
    recommended_version: str | None = None
    reason: str


class FastValidationResult(BaseModel):
    """Structured result returned by fast manifest validation."""

    status: FastValidationStatus
    changed_files: tuple[str, ...] = ()
    manifest_paths: tuple[str, ...] = ()
    validated_scope: Literal["project.dependencies", "requirements.txt", "mixed"]
    validated_dependencies: int
    findings: tuple[FastValidationFinding, ...] = ()
    reason: str


class PreCommitValidationResult(BaseModel):
    """Structured result returned by the pre-commit entrypoint."""

    model_config = ConfigDict(frozen=True)

    status: FastValidationStatus
    source: Literal["staged", "files"]
    changed_files: tuple[str, ...] = ()
    manifest_paths: tuple[str, ...] = ()
    validated_scope: Literal["project.dependencies", "requirements.txt", "mixed"]
    validated_dependencies: int
    findings: tuple[FastValidationFinding, ...] = ()
    reason: str
