"""Registry adapters for fetching normalized package metadata."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from dependency_advisor.config import RegistryConfig
from dependency_advisor.models import Ecosystem, PackageMetadata, PackageVersion

AdapterFactory = Callable[[httpx.AsyncClient], "RegistryAdapter"]

_PYPI_NORMALIZE_PATTERN = re.compile(r"[-_.]+")


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def normalize_package_name(ecosystem: Ecosystem, package: str) -> str:
    """Normalize package identity for cache keys and registry lookups."""

    normalized = package.strip()
    if ecosystem is Ecosystem.PYTHON:
        return _PYPI_NORMALIZE_PATTERN.sub("-", normalized).lower()
    if ecosystem in {Ecosystem.JAVASCRIPT, Ecosystem.RUST, Ecosystem.SWIFT}:
        return normalized.lower()
    return normalized


class RegistryAdapter(Protocol):
    """Registry adapter contract."""

    ecosystem: Ecosystem

    async def fetch(self, package: str) -> PackageMetadata | None:
        """Return normalized package metadata for a package."""


class PyPIRegistryAdapter:
    """Fetch package metadata from the PyPI JSON API."""

    ecosystem = Ecosystem.PYTHON

    def __init__(self, client: httpx.AsyncClient, *, base_url: str) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    async def fetch(self, package: str) -> PackageMetadata | None:
        encoded_package = quote(package, safe="")
        url = f"{self._base_url}/{encoded_package}/json"
        response = await self._client.get(url)
        if response.status_code == httpx.codes.NOT_FOUND:
            return None
        response.raise_for_status()
        payload = response.json()
        versions: list[PackageVersion] = []
        for version, files in payload.get("releases", {}).items():
            if not files:
                continue
            timestamps = [
                _parse_timestamp(file_info["upload_time_iso_8601"])
                for file_info in files
                if file_info.get("upload_time_iso_8601")
            ]
            if not timestamps:
                continue
            versions.append(
                PackageVersion(
                    version=version,
                    released_on=min(timestamps).date(),
                    yanked=any(bool(file_info.get("yanked")) for file_info in files),
                )
            )
        return PackageMetadata(
            package=package,
            ecosystem=self.ecosystem,
            versions=tuple(versions),
            source="pypi",
            metadata_url=url,
        )


class NPMRegistryAdapter:
    """Fetch package metadata from the npm registry API."""

    ecosystem = Ecosystem.JAVASCRIPT

    def __init__(self, client: httpx.AsyncClient, *, base_url: str) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    async def fetch(self, package: str) -> PackageMetadata | None:
        encoded_package = quote(package, safe="")
        url = f"{self._base_url}/{encoded_package}"
        response = await self._client.get(url)
        if response.status_code == httpx.codes.NOT_FOUND:
            return None
        response.raise_for_status()
        payload = response.json()
        version_times = payload.get("time", {})
        version_metadata = payload.get("versions", {})
        versions: list[PackageVersion] = []
        for version, raw_timestamp in version_times.items():
            if version in {"created", "modified"}:
                continue
            metadata = version_metadata.get(version)
            if metadata is None:
                continue
            versions.append(
                PackageVersion(
                    version=version,
                    released_on=_parse_timestamp(raw_timestamp).date(),
                    deprecated=bool(metadata.get("deprecated")),
                )
            )
        return PackageMetadata(
            package=package,
            ecosystem=self.ecosystem,
            versions=tuple(versions),
            source="npm",
            metadata_url=url,
        )


class CratesIORegistryAdapter:
    """Fetch package metadata from the crates.io API."""

    ecosystem = Ecosystem.RUST

    def __init__(self, client: httpx.AsyncClient, *, base_url: str) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    async def fetch(self, package: str) -> PackageMetadata | None:
        encoded_package = quote(package, safe="")
        url = f"{self._base_url}/{encoded_package}"
        response = await self._client.get(url)
        if response.status_code == httpx.codes.NOT_FOUND:
            return None
        response.raise_for_status()
        payload = response.json()
        versions = tuple(
            PackageVersion(
                version=version["num"],
                released_on=_parse_timestamp(version["created_at"]).date(),
                yanked=bool(version.get("yanked")),
            )
            for version in payload.get("versions", [])
            if version.get("created_at") and version.get("num")
        )
        return PackageMetadata(
            package=package,
            ecosystem=self.ecosystem,
            versions=versions,
            source="crates.io",
            metadata_url=url,
        )


class SwiftRegistryAdapter:
    """Fetch package metadata from a Swift package registry."""

    ecosystem = Ecosystem.SWIFT

    def __init__(self, client: httpx.AsyncClient, *, base_url: str) -> None:
        self._client = client
        self._base_url = base_url.rstrip("/")

    async def fetch(self, package: str) -> PackageMetadata | None:
        scope, separator, name = package.partition(".")
        if separator == "" or not scope or not name:
            return None

        url = f"{self._base_url}/{quote(scope, safe='')}/{quote(name, safe='')}"
        response = await self._client.get(
            url,
            headers={"Accept": "application/vnd.swift.registry.v1+json"},
        )
        if response.status_code == httpx.codes.NOT_FOUND:
            return None
        response.raise_for_status()
        payload = response.json()
        releases = self._extract_swift_releases(payload)
        versions = tuple(
            PackageVersion(
                version=release["version"],
                released_on=_parse_timestamp(
                    release.get("publishedAt")
                    or release.get("metadata", {}).get("originalPublicationTime")
                ).date(),
            )
            for release in releases
            if release.get("version")
            and (
                release.get("publishedAt")
                or release.get("metadata", {}).get("originalPublicationTime")
            )
        )
        return PackageMetadata(
            package=package,
            ecosystem=self.ecosystem,
            versions=versions,
            source="swift-registry",
            metadata_url=url,
        )

    @staticmethod
    def _extract_swift_releases(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [release for release in payload if isinstance(release, dict)]
        if isinstance(payload, dict):
            if isinstance(payload.get("releases"), list):
                return [release for release in payload["releases"] if isinstance(release, dict)]
            if isinstance(payload.get("versions"), list):
                return [release for release in payload["versions"] if isinstance(release, dict)]
        return []


def default_registry_adapter_factories(
    config: RegistryConfig,
) -> Mapping[Ecosystem, AdapterFactory]:
    """Return the default adapter factories for configured ecosystems."""

    factories: dict[Ecosystem, AdapterFactory] = {
        Ecosystem.PYTHON: lambda client: PyPIRegistryAdapter(
            client,
            base_url=config.pypi_base_url,
        ),
        Ecosystem.JAVASCRIPT: lambda client: NPMRegistryAdapter(
            client,
            base_url=config.npm_base_url,
        ),
        Ecosystem.RUST: lambda client: CratesIORegistryAdapter(
            client,
            base_url=config.crates_base_url,
        ),
    }
    if config.swift_registry_base_url:
        factories[Ecosystem.SWIFT] = lambda client: SwiftRegistryAdapter(
            client,
            base_url=config.swift_registry_base_url or "",
        )
    return factories
