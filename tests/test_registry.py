import httpx
import pytest

from dependency_advisor.models import Ecosystem
from dependency_advisor.registry import (
    CratesIORegistryAdapter,
    NPMRegistryAdapter,
    PyPIRegistryAdapter,
    SwiftRegistryAdapter,
)

pytestmark = pytest.mark.anyio


def _json_response(payload: dict | list) -> httpx.Response:
    return httpx.Response(200, json=payload)


async def test_pypi_registry_adapter_parses_release_metadata() -> None:
    transport = httpx.MockTransport(
        lambda request: _json_response(
            {
                "releases": {
                    "2.32.4": [
                        {
                            "upload_time_iso_8601": "2025-06-09T00:00:00Z",
                            "yanked": False,
                        }
                    ],
                    "2.30.0": [
                        {
                            "upload_time_iso_8601": "2023-05-03T00:00:00Z",
                            "yanked": True,
                        }
                    ],
                }
            }
        )
    )

    async with httpx.AsyncClient(transport=transport) as client:
        metadata = await PyPIRegistryAdapter(
            client,
            base_url="https://pypi.example.test/pypi",
        ).fetch("requests")

    assert metadata is not None
    assert metadata.ecosystem is Ecosystem.PYTHON
    assert metadata.source == "pypi"
    assert metadata.versions[0].version == "2.32.4"
    assert metadata.versions[1].yanked is True


async def test_npm_registry_adapter_parses_release_timestamps() -> None:
    transport = httpx.MockTransport(
        lambda request: _json_response(
            {
                "time": {
                    "created": "2020-01-01T00:00:00Z",
                    "modified": "2026-01-01T00:00:00Z",
                    "1.0.0": "2023-03-01T00:00:00Z",
                    "1.1.0": "2024-06-01T00:00:00Z",
                },
                "versions": {
                    "1.0.0": {},
                    "1.1.0": {"deprecated": "use 2.x"},
                },
            }
        )
    )

    async with httpx.AsyncClient(transport=transport) as client:
        metadata = await NPMRegistryAdapter(
            client,
            base_url="https://registry.example.test",
        ).fetch("react")

    assert metadata is not None
    assert metadata.ecosystem is Ecosystem.JAVASCRIPT
    assert {version.version for version in metadata.versions} == {"1.0.0", "1.1.0"}
    assert any(version.deprecated for version in metadata.versions)


async def test_crates_registry_adapter_parses_yanked_versions() -> None:
    transport = httpx.MockTransport(
        lambda request: _json_response(
            {
                "versions": [
                    {
                        "num": "1.0.0",
                        "created_at": "2024-01-01T00:00:00Z",
                        "yanked": False,
                    },
                    {
                        "num": "0.9.0",
                        "created_at": "2023-01-01T00:00:00Z",
                        "yanked": True,
                    },
                ]
            }
        )
    )

    async with httpx.AsyncClient(transport=transport) as client:
        metadata = await CratesIORegistryAdapter(
            client,
            base_url="https://crates.example.test/api/v1/crates",
        ).fetch("serde")

    assert metadata is not None
    assert metadata.ecosystem is Ecosystem.RUST
    assert metadata.versions[1].yanked is True


async def test_swift_registry_adapter_parses_registry_release_list() -> None:
    transport = httpx.MockTransport(
        lambda request: _json_response(
            [
                {
                    "version": "1.1.0",
                    "publishedAt": "2025-03-01T00:00:00Z",
                    "metadata": {},
                },
                {
                    "version": "1.0.0",
                    "metadata": {
                        "originalPublicationTime": "2024-03-01T00:00:00Z",
                    },
                },
            ]
        )
    )

    async with httpx.AsyncClient(transport=transport) as client:
        metadata = await SwiftRegistryAdapter(
            client,
            base_url="https://packages.example.test",
        ).fetch("mona.linkedlist")

    assert metadata is not None
    assert metadata.ecosystem is Ecosystem.SWIFT
    assert [version.version for version in metadata.versions] == ["1.1.0", "1.0.0"]
