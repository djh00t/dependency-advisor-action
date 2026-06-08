"""Configuration defaults for Dependency Advisor."""

from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict, Field

from dependency_advisor.models import PolicyMode


def _default_policy_release_ages() -> Mapping[PolicyMode, timedelta]:
    return MappingProxyType(
        {
            PolicyMode.LOCO: timedelta(hours=0),
            PolicyMode.AGGRESSIVE: timedelta(hours=48),
            PolicyMode.STANDARD: timedelta(days=14),
            PolicyMode.CONSERVATIVE: timedelta(days=30),
        }
    )


def _default_cache_path() -> Path:
    return Path(".cache") / "dependency-advisor.sqlite3"


class RegistryConfig(BaseModel):
    """Runtime settings for registry access and local caching."""

    model_config = ConfigDict(frozen=True)

    timeout_seconds: float = 10.0
    cache_ttl: timedelta = timedelta(hours=24)
    cache_path: Path = Field(default_factory=_default_cache_path)
    allow_stale_on_error: bool = True
    user_agent: str = "dependency-advisor/0.1.0"
    pypi_base_url: str = "https://pypi.org/pypi"
    npm_base_url: str = "https://registry.npmjs.org"
    crates_base_url: str = "https://crates.io/api/v1/crates"
    swift_registry_base_url: str | None = None


class AdvisorConfig(BaseModel):
    """Runtime configuration for recommendation policy."""

    model_config = ConfigDict(frozen=True)

    default_policy: PolicyMode = PolicyMode.STANDARD
    registry: RegistryConfig = Field(default_factory=RegistryConfig)
    policy_release_ages: Mapping[PolicyMode, timedelta] = Field(
        default_factory=_default_policy_release_ages
    )

    def minimum_release_age_hours(self, policy: PolicyMode) -> int:
        """Return the configured minimum release age for a policy in hours."""

        return int(self.policy_release_ages[policy].total_seconds() // 3600)

    @classmethod
    def from_env(cls) -> AdvisorConfig:
        """Build configuration from environment overrides."""

        ttl_seconds = int(os.environ.get("DEPENDENCY_ADVISOR_CACHE_TTL_SECONDS", "86400"))
        swift_registry_base_url = os.environ.get("DEPENDENCY_ADVISOR_SWIFT_REGISTRY_BASE_URL")
        return cls(
            registry=RegistryConfig(
                cache_path=Path(
                    os.environ.get(
                        "DEPENDENCY_ADVISOR_CACHE_PATH",
                        _default_cache_path().as_posix(),
                    )
                ),
                cache_ttl=timedelta(seconds=ttl_seconds),
                allow_stale_on_error=os.environ.get(
                    "DEPENDENCY_ADVISOR_ALLOW_STALE_ON_ERROR",
                    "1",
                )
                != "0",
                swift_registry_base_url=swift_registry_base_url or None,
            )
        )
