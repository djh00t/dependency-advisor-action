"""Core package for Dependency Advisor."""

from dependency_advisor.agent import AgentTarget, InstallResult
from dependency_advisor.config import AdvisorConfig
from dependency_advisor.models import (
    FastValidationResult,
    PackageMetadata,
    RecommendationResult,
    RepositoryScanReport,
)
from dependency_advisor.policy import DependencyAdvisor, recommend
from dependency_advisor.scan import RepositoryScanner
from dependency_advisor.validation import ManifestValidator

__all__ = [
    "AdvisorConfig",
    "AgentTarget",
    "DependencyAdvisor",
    "FastValidationResult",
    "InstallResult",
    "ManifestValidator",
    "PackageMetadata",
    "RecommendationResult",
    "RepositoryScanReport",
    "RepositoryScanner",
    "recommend",
]
