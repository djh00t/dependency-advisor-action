"""Repository scanning and reporting helpers for CI usage."""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dependency_advisor.models import (
    Ecosystem,
    ManifestDependency,
    PolicyMode,
    RecommendationStatus,
    RepositoryDependencyResult,
    RepositoryScanReport,
    RepositoryScanSummary,
)
from dependency_advisor.policy import DependencyAdvisor

SUPPORTED_MANIFESTS = frozenset({"pyproject.toml", "requirements.txt"})
IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "fixtures",
        "htmlcov",
        "node_modules",
    }
)
PACKAGE_NAME_PATTERN = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)")


def _extract_package_name(requirement: str) -> str | None:
    cleaned = requirement.strip()
    if not cleaned:
        return None
    if cleaned.startswith(("-", ".", "git+", "http://", "https://")):
        return None
    match = PACKAGE_NAME_PATTERN.match(cleaned)
    if match is None:
        return None
    return match.group("name").lower()


def _find_line(
    lines: list[str],
    needle: str,
    package: str,
    *,
    start_at: int = 1,
) -> int | None:
    for index, line in enumerate(lines[start_at - 1 :], start=start_at):
        if needle in line:
            return index
    for index, line in enumerate(lines[start_at - 1 :], start=start_at):
        if package in line.lower():
            return index
    if start_at > 1:
        return _find_line(lines, needle, package)
    return None


class RepositoryScanner:
    """Scan a repository and evaluate direct Python dependencies."""

    def __init__(self, advisor: DependencyAdvisor | None = None) -> None:
        self._advisor = advisor or DependencyAdvisor()

    def scan(
        self,
        root: Path,
        *,
        policy: PolicyMode = PolicyMode.STANDARD,
    ) -> RepositoryScanReport:
        """Scan supported manifests beneath a path."""

        resolved_root = root.resolve()
        report_root = resolved_root.parent if resolved_root.is_file() else resolved_root
        manifests = self._discover_manifests(resolved_root)
        dependencies = [
            dependency
            for manifest in manifests
            for dependency in self._parse_manifest(manifest, report_root)
        ]
        results = [self._evaluate_dependency(dependency, policy) for dependency in dependencies]
        status_counts = Counter(result.status for result in results)
        findings = sum(
            1 for result in results if result.status is not RecommendationStatus.RECOMMENDED
        )

        return RepositoryScanReport(
            root_path=str(resolved_root),
            scanned_at=datetime.now(tz=UTC),
            policy=policy,
            manifests_scanned=[str(manifest.relative_to(report_root)) for manifest in manifests],
            results=results,
            summary=RepositoryScanSummary(
                manifests_scanned=len(manifests),
                dependencies_scanned=len(results),
                findings=findings,
                status_counts=dict(status_counts),
            ),
        )

    def _discover_manifests(self, root: Path) -> list[Path]:
        if root.is_file():
            return [root] if root.name in SUPPORTED_MANIFESTS else []

        manifests: list[Path] = []
        for current_root, dirnames, filenames in os.walk(root):
            dirnames[:] = [dirname for dirname in dirnames if dirname not in IGNORED_DIRECTORIES]
            for filename in filenames:
                if filename in SUPPORTED_MANIFESTS:
                    manifests.append(Path(current_root) / filename)
        return sorted(manifests)

    def _parse_manifest(self, manifest: Path, root: Path) -> list[ManifestDependency]:
        if manifest.name == "pyproject.toml":
            return self._parse_pyproject(manifest, root)
        if manifest.name == "requirements.txt":
            return self._parse_requirements(manifest, root)
        return []

    def _parse_pyproject(self, manifest: Path, root: Path) -> list[ManifestDependency]:
        text = manifest.read_text(encoding="utf-8")
        data = tomllib.loads(text)
        lines = text.splitlines()
        dependencies: list[str] = []

        project = data.get("project", {})
        dependencies.extend(
            entry for entry in project.get("dependencies", []) if isinstance(entry, str)
        )

        for entries in project.get("optional-dependencies", {}).values():
            if isinstance(entries, list):
                dependencies.extend(entry for entry in entries if isinstance(entry, str))

        for entries in data.get("dependency-groups", {}).values():
            if isinstance(entries, list):
                dependencies.extend(entry for entry in entries if isinstance(entry, str))

        manifest_dependencies: list[ManifestDependency] = []
        next_line = 1
        for requirement in dependencies:
            package = _extract_package_name(requirement)
            if package is None:
                continue
            line = _find_line(lines, requirement, package, start_at=next_line)
            if line is not None:
                next_line = line + 1
            dependency = self._build_dependency(
                requirement=requirement,
                manifest=manifest,
                root=root,
                lines=lines,
                line=line,
            )
            if dependency is not None:
                manifest_dependencies.append(dependency)
        return manifest_dependencies

    def _parse_requirements(self, manifest: Path, root: Path) -> list[ManifestDependency]:
        dependencies: list[ManifestDependency] = []
        lines = manifest.read_text(encoding="utf-8").splitlines()

        for index, line in enumerate(lines, start=1):
            requirement = line.split("#", 1)[0].strip()
            if not requirement:
                continue
            dependency = self._build_dependency(
                requirement=requirement,
                manifest=manifest,
                root=root,
                lines=lines,
                line=index,
            )
            if dependency is not None:
                dependencies.append(dependency)
        return dependencies

    def _build_dependency(
        self,
        *,
        requirement: str,
        manifest: Path,
        root: Path,
        lines: list[str],
        line: int | None = None,
    ) -> ManifestDependency | None:
        package = _extract_package_name(requirement)
        if package is None:
            return None
        return ManifestDependency(
            package=package,
            ecosystem=Ecosystem.PYTHON,
            manifest_path=str(manifest.relative_to(root)),
            requirement=requirement,
            line=line if line is not None else _find_line(lines, requirement, package),
        )

    def _evaluate_dependency(
        self,
        dependency: ManifestDependency,
        policy: PolicyMode,
    ) -> RepositoryDependencyResult:
        result = self._advisor.recommend(
            dependency.package,
            ecosystem=dependency.ecosystem,
            policy=policy,
        )
        return RepositoryDependencyResult(
            package=dependency.package,
            ecosystem=dependency.ecosystem,
            manifest_path=dependency.manifest_path,
            requirement=dependency.requirement,
            line=dependency.line,
            status=result.status,
            recommended_version=result.recommended_version,
            reason=result.reason,
            candidates_considered=result.candidates_considered,
            minimum_release_age_hours=result.minimum_release_age_hours,
            source=result.source,
        )


def report_as_json(report: RepositoryScanReport) -> str:
    """Return a stable JSON report payload with sorted keys and indentation."""

    return json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True)


def report_as_markdown(report: RepositoryScanReport) -> str:
    """Render a Markdown summary for repository scan results."""

    status_counts = ", ".join(
        f"{status.value}: {count}"
        for status, count in sorted(
            report.summary.status_counts.items(), key=lambda item: item[0].value
        )
    )
    lines = [
        "# Dependency Advisor Report",
        "",
        f"- Root path: `{report.root_path}`",
        f"- Policy: `{report.policy.value}`",
        f"- Manifests scanned: `{report.summary.manifests_scanned}`",
        f"- Dependencies scanned: `{report.summary.dependencies_scanned}`",
        f"- Findings: `{report.summary.findings}`",
        f"- Status counts: {status_counts or 'none'}",
        "",
        "| Manifest | Package | Status | Recommended | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]

    for result in report.results:
        lines.append(
            "| "
            f"`{result.manifest_path}` | "
            f"`{result.package}` | "
            f"`{result.status.value}` | "
            f"`{result.recommended_version or '-'}` | "
            f"{result.reason} |"
        )

    return "\n".join(lines) + "\n"


def report_as_sarif(report: RepositoryScanReport) -> dict[str, Any]:
    """Render a minimal SARIF payload for repository scan findings."""

    rules: dict[RecommendationStatus, dict[str, Any]] = {
        RecommendationStatus.UNKNOWN_PACKAGE: {
            "id": "DEPADVISOR_UNKNOWN_PACKAGE",
            "name": "Unknown package",
            "shortDescription": {"text": "Dependency Advisor could not classify the package."},
            "fullDescription": {
                "text": "The package is outside the bootstrap catalog and needs review."
            },
            "defaultConfiguration": {"level": "warning"},
        },
        RecommendationStatus.BLOCKED: {
            "id": "DEPADVISOR_BLOCKED",
            "name": "No safe version",
            "shortDescription": {"text": "No package version satisfied the policy checks."},
            "fullDescription": {
                "text": "All known versions failed vulnerability, blocklist, or release-age checks."
            },
            "defaultConfiguration": {"level": "error"},
        },
    }

    results = []
    for finding in report.results:
        if finding.status is RecommendationStatus.RECOMMENDED:
            continue
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.manifest_path},
            }
        }
        if finding.line is not None:
            location["physicalLocation"]["region"] = {"startLine": finding.line}
        results.append(
            {
                "ruleId": rules[finding.status]["id"],
                "level": rules[finding.status]["defaultConfiguration"]["level"],
                "message": {
                    "text": (
                        f"{finding.package}: {finding.reason} "
                        f"Recommended version: {finding.recommended_version or 'none'}."
                    )
                },
                "locations": [location],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dependency-advisor",
                        "informationUri": "https://github.com/djh00t/dependency-advisor",
                        "rules": [
                            rules[status]
                            for status in (
                                RecommendationStatus.UNKNOWN_PACKAGE,
                                RecommendationStatus.BLOCKED,
                            )
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
