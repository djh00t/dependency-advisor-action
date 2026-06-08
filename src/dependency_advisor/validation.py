"""Fast manifest validation for changed dependency files."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from dependency_advisor.models import (
    Ecosystem,
    FastValidationFinding,
    FastValidationResult,
    FastValidationStatus,
    PolicyMode,
    RecommendationStatus,
)
from dependency_advisor.policy import DependencyAdvisor

SUPPORTED_MANIFEST_NAMES = frozenset({"pyproject.toml", "requirements.txt"})
ValidatedScope = Literal["project.dependencies", "requirements.txt", "mixed"]
VALIDATED_SCOPE_BY_MANIFEST_NAME: dict[str, ValidatedScope] = {
    "pyproject.toml": "project.dependencies",
    "requirements.txt": "requirements.txt",
}
_DEPENDENCY_NAME_PATTERN = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)")


def _normalize_changed_paths(paths: Iterable[Path]) -> tuple[Path, ...]:
    seen: set[Path] = set()
    ordered: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        ordered.append(resolved)
    return tuple(ordered)


def _is_supported_manifest(path: Path) -> bool:
    return path.is_file() and path.name in SUPPORTED_MANIFEST_NAMES


def _extract_dependency_name(requirement: str) -> str | None:
    cleaned = requirement.strip()
    if not cleaned or cleaned.startswith(("#", "-")):
        return None
    match = _DEPENDENCY_NAME_PATTERN.match(cleaned)
    if match is None:
        return None
    return match.group("name").lower()


def _find_line(lines: list[str], requirement: str, package: str) -> int | None:
    for index, line in enumerate(lines, start=1):
        if requirement in line:
            return index
    for index, line in enumerate(lines, start=1):
        if package in line.lower():
            return index
    return None


def _validation_scope(manifests: tuple[Path, ...]) -> ValidatedScope:
    scopes = {
        VALIDATED_SCOPE_BY_MANIFEST_NAME[manifest.name]
        for manifest in manifests
        if manifest.name in VALIDATED_SCOPE_BY_MANIFEST_NAME
    }
    if not scopes:
        return "mixed"
    if len(scopes) == 1:
        return next(iter(scopes))
    return "mixed"


class ManifestValidator:
    """Validate changed manifests against the recommendation engine."""

    def __init__(self, advisor: DependencyAdvisor | None = None) -> None:
        self._advisor = advisor or DependencyAdvisor()

    def validate(
        self,
        changed_paths: Iterable[Path],
        *,
        policy: PolicyMode = PolicyMode.STANDARD,
        today: datetime | None = None,
    ) -> FastValidationResult:
        normalized_paths = _normalize_changed_paths(changed_paths)
        manifests = tuple(path for path in normalized_paths if _is_supported_manifest(path))
        changed_files = tuple(str(path) for path in normalized_paths)
        manifest_paths = tuple(str(path) for path in manifests)
        validated_scope = _validation_scope(manifests)
        reference_time = today or datetime.now(tz=UTC)

        if not manifests:
            return FastValidationResult(
                status=FastValidationStatus.NO_MANIFEST_CHANGES,
                changed_files=changed_files,
                manifest_paths=(),
                validated_scope=validated_scope,
                validated_dependencies=0,
                findings=(),
                reason="No supported manifest changes were detected.",
            )

        findings: list[FastValidationFinding] = []
        validated_dependencies = 0
        raw_dependency_entries = 0
        unparseable_entries = 0

        for manifest in manifests:
            lines = manifest.read_text(encoding="utf-8").splitlines()
            for line_number, requirement in self._parse_manifest_entries(manifest):
                raw_dependency_entries += 1
                package_name = _extract_dependency_name(requirement)
                if package_name is None:
                    unparseable_entries += 1
                    continue
                validated_dependencies += 1
                line = (
                    line_number
                    if line_number is not None
                    else _find_line(
                        lines,
                        requirement,
                        package_name,
                    )
                )
                recommendation = self._advisor.recommend(
                    package_name,
                    ecosystem=Ecosystem.PYTHON,
                    policy=policy,
                    today=reference_time.date(),
                )
                findings.append(
                    FastValidationFinding(
                        manifest_path=str(manifest),
                        line=line,
                        package=package_name,
                        status=recommendation.status,
                        recommended_version=recommendation.recommended_version,
                        reason=recommendation.reason,
                    )
                )

        if raw_dependency_entries == 0:
            return FastValidationResult(
                status=FastValidationStatus.NO_MANIFEST_CHANGES,
                changed_files=changed_files,
                manifest_paths=manifest_paths,
                validated_scope=validated_scope,
                validated_dependencies=0,
                findings=(),
                reason="No supported manifest dependency entries were found in the changed files.",
            )

        if unparseable_entries > 0:
            overall_status = FastValidationStatus.BLOCKED
            reason = "Changed manifests contain dependency entries that could not be parsed."
        elif findings and all(
            finding.status is RecommendationStatus.RECOMMENDED for finding in findings
        ):
            overall_status = FastValidationStatus.OK
            reason = "All changed manifest dependencies are approved."
        elif findings:
            overall_status = FastValidationStatus.BLOCKED
            reason = "One or more changed manifest dependencies are not approved."
        else:
            overall_status = FastValidationStatus.NO_MANIFEST_CHANGES
            reason = "No supported manifest dependency entries were found in the changed files."

        return FastValidationResult(
            status=overall_status,
            changed_files=changed_files,
            manifest_paths=manifest_paths,
            validated_scope=validated_scope,
            validated_dependencies=validated_dependencies,
            findings=tuple(findings),
            reason=reason,
        )

    def _parse_manifest_entries(self, manifest: Path) -> tuple[tuple[int | None, str], ...]:
        if manifest.name == "pyproject.toml":
            payload = tomllib.loads(manifest.read_text(encoding="utf-8"))
            project = payload.get("project", {})
            dependencies = project.get("dependencies", [])
            if not isinstance(dependencies, list):
                return ()
            return tuple(
                (None, requirement)
                for requirement in dependencies
                if isinstance(requirement, str) and requirement.strip()
            )

        if manifest.name == "requirements.txt":
            lines = manifest.read_text(encoding="utf-8").splitlines()
            return tuple(
                (line_number, line)
                for line_number, line in enumerate(lines, start=1)
                if line.strip() and not line.lstrip().startswith("#")
            )

        return ()
