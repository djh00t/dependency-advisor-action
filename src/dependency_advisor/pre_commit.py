"""Pre-commit hook orchestration for changed dependency manifests."""

from __future__ import annotations

import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

from dependency_advisor.models import PolicyMode, PreCommitValidationResult
from dependency_advisor.validation import ManifestValidator

_GIT_DIFF_COMMAND = [
    "git",
    "diff",
    "--cached",
    "--name-only",
    "--diff-filter=ACMRTUXB",
]


def collect_staged_paths(*, cwd: Path | None = None) -> tuple[Path, ...]:
    """Return staged paths from git in the current checkout."""

    completed = subprocess.run(
        _GIT_DIFF_COMMAND,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        error = completed.stderr.strip() or completed.stdout.strip() or "git diff failed"
        raise RuntimeError(error)

    return tuple(Path(line.strip()) for line in completed.stdout.splitlines() if line.strip())


def validate_pre_commit(
    changed_paths: Iterable[Path],
    *,
    policy: PolicyMode = PolicyMode.STANDARD,
    source: Literal["staged", "files"] = "files",
) -> PreCommitValidationResult:
    """Validate changed paths through the fast manifest contract."""

    result = ManifestValidator().validate(changed_paths, policy=policy)
    return PreCommitValidationResult(
        status=result.status,
        source=source,
        changed_files=result.changed_files,
        manifest_paths=result.manifest_paths,
        validated_scope=result.validated_scope,
        validated_dependencies=result.validated_dependencies,
        findings=result.findings,
        reason=result.reason,
    )


def validate_staged_pre_commit(
    *,
    cwd: Path | None = None,
    policy: PolicyMode = PolicyMode.STANDARD,
) -> PreCommitValidationResult:
    """Validate the staged dependency paths from git."""

    staged_paths = collect_staged_paths(cwd=cwd)
    return validate_pre_commit(staged_paths, policy=policy, source="staged")
