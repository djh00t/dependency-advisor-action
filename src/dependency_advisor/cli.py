"""Command-line interface for Dependency Advisor."""

from __future__ import annotations

import json
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from dependency_advisor.agent import (
    AgentTarget,
    InstallTarget,
    install_integration,
    install_shared_skill,
    render_codex_agents_markdown,
    render_skill_markdown,
)
from dependency_advisor.config import AdvisorConfig
from dependency_advisor.models import (
    Ecosystem,
    FastValidationStatus,
    PolicyMode,
    RecommendationStatus,
)
from dependency_advisor.policy import DependencyAdvisor
from dependency_advisor.pre_commit import collect_staged_paths, validate_pre_commit
from dependency_advisor.scan import (
    RepositoryScanner,
    report_as_json,
    report_as_markdown,
    report_as_sarif,
)
from dependency_advisor.validation import (
    SUPPORTED_MANIFEST_NAMES,
    VALIDATED_SCOPE_BY_MANIFEST_NAME,
    ManifestValidator,
    ValidatedScope,
)

app = typer.Typer(help="Advise dependency choices.", no_args_is_help=True)
agent_app = typer.Typer(help="Render and install agent integration assets.")
app.add_typer(agent_app, name="agent")
DEFAULT_SHARED_SKILL_ROOT = Path.home() / ".agents" / "skills"


@app.callback()
def cli() -> None:
    """Advise dependency choices."""


def build_advisor() -> DependencyAdvisor:
    """Build a runtime advisor using environment-backed configuration."""

    return DependencyAdvisor(config=AdvisorConfig.from_env())


@app.command("recommend")
def recommend_command(
    package: Annotated[str, typer.Argument(help="Package name to evaluate.")],
    ecosystem: Annotated[Ecosystem, typer.Option(help="Package ecosystem.")] = Ecosystem.PYTHON,
    policy: Annotated[
        PolicyMode, typer.Option(help="Release-age policy mode.")
    ] = PolicyMode.STANDARD,
    version_range: Annotated[
        str | None,
        typer.Option(
            help=(
                "Optional ecosystem-specific version range, for example '<2.32' "
                "for Python or '^18.0.0' for npm."
            ),
        ),
    ] = None,
) -> None:
    """Recommend a dependency version."""

    try:
        result = build_advisor().recommend(
            package,
            ecosystem=ecosystem,
            policy=policy,
            version_range=version_range,
        )
    except ValidationError as error:
        raise typer.BadParameter(str(error)) from error

    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    if result.status is not RecommendationStatus.RECOMMENDED:
        raise typer.Exit(2)


def _write_output(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@app.command("scan")
def scan_command(
    path: Annotated[
        Path,
        typer.Argument(
            help="Repository root or manifest file to scan.",
            exists=True,
            dir_okay=True,
            file_okay=True,
            resolve_path=True,
        ),
    ] = Path("."),
    policy: Annotated[
        PolicyMode, typer.Option(help="Release-age policy mode to apply to all dependencies.")
    ] = PolicyMode.STANDARD,
    json_output: Annotated[
        Path | None, typer.Option(help="Write the JSON report to a file.")
    ] = None,
    sarif_output: Annotated[
        Path | None, typer.Option(help="Write the SARIF report to a file.")
    ] = None,
    markdown_output: Annotated[
        Path | None, typer.Option(help="Write the Markdown report to a file.")
    ] = None,
    fail_on_findings: Annotated[
        bool,
        typer.Option(
            "--fail-on-findings/--no-fail-on-findings",
            help="Exit with code 2 when the scan contains findings.",
        ),
    ] = False,
) -> None:
    """Scan a repository and emit CI-friendly reports."""

    report = RepositoryScanner().scan(path, policy=policy)
    json_report = report_as_json(report)
    typer.echo(json_report)

    if json_output is not None:
        _write_output(json_output, json_report + "\n")
    if sarif_output is not None:
        _write_output(
            sarif_output,
            json.dumps(report_as_sarif(report), indent=2, sort_keys=True) + "\n",
        )
    if markdown_output is not None:
        _write_output(markdown_output, report_as_markdown(report))

    if fail_on_findings and report.summary.findings > 0:
        raise typer.Exit(2)


@agent_app.command("render-skill")
def render_skill_command(
    target: Annotated[
        AgentTarget,
        typer.Option(help="Skill target to render."),
    ] = AgentTarget.PORTABLE,
) -> None:
    """Render the skill package for an agent target."""

    typer.echo(render_skill_markdown(target))


@agent_app.command("render-codex-agents")
def render_codex_agents_command() -> None:
    """Render a minimal AGENTS.md file for Codex dependency policy."""

    typer.echo(render_codex_agents_markdown())


@agent_app.command("install")
def install_command(
    target: Annotated[InstallTarget, typer.Argument(help="Integration target to install.")],
    project_root: Annotated[
        Path,
        typer.Option(
            "--project-root",
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
            help="Project root to receive the generated integration files.",
        ),
    ] = Path("."),
) -> None:
    """Install agent integration assets into a project."""

    result = install_integration(target, project_root)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


@agent_app.command("install-skill")
def install_skill_command(
    skills_root: Annotated[
        Path,
        typer.Option(
            "--skills-root",
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
            help="Shared skills root to receive the portable skill package.",
        ),
    ] = DEFAULT_SHARED_SKILL_ROOT,
) -> None:
    """Install the portable skill package into a shared skills root."""

    result = install_shared_skill(skills_root)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


@app.command("pre-commit")
def pre_commit_command(
    changed_paths: Annotated[
        list[Path] | None,
        typer.Argument(help="Changed paths to validate when not reading staged paths."),
    ] = None,
    staged: Annotated[
        bool,
        typer.Option(
            "--staged/--files",
            help="Read changed paths from git staged files instead of CLI arguments.",
        ),
    ] = False,
    policy: Annotated[
        PolicyMode, typer.Option(help="Release-age policy mode to apply.")
    ] = PolicyMode.STANDARD,
) -> None:
    """Validate changed manifests in the fast pre-commit contract."""

    provided_paths = tuple(changed_paths or ())

    if staged and provided_paths:
        raise typer.BadParameter("Pass either staged mode or explicit paths, not both.")

    if staged:
        try:
            paths = collect_staged_paths()
        except RuntimeError as error:
            raise typer.BadParameter(str(error)) from error
    else:
        paths = provided_paths

    if not staged and not paths:
        raise typer.BadParameter("At least one changed path must be provided, or use --staged.")

    result = validate_pre_commit(paths, policy=policy, source="staged" if staged else "files")
    payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
    typer.echo(payload)

    if result.status is FastValidationStatus.BLOCKED:
        raise typer.Exit(2)


@app.command("validate-manifests")
def validate_manifests_command(
    changed_paths: Annotated[
        list[Path] | None,
        typer.Option(
            "--path",
            "-p",
            help="Changed path to validate; repeat the option for multiple paths.",
        ),
    ] = None,
    policy: Annotated[
        PolicyMode, typer.Option(help="Release-age policy mode to apply.")
    ] = PolicyMode.STANDARD,
    json_output: Annotated[
        Path | None, typer.Option(help="Write the JSON report to a file.")
    ] = None,
) -> None:
    """Validate changed manifests with the fast pre-commit contract."""

    if not changed_paths:
        raise typer.BadParameter("At least one changed path must be provided.")

    try:
        result = ManifestValidator().validate(changed_paths, policy=policy)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError) as error:
        manifest_paths = [
            str(path) for path in changed_paths if path.name in SUPPORTED_MANIFEST_NAMES
        ]
        supported_scopes: set[ValidatedScope] = {
            VALIDATED_SCOPE_BY_MANIFEST_NAME[path.name]
            for path in changed_paths
            if path.name in VALIDATED_SCOPE_BY_MANIFEST_NAME
        }
        validated_scope: ValidatedScope
        if not supported_scopes:
            validated_scope = "mixed"
        elif len(supported_scopes) == 1:
            validated_scope = next(iter(supported_scopes))
        else:
            validated_scope = "mixed"
        payload = json.dumps(
            {
                "changed_files": [str(path) for path in changed_paths],
                "findings": [],
                "manifest_paths": manifest_paths,
                "reason": f"Unable to validate changed manifests: {error}",
                "status": FastValidationStatus.BLOCKED.value,
                "validated_dependencies": 0,
                "validated_scope": validated_scope,
            },
            indent=2,
            sort_keys=True,
        )
        typer.echo(payload)
        raise typer.Exit(2) from error

    payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True)
    typer.echo(payload)

    if json_output is not None:
        json_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(payload + "\n", encoding="utf-8")

    if result.status is FastValidationStatus.BLOCKED:
        raise typer.Exit(2)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Dependency Advisor CLI."""

    try:
        app(
            args=list(argv) if argv is not None else None,
            prog_name="depadvisor",
        )
    except SystemExit as error:
        return int(error.code or 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
