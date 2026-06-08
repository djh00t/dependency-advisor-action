"""Agent skill rendering and installation helpers."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

SKILL_NAME = "dependency-advisor"
SKILL_RELATIVE_PATH = Path(".agents/skills") / SKILL_NAME / "SKILL.md"
SHARED_SKILL_RELATIVE_PATH = Path(SKILL_NAME) / "SKILL.md"
OPENCODE_SKILL_RELATIVE_PATH = Path(".opencode/skills") / SKILL_NAME / "SKILL.md"
CODEX_AGENTS_RELATIVE_PATH = Path("AGENTS.md")
CODEX_AGENTS_SECTION_HEADING = "## Dependency Advisor"


class AgentTarget(StrEnum):
    """Supported agent integration targets."""

    PORTABLE = "portable"
    CODEX = "codex"
    OPENCODE = "opencode"


class InstallTarget(StrEnum):
    """Supported install targets."""

    CODEX = "codex"
    OPENCODE = "opencode"


class InstallResult(BaseModel):
    """Structured summary for an integration install operation."""

    model_config = ConfigDict(frozen=True)

    target: InstallTarget
    project_root: str
    written_files: tuple[str, ...]
    skipped_files: tuple[str, ...] = ()


class SharedSkillInstallResult(BaseModel):
    """Structured summary for installing the shared skills package."""

    model_config = ConfigDict(frozen=True)

    skills_root: str
    written_files: tuple[str, ...]


def render_skill_markdown(target: AgentTarget = AgentTarget.PORTABLE) -> str:
    """Return the SKILL.md payload for a supported target."""

    frontmatter = [
        "---",
        f"name: {SKILL_NAME}",
        ("description: Choose a safe dependency version before adding or upgrading a package."),
    ]
    if target is AgentTarget.OPENCODE:
        frontmatter.append("compatibility: opencode")
    frontmatter.extend(
        [
            "---",
            "",
            "## What I do",
            "",
            (
                "- Run `depadvisor recommend <package> --ecosystem <ecosystem> "
                "--policy <policy>` before adding or upgrading a direct dependency."
            ),
            (
                "- Use the JSON response as the source of truth for `status`, "
                "`recommended_version`, `reason`, and "
                "`minimum_release_age_hours`."
            ),
            "- Stop and explain the blocker when the result is not `recommended`.",
            "",
            "## When to use me",
            "",
            (
                "Use this for direct dependency adds, upgrades, pin updates, or "
                "dependency review tasks in Python, Rust, JavaScript, shell, or "
                "Swift projects."
            ),
            "",
            "## Workflow",
            "",
            "1. Determine the package name, ecosystem, and policy mode.",
            (
                "2. Run `depadvisor recommend` with the requested package, "
                "ecosystem, and `--policy <policy>`."
            ),
            (
                "3. If `status` is `recommended`, use `recommended_version` exactly "
                "and mention the policy mode that approved it."
            ),
            (
                "4. If `status` is `unknown_package` or `no_match`, stop and explain "
                "that Dependency Advisor could not approve a version automatically."
            ),
            (
                "5. Do not bypass this check for direct dependencies unless the user "
                "explicitly instructs you to override the policy outcome."
            ),
            "",
            "## Output",
            "",
            "- State the chosen version or the blocking reason.",
            "- Include the ecosystem, policy mode, and minimum release age in hours.",
        ]
    )
    return "\n".join(frontmatter) + "\n"


def render_codex_agents_markdown() -> str:
    """Return a minimal AGENTS.md contract for Codex dependency changes."""

    return (
        "\n".join(
            [
                "# Dependency Advisor",
                "",
                "## Dependency Changes",
                "",
                (
                    "- Before adding or upgrading a direct dependency, run "
                    "`depadvisor recommend <package> --ecosystem <ecosystem> "
                    "--policy <policy>`."
                ),
                (
                    "- Use the returned `recommended_version` exactly when `status` "
                    "is `recommended`."
                ),
                (
                    "- If `status` is `unknown_package` or `no_match`, stop and "
                    "explain that the package was not auto-approved."
                ),
                (
                    f"- Prefer the repo-local skill at "
                    f"`{SKILL_RELATIVE_PATH.as_posix()}` when the task is "
                    "specifically about dependency selection."
                ),
            ]
        )
        + "\n"
    )


def render_codex_agents_section() -> str:
    """Return the section appended into an existing AGENTS.md file."""

    return (
        "\n".join(
            [
                CODEX_AGENTS_SECTION_HEADING,
                "",
                (
                    "- Before adding or upgrading a direct dependency, run "
                    "`depadvisor recommend <package> --ecosystem <ecosystem> "
                    "--policy <policy>`."
                ),
                (
                    "- Use the returned `recommended_version` exactly when `status` "
                    "is `recommended`."
                ),
                (
                    "- If `status` is `unknown_package` or `no_match`, stop and "
                    "explain that the package was not auto-approved."
                ),
                (
                    f"- Prefer the repo-local skill at "
                    f"`{SKILL_RELATIVE_PATH.as_posix()}` when the task is "
                    "specifically about dependency selection."
                ),
            ]
        )
        + "\n"
    )


def install_integration(target: InstallTarget, project_root: Path) -> InstallResult:
    """Install integration assets for a supported target into a project root."""

    root = project_root.resolve()
    root.mkdir(parents=True, exist_ok=True)

    written_files: list[str] = []
    skipped_files: list[str] = []

    if target is InstallTarget.CODEX:
        _write_text(
            root / SKILL_RELATIVE_PATH,
            render_skill_markdown(AgentTarget.CODEX),
        )
        written_files.append(SKILL_RELATIVE_PATH.as_posix())

        agents_path = root / CODEX_AGENTS_RELATIVE_PATH
        if agents_path.exists():
            existing_content = agents_path.read_text(encoding="utf-8")
            if CODEX_AGENTS_SECTION_HEADING in existing_content:
                skipped_files.append(CODEX_AGENTS_RELATIVE_PATH.as_posix())
            else:
                merged_content = (
                    existing_content.rstrip("\r\n") + "\n\n" + render_codex_agents_section()
                )
                _write_text(agents_path, merged_content)
                written_files.append(CODEX_AGENTS_RELATIVE_PATH.as_posix())
        else:
            _write_text(agents_path, render_codex_agents_markdown())
            written_files.append(CODEX_AGENTS_RELATIVE_PATH.as_posix())
    elif target is InstallTarget.OPENCODE:
        _write_text(
            root / OPENCODE_SKILL_RELATIVE_PATH,
            render_skill_markdown(AgentTarget.OPENCODE),
        )
        written_files.append(OPENCODE_SKILL_RELATIVE_PATH.as_posix())
    else:
        raise ValueError(f"Unsupported install target: {target}")

    return InstallResult(
        target=target,
        project_root=str(root),
        written_files=tuple(written_files),
        skipped_files=tuple(skipped_files),
    )


def install_shared_skill(skills_root: Path) -> SharedSkillInstallResult:
    """Install the portable skill package into a shared skills directory."""

    root = skills_root.resolve()
    root.mkdir(parents=True, exist_ok=True)

    skill_path = root / SHARED_SKILL_RELATIVE_PATH
    _write_text(skill_path, render_skill_markdown(AgentTarget.PORTABLE))

    return SharedSkillInstallResult(
        skills_root=str(root),
        written_files=(SHARED_SKILL_RELATIVE_PATH.as_posix(),),
    )


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
