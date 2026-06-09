import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dependency_advisor.cli import main
from dependency_advisor.models import (
    CacheStatus,
    Ecosystem,
    PolicyMode,
    RecommendationProvenance,
    RecommendationResult,
    RecommendationStatus,
    VulnerabilitySource,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "scan_project"


def test_help_output(capsys: Any) -> None:
    assert main(["--help"]) == 0

    captured = capsys.readouterr()
    assert "Advise dependency choices" in captured.out
    assert "recommend" in captured.out


def test_recommend_requests_outputs_json(monkeypatch: Any, capsys: Any) -> None:
    class StubAdvisor:
        def recommend(self, *args: Any, **kwargs: Any) -> RecommendationResult:
            _unused = (args, kwargs)
            return RecommendationResult(
                package="requests",
                ecosystem=Ecosystem.PYTHON,
                policy=PolicyMode.STANDARD,
                status=RecommendationStatus.RECOMMENDED,
                recommended_version="2.32.3",
                reason="Selected newest candidate after filtering blocked and vulnerable versions.",
                candidates_considered=4,
                minimum_release_age_hours=336,
                source="pypi",
                advisory_sources=(
                    VulnerabilitySource.OSV,
                    VulnerabilitySource.PIP_AUDIT,
                ),
                provenance=RecommendationProvenance(
                    source="pypi",
                    metadata_url="https://pypi.org/pypi/requests/json",
                    fetched_at=datetime(2026, 6, 6, tzinfo=UTC),
                    expires_at=datetime(2026, 6, 7, tzinfo=UTC),
                    cache_status=CacheStatus.HIT,
                ),
            )

    monkeypatch.setattr("dependency_advisor.cli.build_advisor", lambda: StubAdvisor())

    exit_code = main(["recommend", "requests"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["package"] == "requests"
    assert payload["status"] == "recommended"
    assert payload["recommended_version"] == "2.32.3"
    assert payload["source"] == "pypi"
    assert payload["provenance"]["cache_status"] == "hit"
    assert payload["advisory_sources"] == ["osv", "pip-audit"]


def test_unknown_package_uses_nonzero_exit(monkeypatch: Any, capsys: Any) -> None:
    class StubAdvisor:
        def recommend(self, *args: Any, **kwargs: Any) -> RecommendationResult:
            _unused = (args, kwargs)
            return RecommendationResult(
                package="unknown-package",
                ecosystem=Ecosystem.PYTHON,
                policy=PolicyMode.STANDARD,
                status=RecommendationStatus.UNKNOWN_PACKAGE,
                reason="Package is not available from configured metadata sources.",
                candidates_considered=0,
                minimum_release_age_hours=336,
                source="unknown",
            )

    monkeypatch.setattr("dependency_advisor.cli.build_advisor", lambda: StubAdvisor())

    exit_code = main(["recommend", "unknown-package"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "unknown_package"


def test_blocked_result_uses_nonzero_exit(capsys: Any) -> None:
    exit_code = main(["recommend", "requests", "--version-range", ">3"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "blocked"


def test_scan_outputs_json_sarif_and_markdown_reports(capsys: Any, tmp_path: Path) -> None:
    json_output = tmp_path / "report.json"
    sarif_output = tmp_path / "report.sarif"
    markdown_output = tmp_path / "report.md"

    exit_code = main(
        [
            "scan",
            str(FIXTURE_ROOT),
            "--json-output",
            str(json_output),
            "--sarif-output",
            str(sarif_output),
            "--markdown-output",
            str(markdown_output),
        ]
    )

    stdout_payload = json.loads(capsys.readouterr().out)
    sarif_payload = json.loads(sarif_output.read_text(encoding="utf-8"))
    markdown_payload = markdown_output.read_text(encoding="utf-8")

    assert exit_code == 0
    assert stdout_payload["summary"]["findings"] == 2
    assert json.loads(json_output.read_text(encoding="utf-8")) == stdout_payload
    assert sarif_payload["version"] == "2.1.0"
    assert len(sarif_payload["runs"][0]["results"]) == 2
    assert "# Dependency Advisor Report" in markdown_payload
    assert "`unknown_package`" in markdown_payload


def test_scan_fail_on_findings_uses_nonzero_exit_for_findings(capsys: Any) -> None:
    exit_code = main(["scan", str(FIXTURE_ROOT), "--fail-on-findings"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["summary"]["findings"] == 2


def test_render_skill_outputs_markdown(capsys: Any) -> None:
    assert main(["agent", "render-skill", "--target", "opencode"]) == 0

    captured = capsys.readouterr()
    assert "name: dependency-advisor" in captured.out
    assert "compatibility: opencode" in captured.out
    assert "--policy <policy>" in captured.out


def test_render_codex_agents_outputs_markdown(capsys: Any) -> None:
    assert main(["agent", "render-codex-agents"]) == 0

    captured = capsys.readouterr()
    assert "# Dependency Advisor" in captured.out
    assert "--policy <policy>" in captured.out
    assert ".agents/skills/dependency-advisor/SKILL.md" in captured.out


def test_install_codex_writes_expected_files(tmp_path: Any, capsys: Any) -> None:
    exit_code = main(
        [
            "agent",
            "install",
            "codex",
            "--project-root",
            str(tmp_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["target"] == "codex"
    assert payload["written_files"] == [
        ".agents/skills/dependency-advisor/SKILL.md",
        "AGENTS.md",
    ]
    skill_contents = (tmp_path / ".agents/skills/dependency-advisor/SKILL.md").read_text(
        encoding="utf-8"
    )
    agents_contents = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert "--policy <policy>" in skill_contents
    assert "--policy <policy>" in agents_contents


def test_install_codex_merges_existing_agents_file(tmp_path: Any, capsys: Any) -> None:
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text("# Existing guidance  \n", encoding="utf-8")

    exit_code = main(
        [
            "agent",
            "install",
            "codex",
            "--project-root",
            str(tmp_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    merged_contents = agents_path.read_text(encoding="utf-8")
    assert exit_code == 0
    assert payload["written_files"] == [
        ".agents/skills/dependency-advisor/SKILL.md",
        "AGENTS.md",
    ]
    assert payload["skipped_files"] == []
    assert merged_contents.startswith("# Existing guidance  \n\n## Dependency Advisor")
    assert "## Dependency Advisor" in merged_contents
    assert "--policy <policy>" in merged_contents


def test_install_opencode_writes_expected_file(tmp_path: Any, capsys: Any) -> None:
    exit_code = main(
        [
            "agent",
            "install",
            "opencode",
            "--project-root",
            str(tmp_path),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["target"] == "opencode"
    assert payload["written_files"] == [
        ".opencode/skills/dependency-advisor/SKILL.md",
    ]
    assert (tmp_path / ".opencode/skills/dependency-advisor/SKILL.md").exists()


def test_install_shared_skill_writes_expected_file(tmp_path: Path, capsys: Any) -> None:
    skills_root = tmp_path / ".agents" / "skills"

    exit_code = main(
        [
            "agent",
            "install-skill",
            "--skills-root",
            str(skills_root),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["skills_root"] == str(skills_root.resolve())
    assert payload["written_files"] == [
        "dependency-advisor/SKILL.md",
    ]
    skill_path = skills_root / "dependency-advisor" / "SKILL.md"
    assert skill_path.exists()
    assert "## What I do" in skill_path.read_text(encoding="utf-8")


def test_validate_manifests_outputs_structured_json(tmp_path: Path, capsys: Any) -> None:
    manifest = tmp_path / "pyproject.toml"
    notes = tmp_path / "notes.md"
    manifest.write_text(
        "\n".join(
            [
                "[project]",
                'name = "validation-fixture"',
                'version = "0.1.0"',
                "dependencies = [",
                '  "requests>=2.31",',
                '  "demo-unknown>=1.0",',
                "]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    notes.write_text("not a manifest\n", encoding="utf-8")

    exit_code = main(["validate-manifests", "--path", str(manifest), "--path", str(notes)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "blocked"
    assert payload["changed_files"] == [str(manifest), str(notes)]
    assert payload["manifest_paths"] == [str(manifest)]
    assert payload["validated_scope"] == "project.dependencies"
    assert payload["validated_dependencies"] == 2
    assert payload["findings"][1]["package"] == "demo-unknown"


def test_validate_manifests_supports_requirements_txt(tmp_path: Path, capsys: Any) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests>=2.31\ndemo-unknown>=1.0\n", encoding="utf-8")

    exit_code = main(["validate-manifests", "--path", str(requirements)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "blocked"
    assert payload["changed_files"] == [str(requirements)]
    assert payload["manifest_paths"] == [str(requirements)]
    assert payload["validated_scope"] == "requirements.txt"
    assert payload["validated_dependencies"] == 2


def test_validate_manifests_reports_mixed_scope_for_mixed_manifests(
    tmp_path: Path, capsys: Any
) -> None:
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "\n".join(
            [
                "[project]",
                'name = "validation-fixture"',
                'version = "0.1.0"',
                "dependencies = [",
                '  "requests>=2.31",',
                '  "demo-unknown>=1.0",',
                "]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests>=2.31\ndemo-unknown>=1.0\n", encoding="utf-8")

    exit_code = main(["validate-manifests", "--path", str(manifest), "--path", str(requirements)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "blocked"
    assert payload["changed_files"] == [str(manifest), str(requirements)]
    assert payload["manifest_paths"] == [str(manifest), str(requirements)]
    assert payload["validated_scope"] == "mixed"
    assert payload["validated_dependencies"] == 4


def test_validate_manifests_ignores_non_manifest_paths(tmp_path: Path, capsys: Any) -> None:
    notes = tmp_path / "notes.md"
    notes.write_text("not a manifest\n", encoding="utf-8")

    exit_code = main(["validate-manifests", "--path", str(notes)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["status"] == "no_manifest_changes"
    assert payload["changed_files"] == [str(notes)]
    assert payload["manifest_paths"] == []


def test_pre_commit_accepts_explicit_changed_paths(tmp_path: Path, capsys: Any) -> None:
    manifest = tmp_path / "pyproject.toml"
    notes = tmp_path / "notes.md"
    manifest.write_text(
        "\n".join(
            [
                "[project]",
                'name = "validation-fixture"',
                'version = "0.1.0"',
                "dependencies = [",
                '  "requests>=2.31",',
                '  "demo-unknown>=1.0",',
                "]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    notes.write_text("not a manifest\n", encoding="utf-8")

    exit_code = main(["pre-commit", str(manifest), str(notes)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["source"] == "files"
    assert payload["status"] == "blocked"
    assert payload["changed_files"] == [str(manifest), str(notes)]
    assert payload["manifest_paths"] == [str(manifest)]


def test_pre_commit_reads_staged_paths(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "\n".join(
            [
                "[project]",
                'name = "validation-fixture"',
                'version = "0.1.0"',
                "dependencies = [",
                '  "requests>=2.31",',
                '  "demo-unknown>=1.0",',
                "]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("dependency_advisor.cli.collect_staged_paths", lambda: (manifest,))

    exit_code = main(["pre-commit", "--staged"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["source"] == "staged"
    assert payload["status"] == "blocked"
    assert payload["manifest_paths"] == [str(manifest)]


def test_validate_manifests_returns_blocked_json_for_invalid_toml(
    tmp_path: Path, capsys: Any
) -> None:
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text("[project\n", encoding="utf-8")

    exit_code = main(["validate-manifests", "--path", str(manifest)])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["status"] == "blocked"
    assert "Unable to validate changed manifests" in payload["reason"]


def test_action_manifest_uses_rich_summary() -> None:
    action_path = REPO_ROOT / "action.yml"
    action_contents = action_path.read_text(encoding="utf-8")
    assert "Publish rich summary" in action_contents
    assert "GITHUB_STEP_SUMMARY" in action_contents
