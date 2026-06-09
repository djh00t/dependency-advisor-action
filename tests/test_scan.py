import json
import tomllib
from pathlib import Path

import pytest

from dependency_advisor.models import RecommendationStatus
from dependency_advisor.scan import (
    RepositoryScanner,
    report_as_json,
    report_as_markdown,
    report_as_sarif,
)

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "scan_project"
REPO_ROOT = Path(__file__).resolve().parents[1]


def test_repository_scanner_collects_supported_manifests() -> None:
    report = RepositoryScanner().scan(FIXTURE_ROOT)

    assert report.summary.manifests_scanned == 2
    assert report.summary.dependencies_scanned == 4
    assert report.summary.findings == 2
    assert report.summary.status_counts[RecommendationStatus.RECOMMENDED] == 2
    assert report.summary.status_counts[RecommendationStatus.UNKNOWN_PACKAGE] == 2
    assert report.manifests_scanned == ["pyproject.toml", "requirements.txt"]


def test_repository_scanner_supports_single_manifest_paths() -> None:
    report = RepositoryScanner().scan(FIXTURE_ROOT / "requirements.txt")

    assert report.manifests_scanned == ["requirements.txt"]
    assert report.results[0].manifest_path == "requirements.txt"


def test_repository_scanner_ignores_fixture_manifests_in_repo_root_scan() -> None:
    report = RepositoryScanner().scan(REPO_ROOT)

    assert "tests/fixtures/scan_project/pyproject.toml" not in report.manifests_scanned
    assert "tests/fixtures/scan_project/requirements.txt" not in report.manifests_scanned


def test_repository_scanner_raises_for_manifest_parse_errors(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project\nname = 'broken'\n", encoding="utf-8")

    with pytest.raises(tomllib.TOMLDecodeError):
        RepositoryScanner().scan(tmp_path)


def test_markdown_report_contains_summary_and_table() -> None:
    report = RepositoryScanner().scan(FIXTURE_ROOT)

    markdown = report_as_markdown(report)

    assert "- Findings: `2`" in markdown
    assert "- Status counts: recommended: 2, unknown_package: 2" in markdown
    assert "| Manifest | Package | Status | Recommended | Reason |" in markdown
    assert "`requests`" in markdown
    assert "`demo-unknown`" in markdown


def test_sarif_report_only_emits_findings() -> None:
    report = RepositoryScanner().scan(FIXTURE_ROOT)

    sarif = report_as_sarif(report)

    assert sarif["runs"][0]["tool"]["driver"]["name"] == "dependency-advisor"
    assert {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]} == {
        "DEPADVISOR_UNKNOWN_PACKAGE",
        "DEPADVISOR_BLOCKED",
    }
    assert len(sarif["runs"][0]["results"]) == 2
    assert {result["ruleId"] for result in sarif["runs"][0]["results"]} == {
        "DEPADVISOR_UNKNOWN_PACKAGE"
    }


def test_duplicate_dependencies_track_distinct_source_lines(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "\n".join(
            [
                "[project]",
                'name = "line-fixture"',
                'version = "0.1.0"',
                "dependencies = [",
                '  "demo-unknown>=1.0",',
                "]",
                "",
                "[dependency-groups]",
                "dev = [",
                '  "demo-unknown==2.0",',
                "]",
                "",
            ]
        ),
        encoding="utf-8",
    )

    report = RepositoryScanner().scan(pyproject)
    sarif = report_as_sarif(report)

    assert [result.line for result in report.results] == [5, 10]
    assert [
        finding["locations"][0]["physicalLocation"]["region"]["startLine"]
        for finding in sarif["runs"][0]["results"]
    ] == [5, 10]


def test_json_report_is_stable_json() -> None:
    report = RepositoryScanner().scan(FIXTURE_ROOT)

    payload = json.loads(report_as_json(report))

    assert payload["policy"] == "standard"
    assert payload["summary"]["dependencies_scanned"] == 4
