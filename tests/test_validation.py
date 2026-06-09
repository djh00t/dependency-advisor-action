from pathlib import Path

from dependency_advisor.models import FastValidationStatus, RecommendationStatus
from dependency_advisor.validation import ManifestValidator


def _write_pyproject(path: Path) -> None:
    path.write_text(
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


def _write_requirements(path: Path) -> None:
    path.write_text("requests>=2.31\ndemo-unknown>=1.0\n", encoding="utf-8")


def test_validate_changed_manifest_blocks_unknown_dependency(tmp_path: Path) -> None:
    manifest = tmp_path / "pyproject.toml"
    notes = tmp_path / "notes.md"
    _write_pyproject(manifest)
    notes.write_text("not a manifest\n", encoding="utf-8")

    result = ManifestValidator().validate([notes, manifest])

    assert result.status is FastValidationStatus.BLOCKED
    assert result.changed_files == (str(notes), str(manifest))
    assert result.manifest_paths == (str(manifest),)
    assert result.validated_dependencies == 2
    assert result.validated_scope == "project.dependencies"
    assert [finding.status for finding in result.findings] == [
        RecommendationStatus.RECOMMENDED,
        RecommendationStatus.UNKNOWN_PACKAGE,
    ]
    assert [finding.line for finding in result.findings] == [5, 6]


def test_validate_only_non_manifest_files_reports_no_changes(tmp_path: Path) -> None:
    notes = tmp_path / "notes.md"
    notes.write_text("not a manifest\n", encoding="utf-8")

    result = ManifestValidator().validate([notes])

    assert result.status is FastValidationStatus.NO_MANIFEST_CHANGES
    assert result.changed_files == (str(notes),)
    assert result.manifest_paths == ()
    assert result.reason == "No supported manifest changes were detected."
    assert result.validated_dependencies == 0
    assert not result.findings


def test_validate_pyproject_with_no_dependency_changes_is_ok(tmp_path: Path) -> None:
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text(
        "\n".join(
            [
                "[project]",
                'name = "validation-fixture"',
                'version = "0.1.0"',
                "dependencies = []",
                "",
            ]
        ),
        encoding="utf-8",
    )

    result = ManifestValidator().validate([manifest])

    assert result.status is FastValidationStatus.NO_MANIFEST_CHANGES
    assert result.reason == (
        "No supported manifest dependency entries were found in the changed files."
    )
    assert result.changed_files == (str(manifest),)
    assert result.manifest_paths == (str(manifest),)
    assert result.validated_dependencies == 0
    assert not result.findings


def test_validate_requirements_txt_is_supported(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    _write_requirements(requirements)

    result = ManifestValidator().validate([requirements])

    assert result.status is FastValidationStatus.BLOCKED
    assert result.changed_files == (str(requirements),)
    assert result.manifest_paths == (str(requirements),)
    assert result.validated_scope == "requirements.txt"
    assert result.validated_dependencies == 2
    assert [finding.line for finding in result.findings] == [1, 2]
    assert result.findings[1].status is RecommendationStatus.UNKNOWN_PACKAGE


def test_validate_blocks_requirements_directives(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("-r other.txt\n", encoding="utf-8")

    result = ManifestValidator().validate([requirements])

    assert result.status is FastValidationStatus.BLOCKED
    assert result.reason == "Changed manifests contain dependency entries that could not be parsed."
    assert result.changed_files == (str(requirements),)
    assert result.manifest_paths == (str(requirements),)
    assert result.validated_dependencies == 0
    assert not result.findings


def test_validate_mixed_manifest_scope_combines_supported_manifests(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "pyproject.toml"
    requirements = tmp_path / "requirements.txt"
    _write_pyproject(manifest)
    _write_requirements(requirements)

    result = ManifestValidator().validate([manifest, requirements])

    assert result.status is FastValidationStatus.BLOCKED
    assert result.changed_files == (str(manifest), str(requirements))
    assert result.manifest_paths == (str(manifest), str(requirements))
    assert result.validated_scope == "mixed"
    assert result.validated_dependencies == 4
    assert len(result.findings) == 4


def test_validate_blocks_unparseable_dependency_entries(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests>=2.31\n!!!\n", encoding="utf-8")

    result = ManifestValidator().validate([requirements])

    assert result.status is FastValidationStatus.BLOCKED
    assert result.reason == "Changed manifests contain dependency entries that could not be parsed."
    assert result.changed_files == (str(requirements),)
    assert result.manifest_paths == (str(requirements),)
    assert result.validated_dependencies == 1
    assert len(result.findings) == 1
