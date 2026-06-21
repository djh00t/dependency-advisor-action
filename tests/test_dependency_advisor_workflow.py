from pathlib import Path


def test_dependency_advisor_workflow_uses_the_dedicated_action_repo() -> None:
    workflow_path = Path(".github/workflows/dependency-advisor.yml")
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "uses: ./" in workflow
    assert 'fail-on-findings: "true"' in workflow
    assert "Upload dependency advisor reports" in workflow
