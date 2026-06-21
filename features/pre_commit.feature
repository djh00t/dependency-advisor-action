Feature: Validate changed dependency manifests before commit
  Scenario: A changed pyproject manifest blocks the pre-commit contract
    Given a repository with a changed pyproject manifest and a changed non-manifest file
    When I run depadvisor pre-commit on the changed paths
    Then the command exits with code 2
    And the validation status is "blocked"
    And the validation scope is "project.dependencies"
    And the validation reports 1 changed manifest
    And the validation reports 2 validated dependencies
    And the validation reports 2 findings
    And the validation finding for "demo-unknown" has status "unknown_package"

  Scenario: No supported changes are ignored by pre-commit
    Given a repository with only changed non-manifest files
    When I run depadvisor pre-commit on the changed paths
    Then the command exits with code 0
    And the validation status is "no_manifest_changes"
    And the validation reports 0 changed manifests
    And the validation reports 0 validated dependencies
    And the validation reports 0 findings
