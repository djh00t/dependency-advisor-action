Feature: Validate changed manifests quickly
  Scenario: A changed pyproject manifest with an unsafe package is blocked
    Given a repository with a changed pyproject manifest and a changed non-manifest file
    When I validate the changed manifest paths
    Then the command exits with code 2
    And the validation status is "blocked"
    And the validation scope is "project.dependencies"
    And the validation reports 1 changed manifest
    And the validation reports 2 validated dependencies
    And the validation reports 2 findings
    And the validation finding for "demo-unknown" has status "unknown_package"

  Scenario: A changed requirements manifest with an unsafe package is blocked
    Given a repository with a changed requirements manifest and a changed non-manifest file
    When I validate the changed manifest paths
    Then the command exits with code 2
    And the validation status is "blocked"
    And the validation scope is "requirements.txt"
    And the validation reports 1 changed manifest
    And the validation reports 2 validated dependencies
    And the validation reports 2 findings
    And the validation finding for "demo-unknown" has status "unknown_package"

  Scenario: Changed pyproject and requirements manifests share validation scope
    Given a repository with changed pyproject and requirements manifests and a changed non-manifest file
    When I validate the changed manifest paths
    Then the command exits with code 2
    And the validation status is "blocked"
    And the validation scope is "mixed"
    And the validation reports 2 changed manifests
    And the validation reports 4 validated dependencies
    And the validation reports 4 findings
    And the validation finding for "demo-unknown" has status "unknown_package"

  Scenario: No supported manifest changes are ignored
    Given a repository with only changed non-manifest files
    When I validate the changed manifest paths
    Then the command exits with code 0
    And the validation status is "no_manifest_changes"
    And the validation reports 0 changed manifests
    And the validation reports 0 validated dependencies
    And the validation reports 0 findings
