Feature: Scan a repository for CI reporting
  Scenario: Generating repository scan artifacts
    When I run depadvisor scan-repo on the fixture repository
    Then the repository scan succeeds
    And the scan summary reports findings
    And a SARIF report is written
    And a Markdown report is written

  Scenario: Failing a repository scan on execution errors
    Given a repository with an invalid pyproject manifest
    When I run depadvisor scan-repo on that repository failing on execution-errors
    Then the repository scan exits with code 2
    And the scan summary reports 1 execution error
    And the scan report records the invalid manifest error
