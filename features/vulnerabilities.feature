Feature: Inspect vulnerability evidence and blocked decisions
  Scenario: Inspect normalized vulnerability records for a package
    Given the CLI uses the built-in catalog
    When I run depadvisor vulnerabilities requests
    Then the command exits with code 0
    And the vulnerability report package is "requests"
    And the vulnerability report ecosystem is "python"
    And the vulnerability report contains 2 records
    And the vulnerability report advisory sources are:
      | osv       |
      | pip-audit |

  Scenario: Explain why a vulnerable version range is blocked
    Given the CLI uses the built-in catalog
    When I run depadvisor explain requests with version range ">=2.32.4,<=2.32.4"
    Then the command exits with code 2
    And the output status is "blocked"
    And no version is recommended
    And the output fixed versions are:
      | 2.32.3 |
    And the advisory sources are:
      | osv       |
      | pip-audit |
