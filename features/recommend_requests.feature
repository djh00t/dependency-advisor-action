Feature: Recommend dependencies with policy and vulnerability filtering
  Scenario: Happy-path recommendation for requests
    Given the CLI uses the built-in catalog
    When I run depadvisor recommend requests
    Then the command exits with code 0
    And the output status is "recommended"
    And the output package is "requests"
    And the output recommended version is "2.32.3"
    And the candidate count is 4
    And the advisory sources are:
      | osv       |
      | pip-audit |

  Scenario: Version range can select an older safe release
    Given the CLI uses the built-in catalog
    When I run depadvisor recommend requests with version range "<2.32"
    Then the command exits with code 0
    And the output status is "recommended"
    And the output package is "requests"
    And the output recommended version is "2.31.0"
    And the candidate count is 4

  Scenario: Blocked result when no candidate satisfies the version range
    Given the CLI uses the built-in catalog
    When I run depadvisor recommend requests with version range ">3"
    Then the command exits with code 2
    And the output status is "blocked"
    And the output package is "requests"
    And no version is recommended
    And the candidate count is 4

  Scenario: Unknown package returns structured output
    Given the CLI uses the built-in catalog
    When I run depadvisor recommend unknown-package
    Then the command exits with code 2
    And the output status is "unknown_package"
    And the output package is "unknown-package"
    And no version is recommended
    And the candidate count is 0

  Scenario: Requesting advice for requests from a warm cache
    Given registry metadata for requests is cached
    When I run depadvisor recommend requests
    Then the command exits with code 0
    And the output status is "recommended"
    And the output package is "requests"
    And the output recommended version is "2.34.2"
    And the output source is "pypi"
    And the output provenance cache status is "hit"

  Scenario: Refreshing stale registry metadata
    Given stale registry metadata for requests is cached
    And refreshed registry metadata for requests is available
    When I run depadvisor recommend requests
    Then the command exits with code 0
    And the output status is "recommended"
    And the output package is "requests"
    And the output recommended version is "2.34.2"
    And the output source is "pypi"
    And the output provenance cache status is "refresh"

  Scenario: Installing the Codex integration
    When I install the Codex integration into a temporary project
    Then the command succeeds
    And the install reports written files
    And the temporary project contains a Codex skill file
    And the temporary project contains an AGENTS.md file

  Scenario: Installing the OpenCode integration
    When I install the OpenCode integration into a temporary project
    Then the command succeeds
    And the install reports written files
    And the temporary project contains an OpenCode skill file

  Scenario: Installing the Codex integration into a project with existing guidance
    When I install the Codex integration into a temporary project with an existing AGENTS.md file
    Then the command succeeds
    And the install reports written files
    And the temporary project contains a Codex skill file
    And the temporary project preserves the existing AGENTS.md content
    And the temporary project contains the Dependency Advisor AGENTS section

  Scenario: Rust recommendation reports advisory sources
    When I run depadvisor recommend "serde" for ecosystem "rust"
    Then the command exits with code 0
    And the output status is "recommended"
    And the output package is "serde"
    And the output recommended version is "1.0.228"
    And the candidate count is 315
    And the advisory sources are:
      | osv        |
      | cargo-deny |

  Scenario: JavaScript recommendation reports advisory sources
    When I run depadvisor recommend "minimist" for ecosystem "javascript"
    Then the command exits with code 0
    And the output status is "recommended"
    And the output package is "minimist"
    And the output recommended version is "0.2.4"
    And the candidate count is 31
    And the advisory sources are:
      | osv       |
      | npm-audit |
