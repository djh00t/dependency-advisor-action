Feature: Install shared agent tooling
  Scenario: Installing the portable skill into a shared skills root
    When I install the shared skill into a temporary skills root
    Then the command succeeds
    And the install reports written files
    And the temporary skills root contains a shared skill file
