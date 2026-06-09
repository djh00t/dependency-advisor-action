Feature: Release management

  Scenario: A merged feature PR updates the changelog and bumps a minor release
    Given a release changelog with version "0.1.0"
    When I record a merged PR titled "feat(action): add detailed release notes" with number 42
    Then the changelog records the PR under "Added"
    And the next release version is "0.2.0"
    And the release notes include "feat(action): add detailed release notes (#42)"

  Scenario: A merged fix PR updates the changelog and bumps a patch release
    Given a release changelog with version "0.1.0"
    When I record a merged PR titled "fix(release): keep changelog notes stable" with number 43
    Then the changelog records the PR under "Fixed"
    And the next release version is "0.1.1"
    And the release notes include "fix(release): keep changelog notes stable (#43)"

  Scenario: A merged breaking PR updates the changelog and bumps a major release
    Given a release changelog with version "0.1.0"
    When I record a merged PR titled "feat(api)!: drop legacy release flags" with number 44
    Then the changelog records the PR under "Breaking"
    And the next release version is "1.0.0"
    And the release notes include "feat(api)!: drop legacy release flags (#44)"
