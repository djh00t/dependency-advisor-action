Feature: Registry metadata and cache flows
  Scenario: Inspecting warm registry metadata returns a cached snapshot
    Given registry metadata for requests is cached
    When I run depadvisor metadata requests
    Then the command exits with code 0
    And the output status is "hit"
    And the output package is "requests"
    And the output version count is 1
    And the output provenance cache status is "hit"

  Scenario: Inspecting cache freshness does not hit the network
    Given registry metadata for requests is cached
    When I run depadvisor cache inspect requests
    Then the command exits with code 0
    And the output status is "hit"
    And the output package is "requests"
    And the output version count is 1

  Scenario: Offline metadata lookup returns a cached snapshot
    Given registry metadata for requests is cached
    When I run depadvisor metadata requests offline
    Then the command exits with code 0
    And the output status is "hit"
    And the output package is "requests"
    And the output version count is 1

  Scenario: Offline metadata lookup fails clearly when the cache is empty
    Given no registry metadata for requests is cached
    When I run depadvisor metadata requests offline
    Then the command exits with code 2
    And the output status is "miss"
    And the output package is "requests"
    And the output version count is 0

  Scenario: Cache refresh replaces stale metadata with a fresh snapshot
    Given stale registry metadata for requests is cached
    And refreshed registry metadata for requests is available
    When I run depadvisor cache refresh requests
    Then the command exits with code 0
    And the output status is "refresh"
    And the output package is "requests"
    And the output version count is 1
    And the output provenance cache status is "refresh"
