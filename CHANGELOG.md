# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Public release packaging metadata, repository URLs, and MIT licensing.
- Contributor, security, and code-of-conduct guidance for a public GitHub
  repository.
- A GitHub Actions workflow that runs `make check` on pull requests and
  `make quality-gates` on pushes to `main`.
- A shared skill install target that defaults `make install` to
  `~/.agents/skills` with a repo-local override.
- A pre-commit hook manifest and `depadvisor pre-commit` entrypoint for fast
  manifest validation.
- A dedicated GitHub Action release workflow that syncs the action bundle into
  a separate publish repository.

### Changed

- README examples now use stable example timestamps instead of date values tied
  to a specific day.
- Roadmap wording now describes MCP as deferred until there is explicit demand.
- Phase 6 scan now skips SARIF uploads on private repository runs and only
  attempts code scanning uploads for public `main` pushes.
- Phase 6 scan now runs the repo's `make report-check` command directly and
  uploads artifacts with the published `actions/upload-artifact` release.
- The GitHub Action now publishes a step summary with report metrics and top
  findings for a richer UI.
- The GitHub Action release flow now publishes from a dedicated repository
  instead of the main source repo.
