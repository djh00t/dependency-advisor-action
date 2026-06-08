# Dependency Advisor GitHub Action

Use this action to run Dependency Advisor scans in GitHub Actions and publish JSON, SARIF, and Markdown reports.

## Quick Start

```yaml
name: Dependency Advisor

on:
  pull_request:
  push:
    branches:
      - main

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6
      - uses: djh00t/dependency-advisor-action@vX.Y.Z
        with:
          path: .
          policy: standard
          fail-on-findings: "true"
          json-output: build/reports/dependency-advisor.json
          sarif-output: build/reports/dependency-advisor.sarif
          markdown-output: build/reports/dependency-advisor.md
```

## Inputs

| Input | Default | Purpose |
| --- | --- | --- |
| `path` | `.` | Repository or subdirectory to scan. |
| `policy` | `standard` | Policy mode passed to `depadvisor scan`. |
| `fail-on-findings` | `false` | Fail the job when findings are reported. |
| `python-version` | `3.13` | Python version used by the action runtime. |
| `json-output` | `dependency-advisor.json` | JSON report output path. |
| `sarif-output` | `dependency-advisor.sarif` | SARIF report output path. |
| `markdown-output` | `dependency-advisor.md` | Markdown report output path. |

## Outputs

| Output | Purpose |
| --- | --- |
| `json_output` | Path to the generated JSON report. |
| `sarif_output` | Path to the generated SARIF report. |
| `markdown_output` | Path to the generated Markdown report. |

## Configure It

1. Check out the repository you want to scan.
2. Add the action to a workflow job with a pinned release tag.
3. Set `fail-on-findings` to `true` if the job should fail when Dependency Advisor reports issues.
4. Point the output paths at a build directory if you want to upload or archive the generated reports.

## Notes

- Pin a release tag for stable CI. Use `main` only when you are validating the action itself.
- Replace `vX.Y.Z` in the example with the release tag you want to pin.
- The action runs `uv sync --all-groups` and then executes `depadvisor scan` against the requested path.
- Use the generated reports as build artifacts or code-scanning input.
