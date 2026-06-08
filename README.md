# Dependency Advisor

Dependency Advisor is an agent-first dependency safety advisor for Rust, Python, JavaScript/Node/TypeScript, Bash/shell, and Swift projects.

It helps agents and developers choose dependency versions, scan repositories, validate changed manifests, and install Codex/OpenCode guidance that points back to `depadvisor recommend`.

This repository is the public open-source home for Dependency Advisor. It is MIT licensed, publishes the current release status in `CHANGELOG.md`, and accepts contributions and security reports through the project docs linked below.

## What It Does

| Command | Purpose |
| --- | --- |
| `depadvisor recommend <package>` | Recommends a dependency version using the selected ecosystem and policy. |
| `depadvisor scan <path>` | Scans a repository or manifest file and emits JSON, SARIF, and Markdown reports. |
| `depadvisor pre-commit` | Validates changed dependency manifests in a fast pre-commit workflow. |
| `depadvisor validate-manifests --path <path>` | Validates changed manifests for fast local and pre-commit workflows. |
| `depadvisor agent render-skill` | Renders the portable agent skill payload. |
| `depadvisor agent render-codex-agents` | Renders repo guidance for Codex. |
| `depadvisor agent install-skill` | Installs the portable skill package into the shared `~/.agents/skills` root. |
| `depadvisor agent install codex` | Installs the Codex skill and repo guidance into a target project. |
| `depadvisor agent install opencode` | Installs the OpenCode skill into a target project. |

## Recommendation Workflow

Use `recommend` before adding or upgrading a direct dependency:

```bash
depadvisor recommend requests --ecosystem python --policy standard
```

Recommendation results are filtered in this order:

1. Version satisfies the requested range.
2. Version is not yanked, deprecated, or blocked.
3. Version satisfies the selected minimum release age.
4. Version is the newest remaining valid candidate.

If no safe candidate remains, the advisor returns `blocked`.

Use `--version-range` to constrain acceptable releases:

```bash
uv run depadvisor recommend requests --version-range "<2.32"
```

The command returns structured JSON including `status`, `recommended_version`, `reason`, and provenance fields.

## Policy Modes

| Mode | Minimum release age | Intent |
| --- | ---: | --- |
| `loco` | 0 hours | Allow latest versions immediately. |
| `aggressive` | 48 hours | Fast-moving projects that still avoid zero-day publish risk. |
| `standard` | 14 days | Default. Avoid very new releases unless explicitly overridden. |
| `conservative` | 30 days | Production and security-sensitive projects. |

## Scan Reports

Use `scan` for repository-wide or manifest-level reporting:

```bash
uv run depadvisor scan . \
  --json-output build/reports/dependency-advisor.json \
  --sarif-output build/reports/dependency-advisor.sarif \
  --markdown-output build/reports/dependency-advisor.md
```

`scan` emits JSON to stdout and can also write JSON, SARIF, and Markdown report files for CI pipelines and local review.

The scanner:

- scans direct Python dependencies from `pyproject.toml` and `requirements.txt`,
- reuses the recommendation policy for dependency decisions,
- writes reports that CI can upload as artifacts or code-scanning input.

## Agent Integrations

Dependency Advisor ships integrations for Codex and OpenCode.

Render the portable skill payload:

```bash
depadvisor agent render-skill
```

Render the Codex guidance file:

```bash
depadvisor agent render-codex-agents
```

Install the portable skill package into the shared skills root:

```bash
depadvisor agent install-skill --skills-root ~/.agents/skills
```

Use `--skills-root /path/to/repo/.agents/skills` if you want a repo-local install instead of the shared default.

Install Codex integration into a project root:

```bash
depadvisor agent install codex --project-root /path/to/project
```

This writes:

- `.agents/skills/dependency-advisor/SKILL.md`
- `AGENTS.md` when the target project does not already define one
- an appended `## Dependency Advisor` section when the target project already has `AGENTS.md`

Install the OpenCode skill into a project root:

```bash
depadvisor agent install opencode --project-root /path/to/project
```

This writes:

- `.opencode/skills/dependency-advisor/SKILL.md`

The shipped skill tells an agent to run `depadvisor recommend --policy <policy>` before adding or upgrading direct dependencies and to stop when the recommendation status is not `recommended`.

The repository also ships:

- `.pre-commit-hooks.yaml` for `pre-commit` consumers
- `action.yml` as the source for the dedicated GitHub Action release repo

To test the dedicated action release path without publishing a main-repo release, run the
`Publish GitHub Action` workflow with `workflow_dispatch` and provide a temporary
`release_tag` such as `v0.0.0-action-test`.

## Performance Targets

| Operation | Target |
| --- | ---: |
| Warm-cache agent recommendation | <25 ms |
| Single dependency validation | <50 ms |
| Changed manifest pre-commit check | <250 ms typical, <1 s target |
| CI full dependency audit | <30 s target for normal repos |

## Development

```bash
make install
make check
make quality-gates
```

`make install` installs dependencies and refreshes the shared skill package in `~/.agents/skills` by default. Set `SKILL_INSTALL_ROOT=./.agents/skills` if you want a repo-local install instead.

The package is a typed Python 3.13 project managed by `uv`. It provides:

- `dependency_advisor.models`: Pydantic request and result models.
- `dependency_advisor.policy`: recommendation flow with warm-cache and built-in fallback behaviour.
- `dependency_advisor.config`: policy release-age, registry endpoint, and cache configuration.
- `dependency_advisor.cache`: SQLite persistence for normalized package metadata.
- `dependency_advisor.registry`: adapters for PyPI, npm, crates.io, and Swift-compatible registries.
- `dependency_advisor.scan`: repository scan and report formatting.
- `dependency_advisor.validation`: fast changed-manifest validation.
- `dependency_advisor.vulnerabilities`: bootstrap advisory providers for OSV-, `pip-audit`-, `cargo-deny`-, and `npm audit`-style sources.
- `dependency_advisor.cli`: the Typer-based `depadvisor` command-line interface.

Install dependencies and run the CLI:

```bash
make install
uv run depadvisor recommend requests
uv run depadvisor scan .
uv run depadvisor pre-commit --staged
uv run depadvisor validate-manifests --path pyproject.toml --path requirements.txt
```

Warm-cache lookups are served from SQLite. Cache misses fetch live metadata from the configured registry adapter, store freshness timestamps, and emit provenance in the JSON response. The built-in catalog remains as a small offline fallback when registry metadata is unavailable.

Unknown packages return structured `unknown_package` output instead of performing live registry or vulnerability lookups. Known packages that have no safe candidate after version-range and policy filtering return structured `blocked` output and a non-zero CLI exit code.

Environment overrides:

- `DEPENDENCY_ADVISOR_CACHE_PATH`: override the SQLite cache location.
- `DEPENDENCY_ADVISOR_CACHE_TTL_SECONDS`: override metadata freshness TTL.
- `DEPENDENCY_ADVISOR_ALLOW_STALE_ON_ERROR=0`: disable stale-cache fallback on registry fetch errors.
- `DEPENDENCY_ADVISOR_SWIFT_REGISTRY_BASE_URL`: enable the Swift registry adapter with an explicit registry base URL.

## Project Docs

- Contributing: `CONTRIBUTING.md`
- Security: `SECURITY.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Change history: `CHANGELOG.md`
- License: `LICENSE`
