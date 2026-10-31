# Vexa SCA CLI Usage Guide (v2.0 / GA v1.2.0+)

## Status & Operational Readiness

Vexa SCA is **Generally Available (GA)** for Tier 1 ecosystems (Node.js / JavaScript / TypeScript: `package-lock.json` v2/v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v5/v6/v9). Other ecosystems (Python, Java Maven, Go, Cargo, Yarn, Container OS) are provided under Tier 2 (Experimental) preview.

Vexa SCA provides a deterministic, zero-external-dependency CLI engine for local developer triage (`vexa-sca scan`), automated CI enforcement (`vexa-sca ci`), dependency remediation proposals (`vexa-sca fix`), license auditing (`vexa-sca licenses`), SBOM generation (`--sbom cyclonedx|spdx`), pre-installation package security firewall (`vexa-sca wrap`), and an MCP server for AI coding assistants (`vexa-sca mcp`).

### Core Operational Principles
- **Verdict Integrity:** The analyzer emits heuristic **Repository Usage Signals** based on static AST parsing via a single-pass `WorkspaceAstIndex`. It assists developers in prioritizing actionable items without unsafely suppressing unproven findings. Quality gates evaluate the complete unsuppressed vulnerability set.
- **`UNREACHABLE` Verdict (v2.0):** Emitted only when AST coverage is complete (no file-limit hit, no parse failures, no unresolved dynamic imports, no barrel re-exports, not a transitive dependency) **and** no import or call site is found. All other cases produce `UNKNOWN`. This is a strict no-false-safe verdict — ambiguity always falls back to `UNKNOWN`.
- **Multi-Language Coverage (v2.0):** JS/TS (full oxc AST), Python (import/call-site regex), Rust (`use` + direct call matching), Go, and Java are all indexed in one pass. Non-JS files are never fed to `oxc_parser`.
- **Deterministic Exit Contract:** Exit codes strictly follow the precedence: `2` (Config error) > `3` (Incomplete scan data) > `1` (Quality gate failure) > `0` (Success).
- **Remediation Safety:** `vexa-sca fix` prioritizes same-major patch and minor updates, providing best-effort byte-for-byte rollback of captured root manifests and lockfiles upon install failure.
- **Privacy & Upstream Queries:** Scans query public OSV advisories (`api.osv.dev`) with package coordinates (`ecosystem`, `name`, `version`). No first-party source code or git history is transmitted. The `.sca-cache/` directory accelerates repeat runs.

## Reachability Verdicts at a Glance

| Verdict | What it means |
|---|---|
| `Reachable` | Import AND call site confirmed in non-test production source |
| `Unknown` | Coverage incomplete — see `reason_code` for detail |
| `Unreachable` | **Positive-proof absence**: full coverage, no usage found |

`Unknown` reason codes include: `NO_SYMBOL_DATA`, `TRANSITIVE_NOT_ANALYZED`, `FILE_LIMIT_HIT`, `PARSE_FAILURE`, `DYNAMIC_IMPORT`, `HAS_REEXPORTS`.

## Scan and inspect

Run a basic scan from the project root:

```sh
vexa-sca scan
```

A successful parse is not proof that every manifest, workspace importer, lockfile edge, or source construct was covered. Review diagnostics, identified manifests, dependency counts, and the completeness status before interpreting findings.

The analyzer emits heuristic **Repository Usage Signals** based on selected syntactic patterns in a single-pass `WorkspaceAstIndex`. For JS/TS, it uses full `oxc` AST parsing; for Python, Rust, Go, and Java it uses language-appropriate import and call-site matchers. Non-JS/TS files are never fed to the JavaScript parser. It does not prove runtime reachability or exploitability and does not model general cross-file dataflow, control flow, reflection, all dynamic imports, or every bundler/workspace rule.

`UNREACHABLE` verdicts are only emitted when the workspace index achieved full coverage AND found no import or call site for the vulnerable symbol. Any ambiguity (file-limit hit, parse failure, dynamic import, barrel re-export, transitive dependency) produces `UNKNOWN` instead. Use `--reachable-only` only to filter presentation for triage; severity gates must evaluate the complete unsuppressed finding set. Do not use `--allow-unknown-reachability` or `--fail-on-reachable` as a substitute for a validated security policy.

The scanner sends package coordinates to OSV for advisory lookup. Review that data flow against your privacy requirements. `.sca-cache/` can reduce repeat queries but is not a complete, signed, or indefinitely fresh offline advisory database.

## Reports

The CLI exposes report formats such as JSON, SARIF, Markdown, HTML, and SBOM output; validate each artifact against the downstream consumer and schema version you use. Example for an HTML report:

```sh
vexa-sca scan --html-file sca-report.html
```

The HTML report is intended to be self-contained, but it reflects only the scan inputs and findings actually produced; an offline report does not imply an offline-complete vulnerability database.

## Exit behavior for automation

The intended exit-code contract in the current source is:

| Code | Meaning |
|---:|---|
| `0` | No configured gate failure was found in the processed data. This is not a completeness certificate. |
| `1` | A configured quality gate failed. |
| `2` | Invalid arguments or policy/configuration. |
| `3` | Scan data is incomplete, including relevant advisory, manifest, source-read/traversal, or analysis-limit failures. |

`--allow-unavailable` is limited to advisory-only unavailability; it must not waive source or manifest failures. `--no-fail` applies to quality-gate failures only; it must not turn configuration errors or incomplete scans into success. These changes still require release-matched tests on all supported operating systems before they can be treated as a production contract.

During evaluation, make the job non-blocking and archive outputs. Before enforcement, independently test a clean scan, a finding that violates a gate, malformed policy, unreadable source, malformed/unsupported manifest, advisory timeout/detail failure, and the advisory-only override. Confirm that reports are preserved on every outcome.

## Remediation helper

`vexa-sca fix --dry-run` is intended to preview proposals. Before applying changes, use a clean worktree and review the entire diff; then run the package manager, application tests, and build yourself. The helper may edit the root manifest and invoke package-manager lockfile regeneration. On failure, it attempts to restore captured root manifests/lockfiles, but it does not roll back `node_modules`, nested workspace files, registry effects, or arbitrary process side effects. Do not auto-merge generated changes.

## Policy files

Policy is repository-local (`.vexa-sca` or `.vexa-sca.json`); this project does not provide a centralized policy distribution or organization-wide waiver dashboard. Validate policy changes in review, require named ownership and expiry for exceptions, and monitor waivers through your existing governance systems.

---

## Package Manager Firewall (`vexa-sca wrap`)

`vexa-sca wrap` is a **pre-installation security gate** that intercepts package manager commands, evaluates each requested package against multiple threat signals, and blocks the installation if any risk is confirmed — using zero shell interpolation (safe against shell injection).

### Supported Package Managers

`npm`, `pnpm`, `yarn`, `bun`, `pip`, `uv`, `cargo`

### Usage

```sh
vexa-sca wrap <PACKAGE_MANAGER> [ARGS...]
```

### Examples

```sh
# Intercept npm install — scan all packages before allowing install
vexa-sca wrap npm install lodash express

# Intercept pnpm add
vexa-sca wrap pnpm add react react-dom

# Intercept pip install
vexa-sca wrap pip install flask requests

# Intercept cargo add
vexa-sca wrap cargo add serde tokio

# In CI — integrate as a drop-in replacement for your package manager
vexa-sca wrap npm ci
```

### What it checks (in order)

1. **Typosquatting detection (SC-010)** — Computes Damerau-Levenshtein edit distance ≤ 1 against a curated list of popular packages. Blocks `loadsh`, `reqests`, `expres`, `serde-json` (vs `serde_json`), etc.
2. **CISA KEV check** — Fetches and caches the CISA Known Exploited Vulnerabilities catalog (24 h TTL at `.sca-cache/cisa_kev.json`). Blocks any package with a KEV-listed CVE.
3. **OSV advisory scan** — Queries `api.osv.dev` for published advisories against each package name + version.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | All checks passed — original package manager command executed |
| `1` | Security check failed — install **blocked**, original command NOT executed |
| `2` | Invalid arguments or package manager not recognized |

> [!CAUTION]
> When `vexa-sca wrap` exits 1 (FIREWALL BLOCKED), the underlying package manager command is **never executed**. This is by design. Review the printed finding before proceeding.

> [!NOTE]
> Team+ authenticated mode: set `VEXA_SCA_API_KEY` to enable additional server-side supply chain checks.

---

## MCP Server (`vexa-sca mcp`)

`vexa-sca mcp` starts a **Model Context Protocol (MCP)** server over `stdin`/`stdout` using the JSON-RPC 2.0 protocol. This integrates Vexa SCA security tooling directly into AI coding assistants such as **Cursor**, **Claude Code**, **Windsurf**, and **GitHub Copilot**.

### Usage

```sh
vexa-sca mcp
```

The server runs indefinitely, reading one JSON-RPC 2.0 request per line from `stdin` and writing one response per line to `stdout`.

### MCP Tools Exposed

| Tool Name | Input Parameters | Description |
| :--- | :--- | :--- |
| `vexa_check_package` | `name: str`, `version: str`, `ecosystem?: str` | Check a single package for known vulnerabilities, CISA KEV status, and supply chain risks |
| `vexa_scan_workspace` | `path: str` | Scan an entire workspace directory; returns structured findings (vulnerabilities + supply chain) |
| `vexa_explain_finding` | `finding_id: str` or `rule_id: str` | Plain-English explanation of a CVE finding or supply chain rule (SC-001–SC-015) |
| `vexa_remediate_manifest` | `path: str`, `package: str`, `target_version: str` | Propose a patched version for a vulnerable dependency in a manifest file |

### MCP Client Configuration

**Cursor** (`.cursor/mcp.json` or global `mcp.json`):
```json
{
  "mcpServers": {
    "vexa-sca": {
      "command": "vexa-sca",
      "args": ["mcp"]
    }
  }
}
```

**Claude Code** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "vexa-sca": {
      "command": "vexa-sca",
      "args": ["mcp"],
      "env": {}
    }
  }
}
```

### Protocol Details

- Transport: `stdin`/`stdout`, newline-delimited JSON-RPC 2.0
- Initialization: client sends `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}`; server responds with capabilities and tool list
- Tool discovery: `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
- Tool call: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vexa_check_package","arguments":{"name":"lodash","version":"4.17.15"}}}`

> [!NOTE]
> The MCP server does not require network access for local supply chain analysis. OSV advisory lookups and CISA KEV checks require outbound HTTPS to `api.osv.dev` and `www.cisa.gov`.

---

## Zero-Code-Retention Facts Export (`--upload-facts`)

The `--upload-facts` flag generates a `.vexa.facts.json` file in the scan root. This file contains workspace scan facts — dependency graph topology, resolved package coordinates, and AST import facts (which packages are imported in which files, with call locations) — structured for Team+ upload.

### What it does NOT include

- First-party source code content
- File contents of any kind
- Git history, commit SHAs, or author metadata

### Usage

```sh
# Generate .vexa.facts.json alongside a normal scan
vexa-sca scan --upload-facts

# Combine with other outputs
vexa-sca scan --upload-facts --json --sarif-file results.sarif
```

### Output schema (`.vexa.facts.json`)

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-10-31T17:00:00Z",
  "workspace_root": "/path/to/project",
  "manifests": [
    {
      "path": "package.json",
      "ecosystem": "npm",
      "dependencies": [
        { "name": "lodash", "version": "4.17.15", "is_direct": true, "is_dev": false }
      ]
    }
  ],
  "ast_facts": {
    "total_files_indexed": 142,
    "package_importers": {
      "lodash": ["src/utils.ts", "src/api/handler.ts"]
    },
    "call_locations": [
      { "package": "lodash", "symbol": "merge", "file": "src/utils.ts", "line": 14 }
    ]
  }
}
```

> [!NOTE]
> `.vexa.facts.json` is designed for the Zero-Code-Retention architecture: only dependency coordinates and import-graph facts are exported — no source code leaves your environment.
