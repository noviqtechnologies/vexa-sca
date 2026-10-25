# Vexa SCA CLI Usage Guide

## Executive Summary
The Vexa SCA Command-Line Interface (CLI) provides a fast, deterministic Software Composition Analysis engine. Built in pure Rust, it is optimized for modern JavaScript and TypeScript development (`package-lock.json` v2/v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml`) in pull request automation workflows and GitHub Actions pipelines.

Vexa SCA analyzes dependency manifests, classifies findings using **Repository Usage Signals** (direct source imports, dynamic require/imports, and script entries) without unsafe suppression under positive-proof verdict integrity rules, enforces deterministic quality gates, and generates compliant Software Bill of Materials (SBOMs) and automated same-major pull requests.

> [!NOTE]
> **Ecosystem Maturity Tiers:**
> - **Production Pilot Ready (P0):** Node.js / JavaScript / TypeScript (`package-lock.json` v2 & v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v5/v6/v9), PR-differential scanning (`--baseline`), GitHub Actions integration (`vexa-sca ci`, `vexa-sca init`), transactional remediation (`vexa-sca fix`), strict policy engine (`.vexa-sca`), process exit code contract (0, 1, 2, 3).
> - **Experimental / Fixture Coverage (P2):** Python (`requirements.txt`), Java Maven (`pom.xml`), Yarn (`yarn.lock`), Container OS packages (`vexa-sca container`), Copyleft license audit (`vexa-sca licenses`).

---

## Prerequisites
Before executing Vexa SCA, verify that your environment satisfies the following requirements:

### Common Requirements
- **Operating System**: Linux (glibc 2.28+ or musl/Alpine), macOS (11.0+ Big Sur or later, Apple Silicon or Intel), or Windows (10, 11, or Windows Server 2019+).
- **Network Access**: Outbound HTTPS (TCP port 443) to vulnerability advisory databases (`api.osv.dev`) or access to an air-gapped pre-seeded cache directory (`.sca-cache/`).
- **Disk Space**: ~30 MB for the standalone compiled binary.

### Toolchain Prerequisites by Installation Method
| Installation Path | Required Software & Minimum Version | Applicable Environments |
| :--- | :--- | :--- |
| **Native Rust (Direct / Source)** | Rust Toolchain & Cargo (`v1.75.0+`) | Linux, macOS, Windows |
| **Node.js Wrapper / NPX** | Node.js (`v16.0.0+`) & npm (`v8.0.0+`) | Linux, macOS, Windows |
| **Standalone Binary** | None (Pre-compiled native executable with static `rustls`) | Linux (x86_64, aarch64), macOS (ARM64/x86_64), Windows (x64) |

---

## Installation / Initialization

### Option A: Global Installation via Cargo (Recommended for Rust Developers)
Compiles and places the `vexa-sca` binary (along with aliases `vexa` and `sca`) directly onto your system `PATH`.

#### Linux & macOS
```bash
# Install globally from Git repository
cargo install --git https://github.com/noviqtechnologies/vexa-sca.git

# Verify binary availability
vexa-sca --version
```

#### Windows (PowerShell)
```powershell
# Install globally from Git repository
cargo install --git https://github.com/noviqtechnologies/vexa-sca.git

# Verify binary availability
vexa-sca.exe --version
```

---

### Option B: Node.js / NPX Cross-Platform Wrapper
If your environment standardizes on npm, Vexa SCA provides a zero-setup JavaScript launcher (`bin/vexa-sca.js`) that detects your operating system and invokes the native compiled engine:

#### Global npm Installation
```bash
# Linux / macOS (may require sudo depending on npm prefix)
npm install -g vexa-sca

# Windows (Command Prompt or PowerShell)
npm install -g vexa-sca
```

#### Zero-Install Ad-Hoc Invocations (NPX)
```bash
# Linux, macOS, and Windows
npx vexa-sca scan --help
```

---

### Option C: Manual Pre-Compiled Binary Download
Download standalone, self-contained binaries with zero dependencies from the [GitHub Releases](https://github.com/noviqtechnologies/vexa-sca/releases) page.

#### Linux & macOS (Bash/Zsh)
```bash
# Download and extract the archive for your architecture
curl -sSL "https://github.com/noviqtechnologies/vexa-sca/releases/latest/download/vexa-sca-linux-x86_64.tar.gz" | tar -xz

# Move to a directory in your system PATH
sudo mv vexa-sca /usr/local/bin/
sudo chmod +x /usr/local/bin/vexa-sca

# Test binary
vexa-sca --help
```

#### Windows (PowerShell)
```powershell
# Create destination directory
New-Item -ItemType Directory -Force -Path "$HOME\bin"

# Download and extract release archive
Invoke-WebRequest -Uri "https://github.com/noviqtechnologies/vexa-sca/releases/latest/download/vexa-sca-windows-x86_64.zip" -OutFile "$HOME\bin\vexa-sca.zip"
Expand-Archive -Path "$HOME\bin\vexa-sca.zip" -DestinationPath "$HOME\bin" -Force
Remove-Item "$HOME\bin\vexa-sca.zip"

# Add to user PATH for current and future sessions
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$HOME\bin*") {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$HOME\bin", "User")
    $env:Path += ";$HOME\bin"
}

# Test execution
vexa-sca.exe --help
```

---

## Step-by-Step Implementation Guide

### 1. Basic Workspace Scan
Navigate to your application repository containing a supported manifest or lockfile (e.g., `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `requirements.txt`, `Cargo.lock`, `go.sum`, or `pom.xml`):

```bash
# Scan the current working directory
vexa-sca scan

# Scan an explicit target path
vexa-sca scan /path/to/[project-root]
```

### 2. Prioritizing Findings with Repository Usage Signals
Vexa SCA parses repository source code (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, `.cts`) to identify syntactic imports and function call sites:

```bash
# Display only vulnerabilities with confirmed syntactic call paths
vexa-sca scan --reachable-only

# Filter only production dependencies (excluding devDependencies)
vexa-sca scan --prod-only --reachable-only
```

> [!NOTE]
> **Usage Signals vs Control-Flow Proof**:
> Syntactic call-site matching proves that a module or function is referenced in source files. It does **not** evaluate runtime execution paths, input validation, or exploitability. Findings that cannot be proven or resolved are classified as `UNKNOWN` reachability and fail reachable-only gates by default.

### 3. Actionable-Only Filtering (Ignore Unfixed)
Avoid backlog churn by focusing solely on vulnerabilities that have a known patch or upgrade available:

```bash
vexa-sca scan --ignore-unfixed
```

### 4. Prioritizing by EPSS Exploit Likelihood
Filter vulnerabilities using FIRST.org Exploit Prediction Scoring System (EPSS) probabilities (0.0 to 1.0) to focus strictly on CVEs being actively weaponized in the wild:

```bash
# Isolate vulnerabilities with >= 20% probability of exploitation
vexa-sca scan --epss-threshold 0.20

# Strict prioritization: Must have confirmed usage AND >= 50% exploit likelihood
vexa-sca scan --reachable-only --epss-threshold 0.50
```

### 5. Exporting Reports in Multi-Format Standards
Vexa SCA supports standard export formats without requiring external conversion tools.

#### Structured Machine Formats (JSON & Markdown)
```bash
# Export formatted JSON to stdout or file
vexa-sca scan --json > audit-results.json

# Export formatted Markdown summary
vexa-sca scan --markdown > audit-summary.md
```

#### OASIS SARIF v2.1.0 (Static Analysis Results Interchange Format)
```bash
# Stream SARIF directly to stdout
vexa-sca scan --sarif

# Save directly to a designated file
vexa-sca scan --sarif-file results.sarif
```

#### Standalone Interactive HTML Audit Dashboard
Vexa SCA generates an offline-ready, glassmorphism dark-theme HTML report with zero external CDN dependencies, embedded interactive charts, and call-site inspectors:

```bash
# Write interactive HTML dashboard directly to a file
vexa-sca scan --html-file sca-report.html
```

#### Software Bill of Materials (SBOM) Generation
Generate regulatory-compliant SBOM files with Package URLs (PURLs), licenses, and vulnerability metadata:

```bash
# CycloneDX v1.5 JSON
vexa-sca scan --sbom cyclonedx --sbom-file cyclonedx-sbom.json

# SPDX v2.3 JSON
vexa-sca scan --sbom spdx --sbom-file spdx-sbom.json
```

---

### 6. Automated Transactional Remediation (`vexa-sca fix`)
Vexa SCA applies security remediation recommendations with transactional filesystem guarantees and automatic backup:

```bash
# Step A: Perform a dry run to inspect proposed upgrades (guarantees 0 filesystem writes)
vexa-sca fix --dry-run

# Step B: Apply direct upgrades and lockfile overrides in-place (creates <manifest>.bak)
vexa-sca fix

# Step C: Automatically create a git branch, commit fixes, and open a GitHub PR
vexa-sca fix \
  --create-pr \
  --repo <OWNER>/<REPOSITORY> \
  --token <YOUR_GITHUB_TOKEN> \
  --branch "vexa/security-remediations" \
  --base "main"
```

- **Manager-Specific Overrides**:
  - `npm`: Modifies or adds `"overrides"` in `package.json`.
  - `yarn`: Modifies or adds `"resolutions"` in `package.json`.
  - `pnpm`: Modifies or adds `"pnpm.overrides"` in `package.json`.
- **Range Intent Preservation**: Preserves existing version intent (caret `^`, tilde `~`, exact pins).

---

### 7. License Compliance Auditing (`vexa-sca licenses`)
Scan your dependency graph to identify copyleft license risks (GPL, AGPL) and weak copyleft (LGPL, MPL):

```bash
# Summarize license distribution
vexa-sca licenses

# Display every evaluated dependency package
vexa-sca licenses --all

# Output structured JSON for legal and audit pipelines
vexa-sca licenses --json > license-inventory.json

# Enforce licensing policy (fails on copyleft)
vexa-sca licenses --fail-on copyleft
```

---

### 8. Dependency Graph Visualizer (`vexa-sca graph`)
Display the directed acyclic graph (DAG) representing all package nodes, depths, and propagation paths:

```bash
# Print ASCII dependency tree
vexa-sca graph

# Limit tree depth
vexa-sca graph --max-depth 3

# Export Schema v1.2.0 JSON representation
vexa-sca graph --json > dep-graph.json
```

---

### 9. Ad-Hoc Package Testing (`vexa-sca test`)
Query security databases for a specific package version without requiring a local project or lockfile:

```bash
# npm package query
vexa-sca test lodash@4.17.15 npm

# Python PyPI package query
vexa-sca test flask@0.12.2 PyPI

# Java Maven package query
vexa-sca test org.apache.logging.log4j:log4j-core@2.14.1 Maven

# Crates.io (Rust) package query
vexa-sca test smallvec@0.6.13 crates.io
```

---

### 10. Scan Quota & Usage Status (`vexa-sca usage`)
Check your active plan tier and monthly scan volume. In the **Free Developer Edition**, local CLI scans and open-source repository tests are **100% unlimited**:

```bash
# Display formatted quota status box
vexa-sca usage

# Output structured JSON
vexa-sca usage --json
```

---

## Process Exit Code Contract

Vexa SCA implements a deterministic, automation-grade process exit code contract designed for CI/CD pipelines, pre-commit hooks, and compliance gating:

| Exit Code | Meaning | Triggers & Conditions | Suppressed by `--no-fail`? |
| :---: | :--- | :--- | :---: |
| **`0`** | **Pass / Clean** | No vulnerabilities found, all findings below gate thresholds, or all findings suppressed under valid active policy waivers. | N/A |
| **`1`** | **Quality Gate Failure** | Vulnerabilities detected that violate active quality gate criteria (`--fail-on <severity>`, `--fail-on-reachable`, `--fail-on-licenses`, or unmaintained dependencies). | **Yes** (converted to `0`) |
| **`2`** | **Configuration / Schema Error** | Invalid CLI arguments, mutually contradictory flags (e.g., `--fail-on-unknown-reachability` with `--allow-unknown-reachability`), invalid/expired `.vexa-sca` policy file, unknown policy fields, malformed dates, or missing required audit fields. | **No** (never suppressed) |
| **`3`** | **Incomplete Scan Data** | Upstream advisory service (`api.osv.dev`) outage, partial response failures, or source file limit exceeded during analysis in CI profile. Prevents silent false negatives. Suppress explicitly with `--allow-unavailable` if intentional. | **No** (never suppressed) |

> [!WARNING]
> **`--no-fail` Scope**:
> The `--no-fail` flag (or `report-only` alias) strictly suppresses exit code `1` (quality gate failure) for non-blocking report generation. It **does NOT suppress** exit code `2` (configuration error) or exit code `3` (incomplete scan data due to network outage). A pipeline with broken arguments or missing advisory data will always fail closed.

---

## Repository Usage Signals & Reachability Gating

Vexa SCA uses a single-pass AST parser (`oxc`) to identify repository usage signals across `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`, `.mts`, and `.cts` source files.

### Syntactic Call-Site Matcher vs Runtime Exploitability
- **Usage Signals**: Vexa classifies dependency references into `IMPORTED_SOURCE` (direct `import` or `require`), `REFERENCED_CONFIG_OR_SCRIPT` (build tool or script reference), or `NO_REFERENCE_FOUND_WITHIN_SCOPE`.
- **Not Control-Flow Proof**: Syntactic import/call matching does not evaluate runtime input validation, network barriers, or control-flow branches. A vulnerability marked `NOT_REACHABLE` within the repository source may still be exploitable via indirect entrypoints.
- **Test File Segregation**: Imports occurring strictly in test files (`*.test.ts`, `__tests__/**`) are classified as `TEST_ONLY_USAGE` and do not satisfy production reachability proof.
- **Fail-Safe Reachability Gating**:
  - Gating with `--fail-on reachable` fails on any finding with confirmed `REACHABLE` usage.
  - Vulnerabilities with `UNKNOWN` reachability (syntax errors, dynamic `eval`/constructs, re-exports `export *`, or unanalyzed modules) **fail the quality gate by default** unless explicitly allowed with `--allow-unknown-reachability`.
  - To explicitly enforce gate failure on any unproven `UNKNOWN` status, use `--fail-on-unknown-reachability`.
- **Decoupled Quality Gating**:
  - `--reachable-only` is a display/report filter, not a gate bypass.
  - Severity gating rules (`--fail-on high`) evaluate against all unsuppressed findings by default regardless of reachability, ensuring unproven risks are never silently ignored.

---

## Advanced Configuration & Policy Engine

### Strict Policy Engine (`.vexa-sca` / `.vexa-sca.json`)
Manage audited risks, temporary waivers, and grace periods with strict schema enforcement (`deny_unknown_fields`). Misspelled or unknown fields cause scans to exit immediately with code `2`.

#### `.vexa-sca` (v1.0.0 Specification)
```yaml
version: "v1.0.0"
max_waiver_days: 90 # Global ceiling; individual waivers cannot exceed this lifetime

ignore:
  - id: "GHSA-35jh-r3h4-6jhm"
    package: "lodash"
    reason: "Prototype pollution input vector sanitized by ingress API schema validation"
    owner: "sec-team@example.com"
    ticket: "SEC-1042"
    created: "2026-10-01"
    expires: "2026-12-15"

  - id: "CVE-2021-23337"
    package: "lodash"
    reason: "Internal CLI utility only; service is strictly air-gapped without remote inputs"
    owner: "platform@example.com"
    ticket: "INFRA-501"
    created: "2026-10-15"
    expires: "2026-11-30"
```

#### Policy Enforcement Rules:
1. **Mandatory Non-Empty Fields**: Every rule MUST specify `id`, `package`, `reason`, `owner`, `ticket`, and `expires`.
2. **Valid ISO Dates**: `created` (optional, defaults to file load time) and `expires` must be valid `YYYY-MM-DD` dates. `created` cannot be after `expires`.
3. **Maximum Waiver Duration**: Waiver duration (`expires - created`) cannot exceed `max_waiver_days` (default: 90 days).
4. **Immediate Expiration Diagnostics**: Expired rules are rejected during policy loading, exiting with code `2`.

---

## Troubleshooting & FAQs

### 1. `Error: Policy configuration error in .vexa-sca` (Exit Code 2)
- **Cause**: A `.vexa-sca` policy file contains unknown fields, an expired waiver, a missing mandatory field (`reason`, `owner`, `ticket`, `expires`), or exceeds `max_waiver_days`.
- **Resolution**: Check the terminal error message. Update the waiver with a valid future expiration date (`YYYY-MM-DD`), owner email, and ticket reference.

### 2. `Error: Cannot specify both --fail-on-unknown-reachability and --allow-unknown-reachability` (Exit Code 2)
- **Cause**: Contradictory reachability flags were passed to the scan or CI profile.
- **Resolution**: Use `--allow-unknown-reachability` if you wish to ignore unanalyzed/dynamic imports, or omit both to maintain the fail-safe default.

### 3. `CI Failure: Advisory database unavailable` (Exit Code 3)
- **Cause**: The OSV advisory database could not be reached, network requests timed out, or file limits were hit in CI profile.
- **Resolution**: Verify network access to `api.osv.dev` or populate the local cache (`.sca-cache/`). To explicitly permit execution during advisory downtime, pass `--allow-unavailable`. Note that `--no-fail` does not suppress exit code 3.
