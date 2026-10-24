# Vexa SCA CLI Usage Guide

## Executive Summary
The Vexa SCA Command-Line Interface (CLI) provides a fast, deterministic Software Composition Analysis engine. Built in pure Rust, it is optimized for modern JavaScript and TypeScript development (`package-lock.json` v2/v3, `pnpm`) in pull request automation workflows and GitHub Actions pipelines.

Vexa SCA analyzes multi-ecosystem dependency manifests, classifies findings using **Repository Usage Signals** (direct source imports, `package.json` scripts/bin entries, and configs) without unsafe suppression under positive-proof verdict rules, enforces deterministic quality gates, and generates compliant Software Bill of Materials (SBOMs) and automated same-major pull requests.

> [!NOTE]
> **Ecosystem Maturity Tiers:**
> - **Production Ready / GA (P0):** Node.js / JavaScript / TypeScript (`package-lock.json` v2 & v3, `pnpm-lock.yaml`), PR-differential scanning (`--baseline`), GitHub Actions integration (`vexa-sca ci`, `vexa-sca init`), same-major remediation (`vexa-sca fix`), policy engine (`.vexa-sca`), process exit code contract (0, 1, 2, 3, 4).
> - **Experimental / Early Access (P2):** Python (`requirements.txt`), Java Maven (`pom.xml`), Yarn v1 (`yarn.lock`), Container OS packages (`vexa-sca container`), Copyleft license audit (`vexa-sca licenses`).

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
If your environment standardizes on npm, Vexa SCA ships with a zero-setup launcher that detects your operating system and invokes the native engine automatically.

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
Navigate to your application repository containing a supported manifest or lockfile (e.g., `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Cargo.lock`, `go.sum`, or `pom.xml`):

```bash
# Scan the current working directory
vexa-sca scan

# Scan an explicit target path
vexa-sca scan /path/to/[project-root]
```

### 2. Eliminating False Positives with Reachability Analysis
Standard SCA tools notify on every dependency vulnerability, generating alert fatigue. Vexa SCA uses AST static call-graph parsing (`.js`, `.jsx`, `.ts`, `.tsx`, `.py`) to confirm whether the vulnerable code paths are actually reached in your source files:

```bash
# Isolate only exploitable vulnerabilities with confirmed call sites
vexa-sca scan --reachable-only

# Filter only production dependencies (ignoring devDependencies)
vexa-sca scan --prod-only --reachable-only
```

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

# Strict prioritization: Must be reachable in AST call-graph AND have >= 50% exploit likelihood
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

### 6. Automated Lockfile Remediation (`vexa-sca fix`)
Vexa SCA does not merely detect vulnerabilities; it resolves them directly in your package manifests and lockfiles.

```bash
# Step A: Perform a dry run to inspect proposed bumps and transitive overrides
vexa-sca fix --dry-run

# Step B: Apply direct upgrades and lockfile overrides in-place (creates backup)
vexa-sca fix

# Step C: Automatically create a git branch, commit fixes, and open a GitHub PR
vexa-sca fix \
  --create-pr \
  --repo <OWNER>/<REPOSITORY> \
  --token <YOUR_GITHUB_TOKEN> \
  --branch "vexa/security-remediations" \
  --base "main"
```

---

### 7. License Compliance Auditing (`vexa-sca licenses`)
Scan your direct and transitive dependency graph to identify intellectual property legal risks, viral copyleft licenses (GPL/AGPL), and weak copyleft (LGPL/MPL):

```bash
# Summarize license distribution and highlight risky licenses
vexa-sca licenses

# Display every evaluated dependency package
vexa-sca licenses --all

# Output structured JSON for legal and audit pipelines
vexa-sca licenses --json > license-inventory.json

# Enforce licensing policy (fails with non-zero exit code on copyleft)
vexa-sca licenses --fail-on copyleft
```

---

### 8. Dependency Graph Visualizer (`vexa-sca graph`)
Display the directed acyclic graph (DAG) representing all package nodes, depths, and propagation paths:

```bash
# Print ASCII dependency tree up to default depth
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

# Output structured JSON for automation or monitoring
vexa-sca usage --json

# Include quota details directly inside scan output
vexa-sca scan --usage
```

---

## Advanced Configuration & Edge Cases

### Policy File Configuration (`.vexa-sca` / `.vexa-sca.json`)
Manage false positives, accepted risks, and grace periods declaratively. Place a `.vexa-sca` (YAML) or `.vexa-sca.json` (JSON) file at the root of your project:

#### `.vexa-sca` (YAML Specification)
```yaml
version: v1.0.0
ignore:
  CVE-2021-23337:
    - reason: "Command injection payload is sanitized at API gateway ingress"
      expires: 2026-12-31
  GHSA-35jh-r3h4-6jhm:
    - reason: "Development prototype build only; service is strictly internal"
      expires: 2027-01-15
  lodash@4.17.15:
    - reason: "Scheduled for removal in v2.0 refactor"
      expires: 2026-11-30
```

Execute a scan pointing to a custom policy file location:
```bash
vexa-sca scan --policy /path/to/custom-policy.yaml
```

> [!IMPORTANT]
> **Enforced Expirations**: When the specified `expires` date is reached or passed, Vexa SCA automatically revokes the suppression rule and flags the vulnerability in subsequent scans.

### Offline & Air-Gapped Scanning (`.sca-cache/`)
Vexa SCA hashes vulnerability queries with SHA-256 and writes responses to a local `.sca-cache/` directory. 
- In connected environments, cache entries accelerate scans to sub-second runtimes.
- In isolated/air-gapped CI or defense networks, pre-populate the `.sca-cache/` directory in your container or filesystem to run comprehensive scans without internet access.

### Monorepo & Multi-Manifest Detection
When scanning workspaces with multiple ecosystems (e.g., a root `package.json` with nested Python services in `backend/requirements.txt`), point Vexa SCA explicitly to the subfolder:
```bash
vexa-sca scan ./services/payment-gateway
vexa-sca scan ./services/notification-worker
```

---

## Troubleshooting & FAQs

### 1. `Error: No manifest or supported lockfile found in path`
- **Cause**: Vexa SCA could not locate any of the supported manifest/lockfile files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Cargo.lock`, `go.sum`, `pom.xml`) in the designated folder.
- **Resolution**:
  - Run the package manager install command first to generate the lockfile (e.g., `npm install`, `yarn install`, `cargo generate-lockfile`, or `pip freeze > requirements.txt`).
  - Pass the explicit directory path: `vexa-sca scan [project-root]`.

### 2. `'vexa-sca' is not recognized as an internal or external command` (Windows)
- **Cause**: Cargo's binary directory (`%USERPROFILE%\.cargo\bin`) or your custom binary folder is missing from the Windows `PATH` environment variable.
- **Resolution**:
  - Open PowerShell and verify:
    ```powershell
    $env:Path -split ";" | Select-String "cargo"
    ```
  - If missing, append it permanently:
    ```powershell
    [Environment]::SetEnvironmentVariable("Path", $env:Path + ";$HOME\.cargo\bin", "User")
    ```
  - Restart your PowerShell or Command Prompt terminal.

### 3. Reachability flags zero vulnerabilities when vulnerable packages are present
- **Cause**: You ran `vexa-sca scan --reachable-only`. While vulnerable packages exist in your lockfile, none of their exploitable functions are referenced in your application code.
- **Resolution**:
  - Run `vexa-sca scan` (without `--reachable-only`) to view all detected dependencies regardless of source code call paths.
  - Review the terminal output or HTML report to verify the call traces identified by the AST reachability scanner.

### 4. Automated PR creation fails with `401 Unauthorized` or `404 Not Found`
- **Cause**: The GitHub authentication token is missing or lacks the required write permissions for Git repositories and Pull Requests.
- **Resolution**:
  - Set the `GITHUB_TOKEN` or `GH_TOKEN` environment variable with `contents: write` and `pull-requests: write` scopes:
    ```bash
    export GITHUB_TOKEN="ghp_YourPersonalAccessTokenWithRepoScope"
    vexa-sca fix --create-pr --repo owner/repo
    ```
