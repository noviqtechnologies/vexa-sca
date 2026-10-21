# Vexa SCA: Software Composition Analysis & Security Engine

[![Rust Edition](https://img.shields.io/badge/Rust-2021%20Edition-DEA584?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-brightgreen.svg)](#cross-platform-installation--setup)
[![Tests](https://img.shields.io/badge/Tests-34%2F34%20Passing-success.svg)](#automated-tests--verification)
[![Node.js CLI Shim](https://img.shields.io/badge/Node.js%20Wrapper-npx%20vexa--sca%20ready-339933?logo=node.js&logoColor=white)](#option-2-run-via-nodejs--npx-wrapper-all-platforms)
[![Docs](https://img.shields.io/badge/Docs-Guides%20%26%20Reference-blueviolet?logo=read-the-docs&logoColor=white)](#-documentation--workflow-guides)

**Vexa SCA** (`vexa-sca`) is its commercial-grade, blazingly fast Software Composition Analysis & Security Engine. Built with a native **Rust Core Engine** (`vexa-sca`, with backwards-compatible binary aliases `vexa` and `sca`) and an optional cross-platform Node.js launcher (`bin/vexa-sca.js`), Vexa SCA audits vulnerabilities across 6+ package ecosystems, performs AST runtime reachability analysis to eliminate false positives, audits open source licenses, generates CycloneDX v1.5 and SPDX v2.3 SBOMs, inspects container filesystems and tarballs, enforces CI/CD quality gates, and automatically patches lockfiles or opens GitHub pull requests.

<p align="center">
  <a href="#quick-start"><b>Quick Start</b></a> •
  <a href="#-documentation--workflow-guides"><b>Documentation</b></a> •
  <a href="docs/open-source-sca.md"><b>Open Source SCA Guide</b></a> •
  <a href="docs/cli-usage.md"><b>CLI Guide</b></a> •
  <a href="docs/cicd-integration.md"><b>CI/CD Pipelines</b></a> •
  <a href="docs/container-deployment.md"><b>Containers</b></a> •
  <a href="docs/git-hooks.md"><b>Git Hooks</b></a>
</p>

---

### ⚡ Highlights & Value at a Glance

*Click any feature to jump directly to its in-depth guide and CLI commands:*

| Key Feature | Security & Developer Value | Quick Command |
| :--- | :--- | :--- |
| 🎯 [**Deep Reachability (Call-Graph AST)**](#1-reachability-analysis-deep-sca) | Eliminates up to **80% of false positives** by verifying if vulnerable package functions are actually invoked in your application code. | `vexa-sca scan --reachable-only` |
| ⚡ [**Sub-Second Pure Rust Core**](#cross-platform-installation--setup) | High-throughput multi-threaded dependency graph analysis with **zero external C / OpenSSL dependencies**. Native binaries for Linux, macOS & Windows. | `vexa-sca scan` |
| 🛠️ [**Automated Lockfile Patcher & PR Opener**](#2-automated-lockfile-patcher--pr-opener-fix) | Automatically bumps direct dependencies, injects transitive `overrides`/`resolutions`, and opens complete remediation GitHub PRs. | `vexa-sca fix --create-pr` |
| 📊 [**Standalone Interactive HTML Dashboard**](#6-standalone-interactive-html-audit-dashboard) | Offline-ready single-file HTML report with glassmorphism dark UI, live search/filtering, and deep call-site inspector—**zero external CDNs**. | `vexa-sca scan --html-file sca.html` |
| 📋 [**CycloneDX & SPDX SBOM Generator**](#5-software-bill-of-materials-sbom-cyclonedx--spdx) | Export compliant **CycloneDX v1.5 JSON** and **SPDX v2.3 JSON** with package URLs (PURLs), licenses, and vulnerability metadata. | `vexa-sca scan --sbom cyclonedx` |
| 📦 [**Container & OS Package Scanner**](#8-container--os-package-scanner-container) | Scans Alpine (`apk`), Debian/Ubuntu (`dpkg`), Dockerfiles, and `.tar`/`.tar.gz` image layers without requiring Docker daemon or root privileges. | `vexa-sca container my-image.tar` |
| 🛡️ [**Policy-as-Code & Suppression Engine**](#3-policy--suppression-engine-vexa-sca) | Define accepted risks in `.vexa-sca` YAML/JSON with mandatory expiration dates and alias matching (CVE/GHSA/Package). | `vexa-sca scan --policy .vexa-sca` |
| ⚖️ [**Copyleft License Compliance Auditor**](#4-license-compliance-scanner) | Automatically flags viral GPL, AGPL, and weak-copyleft intellectual property risks across all direct and transitive dependencies. | `vexa-sca licenses` |
| 📈 [**EPSS Exploit Prediction**](#epss-exploit-prediction-likelihood) | Prioritizes CVEs by real-world 30-day exploit likelihood (FIRST.org EPSS), cutting false-positive triage by up to 85%. | `vexa-sca scan --epss-threshold 0.50` |
| ♾️ [**Unlimited Developer Quota**](#scan-volume--usage-quota) | Free Developer Edition provides 100% unlimited local CLI and open-source repo scans with zero seat-tax or rate limits. | `vexa-sca usage` |
| 🚦 [**CI/CD Quality Gates & SARIF v2.1.0**](#7-cicd-quality-gates--policy-enforcement) | Enforce deterministic pipeline pass/fail gates and upload native SARIF directly to GitHub Security Code Scanning and GitLab SAST. | `vexa-sca scan --sarif-file results.sarif` |

> [!TIP]
> **Try It in 30 Seconds**:
> 
> **1. To scan ANY project on your machine (No manual clone needed):**
> Install the standalone binary globally via Cargo in 1 command:
> ```bash
> cargo install --git https://github.com/noviqtechnologies/vexa-sca.git
> 
> # Navigate to any repository on your computer and scan:
> vexa-sca scan
> ```
> *(Or via `npx vexa-sca scan` once published to npm).*
> 
> **2. To evaluate from source in this cloned repository:**
> ```bash
> # Run against the included sample application fixtures:
> cargo run -- scan test/fixtures/npm-app
> 
> # Or using the Node.js launcher:
> node bin/vexa-sca.js scan test/fixtures/npm-app
> ```
> *(See [Prerequisites by OS](#prerequisites-by-os) below for 1-command toolchain installation).*

---

## Table of Contents
- [Quick Start](#quick-start)
- [Cross-Platform Installation & Setup](#cross-platform-installation--setup)
  - [Prerequisites by OS](#prerequisites-by-os)
  - [Building from Source](#building-from-source)
  - [Running the CLI](#running-the-cli)
- [Architecture & Core Concepts](#architecture--core-concepts)
- [Multi-Ecosystem Coverage](#multi-ecosystem-coverage)
- [Key Features](#key-features)
  - [1. Reachability Analysis (Deep SCA)](#1-reachability-analysis-deep-sca)
  - [2. Automated Lockfile Patcher & PR Opener (`fix`)](#2-automated-lockfile-patcher--pr-opener-fix)
  - [3. Policy & Suppression Engine (`.vexa-sca`)](#3-policy--suppression-engine-vexa-sca)
  - [4. License Compliance Scanner](#4-license-compliance-scanner)
  - [5. Software Bill of Materials (SBOM: CycloneDX & SPDX)](#5-software-bill-of-materials-sbom-cyclonedx--spdx)
  - [6. Standalone Interactive HTML Audit Dashboard](#6-standalone-interactive-html-audit-dashboard)
  - [7. CI/CD Quality Gates & Policy Enforcement](#7-cicd-quality-gates--policy-enforcement)
  - [8. Container & OS Package Scanner (`container`)](#8-container--os-package-scanner-container)
- [CLI Reference](#cli-reference)
  - [`vexa-sca scan`](#1-vexa-sca-scan)
  - [`vexa-sca fix`](#2-vexa-sca-fix)
  - [`vexa-sca licenses`](#3-vexa-sca-licenses)
  - [`vexa-sca graph`](#4-vexa-sca-graph)
  - [`vexa-sca test`](#5-vexa-sca-test)
  - [`vexa-sca container`](#6-vexa-sca-container)
- [Documentation & Workflow Guides](#-documentation--workflow-guides)
  - [🛡️ Open Source SCA Guide (`docs/open-source-sca.md`)](docs/open-source-sca.md)
  - [💻 CLI Usage Guide (`docs/cli-usage.md`)](docs/cli-usage.md)
  - [🚀 CI/CD Integration Guide (`docs/cicd-integration.md`)](docs/cicd-integration.md)
  - [🐳 Container Deployment Guide (`docs/container-deployment.md`)](docs/container-deployment.md)
  - [🪝 Git Hooks Setup Guide (`docs/git-hooks.md`)](docs/git-hooks.md)
  - [Quick Implementation Snippets](#quick-implementation-snippets-by-workflow)
- [Automated Tests & Verification](#automated-tests--verification)
- [License](#license)

---

## Quick Start

### Option 1: Native Rust Binary (Recommended for CI & High Performance)

The native Rust engine has zero external C/runtime dependencies and executes scans with sub-second performance.

#### Linux / macOS
```bash
# Build optimized native release binaries (`vexa-sca`, `vexa`, `sca`)
cargo build --release

# Run scan against current project using primary binary `vexa-sca`
./target/release/vexa-sca scan

# Or run directly via Cargo (default-run is configured to vexa-sca)
cargo run -- scan
```

#### Windows (PowerShell / Command Prompt / Git Bash)
```powershell
# Build optimized native release binaries
cargo build --release

# Run scan against current project (PowerShell / CMD)
.\target\release\vexa-sca.exe scan

# Or run directly via Cargo
cargo run -- scan
```

> [!TIP]
> **Backwards-Compatible Aliases**: Both `vexa` and `sca` are compiled alongside `vexa-sca`. You can invoke `./target/release/vexa-sca scan`, `./target/release/vexa scan`, or `./target/release/sca scan` identically.

---

### Option 2: Run via Node.js / NPX Wrapper (All Platforms)

Vexa SCA provides a cross-platform shim (`bin/vexa-sca.js`, with aliases `bin/vexa.js` and `bin/sca.js`) registered in `package.json`. It automatically resolves the native executable across **Windows**, **macOS**, and **Linux**, falling back to `cargo run` if uncompiled:

```bash
# Using Node.js directly
node bin/vexa-sca.js scan

# Using npm scripts
npm run scan

# Backwards-compatible script invocations
node bin/vexa.js scan
node bin/sca.js scan

# If published or linked globally via npm
npx vexa-sca scan
npx vexa scan
```

---

### Option 3: Pre-Built Binary Download (GitHub Releases)

Download pre-compiled standalone binaries with zero installation prerequisites directly from [GitHub Releases](https://github.com/noviqtechnologies/vexa-sca/releases):

```bash
# Linux / macOS (curl download & run)
curl -sSL https://github.com/noviqtechnologies/vexa-sca/releases/latest/download/vexa-sca-linux-x86_64.tar.gz | tar -xz
./vexa-sca scan

# Windows: Download vexa-sca-windows-x86_64.zip, extract, and run vexa-sca.exe
```

---

### Option 4: Run via Docker Container (GitHub Packages / GHCR)

Run scans in any CI/CD runner or containerized environment without installing Rust or Node.js:

```bash
# Pull and scan current directory:
docker run --rm -v "${PWD}:/workspace" ghcr.io/noviqtechnologies/vexa-sca:latest scan .

# Run with reachability analysis and HTML dashboard export:
docker run --rm -v "${PWD}:/workspace" ghcr.io/noviqtechnologies/vexa-sca:latest scan . --reachable-only --html-file sca-report.html
```

---

## Cross-Platform Installation & Setup

Vexa SCA is fully cross-platform and operates identically on **Linux** (x86_64, aarch64, musl/Alpine, glibc), **macOS** (Apple Silicon M1-M4 & Intel), and **Windows** (PowerShell, Command Prompt, Git Bash, WSL).

> [!NOTE]
> **Zero External C / OpenSSL Dependencies**: Vexa SCA uses a pure Rust TLS implementation (`rustls-tls`) and pure Rust decompression (`miniz_oxide`). You do not need to install Perl, OpenSSL dev headers, or build tools solely for cryptographic handshakes or tarball unpacking.

### Prerequisites by OS

| Operating System | Recommended Rust Installation | Optional Node.js (for `npx` wrapper) |
| :--- | :--- | :--- |
| **Linux** (Ubuntu, Debian, Fedora, RHEL, Arch, Alpine) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` | `v16.0.0+` (via `nvm` or package manager) |
| **macOS** (Apple Silicon M1-M4 & Intel) | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` | `brew install node` |
| **Windows** (10 / 11, Windows Server) | `winget install Rustlang.Rustup` or download [rustup-init.exe](https://rustup.rs) | `winget install OpenJS.NodeJS.LTS` |

### Building from Source

```bash
# Clone the repository
git clone https://github.com/noviqtechnologies/vexa-sca.git
cd vexa-sca

# Compile release binaries (produces `vexa-sca`, `vexa`, and `sca`)
cargo build --release
```

Compiled binaries are located at:
- **Linux & macOS**: `target/release/vexa-sca`, `target/release/vexa`, and `target/release/sca`
- **Windows**: `target\release\vexa-sca.exe`, `target\release\vexa.exe`, and `target\release\sca.exe`

### Running the CLI

You can install the native binary to your user `PATH` using Cargo:
```bash
cargo install --path .

# Now available globally from any terminal or OS:
vexa-sca --help
```

---

## Architecture & Core Concepts

```mermaid
graph TD
    A["Manifests & Lockfiles\n(npm, pnpm, Yarn, Pip, Cargo, Go, Maven)"] --> B["Lockfile Ingestion & Parser\n(Multi-Format Detection)"]
    K["Container Images & Rootfs\n(Alpine APK, Debian DPKG, Dockerfile, Tarballs)"] --> B2["OS Package Parser\n(Container Scanner Engine)"]
    B --> C["DAG Dependency Graph Engine\n(Vexa DepGraph Schema v1.2.0)"]
    B2 --> C
    C --> D["Vulnerability & License Intelligence\n(OSV / CVE / SPDX / Local Cache)"]
    D --> E["Reachability Engine (Deep SCA)\n(AST Source Call-Graph Tracing)"]
    E --> F[".vexa-sca Policy Engine\n(Suppression Rules & Expiry Validation)"]
    F --> G["Terminal, JSON, Markdown, SARIF v2.1.0\n(GitHub Security / GitLab SAST)"]
    F --> H["Automated Lockfile Patcher\n(vexa-sca fix & GitHub PR Opener)"]
    F --> I["SBOM Exporter\n(CycloneDX v1.5 / SPDX v2.3 JSON)"]
    F --> J["Interactive HTML Audit Dashboard\n(Single-File, Offline-Ready UI)"]
    F --> L["CI/CD Quality Gate\n(Threshold Enforcement & Exit Codes)"]
```

### Core Architectural Pillars
1. **DAG Dependency Representation**: Modeled after standard dep-graph schema (Schema v1.2.0). Every dependency node is mapped in a Directed Acyclic Graph with distinct `nodeId` and `pkgId` coordinates (`name@version`).
2. **Deep-Path DFS Tracing (`pkgPathsToRoot`)**: Transitive (nested) vulnerabilities trace their exact propagation chains back to the root application.
3. **Reachability Analysis (Deep SCA)**: Static AST inspection scans your actual source code to verify if the vulnerable function (e.g., `_.template`, `parse()`, `Session.request`) is invoked at runtime, eliminating up to 80% of false positives.
4. **Resilient Offline Cache**: Vulnerability lookups are cached on disk (`.sca-cache/`) with SHA-256 hashed keys to minimize network roundtrips and enable air-gapped CI scanning.
5. **Quality Gates & Policy Compliance**: Comprehensive policy evaluation that integrates seamlessly into automated CI/CD pipelines.

---

## Multi-Ecosystem Coverage

Vexa SCA automatically identifies project manifests, lockfiles, and container images without manual configuration:

| Ecosystem | Supported Files | Detection & Features |
| :--- | :--- | :--- |
| **Node.js / JavaScript / TypeScript** | `package-lock.json` (v1, v2, v3)<br>`yarn.lock` (v1)<br>`pnpm-lock.yaml` (v5, v6, v9) | Full dependency tree, transitive dependencies, peer resolution, AST call-graph reachability |
| **Python** | `requirements.txt` | Specifiers (`==`, `>=`, `<=`, `~=`), comments, environment markers, Python AST reachability |
| **Go** | `go.sum`, `go.mod` | Go modules dependency tree, version extraction (`vX.Y.Z`) |
| **Rust** | `Cargo.lock` | TOML package blocks, workspace dependency resolution |
| **Java** | `pom.xml` | Maven XML coordinate parsing (`groupId:artifactId@version`) |
| **Container & OS Packages** | Alpine (`/lib/apk/db/installed`), Debian/Ubuntu (`/var/lib/dpkg/status`), Dockerfile, `.tar` / `.tar.gz` images | Linux distribution detection (`/etc/os-release`), OS package vulnerability auditing |

---

## Key Features

### 1. Reachability Analysis (Deep SCA)

Standard SCA tools flag every vulnerable package in your dependency tree, causing alert fatigue. Vexa SCA's reachability engine inspects your source code (`.js`, `.jsx`, `.ts`, `.tsx`, `.py`) to identify if vulnerable functions are executed:

- `🚨 REACHABLE`: An active invocation was found in your code.
- `🛡️ UNREACHABLE`: The package is installed, but the vulnerable function is never called.

Filter directly in CLI:
```bash
# Focus strictly on exploitable vulnerabilities
vexa-sca scan --reachable-only
```

---

### 2. Automated Lockfile Patcher & PR Opener (`fix`)

Remediate vulnerabilities automatically without breaking application builds:
- **Direct Upgrades**: Bumps direct package versions in `package.json` to the minimum non-vulnerable release.
- **Transitive Pinning via Overrides**: For nested dependencies, injects package manager `overrides` (npm) or `resolutions` (Yarn).
- **Automated Pull Requests**: Creates a git branch, commits the modified files, and opens a GitHub Pull Request with full vulnerability summaries.

```bash
# Preview proposed fixes without altering files
vexa-sca fix --dry-run

# Apply fixes locally
vexa-sca fix

# Automatically open a GitHub Pull Request
vexa-sca fix --create-pr --repo owner/my-repo --token $GITHUB_TOKEN
```

---

### 3. Policy & Suppression Engine (`.vexa-sca`)

Manage false positives, accepted risks, or delayed remediations via YAML or JSON policy files:
- **Exact & Alias Matching**: Suppress by CVE ID (`CVE-2021-23337`), GHSA ID (`GHSA-35jh-r3h4-6jhm`), or Package ID (`lodash@4.17.15`).
- **Mandatory Expiration Date**: Set an `expires: YYYY-MM-DD`. Once expired, the suppression is automatically invalidated and the vulnerability re-alerts.
- **Native Format**: Supports both `.vexa-sca` (YAML) and `.vexa-sca.json` (JSON) policy specifications.

#### Example `.vexa-sca` (YAML):
```yaml
version: v1.0.0
ignore:
  CVE-2021-23337:
    - reason: "Command injection vector unreachable; untrusted input is sanitised at ingress"
      expires: 2026-12-31
  GHSA-29mw-wpgm-hmr9:
    - reason: "Internal microservice not exposed to public internet"
      expires: 2027-01-01
```

#### Example `.vexa-sca.json` (JSON):
```json
{
  "version": "v1.0.0",
  "ignore": {
    "CVE-2021-23337": [
      {
        "reason": "Untrusted input sanitized at ingress",
        "expires": "2026-12-31"
      }
    ]
  }
}
```

---

### 4. License Compliance Scanner

Categorize every third-party dependency by open source license and intellectual property risk:
- **Permissive (Low Risk)**: MIT, Apache-2.0, BSD-2/3-Clause, ISC, CC0, Unlicense. Safe for proprietary and commercial distribution.
- **Weak Copyleft (Medium Risk)**: LGPL-2.1/3.0, MPL-2.0, EPL-1.0/2.0, CDDL. Modifications to the library itself must typically remain open source.
- **Strong Copyleft (High Risk / Viral GPL)**: GPL-2.0/3.0, AGPL-3.0, SSPL, EUPL. Can obligate the entire proprietary project to be licensed as open source.

> [!NOTE]
> **Metadata Resolution**: License discovery extracts declared licenses from lockfile fields and local package descriptors (`package.json`, Cargo lockfiles, etc.). For lockfiles without embedded license fields (such as standard npm/pnpm lockfiles when `node_modules` is not yet installed locally), packages are conservatively classified as `UNKNOWN` rather than making unverified guesses.

```bash
vexa-sca licenses ./my-project
```

---

### 5. Software Bill of Materials (SBOM: CycloneDX & SPDX)

Generate industry-standard Software Bill of Materials compliant with executive cybersecurity orders and enterprise procurement standards:

- **CycloneDX v1.5 JSON**: Standardized components with Package URLs (`pkg:npm/lodash@4.17.15`), licenses, transitive dependency trees, and integrated vulnerability records with severity ratings and advisory URLs.
- **SPDX v2.3 JSON**: Official Linux Foundation SPDX document structure with packages, SPDX license identifiers, download locations, verification checksums, and `DEPENDS_ON` relationship graphs.

```bash
# Output CycloneDX v1.5 JSON to stdout
vexa-sca scan --sbom cyclonedx

# Export CycloneDX SBOM directly to file
vexa-sca scan --sbom cyclonedx --sbom-file sbom-cyclonedx.json

# Export SPDX v2.3 JSON directly to file
vexa-sca scan --sbom spdx --sbom-file sbom-spdx.json
```

---

### 6. Standalone Interactive HTML Audit Dashboard

Generate a modern, self-contained, offline-ready HTML security report:
- **Zero External CDNs**: All CSS styles and interactivity are embedded directly in a single HTML file—perfect for air-gapped CI/CD artifacts and compliance audits.
- **Glassmorphism Dark Theme**: Sleek UI with KPI metrics cards, severity distribution progress bars, and high-contrast status tags.
- **Client-Side Live Filtering & Search**: Instant real-time search across packages, CVEs, and summaries, with filter tabs for `All`, `Critical`, `High`, `Reachable`, and `License Risk`.
- **Deep Call-Site Inspector**: Expandable vulnerability cards displaying call-graph AST traces, vulnerable function references, and reproduction snippets.

```bash
# Generate single-file interactive HTML dashboard
vexa-sca scan --html-file sca-report.html

# Stream HTML directly to standard output
vexa-sca scan --html > report.html
```

---

### 7. CI/CD Quality Gates & Policy Enforcement

Automate pass/fail gates in build pipelines with customizable failure conditions and deterministic exit codes.

#### Exit Code Contract:
- **`0` (Success)**: Clean scan with no policy violations, OR `--no-fail` / `--report-only` is passed.
- **`1` (Quality Gate Failure)**: Policy violations or active security vulnerabilities detected. **By default in CI and local runs**, discovering active vulnerabilities returns exit code `1` so CI pipelines fail securely without silent pass-throughs. If you only want to generate report files (JSON, HTML, SARIF, SBOM) or inspect vulnerabilities without breaking build scripts, pass `--no-fail` (or `--report-only`).
- **`2` (Scan Error)**: Unrecoverable execution error (e.g. malformed lockfile, invalid file path, unreadable container archive).

- `--fail-on <low|medium|high|critical>`: Block builds when vulnerabilities equal or exceed the given severity.
- `--fail-on-reachable`: Break builds only if a vulnerability has verified AST call-graph reachability.
- `--fail-on-licenses <copyleft|weak-copyleft|unapproved>`: Fail if non-compliant copyleft or unapproved licenses are present in the dependency tree.
- `--no-fail` / `--report-only`: Always exit 0 even if security vulnerabilities are found (useful for report-generating cron jobs).

```bash
# Default Secure CI Behavior: generates results.json, exits 1 if findings exist
vexa-sca scan --json > results.json

# Report-Only Generation: generates results.json and always exits 0
vexa-sca scan --json --no-fail > results.json

# Fail CI build if any critical vulnerability is found
vexa-sca scan --fail-on critical

# Fail CI build only if an exploitable (reachable) vulnerability exists
vexa-sca scan --fail-on-reachable

# Enforce open source compliance: block viral copyleft licenses (GPL, AGPL)
vexa-sca scan --fail-on-licenses copyleft

# Combine gates for zero-tolerance security
vexa-sca scan --fail-on high --fail-on-reachable --fail-on-licenses copyleft
```

When a gate fails, Vexa SCA prints a detailed colored terminal banner listing every triggering policy violation:
```text
======================================================================
 [QUALITY GATE FAILED] Policy Violations Detected (1)
======================================================================
  [FAIL] 1 critical vulnerabilities found (threshold: critical)
  [FAIL] 1 verified reachable vulnerabilities found
======================================================================
```

---

### 8. Container & OS Package Scanner (`container`)

Inspect containerized environments and operating system packages for Linux CVEs:
- **Alpine Linux**: Parses `/lib/apk/db/installed` package database and version coordinates.
- **Debian / Ubuntu**: Parses `/var/lib/dpkg/status` package metadata and architectures.
- **Distribution Auto-Detection**: Reads `/etc/os-release` or `/usr/lib/os-release` to resolve OS names, versions, and codenames (e.g. Alpine 3.18, Ubuntu 22.04 LTS).
- **Tarball Archive Inspection**: Scans uncompressed `.tar` and gzip-compressed `.tar.gz` / `.tgz` container image layers without requiring Docker or root privileges.
- **Dockerfile Base Analysis**: Extracts base image declarations (`FROM alpine:3.18`, `FROM node:18-bullseye`).

```bash
# Scan an extracted container rootfs or sysroot
vexa-sca container /path/to/container/rootfs

# Scan an exported Docker image archive
docker save my-app:latest -o my-app.tar
vexa-sca container my-app.tar

# Output container scan as structured JSON or SARIF
vexa-sca container my-app.tar --json
vexa-sca container my-app.tar --sarif-file container-sarif.json

# Enforce quality gates on container scanning
vexa-sca container /var/chroot/alpine --fail-on high
```

---

## CLI Reference

All commands support relative and absolute paths, cross-platform path separators (`/` or `\`), and default to the current working directory (`.`). You can use `vexa-sca`, `vexa`, or `sca` interchangeably.

### 1. `vexa-sca scan`
Scan project dependencies for known security vulnerabilities.

```bash
vexa-sca scan [PATH] [OPTIONS]
```

| Flag | Type | Description |
| :--- | :--- | :--- |
| `[PATH]` | Argument | Target directory to scan (defaults to `.`) |
| `--reachable-only` | Flag | Only show vulnerabilities with confirmed AST execution call paths |
| `--prod-only` | Flag | Exclude development dependencies (`devDependencies`) |
| `--policy <FILE>` | Option | Path to custom policy file (`.vexa-sca` or `.vexa-sca.json`) |
| `--severity-threshold <LVL>` | Option | Minimum severity to report: `low`, `medium`, `high`, `critical` |
| `--json` | Flag | Output structured JSON report to standard output |
| `--markdown` | Flag | Output formatted Markdown report to standard output |
| `--sarif` | Flag | Output OASIS SARIF v2.1.0 report to standard output |
| `--sarif-file <PATH>` | Option | Write SARIF v2.1.0 report directly to a file |
| `--html` | Flag | Output standalone interactive HTML dashboard to standard output |
| `--html-file <PATH>` | Option | Write standalone interactive HTML dashboard to a file |
| `--sbom <FORMAT>` | Option | Output SBOM in `cyclonedx` (v1.5) or `spdx` (v2.3) JSON format |
| `--sbom-file <PATH>` | Option | Write SBOM report directly to a file |
| `--fail-on <LVL>` | Option | Fail scan with exit code 1 if vulnerabilities meet/exceed severity |
| `--fail-on-reachable` | Flag | Fail scan with exit code 1 if any vulnerability is reachable in code |
| `--fail-on-licenses <CAT>` | Option | Fail scan with exit code 1 on license risk (`copyleft`, `weak-copyleft`) |
| `--no-fail`, `--report-only` | Flag | Exit with code 0 even when security vulnerabilities are detected (ideal for report generation) |
| `--epss-threshold <FLOAT>` | Option | Filter vulnerabilities by minimum EPSS probability (0.0 to 1.0, e.g. `0.20` for 20%) |
| `--usage` | Flag | Display scan volume quota and plan usage details directly in scan output |

---

### 2. `vexa-sca fix`
Automatically remediate vulnerabilities in manifest dependencies and lockfiles.

```bash
vexa-sca fix [PATH] [OPTIONS]
```

| Flag | Type | Description |
| :--- | :--- | :--- |
| `[PATH]` | Argument | Target directory (defaults to `.`) |
| `--dry-run` | Flag | Preview changes and PR details without modifying files |
| `--create-pr` | Flag | Create git branch, commit changes, and open a GitHub PR |
| `--repo <OWNER/REPO>` | Option | Target GitHub repository (e.g. `acme/backend`) |
| `--token <TOKEN>` | Option | GitHub token (defaults to `GITHUB_TOKEN` or `GH_TOKEN` env) |
| `--branch <NAME>` | Option | Custom branch name for security fix PR |
| `--base <NAME>` | Option | Base branch to target (defaults to repo default branch) |

---

### 3. `vexa-sca licenses`
Audit licenses across the entire dependency graph.

```bash
vexa-sca licenses [PATH]
```

| Flag | Type | Description |
| :--- | :--- | :--- |
| `[PATH]` | Argument | Target directory (defaults to `.`) |

---

### 4. `vexa-sca graph`
Inspect and visualize the dependency graph representation.

```bash
# Print visual DAG hierarchy
vexa-sca graph

# Export JSON schema v1.2.0 dependency graph
vexa-sca graph --json
```

---

### 5. `vexa-sca test`
Perform an ad-hoc query on an individual package version without needing a lockfile.

```bash
vexa-sca test <PACKAGE@VERSION> [ECOSYSTEM]
```

Supported ecosystems: `npm` (default), `PyPI`, `Go`, `crates.io`, `Maven`.

```bash
vexa-sca test lodash@4.17.15 npm
vexa-sca test flask@0.12.2 PyPI
vexa-sca test org.apache.logging.log4j:log4j-core@2.14.1 Maven
```

---

### 6. `vexa-sca container`
Scan container images, exported root filesystems, and Dockerfiles for OS package vulnerabilities.

```bash
vexa-sca container [TARGET] [OPTIONS]
```

| Flag | Type | Description |
| :--- | :--- | :--- |
| `[TARGET]` | Argument | Path to rootfs directory, `.tar` / `.tar.gz` image, or Dockerfile (defaults to `.`) |
| `--severity-threshold <LVL>` | Option | Minimum severity to report: `low`, `medium`, `high`, `critical` |
| `--json` | Flag | Output structured JSON report to standard output |
| `--markdown` | Flag | Output formatted Markdown report to standard output |
| `--sarif` | Flag | Output OASIS SARIF v2.1.0 report to standard output |
| `--sarif-file <PATH>` | Option | Write SARIF v2.1.0 report directly to a file |
| `--html` | Flag | Output standalone interactive HTML dashboard to standard output |
| `--html-file <PATH>` | Option | Write standalone interactive HTML dashboard to a file |
| `--sbom <FORMAT>` | Option | Output SBOM in `cyclonedx` (v1.5) or `spdx` (v2.3) JSON format |
| `--sbom-file <PATH>` | Option | Write SBOM report directly to a file |
| `--fail-on <LVL>` | Option | Fail scan with exit code 1 if OS package vulnerabilities meet/exceed severity |
| `--fail-on-licenses <CAT>` | Option | Fail scan with exit code 1 on license risk category |

**Examples:**
```bash
# Scan an extracted Alpine or Debian container rootfs
vexa-sca container /path/to/rootfs

# Scan an exported Docker image archive and export SARIF
vexa-sca container my-image.tar --sarif-file container.sarif

# Output container scan as structured JSON
vexa-sca container my-image.tar.gz --json

# Enforce CI quality gate on container images
vexa-sca container /path/to/rootfs --fail-on high
```

---

### 7. `vexa-sca usage`
Display active plan tier and scan quota volume. In the **Free Developer Edition**, local CLI tests and open-source repository scans are **100% unlimited**:

```bash
# Display human-readable quota and usage box
vexa-sca usage

# Output structured JSON for automation or dashboards
vexa-sca usage --json
```

---

## 📈 EPSS Exploit Prediction Likelihood

Standard CVSS scores reflect theoretical severity, not whether attackers are actively weaponizing a vulnerability in the wild. Vexa SCA integrates **FIRST.org EPSS (Exploit Prediction Scoring System)** probabilities directly into scan results:

```bash
# Prioritize vulnerabilities with a 20%+ probability of real-world exploitation
vexa-sca scan --epss-threshold 0.20

# Combine with reachability to eliminate both unreachable and non-exploited CVEs
vexa-sca scan --reachable-only --epss-threshold 0.50
```

---

## ♾️ Scan Volume & Usage Quota

Unlike legacy commercial tools that restrict private repository scans to 200 tests/month, Vexa SCA Free Developer Edition is built with a **developer-first, open-core philosophy**:
* **Local CLI Scans**: Completely **Unlimited**. Run as many tests, pre-commit hooks, and dry-run fixes as needed without rate-limiting.
* **Public Open-Source Repos**: Completely **Unlimited**.
* **Audit Tracking**: Local usage statistics are maintained locally in `.sca-cache/usage.json` for full visibility.

---

## 📖 Documentation & Workflow Guides

Vexa SCA provides dedicated, production-ready operational guides tailored for specific engineering workflows, with complete copy-pasteable instructions for **Linux**, **macOS**, and **Windows**:

| Guide | Target Workflow | Key Focus Areas |
| :--- | :--- | :--- |
| 🛡️ [**Open Source SCA Guide**](docs/open-source-sca.md) | Software Supply Chain & Dependencies | Multi-ecosystem dependency analysis, AST reachability analysis, transitive DFS chains, license compliance, policy suppressions, pre-requisites & post-steps |
| 💻 [**CLI Usage Guide**](docs/cli-usage.md) | Local Developer Terminal & Workstations | Global/local installation, reachability analysis, multi-format reporting (HTML, SARIF, SBOM, JSON), automated fixes (`vexa-sca fix`), license auditing |
| 🚀 [**CI/CD Integration Guide**](docs/cicd-integration.md) | Automated Pipelines & Security Dashboards | GitHub Actions, GitLab CI, Bitbucket Pipelines, Azure DevOps, SARIF upload to Code Scanning, automated PR workflows, secret management |
| 🐳 [**Container Deployment Guide**](docs/container-deployment.md) | Containers, Registries & OS Packaging | Multi-stage production `Dockerfile`, Docker Compose, rootless runtime, scanning Docker images (`.tar`/`.tar.gz`), Alpine (`apk`) & Debian (`dpkg`) |
| 🪝 [**Git Hooks Setup Guide**](docs/git-hooks.md) | Shift-Left Developer Commits & Pushes | Native `.git/hooks/pre-commit` & `pre-push`, Husky integration, Python `pre-commit`, incremental manifest scanning, `.vexa-sca` suppressions |

---

### Quick Implementation Snippets by Workflow

#### 1. Local Developer Terminal Workflow

Quickly audit code, reachability, and licenses locally before committing:

```bash
# Standard local scan
vexa-sca scan

# Focus only on exploitable vulnerabilities
vexa-sca scan --reachable-only

# Generate offline HTML dashboard to review in browser
vexa-sca scan --html-file audit.html

# Automatically fix direct & transitive lockfile vulnerabilities
vexa-sca fix
```

---

### 2. GitHub Actions (with SARIF & Code Scanning Alerts)

Upload scan results directly into the **GitHub Security -> Code Scanning Alerts** tab using SARIF v2.1.0 and enforce automated quality gates:

```yaml
name: Vexa SCA Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Setup Rust Toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build Vexa SCA
        run: cargo build --release

      - name: Run Vulnerability Scan & Generate Reports
        run: |
          ./target/release/vexa-sca scan . \
            --sarif-file results.sarif \
            --html-file sca-report.html \
            --sbom cyclonedx \
            --sbom-file sbom-cyclonedx.json \
            --fail-on high \
            --fail-on-reachable

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

      - name: Archive HTML Security Dashboard & SBOM
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-reports
          path: |
            sca-report.html
            sbom-cyclonedx.json
```

---

### 3. GitLab CI/CD Pipeline

Export SARIF and HTML security reports directly as GitLab CI pipeline artifacts:

```yaml
vexa_sca_scan:
  stage: test
  image: rust:latest
  script:
    - cargo build --release
    - ./target/release/vexa-sca scan . \
        --sarif-file gl-sast-report.sarif \
        --html-file report.html \
        --sbom cyclonedx \
        --sbom-file sbom.json \
        --fail-on high
  artifacts:
    when: always
    paths:
      - gl-sast-report.sarif
      - report.html
      - sbom.json
    reports:
      sast: gl-sast-report.sarif
```

---

### 4. Azure DevOps Pipelines

Run Vexa SCA in Azure DevOps build pipelines and publish test and security artifacts:

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: |
      cargo build --release
      ./target/release/vexa-sca scan . \
        --sarif-file $(Build.ArtifactStagingDirectory)/results.sarif \
        --html-file $(Build.ArtifactStagingDirectory)/sca-report.html \
        --fail-on critical
    displayName: 'Run Vexa SCA Audit'

  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)'
      ArtifactName: 'SecurityReports'
      publishLocation: 'Container'
```

---

### 5. Git Pre-Commit Security Hook

Prevent vulnerabilities from entering your repository by adding a pre-commit hook in `.git/hooks/pre-commit`:

```bash
#!/bin/sh
echo "🔍 Running Vexa SCA pre-commit quality gate..."
cargo run --bin vexa-sca -- scan --fail-on high --fail-on-reachable
if [ $? -ne 0 ]; then
    echo "❌ Commit rejected: Reachable High/Critical vulnerabilities detected!"
    exit 1
fi
```

---

## Automated Tests & Verification

Vexa SCA includes a comprehensive automated test suite covering all core engines, parsers, reporters, and gates:

```bash
# Run all unit, integration, and E2E fixture tests (34 tests)
cargo test

# Or via npm script
npm test
```

### Test Suite Validations:
- **DAG Dependency Graph**: Cyclic dependency handling, DFS propagation paths to root, Schema v1.2.0 serialization.
- **Parsers**: `package-lock.json` (v1, v2, v3), `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Cargo.lock`, `go.sum`, `pom.xml`.
- **Policy Engine**: Alias matching, active suppressions, and expired date invalidation.
- **Fixer Engine**: Direct upgrades, `overrides` injection, backup restoration, and PR template generation.
- **Software Bill of Materials (SBOM)**: CycloneDX v1.5 JSON spec conformity (PURLs, component dependencies, vulnerability blocks) & SPDX v2.3 JSON schema conformity.
- **Interactive HTML Dashboard**: Offline zero-dependency HTML generator, glassmorphism UI, search/filtering script integrity, XSS HTML entity escaping.
- **CI/CD Quality Gate**: Severity threshold calculations, reachable flag gating, copyleft license restrictions, and exit code accuracy.
- **Container Scanner**: Alpine Linux `apk` database parsing, Debian/Ubuntu `dpkg` status parsing, `/etc/os-release` identification, Dockerfile analysis, and tarball extraction.
- **SARIF v2.1.0 & Reporting**: Schema validation for OASIS SARIF v2.1.0, JSON, Markdown, and ANSI Terminal output.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
