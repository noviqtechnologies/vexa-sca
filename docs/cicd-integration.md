# Vexa SCA CI/CD Integration Guide

## Executive Summary
This guide details how to integrate Vexa SCA into automated continuous integration and continuous delivery (CI/CD) pipelines. By embedding Vexa SCA into pipeline quality gates, engineering teams can detect high-risk vulnerabilities, filter false positives via AST reachability analysis, upload native SARIF reports to security dashboards, and prevent vulnerable dependencies from ever merging into production branches.

---

## Prerequisites
Ensure your CI/CD runner and repository configuration fulfill the following requirements before implementation:

### 1. Runner Environment
- **Operating Systems**: Ubuntu/Debian Linux runners (e.g., `ubuntu-latest`), macOS runners (`macos-latest`), or Windows Server runners (`windows-latest`).
- **Runtimes**: Either a Rust toolchain (`rust:1.75+`), Node.js (`v16+`), or Docker container runtime (`docker:20.10+`).

### 2. Token & Security Permissions
| Platform | Required Scope / Permission | Purpose |
| :--- | :--- | :--- |
| **GitHub Actions** | `security-events: write` | Ingest OASIS SARIF v2.1.0 into GitHub Code Scanning Alerts |
| **GitHub Actions** | `contents: read` (or `contents: write` for `fix`) | Clone repository and optionally open remediation Pull Requests |
| **GitLab CI** | `artifacts: reports: sast` | Ingest reports into GitLab Security & Compliance dashboards |
| **Bitbucket Pipelines** | Repository / Workspace Permissions | Read manifests and preserve security report artifacts |

---

## Installation / Initialization in CI Runners

Depending on your pipeline runner design, choose one of the following setup mechanisms:

### Method 1: Pre-Compiled Binary Download (Fastest, Sub-Second Startup)
Bypasses toolchain compilation to achieve near-instantaneous pipeline execution.

#### Linux Runner (cURL)
```bash
curl -sSL "https://github.com/noviqtechnologies/vexa-sca/releases/latest/download/vexa-sca-linux-x86_64.tar.gz" | tar -xz
sudo mv vexa-sca /usr/local/bin/
vexa-sca --version
```

#### Windows Runner (PowerShell)
```powershell
Invoke-WebRequest -Uri "https://github.com/noviqtechnologies/vexa-sca/releases/latest/download/vexa-sca-windows-x86_64.zip" -OutFile "$env:TEMP\vexa-sca.zip"
Expand-Archive -Path "$env:TEMP\vexa-sca.zip" -DestinationPath "$env:ProgramFiles\vexa-sca" -Force
$env:Path += ";$env:ProgramFiles\vexa-sca"
vexa-sca.exe --version
```

---

### Method 2: Official Container Runner (Zero Host Dependencies)
Run scans within containerized environments directly using GitHub Container Registry (`ghcr.io`):
```bash
docker run --rm -v "${PWD}:/workspace" ghcr.io/noviqtechnologies/vexa-sca:latest scan . --fail-on high
```

---

## Step-by-Step Implementation Guide

### 1. GitHub Actions Integration

Create `.github/workflows/vexa-sca.yml` in your repository:

```yaml
name: Vexa SCA Security Gate & Compliance Audit

on:
  push:
    branches: [ "main", "release/*" ]
  pull_request:
    branches: [ "main" ]
  schedule:
    # Run nightly at 02:00 UTC to catch newly disclosed CVEs
    - cron: '0 2 * * *'

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    name: Dependency Audit & Reachability Analysis
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Install Vexa SCA Standalone Binary
        run: |
          curl -sSL "https://github.com/noviqtechnologies/vexa-sca/releases/latest/download/vexa-sca-linux-x86_64.tar.gz" | tar -xz
          sudo mv vexa-sca /usr/local/bin/
          vexa-sca --version

      - name: Execute Vexa SCA Quality Gate
        run: |
          vexa-sca scan . \
            --sarif-file vexa-results.sarif \
            --html-file vexa-dashboard.html \
            --sbom cyclonedx \
            --sbom-file cyclonedx-sbom.json \
            --fail-on high \
            --fail-on-reachable \
            --fail-on-licenses copyleft \
            --epss-threshold 0.50

      - name: Upload SARIF to GitHub Code Scanning Alerts
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vexa-results.sarif
          category: vexa-sca

      - name: Archive HTML Dashboard and SBOM Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: vexa-sca-reports
          path: |
            vexa-dashboard.html
            cyclonedx-sbom.json

> [!NOTE]
> **Exit Code Contract & Artifact Preservation**: When vulnerabilities or gate thresholds are violated, `vexa-sca scan` writes all requested report files (`--sarif-file`, `--html-file`, `--sbom-file`) before exiting with status code `1`. Use `if: always()` on downstream upload steps (as shown above) to ensure reports are preserved, or supply `--no-fail` (alias `--report-only`) for non-blocking report generation jobs.
```

#### Automated Pull Request Remediation Workflow
To automatically generate pull requests when fixable vulnerabilities are discovered, configure `.github/workflows/vexa-remediation.yml`:

```yaml
name: Vexa SCA Automated Remediation

on:
  schedule:
    - cron: '0 4 * * 1' # Run weekly on Mondays
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

jobs:
  auto-fix:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Install Vexa SCA
        run: |
          curl -sSL "https://github.com/noviqtechnologies/vexa-sca/releases/latest/download/vexa-sca-linux-x86_64.tar.gz" | tar -xz
          sudo mv vexa-sca /usr/local/bin/

      - name: Execute Auto-Fix and Open Pull Request
        run: |
          vexa-sca fix \
            --create-pr \
            --repo "${{ github.repository }}" \
            --token "${{ secrets.GITHUB_TOKEN }}" \
            --branch "vexa-sca/security-updates" \
            --base "${{ github.event.repository.default_branch }}"
```

---

### 2. GitLab CI/CD Pipeline Integration

Create or update `.gitlab-ci.yml` in your repository root:

```yaml
stages:
  - test
  - security

vexa_sca_security_gate:
  stage: security
  image: 
    name: ghcr.io/noviqtechnologies/vexa-sca:latest
    entrypoint: [""]
  variables:
    SECURE_LOG_LEVEL: "info"
  script:
    - vexa-sca scan . 
        --sarif-file gl-sast-report.sarif 
        --html-file vexa-report.html 
        --sbom cyclonedx 
        --sbom-file sbom-cyclonedx.json 
        --fail-on high 
        --fail-on-reachable
  artifacts:
    when: always
    paths:
      - gl-sast-report.sarif
      - vexa-report.html
      - sbom-cyclonedx.json
    reports:
      sast: gl-sast-report.sarif
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

### 3. Bitbucket Pipelines Integration

Create `bitbucket-pipelines.yml`:

```yaml
image: atlassian/default-image:4

pipelines:
  default:
    - step:
        name: Vexa SCA Security Scan & Quality Gate
        caches:
          - docker
        services:
          - docker
        script:
          # Pull and run container image against pipeline workspace
          - docker run --rm -v "${BITBUCKET_CLONE_DIR}:/workspace" ghcr.io/noviqtechnologies/vexa-sca:latest scan . --sarif-file /workspace/vexa-results.sarif --html-file /workspace/vexa-report.html --fail-on critical
        artifacts:
          - vexa-results.sarif
          - vexa-report.html
```

---

### 4. Azure DevOps Pipelines Integration

Create `azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
      - main
      - release/*

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: |
      curl -sSL "https://github.com/noviqtechnologies/vexa-sca/releases/latest/download/vexa-sca-linux-x86_64.tar.gz" | tar -xz
      sudo mv vexa-sca /usr/local/bin/
      vexa-sca scan . \
        --sarif-file $(Build.ArtifactStagingDirectory)/results.sarif \
        --html-file $(Build.ArtifactStagingDirectory)/sca-report.html \
        --fail-on high \
        --fail-on-reachable
    displayName: 'Execute Vexa SCA Audit Gate'

  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)'
      ArtifactName: 'SecurityAuditReports'
      publishLocation: 'Container'
```

---

## Advanced Configuration & Edge Cases

### Quality Gate Exit Codes and Evaluation Flags
Vexa SCA emits deterministic exit codes for CI orchestration:
- `0`: Scan passed all quality gate criteria, or no vulnerabilities met the failure threshold.
- `1`: Quality gate policy violation detected (e.g., threshold reached, reachable vulnerability confirmed, copyleft license found).
- `2`: Runtime error (e.g., missing manifest, corrupted archive, or network failure).

```bash
# Fail only if reachable vulnerabilities are High or Critical
vexa-sca scan --fail-on high --fail-on-reachable

# Enforce licensing standards (blocks viral copyleft licenses like GPL-3.0 and AGPL-3.0)
vexa-sca scan --fail-on-licenses copyleft

# Combine gates for production compliance
vexa-sca scan \
  --fail-on critical \
  --fail-on-reachable \
  --fail-on-licenses copyleft \
  --fail-on-unmaintained
```

### Secure Secret Management
When utilizing the automated patch engine (`vexa-sca fix --create-pr`), never hardcode API keys or personal access tokens directly into workflow definitions:
- **GitHub Actions**: Use the automated token context `${{ secrets.GITHUB_TOKEN }}` or a custom Organization Secret `${{ secrets.SECURITY_BOT_PAT }}`.
- **GitLab CI**: Inject via masked, protected environment variables: `$GITLAB_TOKEN`.
- **Bitbucket Pipelines**: Configure repository variables marked with the `Secured` checkbox: `$BB_AUTH_TOKEN`.

### Offline & Air-Gapped CI Pipeline Caching
For isolated runners or ephemeral environments that restrict outbound traffic, cache the `.sca-cache/` directory across CI runs:

```yaml
# In GitHub Actions:
- name: Cache Vexa Vulnerability Database
  uses: actions/cache@v4
  with:
    path: .sca-cache
    key: vexa-cache-${{ hashFiles('**/package-lock.json', '**/Cargo.lock', '**/requirements.txt') }}
    restore-keys: |
      vexa-cache-
```

---

## Troubleshooting & FAQs

### 1. `Resource not accessible by integration` during SARIF upload
- **Cause**: GitHub Actions workflow lacks write permissions for the `security-events` API.
- **Resolution**: Explicitly declare `permissions:` block at either the workflow or job level:
  ```yaml
  permissions:
    contents: read
    security-events: write
  ```

### 2. CI build failed with exit code 1, but vulnerabilities are not exploitable
- **Cause**: The pipeline is running `vexa-sca scan --fail-on high` without reachability filtering, causing unreachable transitive dependencies to break the build.
- **Resolution**: Add the `--fail-on-reachable` flag so that only vulnerabilities verified to have active invocation call-paths in your source code will trigger a non-zero exit code:
  ```bash
  vexa-sca scan --fail-on high --fail-on-reachable
  ```

### 3. Pipeline build duration is prolonged due to Rust compilation
- **Cause**: The CI runner is building Vexa SCA from source (`cargo build --release`) on every run without caching cargo binaries.
- **Resolution**: Download pre-compiled native binaries directly in your workflow (as demonstrated in Method 1 above) or execute via the official container image `ghcr.io/noviqtechnologies/vexa-sca:latest`.
