# Vexa SCA CI/CD Integration Guide (GA v1.2.0)

## Scope and Status

Vexa SCA is **Generally Available (GA)** for Tier 1 ecosystems (Node.js / JavaScript / TypeScript: `package-lock.json` v2/v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v5/v6/v9). It provides deterministic quality-gate exit codes (`0`, `1`, `2`, `3`), native PR-differential scanning (`--baseline`), GitHub Actions Step Summaries, workflow annotations, and schema-validated SARIF v2.1.0 and CycloneDX v1.5 / SPDX v2.3 SBOM exports.

In enterprise DevSecOps pipelines, Vexa SCA supports two deployment patterns:
1. **Enforcement Gate (Blocking):** Fails builds (`exit 1`) when vulnerabilities breach defined thresholds (e.g., `--fail-on high`), preventing risky dependencies from merging into protected branches.
2. **Audit / Report-Only (Non-blocking):** Uses `--no-fail` to record security findings, upload SARIF alerts to GitHub Code Scanning, and generate audit dashboards without breaking builds during team onboarding.

### Security & Integrity Principles for CI
- **Immutable Action Pinning:** Pin all third-party CI actions to full commit SHAs (e.g. `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`) to protect against supply chain tampering.
- **Least-Privilege Token Scopes:** Use `contents: read` for audit-only runs, adding `security-events: write` only when uploading SARIF to GitHub Code Scanning.
- **Verdict Integrity:** Repository Usage Signals (`IMPORTED_SOURCE`, `REFERENCED_CONFIG_OR_SCRIPT`) are heuristic triage aids. Quality gates must evaluate the full unsuppressed finding set; `--reachable-only` is for presentation filtering, not for suppressing unverified findings.
- **Exit Code Contract:** Precedence ensures configuration errors (`2`) and incomplete scan data (`3`) are never hidden as clean passes. `--no-fail` waives gate failure (`1`) only.

Example shell commands for a controlled evaluation runner (set `VEXA_REVIEWED_SHA` to an approved full SHA):

Set `SCANNER_DIR` to a location outside the project being scanned and `TARGET_DIR` to the checkout under evaluation. This POSIX-shell example must be adapted to the runner's native shell on Windows.

```sh
mkdir -p "$(dirname "$SCANNER_DIR")"
git clone https://github.com/noviqtechnologies/vexa-sca.git "$SCANNER_DIR"
git -C "$SCANNER_DIR" checkout --detach "$VEXA_REVIEWED_SHA"
cargo build --locked --release --manifest-path "$SCANNER_DIR/Cargo.toml"

# Automated CI profile (emits $GITHUB_STEP_SUMMARY, workflow annotations, SARIF, and SBOM):
"$SCANNER_DIR/target/release/vexa-sca" ci "$TARGET_DIR" \
  --fail-on high \
  --sarif-file vexa-report.sarif \
  --sbom cyclonedx \
  --sbom-file vexa-sbom.cdx.json

# Or developer scan profile when generating standalone offline HTML dashboard:
# "$SCANNER_DIR/target/release/vexa-sca" scan "$TARGET_DIR" --html-file vexa-report.html --no-fail
```

`--no-fail` is not an incomplete-data bypass: it suppresses quality-gate exit `1` only; configuration errors (`2`) and incomplete data (`3`) remain nonzero. Store output files in the job artifact area and upload them under an always-run/finally step. Confirm that the exact CLI build supports every requested output flag before adopting the command.

## CI platform integration

The same principles apply to GitHub Actions, GitLab CI, Bitbucket Pipelines, and Azure DevOps:

- Store the reviewed scanner SHA as a protected variable; reject missing or non-full-SHA values.
- Pin checkout/build/upload tasks to reviewed immutable versions.
- Use read-only source permissions for scan-only jobs; do not grant pull-request write permissions.
- Make the evaluation step non-blocking for vulnerability thresholds, but allow incomplete-data/configuration failure to be visible in job status.
- Upload raw JSON and any other explicitly requested reports even when the scan step fails; do not claim SARIF is natively accepted by a platform without testing ingestion.
- Avoid `--fail-on-reachable`, `--reachable-only` suppression, `--allow-unknown-reachability`, and auto-remediation PR creation during evaluation.

Do not copy legacy workflow samples that use unpinned actions, build the current application checkout as though it were the scanner, assign SARIF to an unsupported native report field, or grant broad token permissions. Use your platform's official workflow documentation to construct a pinned job following the sequence above.

### Complete GitHub Actions Workflow (`.github/workflows/vexa-sca.yml`)

Copy and paste this into `.github/workflows/vexa-sca.yml` in your target repository:

```yaml
name: Vexa SCA Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write # Required for GitHub Code Scanning tab integration

jobs:
  vexa-sca:
    name: Vexa SCA Dependency Audit
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Build and install Vexa SCA CLI
        run: |
          # Build scanner in /tmp to prevent workspace collisions with target Cargo.toml
          git clone --depth 1 https://github.com/noviqtechnologies/vexa-sca.git /tmp/vexa-sca
          cargo build --locked --release --manifest-path /tmp/vexa-sca/Cargo.toml
          sudo cp /tmp/vexa-sca/target/release/vexa-sca /usr/local/bin/vexa-sca
          rm -rf /tmp/vexa-sca

      - name: Run Vexa SCA CI Scan
        # In CI, vexa-sca ci writes directly to $GITHUB_STEP_SUMMARY and emits PR annotations
        # Use --fail-on high for blocking gates, or add --no-fail for non-blocking evaluation
        run: |
          vexa-sca ci . \
            --fail-on high \
            --sarif-file vexa-report.sarif \
            --sbom cyclonedx \
            --sbom-file vexa-sbom.cdx.json

      - name: Archive Scan Artifacts
        if: always()
        uses: actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1 # v4.6.1
        with:
          name: vexa-sca-artifacts
          path: |
            vexa-report.sarif
            vexa-sbom.cdx.json

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vexa-report.sarif
          category: vexa-sca
        continue-on-error: true
```

### Complete GitLab CI Pipeline (`.gitlab-ci.yml`)

Copy and paste this into `.gitlab-ci.yml` in your target repository:

```yaml
stages:
  - test

vexa-sca-scan:
  stage: test
  image: rust:latest
  script:
    - git clone --depth 1 https://github.com/noviqtechnologies/vexa-sca.git /tmp/vexa-sca
    - cargo build --locked --release --manifest-path /tmp/vexa-sca/Cargo.toml
    - cp /tmp/vexa-sca/target/release/vexa-sca /usr/local/bin/vexa-sca
    - rm -rf /tmp/vexa-sca
    - vexa-sca ci . --fail-on high --sarif-file vexa-report.sarif --sbom cyclonedx --sbom-file vexa-sbom.cdx.json
  artifacts:
    when: always
    paths:
      - vexa-report.sarif
      - vexa-sbom.cdx.json
    reports:
      cyclonedx: vexa-sbom.cdx.json
```

## Exit and completeness semantics

The current source intends this contract, which must be verified against the exact built release before use:

| Exit code | Meaning |
|---:|---|
| `0` | No configured gate failure in processed data; not a coverage certificate. |
| `1` | A configured quality gate failed. |
| `2` | Invalid CLI or policy/configuration. |
| `3` | Scan data is incomplete, including relevant advisory, manifest, source-read/traversal, or analysis-limit failures. |

`--allow-unavailable` may permit an advisory-only outage; it must never waive source/manifest failures. `--no-fail` may suppress gate exit `1` only. Do not set `continue-on-error` or equivalent in a way that hides exit `2`/`3` from the job summary.

## Do not gate on usage signals

AST usage signals are syntactic triage metadata. They do not model general control flow, cross-file dataflow, reflection, every dynamic import, plugin entry points, or every bundler/workspace resolution. `--reachable-only` is a presentation filter. Severity gates must operate on the complete unsuppressed finding set, including findings whose source usage status is unknown or not observed.

## Production Quality Gate Enforcement

All release criteria for Tier 1 GA enforcement have been evidenced and recorded in [RELEASE_VALIDATION.md](../RELEASE_VALIDATION.md):
- Locked builds and 153 automated tests passing.
- Real `npm` and `pnpm` install failure and byte-for-byte rollback verified.
- Pinned JSON schema conformity verified for SARIF 2.1.0, CycloneDX 1.5, and SPDX 2.3.
- Deterministic exit code precedence (`2` > `3` > `1` > `0`) verified by table-driven test suites.

Teams can configure blocking gates (`--fail-on high`) with confidence that incomplete scans (`exit 3`) and invalid configurations (`exit 2`) fail closed predictably.
