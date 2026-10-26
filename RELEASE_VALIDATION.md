# Vexa SCA Release Validation & GA Closure Record (v1.2.0)

**Project:** `noviqtechnologies/vexa-sca`  
**Version:** `1.2.0`  
**Target Release Tag:** `v1.2.0` (Clean, immutable tag distinct from superseded `v1.0.0` / `v1.1.0` tags)  
**Historical CI Context:** [CI run 40310425395](https://github.com/noviqtechnologies/vexa-sca/actions/runs/40310425395) | [Release run 40310432176](https://github.com/noviqtechnologies/vexa-sca/actions/runs/40310432176) (commit `55fa9cd`)  
**Superseded Reports:** `completed/vexa-sca-validation-final.md` and `completed/vexa-sca-validation-latest.md` (labeled as superseded)  

---

## Executive Summary & Status

This document is the **single authoritative release validation record** for `vexa-sca` version `1.2.0`. It addresses and closes all seven release blockers identified in the GA Release Review.

| Item | Requirement | Resolution Status | Evidence Location |
| :---: | :--- | :---: | :--- |
| **1** | **Exit-Code Precedence Contract** | **RESOLVED & VERIFIED** | `src/cli.rs`, `src/scanner/quality_gate.rs`, `tests/cli_e2e_tests.rs` |
| **2** | **Reconcile Documentation & Claims** | **RESOLVED & VERIFIED** | `README.md`, `COMPATIBILITY_MATRIX.md`, `docs/*` |
| **3** | **Real pnpm & npm Rollback Verification** | **RESOLVED & VERIFIED** | `tests/cli_e2e_tests.rs`, `.github/workflows/ci.yml` |
| **4** | **Reproducible Repository Scan Modeling** | **RESOLVED & VERIFIED** | `COMPATIBILITY_MATRIX.md` |
| **5** | **Independently Verifiable Schema Validation** | **RESOLVED & VERIFIED** | `scripts/validate_reports.mjs`, `REPORT_SCHEMA_VALIDATION.md` |
| **6** | **Trustworthy & Immutable Tags/Artifacts** | **RESOLVED & VERIFIED** | `.github/workflows/release.yml`, `Cargo.toml`, `package.json` |
| **7** | **Authoritative Validation Record Bundle** | **RESOLVED & VERIFIED** | This document (`RELEASE_VALIDATION.md`) |

---

## 1. Exit-Code Precedence Contract

Vexa SCA enforces a deterministic precedence hierarchy across both `scan` and `ci` profiles:

```
[Pre-scan config/arg error]  --> Code 2 (Reject immediately, never scan)
        │
[Scan execution]
        ├─ Incomplete data?   --> Code 3 (Takes precedence; records gate failures in JSON/HTML/Summary)
        ├─ Gate failed?       --> Code 1 (Suppressed to Code 0 ONLY by --no-fail)
        └─ Gate passed?       --> Code 0 (Complete pass)
```

### Exact Precedence Rules
1. **Exit Code 2 (Configuration / Argument Error):** Invalid CLI options, conflicting flags, malformed `.vexa-sca` policy file, missing mandatory audit fields (`reason`, `owner`, `ticket`, `expires`). **Rejects execution before scanning begins.** Never suppressed by `--no-fail` or `--allow-unavailable`.
2. **Exit Code 3 (Incomplete Requested Scan Data):** Manifest parsing failures, analysis limits exceeded (e.g. 500-source-file cap hit), upstream advisory lookup failure without usable cache, or report file generation/write failure. **Takes precedence over a simultaneous finding gate failure.** Findings and severity gate failure details remain captured in output reports (`"qualityGate": { "passed": false, "severityGateFailed": true }`). `--no-fail` does **not** suppress code 3. `--allow-unavailable` waives advisory outages only, never manifest, source-limit, or write failures.
3. **Exit Code 1 (Quality Gate Failure):** Complete scan finished with complete data, but findings violate configured thresholds (`--fail-on <severity>`, `--fail-on-reachable`, or license policies). Suppressed to `0` by `--no-fail`.
4. **Exit Code 0 (Success / Clean):** Complete scan finished with complete data and all configured quality gates passed.

### Test Verification
Table-driven integration tests in `tests/cli_e2e_tests.rs`:
- `test_cli_table_driven_incomplete_scan_matrix`: Exercises complete pass (exit 0), complete gate failure (exit 1), incomplete-only (exit 3), incomplete PLUS gate failure (exit 3 with JSON gate failure assertions), `--no-fail` non-suppression of code 3, and `--allow-unavailable` non-suppression of source limits.
- `test_cli_malformed_manifest_exits_code_3_and_not_suppressed`: Asserts malformed manifests exit code 3 even when `--no-fail` and `--allow-unavailable` are provided.
- `test_cli_report_generation_write_failure_exits_code_3`: Asserts unwritable report paths exit code 3.

---

## 2. Documentation Reconciliation & Boundary Disclosures

All root guides (`README.md`, `COMPATIBILITY_MATRIX.md`, `docs/cli-usage.md`, `docs/cicd-integration.md`, `docs/container-deployment.md`, `docs/git-hooks.md`, `docs/open-source-sca.md`) describe the exact same support scope and maturity:

1. **Release Status:** Promoted to **General Availability (GA v1.2.0)** for Tier 1: Node.js / JavaScript / TypeScript (`package-lock.json` v2/v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v5/v6/v9). Other ecosystems (Python, Java Maven, Go, Cargo, Yarn, Container OS) are explicitly labeled **Tier 2: Experimental / Preview**.
2. **Repository Usage Signals:** Replaced "runtime reachability" and "Deep SCA" claims with **Heuristic Repository Usage Signals**. Stated explicitly that syntactic signals cannot prove runtime safety or absence of exploitability, and never suppress findings from reports.
3. **Remediation Boundaries:** Described `vexa-sca fix` as a reviewed upgrade proposal with **best-effort restoration** of captured root manifests and lockfiles (`package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`). Disclosed that `node_modules`, registry caches, and uncaptured filesystem modifications cannot be rolled back.
4. **Privacy & Network Dataflow:** Disclosed that OSV advisory lookups transmit package coordinates (`ecosystem`, package name, version) over HTTPS to `api.osv.dev`. Clarified that `.sca-cache/` is a local cache to reduce repeat queries, not a signed, complete, or indefinitely fresh offline vulnerability database. Removed air-gapped coverage claims.
5. **License Scanner Legal Disclaimer:** Removed legal conclusions (such as "safe for commercial distribution"). Clarified that detected SPDX identifiers and license categorizations are informational and do not substitute for legal counsel.
6. **Immutable Installation:** Replaced mutable branch `cargo install --git` instructions with building from a reviewed immutable source revision (`git checkout v1.2.0 && cargo build --locked --release`).

---

## 3. Real pnpm and npm Rollback Evidence

Prior testing only exercised simulated missing executables. To provide indisputable evidence:
1. Pinned **pnpm v9.15.4** and **npm v11.13.0** were installed on the host environment and added to `.github/workflows/ci.yml`.
2. Integration tests in `tests/cli_e2e_tests.rs`:
   - `test_real_pnpm_install_failure_and_byte_for_byte_rollback`
   - `test_real_npm_install_failure_and_byte_for_byte_rollback`
3. Verification results:
   - `--dry-run` performs zero disk writes, creates no `.bak` files, and executes no package managers.
   - Deterministic install failure induced via `.npmrc` pointing to unreachable port (`registry=http://127.0.0.1:9/`) with zero retries.
   - Real `pnpm` and `npm` executables launched via Windows command shim (`cmd.exe /d /s /c`) and native POSIX shims.
   - Failed install triggers `restore_project_state`.
   - **Byte-for-byte SHA-256 restoration:** Before and after SHA-256 digests of `package.json`, `pnpm-lock.yaml`, and `package-lock.json` are byte-for-byte identical.
   - **Extraneous file removal:** Files created during failed runs (`pnpm-lock.yml`, `npm-shrinkwrap.json`) are deleted upon rollback.
   - **Logging & Exit Code:** Process exits with code 1 and emits:
     `Rollback complete: package.json and captured lockfiles were restored.`

---

## 4. Reproducible Repository Scan Evidence

In `COMPATIBILITY_MATRIX.md`, the six official repository benchmarks are explicitly decoupled across three distinct completeness dimensions:

| Repository | Snapshot Commit | Dependency Graph | Advisory Lookup | Usage Signals (500 Cap) | Overall Status | Exit Code |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `nodejs/node` | `60e6c84f4e353c8a1444c3982365af41e0d1e9ec` | Complete (1,686) | Complete (`cache_hit`) | Incomplete (500 / 24,278) | `INCOMPLETE` | **Code 3** |
| `microsoft/TypeScript` | `8a62bbe746909624b69b6e671026b454da2f02cf` | Complete (307) | Complete (`cache_hit`) | Incomplete (500 / 31,968) | `INCOMPLETE` | **Code 3** |
| `vercel/next.js` | `cbf49db30a655ac17c92c2951885c4256db14b9e` | Partial (1,786 / 4,837) | Incomplete (`partial_failure`)| Incomplete (500 / 25,350) | `INCOMPLETE` | **Code 3** |
| `angular/angular` | `bd4e7816a53aafbd83bd3d2ac876aa6b15ee88c9` | Partial (1,221 / 2,683) | Incomplete (`partial_failure`)| Incomplete (500 / 7,351) | `INCOMPLETE` | **Code 3** |
| `vuejs/core` | `0ff253bfba3ee8d3d65448bd44ad890fd01b0ecd` | Partial (342 / 665) | Incomplete (`partial_failure`)| Incomplete (500 / 528) | `INCOMPLETE` | **Code 3** |
| `facebook/react` | `b8562d9a3381a833d7b4093952f4422e1b8bca87` | Incomplete (parse only) | Not Run | Not Run | `INCOMPLETE` | **Code 3** |

Under the precedence contract, every scan that encounters the 500-file cap or partial advisory coverage exits with **Code 3**. No capped or unresolved scan is ever claimed to be a complete security inventory.

---

## 5. Independently Verifiable Report & Schema Validation

Report generation was verified against official JSON schemas using pinned validators (`ajv@8.17.1`, `ajv-formats@3.0.1`, `ajv-draft-04@1.0.0`):

### Pinned Schema Specifications
- **SARIF 2.1.0:** `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`  
  *SHA-256:* `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`
- **CycloneDX 1.5 JSON:** `https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json`  
  *SHA-256:* `2d956c1d05c092695457a91f3b5c57c749793c013ec224a0935807cfc8ae4480`
- **SPDX 2.3 JSON:** `https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json`  
  *SHA-256:* `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b`

### Validation Test Run Results (`npm run validate:schemas`)
```
=== Vexa SCA Verifiable Report & Schema Validation Job ===

Verifying pinned schema digests...
  ✔ [SARIF 2.1.0] c3b4bb2d60938974... verified
  ✔ [CycloneDX 1.5] 2d956c1d05c09269... verified
  ✔ [SPDX 2.3] 239208b7ac287b3c... verified

Generating and validating test artifacts:
  ✔ [SARIF 2.1.0] Complete Scan: VALID (SHA-256: f80864c18b8a2733c667789d17cd9caaf89c9a56ca49dd270bf1083e74f5e228)
  ✔ [CycloneDX 1.5] Complete Scan: VALID (SHA-256: e5ccd4af401fd25a14313fff746414bb01f50effe9095280852c5ffb3ab2d732)
  ✔ [SPDX 2.3] Complete Scan: VALID (SHA-256: 0187f55d1798525f6091e388230e1488b37000e2018673f97e4ec223cc98b35e)
  ✔ [SARIF 2.1.0] Incomplete Scan (500/1 Source Cap): VALID (SHA-256: 068400ceb08c09407424ae900a3b24567d4e477255ebc36dc419614b360661ab)
  ✔ [CycloneDX 1.5] Incomplete Scan (500/1 Source Cap): VALID (SHA-256: e8d3f26f623de6d812aba8ef767fbc7e70793b41728afccf68e351f16cf69991)
  ✔ [SPDX 2.3] Incomplete Scan (500/1 Source Cap): VALID (SHA-256: 8439c8e9c3e46e0aa16740abc530abcf88a1a2bf2a596844fc1b00452258b40f)

✔ All generated reports conform strictly to pinned official schemas with 0 errors.
```

### HTML Escaping & Finding Label Verification
In `src/reporters/html.rs`:
- Hostile payloads (`<script>`, `<img src=x onerror=...>`, `<svg/onload=...>`, `<iframe src=...>`, hostile package names, paths, code snippets) are entity-escaped.
- Asserted that report labels never make "Low Risk" claims on absent signals.

---

## 6. Release Tags and Provenance

1. **Tag Policy:** Target version is `1.2.0` (`v1.2.0`), leaving prior tags `v1.0.0` and `v1.1.0` permanently marked as superseded candidate commits.
2. **Workflow Enhancements (`.github/workflows/release.yml`):**
   - **Tag/Version Guard:** Verifies `GITHUB_REF_NAME` matches `Cargo.toml` version `1.2.0`.
   - **Native Smoke Tests:** Runs `./dist/vexa-sca --version` and `./dist/vexa-sca scan --help` on compiled artifacts before packaging.
   - **GitHub Artifact Attestation:** Uses `actions/attest-build-provenance@v2` with scoped permissions (`id-token: write`, `attestations: write`, `contents: write`) to attest SHA-256 digests.
   - **Verification Command:**
     ```bash
     gh attestation verify vexa-sca-linux-x86_64.tar.gz --owner noviqtechnologies
     ```
   - **Container Distribution:** GHCR publishing remains disabled (`if: false`) until container scanning is independently qualified.

---

## Reproducibility Commands

To reproduce the entire validation decision locally:

```bash
# 1. Check formatting, linting, and compilation
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo check --locked --all-targets

# 2. Run full test suite (including table-driven exit precedence and real pnpm/npm rollback)
cargo test --locked --all-targets --verbose

# 3. Build release binaries
cargo build --locked --release

# 4. Run schema validation runner for SARIF 2.1.0, CycloneDX 1.5, and SPDX 2.3
npm run validate:schemas
```
