# Vexa SCA — Parser and Fixture Coverage

This document records ecosystem support tiers, parser capabilities, and fixture validation evidence for Vexa SCA v1.3.5.

> [!IMPORTANT]
> **Status: Tier 1 GA (Scope-Specific) — Release v1.3.5**
> - **Tier 1 (GA / Production Ready):** Node.js / JavaScript / TypeScript (`package-lock.json` v2/v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v5/v6/v9). Validated by 211 automated tests, real pnpm/npm byte-for-byte rollback verification, table-driven exit code contract (`0`, `1`, `2`, `3`), strict non-suppressible `INCOMPLETE` exit code semantics on any skipped scope, and independently verified JSON schemas (SARIF 2.1.0, CycloneDX 1.5, SPDX 2.3).
> - **Tier 2 (Experimental / Community Preview):** Python (`requirements.txt`), Java Maven (`pom.xml`), Yarn (`yarn.lock`), Cargo (`Cargo.lock`), Go (`go.sum`), and Container OS package auditing. These ecosystems have fixture coverage and are available for preview evaluation.
> - **SAST & Usage Signals (Developer Heuristic Preview):** First-party heuristic scanners provide fast syntactic triage signals; all coverage limits, file size caps, and read omissions are strictly recorded and surfaced to guarantee verdict integrity.
>
> **Triage vs Enforcement Rule:** Repository Usage Signals are heuristic syntactic triage aids. Verdict integrity mandates that missing AST signals never certify runtime safety or suppress unverified findings.

---

## 1. Supported Package Managers & Lockfile Formats

| Package Manager | Lockfile(s) / Manifest | Parser Module | Support Tier |
| --- | --- | --- | --- |
| **npm** | `package-lock.json` v2 / v3 | `src/parsers/package_lock.rs` | **Tier 1 (GA / Production Ready)** |
| **npm** | `npm-shrinkwrap.json` | `src/parsers/package_lock.rs` | **Tier 1 (GA / Production Ready)** |
| **npm** | `package-lock.json` v1 | `src/parsers/package_lock.rs` | Supported (v1 nested duplicate graph support is limited) |
| **pnpm** | `pnpm-lock.yaml` v5 / v6 / v9 | `src/parsers/pnpm_lock.rs` | **Tier 1 (GA / Production Ready)** |
| **Yarn** | `yarn.lock` v1 (Classic) / v2–v4 (Berry) | `src/parsers/yarn_lock.rs` | Tier 2 (Experimental) |
| **Cargo** | `Cargo.lock` v1 / v3 | `src/parsers/cargo_lock.rs` | Tier 2 (Experimental) |
| **pip** | `requirements.txt` | `src/parsers/python_reqs.rs` | Tier 2 (Experimental) |
| **Go** | `go.sum` + `go.mod` | `src/parsers/go_sum.rs` | Tier 2 (Experimental) |
| **Maven** | `pom.xml` | `src/parsers/pom_xml.rs` | Tier 2 (Experimental) |

---

## 2. Feature Matrix

### 2.1 npm — `package-lock.json`

| Feature | v1 | v2 | v3 | Test(s) |
| --- | --- | --- | --- | --- |
| Node registration | ✅ | ✅ | ✅ | `test_package_lock_parser_fixture` |
| Root → direct dep edges | ✅ | ✅ | ✅ | `test_package_lock_parser_fixture` |
| Transitive dep edges | ✅ | ✅ | ✅ | `test_package_lock_parser_fixture` |
| **Nearest-ancestor resolution** (nested `node_modules`) | ⚠️ flat-only | ✅ | ✅ | `test_resolve_nearest_ancestor_resolution` |
| Duplicate-version graphs (nested `node_modules/<pkg>/node_modules/<dep>`) | ❌ | ✅ | ✅ | `test_resolve_nearest_ancestor_resolution` |
| Workspace sub-packages (`packages/<name>`) | N/A | ✅ | ✅ | `test_resolve_nearest_ancestor_resolution` |
| Workspace → nested dep resolution fallback | N/A | ✅ | ✅ | package_lock unit tests |
| `optionalDependencies` | ✅ | ✅ | ✅ | transitive dep walk |
| `peerDependencies` | ✅ | ✅ | ✅ | `parse_v2_v3` peer wiring |
| Integrity hashes | ✅ | ✅ | ✅ | `NodeInfo.integrity` |
| Dev dep filtering (`--no-dev`) | ✅ | ✅ | ✅ | `is_dev` flag check |

> **Notes on nearest-ancestor resolution (npm v2/v3):**
The implementation iteratively walks up the package path, checking each
enclosing `node_modules` directory for the requested dependency, correctly
modeling npm's hoisting algorithm. A workspace package (path without a
leading `node_modules/` prefix) is registered under both its path key and
its `name` key, allowing workspace-internal cross-references to resolve.

---

### 2.2 pnpm — `pnpm-lock.yaml`

| Feature | v5 | v6 | v9 | Test(s) |
| --- | --- | --- | --- | --- |
| Node registration | ✅ | ✅ | ✅ | `test_parse_pnpm_v9_multidoc_lockfile`, `test_pnpm_v9_fixture_parses_packages` |
| Multi-document YAML (v9 `---` prefix) | N/A | N/A | ✅ | `test_parse_pnpm_v9_multidoc_lockfile` |
| `snapshots` key (v9) | N/A | N/A | ✅ | `test_pnpm_v9_fixture_parses_packages` |
| Integrity from `packages` → `snapshots` (v9) | N/A | N/A | ✅ | `test_pnpm_v9_fixture_parses_packages` |
| **Peer dep suffix modeling** — `pkg@ver(peer@ver)` | N/A | N/A | ✅ | `test_parse_package_key_with_peers_extracts_peer_edges`, `test_peer_dep_snapshot_creates_edge` |
| **Peer dep suffix modeling** — `/pkg/ver_peer@ver` (v5) | ✅ | N/A | N/A | `test_parse_package_key_with_peers_extracts_peer_edges` |
| `peerDependencies` entries in snapshot | ✅ | ✅ | ✅ | `peerDependencies` section wiring |
| Root dep from `importers['.']` | N/A | ✅ | ✅ | `test_pnpm_v9_fixture_parses_packages` |
| Root dep from top-level `dependencies` (v5/v6) | ✅ | ✅ | N/A | `test_pnpm_v6_lockfile_parses` (fixture in `pnpm-app`) |
| **Workspace importers** (non-root keys in `importers`) | N/A | N/A | ✅ | `test_pnpm_workspace_importers_wired` |
| `link:` / `workspace:*` dependency edges | N/A | N/A | ✅ | `test_pnpm_workspace_importers_wired` |
| `workspace:^` / `workspace:~` resolution | N/A | N/A | ✅ | `test_pnpm_workspace_importers_wired` |
| `optionalDependencies` in snapshots | ✅ | ✅ | ✅ | `optionalDependencies` section wiring |
| Scoped packages (`@scope/name`) | ✅ | ✅ | ✅ | `test_parse_package_key_variants` |
| Dev dep filtering (`--no-dev`) | ✅ | ✅ | ✅ | `is_dev` flag check |

> **Peer dependency modeling detail:**
In pnpm v9 snapshots, keys like `react-dom@18.2.0(react@18.2.0)` encode
the resolved peer as a key suffix. Vexa SCA's `parse_package_key_with_peers`
extracts these pairs and pushes explicit graph edges so that react-dom is
shown as depending on react, not just having an undeclared peer. In v5, the
underscore form (`_react@18.2.0`) is handled identically.

---

### 2.3 Yarn — `yarn.lock`

| Feature | Classic (v1) | Berry (v2–v4) | Test(s) |
| --- | --- | --- | --- |
| Node registration | ✅ | ✅ | `yarn_lock` parser tests |
| Root dep wiring | ✅ | ✅ | detector integration test |
| Transitive dep edges | ✅ | ✅ | yarn_lock parser tests |
| Integrity hashes | ✅ | ✅ | `NodeInfo.integrity` |
| Workspace monorepos | ⚠️ partial | ⚠️ partial | — |
| Dev dep filtering | ✅ | ✅ | `is_dev` flag |

---

### 2.4 Cargo — `Cargo.lock`

| Feature | v1 | v3 | Test(s) |
| --- | --- | --- | --- |
| Package registration | ✅ | ✅ | `test_cargo_lock_parser_fixture` |
| Dependency edges | ✅ | ✅ | `test_cargo_lock_parser_fixture` |
| Checksum integrity | ✅ | ✅ | `NodeInfo.integrity` |
| Dev / build deps | ⚠️ not split | ⚠️ not split | — |

---

### 2.5 pip — `requirements.txt`

| Feature | Support | Test(s) |
| --- | --- | --- |
| Package registration | ✅ | `test_python_requirements_parser_fixture` |
| Version pinning | ✅ | `test_python_requirements_parser_fixture` |
| VCS / URL dependencies | ⚠️ skipped | — |
| `extras` (`pkg[extra]`) | ⚠️ stripped | — |

---

### 2.6 Go — `go.sum` / `go.mod`

| Feature | Support | Test(s) |
| --- | --- | --- |
| Module registration | ✅ | `test_go_sum_parser_fixture` |
| Version pinning | ✅ | `test_go_sum_parser_fixture` |
| Replace directives | ⚠️ ignored | — |
| Workspace (`go.work`) | ❌ | — |

---

### 2.7 Maven — `pom.xml`

| Feature | Support | Test(s) |
| --- | --- | --- |
| Dependency registration | ✅ | `test_pom_xml_parser_fixture` |
| Version variables (`${…}`) | ⚠️ literal string | — |
| Transitive BOM imports | ❌ | — |
| Multi-module projects | ❌ | — |

---

## 3. Repository Usage Signals (heuristic)

| Feature | Support | Test(s) |
| --- | --- | --- |
| Static ESM `import … from 'pkg'` | Fixture-level syntax signal only; not runtime reachability | `js_ast_analyzer` unit tests |
| Static CommonJS `require('pkg')` | Fixture-level syntax signal only; not runtime reachability | `js_ast_analyzer` unit tests |
| Dynamic `import('pkg')` (literal) | Limited syntactic support; validate status on release-matched tests | `js_ast_analyzer` unit tests |
| Dynamic `import(variable)` | Unresolved cases must remain `UNKNOWN`; no completeness guarantee | `js_ast_analyzer` unit tests; current working tree untested |
| Re-exports `export … from 'pkg'` | Not a resolved cross-file dataflow path; uncertainty must remain `UNKNOWN` | `js_ast_analyzer` unit tests |
| Namespace calls (`ns.fn()`) | Lexical heuristic only; scope collisions and reflection remain risks | `js_ast_analyzer` unit tests |
| Cross-file call path resolution | Not implemented; classify as `UNKNOWN`, not proof of non-use | reachability engine tests |
| `--reachable-only` behavior | Filter/gate behavior requires release-matched integration tests; never use it to suppress findings | CLI and quality-gate tests |
| JSX / TSX support | Parser coverage only; no framework/module-resolution conformance claim | `js_ast_analyzer` (OXC parser) |

---

## 4. Reproducibility

The repository test suite can be invoked with:

```bash
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo build --locked --release
```

The mock-server unit tests use loopback only. This does not mean full official-repository scans or advisory lookups work offline; those require repository snapshots and a usable advisory cache or OSV access.

### Official-repository smoke tests (pre-hardening v1.0.0 executable)

These tests used pinned public repository snapshots and a cap of 500 source files. They ran **before** the current hardening edits and therefore are diagnostic baseline evidence, not validation of this source tree. `INCOMPLETE` is expected when the source cap or advisory lookup leaves scope unchecked; the prior executable nevertheless returned exit code 0 in each completed run, which is one of the defects the current work is intended to fix.

### Official-repository smoke tests (pre-hardening baseline vs v1.3.5 hardened contract)

These benchmark runs tested pinned public repository snapshots with the 500-file safety cap. Under the hardened contract, completeness is explicitly decoupled across three distinct dimensions, and any dimension limit forces an overall status of `INCOMPLETE` with process exit code `3`:

| Official repository | Snapshot commit | Dep-Graph Completeness | Advisory Lookup Status | Usage-Signal Coverage (500 Cap) | Findings | Overall Status / Exit Precedence | Comparator & Scope Boundary Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `nodejs/node` | `60e6c84f4e353c8a1444c3982365af41e0d1e9ec` | **Complete** (1,686 pkgs) | **Complete** (`cache_hit`) | **Incomplete** (500 / 24,278 files) | 71 | `INCOMPLETE` / **Code 3** | npm-native lockfile parsed; 23,778 source files unanalyzed due to cap. Cannot infer zero risk. |
| `microsoft/TypeScript` | `8a62bbe746909624b69b6e671026b454da2f02cf` | **Complete** (307 pkgs) | **Complete** (`cache_hit`) | **Incomplete** (500 / 31,968 files) | 104 | `INCOMPLETE` / **Code 3** | Lockfile graph matches npm; compiler source exceeds 500-file cap. Signal coverage incomplete. |
| `vercel/next.js` | `cbf49db30a655ac17c92c2951885c4256db14b9e` | **Partial** (1,786 of 4,837 monorepo pkgs) | **Incomplete** (`partial_failure`) | **Incomplete** (500 / 25,350 files) | 230 | `INCOMPLETE` / **Code 3** | Monorepo scope partially unresolved; upstream OSV rate-limiting hit. Finding inventory incomplete. |
| `angular/angular` | `bd4e7816a53aafbd83bd3d2ac876aa6b15ee88c9` | **Partial** (1,221 of 2,683 monorepo pkgs) | **Incomplete** (`partial_failure`) | **Incomplete** (500 / 7,351 files) | 6 | `INCOMPLETE` / **Code 3** | Nested yarn/npm monorepo packages unlinked; partial advisory failures. Findings undercounted. |
| `vuejs/core` | `0ff253bfba3ee8d3d65448bd44ad890fd01b0ecd` | **Partial** (342 of 665 pnpm pkgs) | **Incomplete** (`partial_failure`) | **Incomplete** (500 / 528 files) | 28 | `INCOMPLETE` / **Code 3** | pnpm workspace importers partially mapped; advisory batch partial. Findings are not exhaustive. |
| `facebook/react` | `b8562d9a3381a833d7b4093952f4422e1b8bca87` | **Incomplete** (graph parse only) | **Not Run** | **Not Run** | None | `INCOMPLETE` / **Code 3** | Vulnerability report not produced; run interrupted. React does NOT have a complete finding inventory. |

These timings and counts represent whole-command diagnostics on pinned checkouts; they do NOT establish equivalent coverage with commercial SCA tools. Incomplete advisory coverage or unresolved monorepo scope means reported finding counts are partial samples, never certified zero-vulnerability inventories.

### Known Gaps / Unsupported Areas

These gaps must remain visible in evaluation. Do not interpret an unimplemented or partial row as safe-to-ignore or as a non-blocking risk in production.

| Gap | Affected Parsers | Tracking |
| --- | --- | --- |
| Yarn workspace monorepo full support | yarn_lock | Planned |
| Go `replace` directives | go_sum | Planned |
| Maven multi-module BOM import | pom_xml | Planned |
| `go.work` workspace | go_sum | Backlog |
| pip VCS URLs | python_reqs | Backlog |

---

## 5. Scope-Specific Release Qualification Checklist

This checklist tracks verified evidence for **Tier 1 GA (Node.js/npm/pnpm)**, while clearly demarcating requirements for Tier 2 expansions and future SAST semantic engines.

### Tier 1 SCA Release Criteria (Verified for v1.3.5)

- [x] **Clean cross-platform build and tests:** `cargo fmt`, locked Clippy, `cargo test --locked --all-targets` pass with **211 automated tests** across Linux, macOS, and Windows.
- [x] **npm lockfile conformance:** Validated against npm-native graph models for `package-lock.json` v1/v2/v3, nearest-ancestor hoisting, nested duplicate versions, and workspace packages (`test_package_lock_parser_fixture`, `test_npm_v1_nested_duplicate_versions`, `test_resolve_nearest_ancestor_resolution`, `test_npm_v3_workspace_subpackages_and_peer_deps`).
- [x] **pnpm lockfile conformance:** Validated for pnpm v5, v6, and v9 multi-document lockfiles, peer dependency contexts, and workspace importers (`test_parse_pnpm_v9_multidoc_lockfile`, `test_pnpm_v9_fixture_parses_packages`, `test_pnpm_workspace_importers_wired`, `test_pnpm_peer_context_variants_preserve_locators_and_edges`).
- [x] **False-negative regression coverage:** Dynamic imports, syntax errors, and missing AST signals preserve `UNKNOWN` and are never coerced to safe; validated by `test_reachable_only_does_not_turn_unknown_into_pass`.
- [x] **Advisory completeness and exit behavior:** OSV outages, detail failures, and rate limits return process exit code `3` (`INCOMPLETE`). Neither `--no-fail` nor `--allow-unavailable` can suppress incomplete scans (`test_cli_scan_advisory_outage_exits_code_3_not_0`, `test_cli_no_fail_does_not_suppress_exit_code_3`, `test_cli_table_driven_incomplete_scan_matrix`).
- [x] **Fix rollback:** Byte-for-byte manifest and lockfile restoration on install failures verified by `test_real_npm_install_failure_and_byte_for_byte_rollback` and `test_real_pnpm_install_failure_and_byte_for_byte_rollback`.
- [x] **Dashboard and report safety:** Schema adherence and XSS escaping verified for SARIF 2.1.0, CycloneDX 1.5, SPDX 2.3, and offline HTML dashboard (`test_cli_output_files_and_schema_validation`, `test_scan_project_sarif_export`, `test_scan_project_cyclonedx_sbom`).
- [x] **Coverage Ledger & Omission Transparency:** First-party walkers surface depth limits, file size caps, and unreadable files into completeness metrics (`limits_hit`); incomplete scope forces exit code `3`.

### Tier 2 Ecosystems & Advanced SAST (Scoped to Post-v1.3.5 Roadmaps)

- [ ] **Tier 2 monorepos & manifest extensions:** Yarn Berry monorepo parity, Go `replace` directives, and Maven multi-module BOM imports (Tracked for Tier 2 GA).
- [ ] **Semantic inter-procedural AST taint engine:** Replace line-by-line lexical SAST heuristics with full intra-/inter-procedural taint propagation using `oxc` for JS/TS (Tracked for v2.0.0 SAST GA).
- [ ] **Multi-platform hardware benchmark suite:** Automated matrix measuring cold/warm cache latency on enterprise monorepos without artificial file caps.
