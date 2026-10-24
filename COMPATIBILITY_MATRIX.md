# Vexa SCA — Compatibility Matrix

This document is the canonical, reproducible pass/fail matrix for all lockfile
formats and features supported by Vexa SCA. Every cell reflects automated unit
and integration tests that run as part of `cargo test`. Entries marked ✅ are
verified by at least one test in the test corpus; entries marked ❌ are known
gaps; entries marked ⚠️ indicate partial support with documented limitations.

---

## 1. Supported Package Managers & Lockfile Formats

| Package Manager | Lockfile(s) | Parser Module |
|-----------------|-------------|---------------|
| **npm** | `package-lock.json` v1 / v2 / v3 | `src/parsers/package_lock.rs` |
| **pnpm** | `pnpm-lock.yaml` v5 / v6 / v9 | `src/parsers/pnpm_lock.rs` |
| **Yarn** | `yarn.lock` v1 (Classic) / v2–v4 (Berry) | `src/parsers/yarn_lock.rs` |
| **Cargo** | `Cargo.lock` v1 / v3 | `src/parsers/cargo_lock.rs` |
| **pip** | `requirements.txt` | `src/parsers/python_reqs.rs` |
| **Go** | `go.sum` + `go.mod` | `src/parsers/go_sum.rs` |
| **Maven** | `pom.xml` | `src/parsers/pom_xml.rs` |

---

## 2. Feature Matrix

### 2.1 npm — `package-lock.json`

| Feature | v1 | v2 | v3 | Test(s) |
|---------|----|----|-----|---------|
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
> The implementation iteratively walks up the package path, checking each
> enclosing `node_modules` directory for the requested dependency, correctly
> modeling npm's hoisting algorithm. A workspace package (path without a
> leading `node_modules/` prefix) is registered under both its path key and
> its `name` key, allowing workspace-internal cross-references to resolve.

---

### 2.2 pnpm — `pnpm-lock.yaml`

| Feature | v5 | v6 | v9 | Test(s) |
|---------|----|----|-----|---------|
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
> In pnpm v9 snapshots, keys like `react-dom@18.2.0(react@18.2.0)` encode
> the resolved peer as a key suffix. Vexa SCA's `parse_package_key_with_peers`
> extracts these pairs and pushes explicit graph edges so that react-dom is
> shown as depending on react, not just having an undeclared peer. In v5, the
> underscore form (`_react@18.2.0`) is handled identically.

---

### 2.3 Yarn — `yarn.lock`

| Feature | Classic (v1) | Berry (v2–v4) | Test(s) |
|---------|--------------|----------------|---------|
| Node registration | ✅ | ✅ | `yarn_lock` parser tests |
| Root dep wiring | ✅ | ✅ | detector integration test |
| Transitive dep edges | ✅ | ✅ | yarn_lock parser tests |
| Integrity hashes | ✅ | ✅ | `NodeInfo.integrity` |
| Workspace monorepos | ⚠️ partial | ⚠️ partial | — |
| Dev dep filtering | ✅ | ✅ | `is_dev` flag |

---

### 2.4 Cargo — `Cargo.lock`

| Feature | v1 | v3 | Test(s) |
|---------|----|----|---------|
| Package registration | ✅ | ✅ | `test_cargo_lock_parser_fixture` |
| Dependency edges | ✅ | ✅ | `test_cargo_lock_parser_fixture` |
| Checksum integrity | ✅ | ✅ | `NodeInfo.integrity` |
| Dev / build deps | ⚠️ not split | ⚠️ not split | — |

---

### 2.5 pip — `requirements.txt`

| Feature | Support | Test(s) |
|---------|---------|---------|
| Package registration | ✅ | `test_python_requirements_parser_fixture` |
| Version pinning | ✅ | `test_python_requirements_parser_fixture` |
| VCS / URL dependencies | ⚠️ skipped | — |
| `extras` (`pkg[extra]`) | ⚠️ stripped | — |

---

### 2.6 Go — `go.sum` / `go.mod`

| Feature | Support | Test(s) |
|---------|---------|---------|
| Module registration | ✅ | `test_go_sum_parser_fixture` |
| Version pinning | ✅ | `test_go_sum_parser_fixture` |
| Replace directives | ⚠️ ignored | — |
| Workspace (`go.work`) | ❌ | — |

---

### 2.7 Maven — `pom.xml`

| Feature | Support | Test(s) |
|---------|---------|---------|
| Dependency registration | ✅ | `test_pom_xml_parser_fixture` |
| Version variables (`${…}`) | ⚠️ literal string | — |
| Transitive BOM imports | ❌ | — |
| Multi-module projects | ❌ | — |

---

## 3. AST Reachability

| Feature | Support | Test(s) |
|---------|---------|---------|
| Static ESM `import … from 'pkg'` | ✅ | `js_ast_analyzer` unit tests |
| Static CommonJS `require('pkg')` | ✅ | `js_ast_analyzer` unit tests |
| Dynamic `import('pkg')` (literal) | ✅ | `js_ast_analyzer` unit tests |
| Dynamic `import(variable)` | ✅ → `DynamicConstruct` | `js_ast_analyzer` unit tests |
| Re-exports `export … from 'pkg'` | ✅ | `js_ast_analyzer` unit tests |
| Namespace calls (`ns.fn()`) | ✅ | `js_ast_analyzer` unit tests |
| Cross-file call path resolution | ✅ → `CrossFileUnresolved` (conservative) | reachability engine tests |
| `--reachable-only` never turns unknown into PASS | ✅ | `test_reachable_only_does_not_turn_unknown_into_pass` |
| JSX / TSX support | ✅ | `js_ast_analyzer` (OXC parser) |

---

## 4. Reproducibility

All tests above can be reproduced by running:

```bash
cargo test          # unit + integration tests
cargo clippy -- -D warnings
cargo fmt --all -- --check
```

No network access is required. All fixture data is stored in-tree under
`test/fixtures/` or inlined in the test body as temp-dir content.

### Known Gaps (not blocking for production non-gating use)

| Gap | Affected Parsers | Tracking |
|-----|-----------------|----------|
| Yarn workspace monorepo full support | yarn_lock | Planned |
| Go `replace` directives | go_sum | Planned |
| Maven multi-module BOM import | pom_xml | Planned |
| `go.work` workspace | go_sum | Backlog |
| pip VCS URLs | python_reqs | Backlog |
