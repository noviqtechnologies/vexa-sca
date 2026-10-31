# Vexa SCA Open Source: Architectural & Operational Guide (v2.0 / GA v1.2.0+)

## Executive Summary

**Vexa SCA** is an open-source, high-performance Software Composition Analysis (SCA) engine built in Rust. It is **Generally Available (GA v1.2.0+)** for Tier 1 ecosystems (Node.js / JavaScript / TypeScript: `package-lock.json` v2/v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v5/v6/v9), providing enterprise-grade dependency auditing, PR-differential baseline scanning, policy enforcement, CycloneDX/SPDX SBOM generation, and automated same-major remediation proposals.

Starting with v2.0, the reachability engine has been substantially improved per the **Stage 1A Handover** milestone:

| Bug Fixed | Description |
|---|---|
| **BUG-002** | Eliminated O(F×V) re-parsing: single-pass `WorkspaceAstIndex` built once at startup |
| **BUG-003** | Non-JS files (`.py`, `.rs`, `.go`, `.java`) are no longer fed to `oxc_parser`; language-appropriate analyzers dispatch correctly |
| **BUG-004** | `UNREACHABLE` verdict now emitted when AST coverage is complete and no call site is found (strict positive-proof, all guards cleared) |
| **BUG-005** | Monorepo multi-scope no longer incorrectly downgrades all `Reachable` findings to `Unknown` |

### Key Capabilities at GA
- **Zero-Dependency Native Core:** Pure Rust execution with zero external C / OpenSSL dependencies (`rustls-tls`). Single static binaries for Linux, macOS, and Windows.
- **Single-Pass Multi-Language AST Index:** `WorkspaceAstIndex` indexes JS/TS (oxc), Python, Rust, Go, and Java source files in one pass, building inverted indexes (`package_importers`, `symbol_calls`) for O(1) per-vulnerability lookup.
- **Repository Usage Signals:** AST inspection flags directly referenced dependencies (`IMPORTED_SOURCE`, `REFERENCED_CONFIG_OR_SCRIPT`) while preserving verdict integrity (conservative `UNKNOWN`, never false-safe suppression). `UNREACHABLE` is only emitted when all coverage guards are satisfied.
- **Automated Remediation (`fix`):** Prioritizes non-breaking same-major patch and minor updates with byte-for-byte rollback protection for captured root manifests and lockfiles.
- **Deterministic DevSecOps Exit Codes:** Strict precedence contract (`2` > `3` > `1` > `0`) for seamless pipeline integration.
- **Schema-Conformant Exports:** Verified compliance with OASIS SARIF v2.1.0, CycloneDX v1.5 JSON, and SPDX v2.3 JSON schemas.

## Reachability Verdict Classification (v2.0)

The engine produces one of four reachability statuses for each vulnerability:

| Status | Meaning | Guards That Must Be Clear |
|---|---|---|
| `Reachable` | Import + call site confirmed in production source | — |
| `Unknown` | Coverage incomplete: parse fail, file limit, dynamic import, transitive dep, or no symbol data | — |
| `Unreachable` | **Positive-proof absence**: full coverage, no import or call site found | `file_limit_hit=false`, `parse_failed=false`, `unresolved_dynamic=false`, `has_reexports=false`, `is_transitive=false` |
| `Unknown` (barrel re-export) | Package is re-exported (`export * from 'pkg'`) — downstream usage unanalyzable | Any re-export flag set |

> [!IMPORTANT]
> `UNREACHABLE` is **never** emitted as a default. It requires all five guards to pass simultaneously. Any ambiguity falls back to `UNKNOWN`.

## Dependency inputs and compatibility

See [COMPATIBILITY_MATRIX.md](../COMPATIBILITY_MATRIX.md) for parser targets, fixture evidence, and explicit gaps. In particular:

- `package-lock.json` v2/v3, pnpm peer contexts/importers/workspaces, and Yarn generations need release-matched conformance testing against real package-manager outputs.
- A committed lockfile improves reproducibility but does not guarantee Vexa SCA parsed every dependency edge.
- Monorepos, aliases, optional/peer dependencies, platform-specific packages, generated manifests, and nested workspaces must be tested in your own layouts.
- Python, Rust, Go, Java, and OS package analysis are experimental unless a passing ecosystem-specific conformance suite demonstrates otherwise.

## Network, data handling, and cache

The scanner sends package names and versions to OSV for advisory lookups. Check this data flow against your privacy and egress requirements. `.sca-cache/` may reduce repeat requests, but it is not a complete, signed, or indefinitely fresh offline advisory snapshot. Do not advertise air-gapped or offline-complete vulnerability coverage based on cache hits.

## Safe evaluation workflow

1. Build from a reviewed full source commit SHA with the locked dependency set; do not use a moving branch or unverified mutable release/container tag.
2. Run Vexa SCA non-blocking against a representative repository set and retain raw reports and diagnostics.
3. Compare dependency inventories and advisory findings with an established SCA tool and package-manager-native dependency output.
4. Include malformed/unsupported manifests, monorepos, npm lockfile v2/v3, pnpm peer/workspace cases, dynamic imports, source-read errors, OSV timeouts, and cache misses in regression fixtures.
5. Verify on Linux, macOS, and Windows, including report paths, file replacement behavior, and package-manager failure handling.
6. Do not promote to enforcement until incomplete scans are distinguishable from clean scans and all acceptance gates pass on the exact release artifact.

Example evaluation command:

```sh
vexa-sca scan
```

Use the CLI guide for report and exit behavior. A zero exit is not a coverage certificate; inspect completeness and diagnostics.

## Usage signals: triage only

The source analyzer matches selected syntactic patterns using a **single-pass `WorkspaceAstIndex`** built at engine startup. It analyzes:

- **JavaScript / TypeScript**: Full AST parsing via `oxc` — ESM `import`, CJS `require()`, dynamic `import()`, barrel re-exports, and named call sites.
- **Python**: Regex-based `import pkg`, `from pkg import fn`, and `alias.fn()` call-site detection.
- **Rust**: `use crate::pkg::fn` import detection plus direct named function call matching (`fn_name(...)`).
- **Go / Java**: Import statement scanning and method invocation patterns.

Verdict integrity guarantees:
- `UNREACHABLE` is only emitted when the index fully covered all source files (no file-limit hit, no parse failures, no unresolved dynamic imports, no barrel re-exports, not a transitive dependency) **and** no import or call site was found.
- All other cases produce `UNKNOWN` — missing signals do not certify absence of use.

It does not establish execution, taint flow, exploitability, or general absence of use. It can miss or misattribute: dynamic loading, reflection, cross-file imports via barrel re-exports, framework/plugin entry points, workspace boundaries, unsupported syntax, and bundler resolution. `--reachable-only` is a presentation filter, not a safe vulnerability policy. Severity gates must include the complete unsuppressed finding set.

## Remediation helper boundaries

The fixer is not an isolated transaction and does not validate application compatibility. It may modify a root manifest and invoke the detected package manager. Restoration attempts cover captured root files on failure; package-manager side effects, nested files, `node_modules`, network/registry effects, and other filesystem changes are outside that rollback guarantee. Use a disposable worktree, review the diff, and run all project tests/builds before accepting changes.

## Distribution and deployment

No mutable `latest` URL or tag is approved by this guide. Before running a release binary or container, require an immutable digest, verified source revision, trustworthy signature/attestation, and release tests tied to that exact source. The repository's checksum workflow by itself does not establish signed provenance. If those controls are absent, build from a reviewed commit in a controlled environment. Container and OS-image scanning remain experimental.

## Central policy and governance

Policy files live with individual repositories. There is no centralized SaaS dashboard, organization-wide waiver analytics, or managed policy distribution in this project. Teams with hundreds of developers must use their existing configuration management, code-owner review, expiry tracking, and exception governance systems.

## Production Adoption & Support
 
Vexa SCA v1.2.0 is **production-ready for Tier 1 environments** (Node.js/npm/pnpm). Organizations can integrate `vexa-sca ci` into GitHub Actions, GitLab CI, and other automation pipelines as an authoritative quality gate. For teams evaluating non-Tier-1 ecosystems (Python, Java, Go, Rust, Container OS), preview scans should be run alongside established controls while ecosystem-specific tests continue to expand. Full validation evidence is documented in [RELEASE_VALIDATION.md](../RELEASE_VALIDATION.md).

---

## Supply Chain Behavioral Analysis (v2.0)

Starting with v2.0, Vexa SCA includes a **static supply chain behavioral analyzer** (`supply_chain::local_analyzer`) that runs as part of every `vexa-sca scan` without requiring external tools, containers, or network calls.

The analyzer produces `SupplyChainFinding` records with rule ID, severity, affected file, and a human-readable message. Findings appear in all report formats (JSON, SARIF, HTML).

### Supply Chain Rules Reference (SC-001 – SC-015)

| Rule ID | Signal Name | Severity | Detection Logic |
| :--- | :--- | :--- | :--- |
| SC-001 | `PostInstall` | 🔴 High | `postinstall` / `preinstall` / `prepare` lifecycle scripts in `package.json` — common initial-access vector |
| SC-002 | `SuspiciousUrl` | 🔴 High | Plain HTTP download URLs (`http://`) in scripts, manifests, or CI workflows — enables MITM substitution |
| SC-003 | `EnvExfiltration` | 🔴 High | Env var reads (`process.env`, `os.environ`, `std::env::var`) adjacent to network egress patterns |
| SC-004 | `ObfuscatedCode` | 🟠 Medium | Shannon entropy > 4.5 bits per character in short string literals — indicator of packed/base64 payloads |
| SC-005 | `SuspiciousScript` | 🟠 Medium | Shell commands (`curl`, `wget`, `bash -c`, `eval`) embedded inside `scripts` blocks or install hooks |
| SC-006 | `CiCdPoisoning` | 🔴 High | Mutable `@latest` tags or unversioned branch references in GitHub Actions `uses:` fields (not pinned to SHA) |
| SC-007 | `SecretsInCode` | 🔴 High | Hardcoded credential patterns: `api_key`, `password`, `secret`, `token` assignments in source or config files |
| SC-008 | `UnpinnedDependency` | 🟡 Low | Semver ranges (`^`, `~`, `>=`, `*`) in manifests — lock files mitigate but ranges still enable supply chain drift |
| SC-009 | `SuspiciousAuthor` | 🟠 Medium | Package `author` or `maintainer` email domains on known compromised/malicious domain lists |
| SC-010 | `Typosquatting` | 🔴 High | Package name within Damerau-Levenshtein edit distance ≤ 1 from a curated list of popular packages (e.g. `loadsh` → `lodash`) |
| SC-011 | `ReverseShell` | 🔴 Critical | Reverse shell command patterns: `bash -i`, `/dev/tcp/`, `nc -e /bin/sh`, `mkfifo /tmp/f` |
| SC-012 | `TrojanSource` | 🔴 High | Unicode bidirectional control characters (U+202A–U+202E, U+2066–U+2069, U+200F) in source files (CVE-2021-42574) |
| SC-013 | `McpPromptInjection` | 🔴 High | Instruction-following prompt patterns in MCP server `description` or `tool.description` fields (`.cursor/mcp.json`, `mcp_config.json`) |
| SC-014 | `ShadowDependency` | 🟠 Medium | Packages resolvable from lockfile but not declared in the root manifest — phantom/shadow dependency risk |
| SC-015 | `RegistryConfusion` | 🔴 High | Scoped packages (`@org/pkg`) with mixed public/private registry origins without explicit `--registry` or `.npmrc` binding |

### Scanned File Categories

| Category | Files Inspected |
| :--- | :--- |
| GitHub Actions workflows | `.github/workflows/*.yml`, `.github/workflows/*.yaml` |
| MCP configuration | `.cursor/mcp.json`, `mcp_config.json`, `*.mcp.json` |
| Package manifests | `package.json`, `Cargo.toml`, `pyproject.toml`, `requirements*.txt`, `pom.xml` |
| Source files | `*.js`, `*.ts`, `*.py`, `*.rs`, `*.go`, `*.java`, `*.sh` |

---

## CISA Known Exploited Vulnerabilities (KEV) Integration (v2.0)

Every vulnerability finding is cross-referenced against the **CISA Known Exploited Vulnerabilities (KEV) catalog**. A CVE present in the KEV catalog means it has been **confirmed exploited in the wild** by threat actors.

### How it works

- The KEV catalog is fetched from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` and cached at `.sca-cache/cisa_kev.json` with a **24-hour TTL**.
- If the network is unreachable, a **builtin fallback catalog** of critical CVEs (Log4Shell, Spring4Shell, ProxyLogon, etc.) is used.
- When a finding's CVE is in KEV:
  - `is_kev: true` is set on the `VulnerabilityFinding`
  - `kev_date_added` records the CISA-published date
  - **+35 points** are added to the deterministic priority score, elevating KEV findings above non-KEV findings at the same CVSS severity

### Priority score formula

```
priority_score = cvss_base_score × severity_multiplier
              + epss_probability × 30
              + if(is_kev, 35, 0)
              + usage_signal_bonus (IMPORTED_SOURCE: +10, REFERENCED: +5)
              + if(is_direct, 5, 0)
```

> [!IMPORTANT]
> KEV status elevates priority score but does not automatically fail scans. Use `--fail-on critical` or `--fail-on high` to gate on severity. All KEV findings are visible in JSON (`"is_kev": true`) and highlighted in the HTML dashboard.

---

## CWE & OWASP Classification (v2.0)

Vulnerability findings are enriched with **CWE (Common Weakness Enumeration)** and **OWASP Top 10 (2021)** classifications from the OSV advisory metadata.

### CWE Top 25 (2025) coverage

The built-in `cwe_owasp_map` covers all **CWE Top 25 Most Dangerous Software Weaknesses (2025 edition)**, including:

| CWE ID | Weakness | OWASP Category |
| :--- | :--- | :--- |
| CWE-787 | Out-of-bounds Write | A03: Injection |
| CWE-79 | Cross-site Scripting (XSS) | A03: Injection |
| CWE-89 | SQL Injection | A03: Injection |
| CWE-416 | Use After Free | A06: Vulnerable Components |
| CWE-78 | OS Command Injection | A03: Injection |
| CWE-20 | Improper Input Validation | A03: Injection |
| CWE-125 | Out-of-bounds Read | A06: Vulnerable Components |
| CWE-22 | Path Traversal | A01: Broken Access Control |
| CWE-352 | CSRF | A01: Broken Access Control |
| CWE-434 | Unrestricted File Upload | A04: Insecure Design |
| CWE-862 | Missing Authorization | A01: Broken Access Control |
| CWE-476 | NULL Pointer Dereference | A06: Vulnerable Components |
| CWE-287 | Improper Authentication | A07: Auth Failures |
| CWE-190 | Integer Overflow | A06: Vulnerable Components |
| CWE-502 | Deserialization of Untrusted Data | A08: Software Integrity Failures |
| CWE-77 | Command Injection | A03: Injection |
| CWE-119 | Buffer Errors | A06: Vulnerable Components |
| CWE-798 | Hard-coded Credentials | A07: Auth Failures |
| CWE-918 | SSRF | A10: SSRF |
| CWE-306 | Missing Authentication | A07: Auth Failures |

CWE/OWASP labels appear in JSON output (`cwe_ids`, `owasp_categories`) and the HTML dashboard finding inspector panel.
