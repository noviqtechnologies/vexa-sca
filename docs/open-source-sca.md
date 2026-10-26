# Vexa SCA Open Source: Architectural & Operational Guide (GA v1.2.0)

## Executive Summary

**Vexa SCA** is an open-source, high-performance Software Composition Analysis (SCA) engine built in Rust. It is **Generally Available (GA v1.2.0)** for Tier 1 ecosystems (Node.js / JavaScript / TypeScript: `package-lock.json` v2/v3, `npm-shrinkwrap.json`, `pnpm-lock.yaml` v5/v6/v9), providing enterprise-grade dependency auditing, PR-differential baseline scanning, policy enforcement, CycloneDX/SPDX SBOM generation, and automated same-major remediation proposals.

### Key Capabilities at GA
- **Zero-Dependency Native Core:** Pure Rust execution with zero external C / OpenSSL dependencies (`rustls-tls`). Single static binaries for Linux, macOS, and Windows.
- **Repository Usage Signals:** AST inspection flags directly referenced dependencies (`IMPORTED_SOURCE`, `REFERENCED_CONFIG_OR_SCRIPT`) while preserving verdict integrity (conservative `UNKNOWN`, never false-safe suppression).
- **Automated Remediation (`fix`):** Prioritizes non-breaking same-major patch and minor updates with byte-for-byte rollback protection for captured root manifests and lockfiles.
- **Deterministic DevSecOps Exit Codes:** Strict precedence contract (`2` > `3` > `1` > `0`) for seamless pipeline integration.
- **Schema-Conformant Exports:** Verified compliance with OASIS SARIF v2.1.0, CycloneDX v1.5 JSON, and SPDX v2.3 JSON schemas.

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

The source analyzer matches selected syntactic patterns. It does not establish execution, taint flow, exploitability, or absence of use. It can miss or misattribute dynamic loading, reflection, cross-file imports, framework/plugin entry points, workspace boundaries, unsupported syntax, and bundler resolution. `--reachable-only` is a presentation filter, not a safe vulnerability policy. Severity gates must include the complete unsuppressed finding set.

## Remediation helper boundaries

The fixer is not an isolated transaction and does not validate application compatibility. It may modify a root manifest and invoke the detected package manager. Restoration attempts cover captured root files on failure; package-manager side effects, nested files, `node_modules`, network/registry effects, and other filesystem changes are outside that rollback guarantee. Use a disposable worktree, review the diff, and run all project tests/builds before accepting changes.

## Distribution and deployment

No mutable `latest` URL or tag is approved by this guide. Before running a release binary or container, require an immutable digest, verified source revision, trustworthy signature/attestation, and release tests tied to that exact source. The repository's checksum workflow by itself does not establish signed provenance. If those controls are absent, build from a reviewed commit in a controlled environment. Container and OS-image scanning remain experimental.

## Central policy and governance

Policy files live with individual repositories. There is no centralized SaaS dashboard, organization-wide waiver analytics, or managed policy distribution in this project. Teams with hundreds of developers must use their existing configuration management, code-owner review, expiry tracking, and exception governance systems.

## Production Adoption & Support
 
Vexa SCA v1.2.0 is **production-ready for Tier 1 environments** (Node.js/npm/pnpm). Organizations can integrate `vexa-sca ci` into GitHub Actions, GitLab CI, and other automation pipelines as an authoritative quality gate. For teams evaluating non-Tier-1 ecosystems (Python, Java, Go, Rust, Container OS), preview scans should be run alongside established controls while ecosystem-specific tests continue to expand. Full validation evidence is documented in [RELEASE_VALIDATION.md](../RELEASE_VALIDATION.md).
