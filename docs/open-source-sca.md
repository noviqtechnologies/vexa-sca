# Vexa SCA Open Source: Evaluation Guide

## Executive summary

Vexa SCA is a **pre-GA** Rust software-composition-analysis project. It parses supported manifests/lockfiles, queries OSV, emits reports, provides heuristic repository usage signals, and includes a best-effort dependency-fix helper. This guide does not establish enterprise throughput, complete ecosystem conformance, runtime reachability, safe automated remediation, or production-grade artifact provenance.

Keep Vexa SCA report-only while validating it on your own repositories. Do not replace an established SCA control based only on feature descriptions or a successful sample scan. Current source changes still require a clean build and full test run on Linux, macOS, and Windows.

## What it does—and does not establish

| Area | Current evidence-bound description | Required operational posture |
|---|---|---|
| Dependency inventory | Parsers exist for the inputs listed in the [compatibility matrix](../COMPATIBILITY_MATRIX.md). Fixture coverage is not proof of complete package-manager semantics. | Compare against the package manager's own resolved graph on representative repositories. |
| Advisory lookup | Package coordinates are queried against OSV; pagination/detail errors and upstream availability affect completeness. | Preserve incomplete status; monitor upstream errors; do not interpret a partial result as clean. |
| Repository usage signals | Selected syntactic import/call-site evidence is available for triage. | Never call it runtime reachability or exploitability proof, and never use it to suppress severity findings. |
| Remediation | A helper proposes manifest changes and regenerates lockfiles through package managers. | Use a clean worktree, review every diff, run tests, and treat rollback as best-effort for captured files only. |
| Policy | Local repository policy files are supported. | Organization-wide distribution, analytics, or centralized exception governance is not included. |
| Reports | JSON, SARIF, Markdown, HTML, and SBOM-related command surfaces exist. | Independently validate schema, completeness, and downstream ingestion. |
| Non-Node ecosystems and container/OS inputs | Experimental; coverage must be validated by ecosystem and distribution. | Do not rely on these results as the sole production control. |

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

## Adoption position

**Do not adopt as a production SCA replacement today.** A constrained, report-only pilot is reasonable only if results are independently compared, source and artifact provenance are controlled, and missing coverage is treated as unknown. Reassess after cross-platform tests, package-manager conformance evidence, scan-completeness regressions, and release-integrity controls are available.
