# Vexa SCA CLI Usage Guide

## Status and safe use

Vexa SCA is **pre-GA**. Keep it report-only while validating its output on your package-manager versions and representative repositories. Do not replace an established SCA control, use usage signals to suppress vulnerability findings, or treat a clean exit as proof of complete coverage. The [compatibility matrix](../COMPATIBILITY_MATRIX.md) records implementation targets and evidence limits.

The primary implementation target is Node.js / JavaScript / TypeScript, but complete npm, pnpm, Yarn, workspace, or TypeScript semantics are not established. Other ecosystems and container/OS parsing are experimental. Current source changes have not passed a clean Rust build and test run on Linux, macOS, and Windows.

## Build from reviewed source

For evaluation, use a full commit SHA reviewed by your organization and the locked dependency set:

```sh
cargo build --locked --release
```

Run the resulting executable from the repository's `target/release` directory. Do not install from a moving branch or use a release artifact unless its source revision, digest/signature or attestation, and release-test provenance have been independently verified. The current release workflow's checksum alone is not a signed provenance chain.

## Scan and inspect

Run a basic scan from the project root:

```sh
vexa-sca scan
```

A successful parse is not proof that every manifest, workspace importer, lockfile edge, or source construct was covered. Review diagnostics, identified manifests, dependency counts, and the completeness status before interpreting findings.

The analyzer emits heuristic **Repository Usage Signals** based on selected syntactic patterns. It does not prove runtime reachability or exploitability and does not model general cross-file dataflow, control flow, reflection, all dynamic imports, or every bundler/workspace rule. Use `--reachable-only` only to filter presentation for triage; severity gates must evaluate the complete unsuppressed finding set. Do not use `--allow-unknown-reachability` or `--fail-on-reachable` as a substitute for a validated security policy.

The scanner sends package coordinates to OSV for advisory lookup. Review that data flow against your privacy requirements. `.sca-cache/` can reduce repeat queries but is not a complete, signed, or indefinitely fresh offline advisory database.

## Reports

The CLI exposes report formats such as JSON, SARIF, Markdown, HTML, and SBOM output; validate each artifact against the downstream consumer and schema version you use. Example for an HTML report:

```sh
vexa-sca scan --html-file sca-report.html
```

The HTML report is intended to be self-contained, but it reflects only the scan inputs and findings actually produced; an offline report does not imply an offline-complete vulnerability database.

## Exit behavior for automation

The intended exit-code contract in the current source is:

| Code | Meaning |
|---:|---|
| `0` | No configured gate failure was found in the processed data. This is not a completeness certificate. |
| `1` | A configured quality gate failed. |
| `2` | Invalid arguments or policy/configuration. |
| `3` | Scan data is incomplete, including relevant advisory, manifest, source-read/traversal, or analysis-limit failures. |

`--allow-unavailable` is limited to advisory-only unavailability; it must not waive source or manifest failures. `--no-fail` applies to quality-gate failures only; it must not turn configuration errors or incomplete scans into success. These changes still require release-matched tests on all supported operating systems before they can be treated as a production contract.

During evaluation, make the job non-blocking and archive outputs. Before enforcement, independently test a clean scan, a finding that violates a gate, malformed policy, unreadable source, malformed/unsupported manifest, advisory timeout/detail failure, and the advisory-only override. Confirm that reports are preserved on every outcome.

## Remediation helper

`vexa-sca fix --dry-run` is intended to preview proposals. Before applying changes, use a clean worktree and review the entire diff; then run the package manager, application tests, and build yourself. The helper may edit the root manifest and invoke package-manager lockfile regeneration. On failure, it attempts to restore captured root manifests/lockfiles, but it does not roll back `node_modules`, nested workspace files, registry effects, or arbitrary process side effects. Do not auto-merge generated changes.

## Policy files

Policy is repository-local (`.vexa-sca` or `.vexa-sca.json`); this project does not provide a centralized policy distribution or organization-wide waiver dashboard. Validate policy changes in review, require named ownership and expiry for exceptions, and monitor waivers through your existing governance systems.
