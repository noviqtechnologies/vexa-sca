# Vexa SCA CI/CD Evaluation Guide

## Scope and status

Vexa SCA is **pre-GA**. The workflow below is for non-blocking evaluation only; it is not a production security gate or endorsement. Keep the existing SCA control in place. Do not let heuristic repository usage signals suppress findings. The current source changes have not yet passed the full build/test matrix on Linux, macOS, and Windows.

Before any CI rollout, pin every third-party action/task to a reviewed immutable revision, build Vexa SCA from a full reviewed commit SHA or use a provenance-verified artifact, and retain the exact source commit, build log, tool version, raw reports, and scan diagnostics. Do not download mutable `latest` binaries or containers. The current release checksum workflow does not by itself establish signed build provenance.

## Safe evaluation sequence

1. Use an isolated runner with a pinned Rust toolchain and least-privilege repository permissions.
2. Build the scanner from a full source SHA approved by your organization, with `--locked` dependencies.
3. Run scans report-only; keep incomplete-scan exit code `3` visible as a failed/incomplete evaluation rather than converting it into a clean result.
4. Preserve any reports that were produced even when the scan step fails. A missing report is not a clean scan.
5. Compare inventory and advisory results against package-manager-native dependency output and an established SCA control.
6. Test OSV timeouts, pagination/detail errors, malformed manifests, unsupported workspaces, source read errors, scan limits, and cache misses.
7. Repeat scanner build/tests on Linux, macOS, and Windows before GA; test target repository scans separately on the runner OSes you intend to use.

Example shell commands for a controlled evaluation runner (set `VEXA_REVIEWED_SHA` to an approved full SHA):

Set `SCANNER_DIR` to a location outside the project being scanned and `TARGET_DIR` to the checkout under evaluation. This POSIX-shell example must be adapted to the runner's native shell on Windows.

```sh
mkdir -p "$(dirname "$SCANNER_DIR")"
git clone https://github.com/noviqtechnologies/vexa-sca.git "$SCANNER_DIR"
git -C "$SCANNER_DIR" checkout --detach "$VEXA_REVIEWED_SHA"
cargo build --locked --release --manifest-path "$SCANNER_DIR/Cargo.toml"
"$SCANNER_DIR/target/release/vexa-sca" scan "$TARGET_DIR" \
  --no-fail \
  --json > vexa-results.json
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

## Before enabling enforcement

Enforcement requires a separate approval after all of these are evidenced: clean locked build and tests on Linux/macOS/Windows; npm lockfile v2/v3 and pnpm/Yarn workspace conformance; official-repository scans within a documented source cap; failure-injection evidence for advisory and source incompleteness; independently validated SARIF/SBOM outputs; release artifact provenance; and a tested rollback/upgrade plan. Until then, Vexa SCA is supplementary reporting only.
